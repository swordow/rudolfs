// Copyright (c) 2021 Jason White
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
mod app;
mod error;
mod hyperext;
mod lfs;
mod logger;
mod lru;
mod sha256;
mod storage;
mod util;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::fs;
use std::io;
use std::pin::Pin;
use futures_util;
use async_stream::stream;
use rustls;
use rustls::internal::pemfile;
use core::task::{Context, Poll};
use std::vec::Vec;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use futures::future::{self, Future, TryFutureExt};
use futures::stream::Stream;
use hyper::{
    self,
    server::conn::{AddrIncoming, AddrStream},
    service::make_service_fn,
};

use crate::app::App;
use crate::error::Error;
use crate::logger::Logger;
use crate::storage::{Cached, Disk, Encrypted, Retrying, Storage, Verify, S3};

#[cfg(feature = "faulty")]
use crate::storage::Faulty;

/// Represents a running LFS server.
pub trait Server: Future<Output = hyper::Result<()>> {
    /// Returns the local address this server is bound to.
    fn addr(&self) -> SocketAddr;
}

impl<S, E> Server for hyper::Server<AddrIncoming, S, E>
where
    hyper::Server<AddrIncoming, S, E>: Future<Output = hyper::Result<()>>,
{
    fn addr(&self) -> SocketAddr {
        self.local_addr()
    }
}

#[derive(Debug)]
pub struct Cache {
    /// Path to the cache.
    dir: PathBuf,

    /// Maximum size of the cache, in bytes.
    max_size: u64,
}

impl Cache {
    pub fn new(dir: PathBuf, max_size: u64) -> Self {
        Self { dir, max_size }
    }
}

#[derive(Debug)]
pub struct S3ServerBuilder {
    bucket: String,
    key: Option<[u8; 32]>,
    prefix: Option<String>,
    cdn: Option<String>,
    cache: Option<Cache>,
}

impl S3ServerBuilder {
    pub fn new(bucket: String, key: Option<[u8; 32]>) -> Self {
        Self {
            bucket,
            prefix: None,
            cdn: None,
            key,
            cache: None,
        }
    }

    /// Sets the bucket to use.
    pub fn bucket(&mut self, bucket: String) -> &mut Self {
        self.bucket = bucket;
        self
    }

    /// Sets the encryption key to use.
    pub fn key(&mut self, key: [u8; 32]) -> &mut Self {
        self.key = Some(key);
        self
    }

    /// Sets the prefix to use.
    pub fn prefix(&mut self, prefix: String) -> &mut Self {
        self.prefix = Some(prefix);
        self
    }

    /// Sets the base URL of the CDN to use. This is incompatible with
    /// encryption since the LFS object is not sent to Rudolfs.
    pub fn cdn(&mut self, url: String) -> &mut Self {
        self.cdn = Some(url);
        self
    }

    /// Sets the cache to use. If not specified, then no local disk cache is
    /// used. All objects will get sent directly to S3.
    pub fn cache(&mut self, cache: Cache) -> &mut Self {
        self.cache = Some(cache);
        self
    }

    /// Spawns the server. The server must be awaited on in order to accept
    /// incoming client connections and run.
    pub async fn spawn(
        mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Server + Unpin + Send>, Box<dyn std::error::Error>>
    {
        let prefix = self.prefix.unwrap_or_else(|| String::from("lfs"));

        if self.cdn.is_some() {
            log::warn!(
                "A CDN was specified. Since uploads and downloads do not flow \
                 through Rudolfs in this case, they will *not* be encrypted."
            );

            if let Some(_) = self.cache.take() {
                log::warn!(
                    "A local disk cache does not work with a CDN and will be \
                     disabled."
                );
            }
        }

        let s3 = S3::new(self.bucket, prefix, self.cdn)
            .map_err(Error::from)
            .await?;

        // Retry certain operations to S3 to make it more reliable.
        let s3 = Retrying::new(s3);

        // Add a little instability for testing purposes.
        #[cfg(feature = "faulty")]
        let s3 = Faulty::new(s3);

        match self.cache {
            Some(cache) => {
                // Use disk storage as a cache.
                let disk = Disk::new(cache.dir, None, false, false)
                    .map_err(Error::from)
                    .await?;

                #[cfg(feature = "faulty")]
                let disk = Faulty::new(disk);

                let cache = Cached::new(cache.max_size, disk, s3).await?;

                if self.key.is_none() {
                    return Ok(Box::new(spawn_server(cache, &addr)));
                }

                let storage = Verify::new(Encrypted::new(
                    self.key.as_ref().unwrap().clone(),
                    cache,
                ));
                Ok(Box::new(spawn_server(storage, &addr)))
            }
            None => {
                if self.key.is_none() {
                    return Ok(Box::new(spawn_server(s3, &addr)));
                }
                let storage = Verify::new(Encrypted::new(
                    self.key.as_ref().unwrap().clone(),
                    s3,
                ));
                Ok(Box::new(spawn_server(storage, &addr)))
            }
        }
    }

    /// Spawns the server. The server must be awaited on in order to accept
    /// incoming client connections and run.
    pub async fn spawn_https(
        mut self,
        addr: SocketAddr,
        enable_https:bool,
        ssl_cert:Option<String>,
        ssl_key:Option<String>
    ) -> Result<(), Box<dyn std::error::Error>>
    {
        let prefix = self.prefix.unwrap_or_else(|| String::from("lfs"));

        if self.cdn.is_some() {
            log::warn!(
                "A CDN was specified. Since uploads and downloads do not flow \
                 through Rudolfs in this case, they will *not* be encrypted."
            );

            if let Some(_) = self.cache.take() {
                log::warn!(
                    "A local disk cache does not work with a CDN and will be \
                     disabled."
                );
            }
        }

        let s3 = S3::new(self.bucket, prefix, self.cdn)
            .map_err(Error::from)
            .await?;

        // Retry certain operations to S3 to make it more reliable.
        let s3 = Retrying::new(s3);

        // Add a little instability for testing purposes.
        #[cfg(feature = "faulty")]
        let s3 = Faulty::new(s3);

        match self.cache {
            Some(cache) => {
                // Use disk storage as a cache.
                let disk = Disk::new(cache.dir, None, false, false)
                    .map_err(Error::from)
                    .await?;

                #[cfg(feature = "faulty")]
                let disk = Faulty::new(disk);

                let cache = Cached::new(cache.max_size, disk, s3).await?;

                if self.key.is_none() {
                    spawn_server_https(cache, &addr, enable_https, ssl_cert, ssl_key).await?;
                    return Ok(());
                }

                let storage = Verify::new(Encrypted::new(
                    self.key.as_ref().unwrap().clone(),
                    cache,
                ));
                spawn_server_https(storage, &addr, enable_https, ssl_cert, ssl_key).await?;
                Ok(())
            }
            None => {
                if self.key.is_none() {
                    spawn_server_https(s3, &addr, enable_https, ssl_cert, ssl_key).await?;
                    return Ok(());
                }
                let storage = Verify::new(Encrypted::new(
                    self.key.as_ref().unwrap().clone(),
                    s3,
                ));
                spawn_server_https(storage, &addr, enable_https, ssl_cert, ssl_key).await?;
                Ok(())
            }
        }
    }

    /// Spawns the server and runs it to completion. This will run forever
    /// unless there is an error or the server shuts down gracefully.
    pub async fn run(
        self,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = self.spawn(addr).await?;

        log::info!("Listening on {}", server.addr());

        server.await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct LocalServerBuilder {
    path: PathBuf,
    key: Option<[u8; 32]>,
    proxy_url: Option<String>,
    proxy_url_keep_org: bool,
    cache: Option<Cache>,
    bare: bool,
}

impl LocalServerBuilder {
    /// Creates a local server builder. `path` is the path to the folder where
    /// all of the LFS data will be stored.
    pub fn new(
        path: PathBuf,
        key: Option<[u8; 32]>,
        proxy_url: Option<String>,
        proxy_url_keep_org:bool,
        bare: bool,
    ) -> Self {
        Self {
            path,
            key,
            proxy_url,
            proxy_url_keep_org,
            cache: None,
            bare,
        }
    }

    /// Sets the encryption key to use.
    pub fn key(&mut self, key: [u8; 32]) -> &mut Self {
        self.key = Some(key);
        self
    }

    /// Sets the cache to use. If not specified, then no local disk cache is
    /// used. It is uncommon to want to use this when the object storage is
    /// already local. However, a cache may be useful when the data storage path
    /// is on a mounted network file system. In such a case, the network file
    /// system could be slow and the local disk storage could be fast.
    pub fn cache(&mut self, cache: Cache) -> &mut Self {
        self.cache = Some(cache);
        self
    }

    /// Spawns the server. The server must be awaited on in order to accept
    /// incoming client connections and run.
    pub async fn spawn(
        self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Server + Unpin + Send>, Box<dyn std::error::Error>>
    {
        log::info!("--path:{:?} --proxy_url:{:?} --proxy_url_keep_org:{} --bare:{}", &self.path, &self.proxy_url, &self.proxy_url_keep_org, &self.bare);
        let storage = Disk::new(self.path, self.proxy_url, self.proxy_url_keep_org, self.bare)
            .map_err(Error::from)
            .await?;

        log::info!("Local disk storage initialized.");

        if self.key.is_none() {
            return Ok(Box::new(spawn_server(storage, &addr)));
        }

        let storage = Verify::new(Encrypted::new(
            self.key.as_ref().unwrap().clone(),
            storage,
        ));
        Ok(Box::new(spawn_server(storage, &addr)))
    }

    /// Spawns the server. The server must be awaited on in order to accept
    /// incoming client connections and run.
    pub async fn spawn_https(
        self,
        addr: SocketAddr,
        enable_https:bool,
        ssl_cert:Option<String>,
        ssl_key:Option<String>
    ) -> Result<(), Box<dyn std::error::Error>>
    {
        log::info!("--path:{:?} --proxy_url:{:?} --proxy_url_keep_org:{} --bare:{}", &self.path, &self.proxy_url, &self.proxy_url_keep_org, &self.bare);
        let storage = Disk::new(self.path, self.proxy_url, self.proxy_url_keep_org, self.bare)
            .map_err(Error::from)
            .await?;

        log::info!("Local disk storage initialized.");

        if self.key.is_none() {
            spawn_server_https(storage, &addr, enable_https, ssl_cert, ssl_key).await?;
            return Ok(());
        }

        let storage = Verify::new(Encrypted::new(
            self.key.as_ref().unwrap().clone(),
            storage,
        ));
        spawn_server_https(storage, &addr, enable_https, ssl_cert, ssl_key).await?;
        return Ok(());
    }

    /// Spawns the server and runs it to completion. This will run forever
    /// unless there is an error or the server shuts down gracefully.
    pub async fn run(
        self,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = self.spawn(addr).await?;

        log::info!("Listening on {}", server.addr());

        server.await?;
        Ok(())
    }
    pub async fn run_https(
        self,
        addr: SocketAddr,
        enable_https:bool,
        ssl_cert:Option<String>,
        ssl_key:Option<String>
    ) -> Result<(), Box<dyn std::error::Error>> {

        log::info!("Listening on {}", addr);
        self.spawn_https(addr, enable_https, ssl_cert, ssl_key).await?;
        Ok(())
    }
}



// copied from https://github.com/rustls/hyper-rustls/blob/master/examples/server.rs
fn io_error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| io_error(format!("failed to open {}: {}", filename, e).into()))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_| io_error("failed to load certificate".into()))
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| io_error(format!("failed to open {}: {}", filename, e).into()))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| io_error("failed to load private key".into()))?;
    if keys.len() != 1 {
        return Err(io_error("expected a single private key".into()));
    }
    Ok(keys[0].clone())
}

struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn futures_util::stream::Stream<Item = Result<TlsStream<TcpStream>, io::Error>> + 'a>>,
}

impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

fn spawn_server<S>(storage: S, addr: &SocketAddr) -> impl Server
where
    S: Storage + Send + Sync + 'static,
    S::Error: Into<Error>,
    Error: From<S::Error>,
{
    let storage = Arc::new(storage);
    let new_service = make_service_fn(move |socket: &AddrStream| {
        // Create our app.
        let service = App::new(storage.clone());

        // Add logging middleware
        future::ok::<_, Infallible>(Logger::new(socket.remote_addr(), service))
    });
    hyper::Server::bind(&addr).serve(new_service)
}

async fn spawn_server_https<S>(storage: S, addr: &SocketAddr,enable_https:bool,
    ssl_cert:Option<String>,
    ssl_key:Option<String>) -> Result<(), Box<dyn std::error::Error>>
where
    S: Storage + Send + Sync + 'static,
    S::Error: Into<Error>,
    Error: From<S::Error>,
{
    let storage = Arc::new(storage);
    let mut tls_cfg = None;

    if enable_https && ssl_cert.is_some() && ssl_key.is_some()
    {
        //copied from https://github.com/rustls/hyper-rustls/blob/master/examples/server.rs
        // Build TLS configuration.

        // Load public certificate.
        let certs = load_certs(&ssl_cert.unwrap_or("".to_string()));
        
        // Load private key.
        let key = load_private_key(&ssl_key.unwrap_or("".to_string()));

        if certs.is_ok() && key.is_ok()
        {
            let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
            cfg.set_protocols(&[b"http/1.1".to_vec()]);

            // Select a certificate to use.
            if cfg.set_single_cert(certs.unwrap(), key.unwrap()).is_ok()
            {
                tls_cfg = Some(std::sync::Arc::new(cfg)) 
            }
        }
    }

    let new_service = make_service_fn(move |socket: &TlsStream<TcpStream>| {
        // Create our app.
        let service = App::new(storage.clone());

        // Add logging middleware
        future::ok::<_, Infallible>(Logger::new(socket.get_ref().0.peer_addr().unwrap(), service))
    });

    if tls_cfg.is_none()
    {
        return Err(Box::new(io_error("Tls config failed!".into())));
    }

     // Create a TCP listener via tokio.
     let tcp = TcpListener::bind(&addr).await?;
     let tls_acceptor = TlsAcceptor::from(tls_cfg.unwrap());
     // Prepare a long-running future stream to accept and serve clients.
     let incoming_tls_stream = stream! {
         loop {
             let (socket, _) = tcp.accept().await?;
             let stream = tls_acceptor.accept(socket).map_err(|e| {
                 println!("[!] Voluntary server halt due to client-connection error...");
                 // Errors could be handled here, instead of server aborting.
                 // Ok(None)
                 io_error(format!("TLS Error: {:?}", e))
             });
             yield stream.await;
         }
     };

    hyper::Server::builder(HyperAcceptor {
        acceptor: Box::pin(incoming_tls_stream),
    })
    .serve(new_service).await?;
    Ok(())
}