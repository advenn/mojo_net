//! hyper for bench/server/run.py (see Cargo.toml).
//!
//!     cargo build --release --manifest-path bench/server/hyper/Cargo.toml
//!     WORKERS=1 hyper_plaintext 127.0.0.1:8080

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header, Request, Response};
use hyper_util::rt::TokioIo;
use socket2::{Domain, Socket, Type};

async fn plaintext(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let res = if req.uri().path() == "/plaintext" {
        Response::builder()
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::SERVER, "hyper")
            .body(Full::new(Bytes::from_static(b"Hello, World!")))
    } else {
        Response::builder().status(404).body(Full::new(Bytes::new()))
    };
    Ok(res.unwrap())
}

fn listener(addr: SocketAddr) -> std::net::TcpListener {
    let s = Socket::new(Domain::IPV4, Type::STREAM, None).expect("socket");
    s.set_reuse_address(true).expect("SO_REUSEADDR");
    s.set_reuse_port(true).expect("SO_REUSEPORT");
    s.set_nonblocking(true).expect("nonblocking");
    s.bind(&addr.into()).expect("bind");
    s.listen(4096).expect("listen");
    s.into()
}

fn serve(addr: SocketAddr) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    rt.block_on(async move {
        let ln = tokio::net::TcpListener::from_std(listener(addr)).expect("listener");
        loop {
            let Ok((stream, _)) = ln.accept().await else { continue };
            let _ = stream.set_nodelay(true);
            tokio::task::spawn(async move {
                let _ = http1::Builder::new()
                    .pipeline_flush(true)
                    .serve_connection(TokioIo::new(stream), service_fn(plaintext))
                    .await;
            });
        }
    });
}

fn main() {
    let addr: SocketAddr = std::env::args().nth(1).as_deref().unwrap_or("127.0.0.1:8080").parse().expect("ADDR");
    let n: usize = std::env::var("WORKERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let threads: Vec<_> = (0..n).map(|_| std::thread::spawn(move || serve(addr))).collect();
    println!("LISTEN {} pid={}", addr, std::process::id());
    for t in threads {
        t.join().expect("worker");
    }
}
