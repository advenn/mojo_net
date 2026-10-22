//! Minimal HTTP/1.1 keep-alive responder on tokio's current_thread runtime,
//! the same program as bench/rt/http_hello.mojo: one task per connection, find
//! each request head's CRLFCRLF, answer every complete head in the buffer
//! with a fixed "Hello, World!" (one write per read batch, so pipelining is
//! safe), keep a partial head for the next read, honor `Connection: close`
//! and HTTP/1.0, 431 for heads over 8 KiB. Raw TcpStream, no hyper.
//!
//!   CARGO_TARGET_DIR=bench/rt/out/tokio-target \
//!     cargo build --release --offline --manifest-path bench/rt/rust_http/Cargo.toml

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!";
const CLOSE_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello, World!";
const TOO_LARGE: &[u8] =
    b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const MAX_HEAD: usize = 8192;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn ieq_at(h: &[u8], at: usize, word: &[u8]) -> bool {
    at + word.len() <= h.len()
        && h[at..at + word.len()].iter().zip(word).all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn crlf(h: &[u8], start: usize) -> usize {
    let mut i = start;
    while i + 1 < h.len() {
        if h[i] == b'\r' && h[i + 1] == b'\n' {
            return i;
        }
        i += 1;
    }
    h.len()
}

fn wants_close(head: &[u8]) -> bool {
    let eol = crlf(head, 0);
    if eol >= 8 && ieq_at(head, eol - 8, b"http/1.0") {
        return true;
    }
    let mut i = eol + 2;
    while i < head.len() {
        let e = crlf(head, i);
        if ieq_at(head, i, b"connection:") {
            let mut j = i + 11;
            while j + 5 <= e {
                if ieq_at(head, j, b"close") {
                    return true;
                }
                j += 1;
            }
        }
        i = e + 2;
    }
    false
}

async fn serve(mut sock: TcpStream) -> io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut out: Vec<u8> = Vec::with_capacity(4096);
    loop {
        if buf.capacity() - buf.len() < 1024 {
            buf.reserve(4096);
        }
        if sock.read_buf(&mut buf).await? == 0 {
            return Ok(());
        }
        let mut start = 0;
        let mut close = false;
        while let Some(p) = head_end(&buf[start..]) {
            let end = start + p + 4;
            close = wants_close(&buf[start..end]);
            start = end;
            if close {
                out.extend_from_slice(CLOSE_RESPONSE);
                break;
            }
            out.extend_from_slice(RESPONSE);
        }
        buf.drain(..start);
        if !close && buf.len() > MAX_HEAD {
            out.extend_from_slice(TOO_LARGE);
            close = true;
        }
        if !out.is_empty() {
            sock.write_all(&out).await?;
            out.clear();
        }
        if close {
            let _ = sock.shutdown().await;
            return Ok(());
        }
    }
}

fn main() -> io::Result<()> {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
        rl.rlim_cur = rl.rlim_max;
        libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
    }
    let port: u16 = arg("--port").map(|p| p.parse().expect("--port")).unwrap_or(8080);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        println!(
            "LISTEN {} pid={} server=rust-http",
            listener.local_addr()?,
            std::process::id()
        );
        loop {
            let sock = match listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    println!("accept: {e}");
                    continue;
                }
            };
            let _ = sock.set_nodelay(true);
            tokio::spawn(async move {
                let _ = serve(sock).await;
            });
        }
    })
}
