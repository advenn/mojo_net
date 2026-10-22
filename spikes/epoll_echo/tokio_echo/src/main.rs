//! Idiomatic tokio echo server on the current_thread runtime: one task per
//! connection, each with its own read buffer (`--buf`, 4096 by default, the
//! usual choice in tokio examples), `read` then `write_all`. Prints the same
//! LISTEN line as server.mojo; it has no syscall counters (no STATS lines).
//!
//!   CARGO_TARGET_DIR=spikes/epoll_echo/out/tokio-target \
//!     cargo build --release --offline --manifest-path spikes/epoll_echo/tokio_echo/Cargo.toml

use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn main() -> io::Result<()> {
    // Same fd budget as the other servers: soft RLIMIT_NOFILE = hard.
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
        rl.rlim_cur = rl.rlim_max;
        libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
    }
    let port: u16 = arg("--port").map(|p| p.parse().expect("--port")).unwrap_or(0);
    let bufsize: usize = arg("--buf").map(|b| b.parse().expect("--buf")).unwrap_or(4096);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        println!(
            "LISTEN {} pid={} nofile_soft={} nofile_hard={} buf={}",
            listener.local_addr()?,
            std::process::id(),
            rl.rlim_cur,
            rl.rlim_max,
            bufsize
        );
        loop {
            let mut sock = match listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    // EMFILE: tokio's accept would otherwise spin.
                    println!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let _ = sock.set_nodelay(true);
            tokio::spawn(async move {
                let mut buf = vec![0u8; bufsize];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    })
}
