//! Local VFun HTTP stub. The client's injected hook DLL redirects VFun web
//! calls (vfun.valofe.com etc.) here. Every request is logged verbatim; the
//! response bodies are placeholders until the client's response parser is
//! reverse-engineered (docs/re-log.md, "VFun login").

use crate::session::Shared;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub async fn serve(shared: Arc<Shared>) -> Result<()> {
    let cfg = shared.cfg.clone();
    let listener = TcpListener::bind((cfg.bind_ip.as_str(), cfg.vfun_port)).await?;
    info!(port = cfg.vfun_port, "vfun http stub listening");
    loop {
        let (mut sock, peer) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            // Read headers (+ body by Content-Length).
            loop {
                let n = match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find(&buf, b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let cl = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + cl {
                        break;
                    }
                }
                if buf.len() > 1 << 20 {
                    return;
                }
            }
            let req = String::from_utf8_lossy(&buf).to_string();
            let first = req.lines().next().unwrap_or("").to_string();
            info!(%peer, "VFUN-REQ {first}");
            {
                use std::io::Write;
                let path = std::path::Path::new(&shared.cfg.log_dir).join("vfun.log");
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    let _ = writeln!(f, "----- {peer}\n{req}");
                }
            }
            let body = crate::vfun::respond(&first, &req);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            if let Err(e) = sock.write_all(resp.as_bytes()).await {
                warn!("vfun write: {e}");
            }
        });
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}
