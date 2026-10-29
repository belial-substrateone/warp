//! Accept loop: peer filtering, TLS termination and per-connection HTTP/1.1 serving.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use super::{Inner, LOG};
use crate::netfilter::{BoundAddr, peer_allowed};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Who is on the other end and which of our addresses they reached.
#[derive(Debug, Clone, Copy)]
pub(super) struct PeerInfo {
    pub peer: SocketAddr,
}

pub(super) async fn accept_loop(
    inner: Arc<Inner>,
    listener: TcpListener,
    bound: BoundAddr,
    local: SocketAddr,
    router: Router,
) {
    // Dropping this set (when the task is aborted) aborts every connection of this listener.
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(a) => a,
                    Err(err) => {
                        log::warn!(target: LOG, "accept on {local} failed: {err}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if !peer_allowed(&bound, peer.ip(), inner.cfg.peer_policy.as_ref().unwrap_or(&inner.cfg.policy)) {
                    log::debug!(target: LOG, "dropped connection from disallowed peer {}", peer.ip());
                    drop(tcp);
                    continue;
                }
                let Ok(permit) = inner.conn_sem.clone().try_acquire_owned() else {
                    log::debug!(target: LOG, "connection limit reached; dropping {}", peer.ip());
                    drop(tcp);
                    continue;
                };
                let _ = tcp.set_nodelay(true);
                let acceptor = inner.acceptor.clone();
                let svc = router.clone().layer(Extension(PeerInfo { peer }));
                conns.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(tls)) = tokio::time::timeout(
                        TLS_HANDSHAKE_TIMEOUT,
                        acceptor.accept(tcp),
                    )
                    .await
                    else {
                        return;
                    };
                    let conn = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .serve_connection(TokioIo::new(tls), TowerToHyperService::new(svc))
                        .with_upgrades();
                    if let Err(err) = conn.await {
                        log::debug!(target: LOG, "connection from {peer} ended: {err}");
                    }
                });
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}
