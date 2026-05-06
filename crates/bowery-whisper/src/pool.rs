//! Persistent peer-connection pool — Phase-10 connection-reuse slice 1.
//!
//! [`PeerConnections`] caches one [`BoweryConnection`] per peer
//! fingerprint so the agent doesn't pay handshake-and-dial latency on
//! every heartbeat / Q&A / fanout dispatch. The Quinn transport is
//! already configured with a 30-second idle timeout and a 10-second
//! keep-alive (see [`crate::transport`]), so a pooled connection that
//! goes silent for tens of seconds stays alive automatically.
//!
//! Eviction policy:
//!
//! - **Lazy.** [`PeerConnections::get_or_dial`] checks
//!   [`BoweryConnection::is_closed`] before returning a cached entry
//!   and re-dials on a hit-but-closed.
//! - **Background.** When an entry is inserted, we spawn a tokio task
//!   that awaits Quinn's `closed()` future and removes the entry
//!   from the map. Cooperative-only — the task drops itself if the
//!   pool itself is dropped.
//! - **Explicit.** [`PeerConnections::invalidate`] is the
//!   "I just got a send error, evict this thing now" door for
//!   callers that detected a dead connection ahead of the watcher
//!   noticing.
//!
//! Concurrency:
//!
//! Two concurrent callers asking for the same fingerprint while the
//! cache is cold will currently *both* dial — only one wins the
//! insert and the other's connection is dropped (which Quinn then
//! cleanly closes). Heartbeats are 30 s apart per peer and Q&A is
//! single-shot, so the dedupe window almost never fires in practice.
//! Slice 2 may add a per-fingerprint dial-in-progress slot; for
//! now, the simpler pattern is correct and observable.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bowery_crypto::Fingerprint;
use tokio::task::JoinHandle;
use tracing::{debug, trace};

use crate::envelope::FingerprintResolver;
use crate::tls::PinnedCertVerifier;
use crate::transport::{self, BoweryConnection, BoweryEndpoint};

/// Hook invoked exactly once per fresh outbound dial, with the
/// newly-pooled connection. The agent uses this to spawn its
/// `handle_connection` accept loop on outbound connections so peers
/// can initiate streams *back* through the same QUIC socket — the
/// "no inbound listener needed for B" property of Phase-10 slice 2.
pub type InboundHandler = Arc<dyn Fn(Fingerprint, BoweryConnection) + Send + Sync + 'static>;

/// A pool of authenticated outbound connections, one per peer
/// fingerprint. Cheap to clone — every clone shares the same backing
/// state.
#[derive(Clone)]
pub struct PeerConnections {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for PeerConnections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnections")
            .field("len", &self.len())
            .finish()
    }
}

struct Inner {
    endpoint: BoweryEndpoint,
    state: Mutex<HashMap<Fingerprint, Entry>>,
    handler: Option<InboundHandler>,
}

#[derive(Debug)]
struct Entry {
    conn: BoweryConnection,
    /// Background task that watches the connection and clears the
    /// entry when it closes. Aborted on explicit invalidation so we
    /// don't leak per-peer tasks.
    watcher: JoinHandle<()>,
}

impl PeerConnections {
    /// Construct a pool that dials through `endpoint`. No inbound
    /// handler — outbound connections are write-only from the
    /// dialler's perspective. Useful for the operator CLI.
    pub fn new(endpoint: BoweryEndpoint) -> Self {
        Self::new_inner(endpoint, None)
    }

    /// Construct a pool that runs `handler` on every fresh outbound
    /// connection. Agents use this so a peer can initiate whisper
    /// streams back through the connection the agent dialled — the
    /// connection is bidirectional even when only one side has an
    /// inbound listener.
    ///
    /// The handler is `Fn`, called immediately on the calling task —
    /// it should `tokio::spawn` the actual accept loop and return.
    pub fn with_handler(endpoint: BoweryEndpoint, handler: InboundHandler) -> Self {
        Self::new_inner(endpoint, Some(handler))
    }

    fn new_inner(endpoint: BoweryEndpoint, handler: Option<InboundHandler>) -> Self {
        Self {
            inner: Arc::new(Inner {
                endpoint,
                state: Mutex::new(HashMap::new()),
                handler,
            }),
        }
    }

    /// Get a connection to `peer_fp` at `addr`, dialing if the cache
    /// is cold or the cached entry is closed. The verifier is
    /// constructed by the caller so they can pin the expected
    /// fingerprint via [`PinnedCertVerifier::expecting`].
    pub async fn get_or_dial<R>(
        &self,
        peer_fp: Fingerprint,
        addr: SocketAddr,
        verifier: Arc<PinnedCertVerifier<R>>,
    ) -> Result<BoweryConnection, transport::Error>
    where
        R: FingerprintResolver + 'static,
    {
        // Fast path — cache hit and the connection is still live.
        if let Some(conn) = self.try_take_live(&peer_fp) {
            trace!(peer = %peer_fp, conn_id = conn.stable_id(), "pool hit");
            return Ok(conn);
        }

        // Cold or stale — dial fresh. Note we don't hold the pool
        // lock during the dial.
        let conn = self.inner.endpoint.dial(verifier, addr).await?;
        debug!(
            peer = %peer_fp,
            conn_id = conn.stable_id(),
            "pool dialled new connection"
        );
        self.insert(peer_fp, conn.clone());
        // Slice 2 — invoke the inbound handler so the dialler
        // processes peer-initiated streams on this connection. The
        // handler is responsible for tokio::spawning the loop; we
        // don't await it here.
        if let Some(handler) = &self.inner.handler {
            handler(peer_fp, conn.clone());
        }
        Ok(conn)
    }

    /// Drop a specific entry. Used by callers that detected a send
    /// failure and want to force the next call to redial without
    /// waiting for the watcher to notice.
    pub fn invalidate(&self, peer_fp: &Fingerprint) {
        let mut state = self.inner.state.lock().expect("pool mutex poisoned");
        if let Some(entry) = state.remove(peer_fp) {
            entry.watcher.abort();
            trace!(peer = %peer_fp, "pool invalidate");
        }
    }

    /// Number of currently-pooled connections. Test/observability hook.
    pub fn len(&self) -> usize {
        self.inner.state.lock().expect("pool mutex poisoned").len()
    }

    /// Local fingerprint of the underlying endpoint — convenience
    /// accessor so callers don't need to plumb a separate
    /// `BoweryEndpoint` reference alongside the pool.
    pub fn local_fingerprint(&self) -> Fingerprint {
        self.inner.endpoint.fingerprint()
    }

    /// `true` when no connections are pooled.
    pub fn is_empty(&self) -> bool {
        self.inner
            .state
            .lock()
            .expect("pool mutex poisoned")
            .is_empty()
    }

    /// `true` if a live connection is currently cached for `peer_fp`.
    /// "Live" means present *and* not in the closed state.
    pub fn contains_live(&self, peer_fp: &Fingerprint) -> bool {
        let state = self.inner.state.lock().expect("pool mutex poisoned");
        state.get(peer_fp).is_some_and(|e| !e.conn.is_closed())
    }

    fn try_take_live(&self, peer_fp: &Fingerprint) -> Option<BoweryConnection> {
        let mut state = self.inner.state.lock().expect("pool mutex poisoned");
        let entry = state.get(peer_fp)?;
        if entry.conn.is_closed() {
            // Stale; remove and let the caller redial.
            if let Some(stale) = state.remove(peer_fp) {
                stale.watcher.abort();
                trace!(peer = %peer_fp, "pool evicting closed entry");
            }
            return None;
        }
        Some(entry.conn.clone())
    }

    fn insert(&self, peer_fp: Fingerprint, conn: BoweryConnection) {
        // Spawn the watcher first so it observes the same connection
        // even if a racing caller overwrites the slot.
        let inner = Arc::clone(&self.inner);
        let watch_conn = conn.clone();
        let watcher = tokio::spawn(async move {
            let _ = watch_conn.closed().await;
            let mut state = inner.state.lock().expect("pool mutex poisoned");
            // Only remove the entry if it's still pointing at the
            // *same* underlying connection. A racing caller may have
            // already replaced this slot with a fresh dial.
            if let Some(entry) = state.get(&peer_fp)
                && entry.conn.stable_id() == watch_conn.stable_id()
            {
                state.remove(&peer_fp);
                trace!(peer = %peer_fp, "pool watcher evicted closed entry");
            }
        });

        let mut state = self.inner.state.lock().expect("pool mutex poisoned");
        if let Some(prev) = state.insert(peer_fp, Entry { conn, watcher }) {
            // A concurrent dial beat us. Drop the previous entry's
            // watcher — its connection is still in use until callers
            // drop their clones, but we don't need to track it here.
            prev.watcher.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::StaticResolver;
    use crate::tls::PinnedCertVerifier;
    use bowery_crypto::Identity;

    fn loopback() -> SocketAddr {
        use std::net::{IpAddr, Ipv4Addr};
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    /// Spin up a pair of pinned endpoints and return the alpha-side
    /// pool, beta endpoint, beta fingerprint, and a verifier alpha
    /// can use to dial beta. Must be called from inside a tokio
    /// runtime (the spawn for beta's accept loop needs one).
    fn setup() -> (
        PeerConnections,
        BoweryEndpoint,
        Fingerprint,
        Arc<PinnedCertVerifier<StaticResolver>>,
        SocketAddr,
    ) {
        let id_alpha = Arc::new(Identity::generate());
        let id_beta = Arc::new(Identity::generate());

        let mut resolver_alpha = StaticResolver::new();
        resolver_alpha.insert(id_beta.verifying_key());
        let mut resolver_beta = StaticResolver::new();
        resolver_beta.insert(id_alpha.verifying_key());

        let dial_verifier = Arc::new(PinnedCertVerifier::expecting(
            resolver_alpha.clone(),
            id_beta.fingerprint(),
        ));
        let accept_verifier_alpha = Arc::new(PinnedCertVerifier::new(resolver_alpha));
        let accept_verifier_beta = Arc::new(PinnedCertVerifier::new(resolver_beta));

        let endpoint_beta =
            BoweryEndpoint::bind(id_beta.clone(), accept_verifier_beta, loopback()).unwrap();
        let endpoint_alpha =
            BoweryEndpoint::bind(id_alpha, accept_verifier_alpha, loopback()).unwrap();

        let beta_addr = endpoint_beta.local_addr().unwrap();

        // Beta accepts connections in the background so dials complete.
        let beta_clone = endpoint_beta.clone();
        tokio::spawn(async move {
            while let Some(Ok(conn)) = beta_clone.accept().await {
                // Hold the connection alive until the test drops the
                // endpoint. recv_envelope wakes when streams arrive
                // (or never, if the test is just measuring connect).
                tokio::spawn(async move {
                    loop {
                        if conn.recv_envelope().await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let pool = PeerConnections::new(endpoint_alpha);
        (
            pool,
            endpoint_beta,
            id_beta.fingerprint(),
            dial_verifier,
            beta_addr,
        )
    }

    #[tokio::test]
    async fn pool_caches_connection_across_calls() {
        let (pool, _ep_beta, beta_fp, verifier, beta_addr) = setup();
        assert!(pool.is_empty());

        let conn_a = pool
            .get_or_dial(beta_fp, beta_addr, verifier.clone())
            .await
            .expect("first dial");
        assert_eq!(pool.len(), 1);

        let conn_b = pool
            .get_or_dial(beta_fp, beta_addr, verifier.clone())
            .await
            .expect("second call hits cache");
        assert_eq!(pool.len(), 1);
        assert_eq!(
            conn_a.stable_id(),
            conn_b.stable_id(),
            "second call must return the cached connection"
        );
    }

    #[tokio::test]
    async fn invalidate_forces_redial() {
        let (pool, _ep_beta, beta_fp, verifier, beta_addr) = setup();

        let conn_a = pool
            .get_or_dial(beta_fp, beta_addr, verifier.clone())
            .await
            .unwrap();
        pool.invalidate(&beta_fp);
        assert_eq!(pool.len(), 0);

        let conn_b = pool
            .get_or_dial(beta_fp, beta_addr, verifier.clone())
            .await
            .unwrap();
        assert_ne!(
            conn_a.stable_id(),
            conn_b.stable_id(),
            "invalidate must result in a fresh connection"
        );
    }

    #[tokio::test]
    async fn handler_runs_once_per_fresh_dial() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let id_alpha = Arc::new(Identity::generate());
        let id_beta = Arc::new(Identity::generate());

        let mut resolver_alpha = StaticResolver::new();
        resolver_alpha.insert(id_beta.verifying_key());
        let mut resolver_beta = StaticResolver::new();
        resolver_beta.insert(id_alpha.verifying_key());

        let dial_verifier = Arc::new(PinnedCertVerifier::expecting(
            resolver_alpha.clone(),
            id_beta.fingerprint(),
        ));
        let accept_verifier_alpha = Arc::new(PinnedCertVerifier::new(resolver_alpha));
        let accept_verifier_beta = Arc::new(PinnedCertVerifier::new(resolver_beta));

        let endpoint_beta =
            BoweryEndpoint::bind(id_beta.clone(), accept_verifier_beta, loopback()).unwrap();
        let endpoint_alpha =
            BoweryEndpoint::bind(id_alpha, accept_verifier_alpha, loopback()).unwrap();

        let beta_addr = endpoint_beta.local_addr().unwrap();
        let beta_clone = endpoint_beta.clone();
        tokio::spawn(async move {
            while let Some(Ok(conn)) = beta_clone.accept().await {
                tokio::spawn(async move {
                    loop {
                        if conn.recv_envelope().await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = calls.clone();
        let handler: InboundHandler = Arc::new(move |_fp, _conn| {
            calls_for_handler.fetch_add(1, Ordering::SeqCst);
        });
        let pool = PeerConnections::with_handler(endpoint_alpha, handler);

        let beta_fp = id_beta.fingerprint();
        let _ = pool
            .get_or_dial(beta_fp, beta_addr, dial_verifier.clone())
            .await
            .unwrap();
        let _ = pool
            .get_or_dial(beta_fp, beta_addr, dial_verifier.clone())
            .await
            .unwrap();
        // Handler runs only on the *fresh* dial — second call hits cache.
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        pool.invalidate(&beta_fp);
        let _ = pool
            .get_or_dial(beta_fp, beta_addr, dial_verifier)
            .await
            .unwrap();
        // Invalidate forces redial → handler runs again.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn closed_remote_evicts_lazily_on_get() {
        let (pool, ep_beta, beta_fp, verifier, beta_addr) = setup();
        let conn_a = pool
            .get_or_dial(beta_fp, beta_addr, verifier.clone())
            .await
            .unwrap();

        // Simulate the remote going away — closing the beta endpoint
        // tears down all its accepted connections.
        ep_beta.close().await;

        // Wait for alpha-side to notice. Quinn surfaces the close
        // through its event loop; brief sleep is fine here.
        for _ in 0..40 {
            if conn_a.is_closed() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(conn_a.is_closed(), "remote-side close should propagate");

        // get_or_dial must not return the dead entry; it'll attempt
        // a redial which is fine to fail — what matters is the
        // pool clears the stale slot rather than handing it back.
        let _ = pool.get_or_dial(beta_fp, beta_addr, verifier.clone()).await; // expected to fail post-close; we don't care here
        assert!(
            !pool.contains_live(&beta_fp),
            "stale entry must be evicted after a failed get"
        );
    }
}
