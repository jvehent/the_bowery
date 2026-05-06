//! Quinn-based QUIC transport with raw-public-key TLS.
//!
//! [`BoweryEndpoint`] wraps a [`quinn::Endpoint`] configured to use the
//! agent's identity for both server-side and client-side TLS (mTLS), with
//! peer authentication delegated to [`crate::tls::PinnedCertVerifier`]. A
//! single endpoint can both accept incoming peers and dial outbound ones.
//!
//! Wire framing on a stream is a 32-bit big-endian length followed by an
//! opaque envelope payload (see [`crate::envelope`]). The transport itself
//! is unaware of envelope contents; framing keeps it neutral.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bowery_crypto::{Fingerprint, Identity};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::ServerName;
use rustls::server::danger::ClientCertVerifier;
use thiserror::Error;

use crate::envelope::FingerprintResolver;
use crate::tls::{self, PinnedCertVerifier, TlsMaterial};

/// ALPN identifier — pinned per major protocol version.
pub const ALPN: &[u8] = b"bowery/1";

/// Hard cap on a single envelope length-prefix. 64 KiB is well above
/// any expected envelope today (heartbeats are ~150 B; the largest
/// `Alerts` response is bounded by inbox capacity × per-alert size,
/// typically a few hundred KiB but capped per-Subscribe). The
/// previous 1 MiB cap was excessive — under no per-peer connection
/// or per-conn stream limit, a single peer could amplify ~100 MiB of
/// pre-fill buffer per connection.
const MAX_FRAME_BYTES: usize = 64 * 1024;

/// QUIC idle timeout — connections sitting silent for this long are
/// dropped. Defends against slow-loris attacks where a peer completes
/// the TLS handshake then never sends an envelope, holding state.
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// QUIC keepalive cadence. Below the idle timeout so legitimate-but-
/// quiet connections don't get torn down.
const QUIC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum concurrent unidirectional streams per connection. The
/// agent's protocol uses one stream per envelope, sequentially, so
/// the legitimate cap is well below 100 (the Quinn default). Lowering
/// this caps the per-connection memory amplification a malicious peer
/// can drive.
const MAX_CONCURRENT_UNI_STREAMS: u32 = 8;

#[derive(Debug, Error)]
pub enum Error {
    #[error("tls setup failed: {0}")]
    Tls(#[from] tls::Error),

    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("no initial crypto provider available: {0}")]
    NoQuicCrypto(quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("quinn endpoint error: {0}")]
    Endpoint(#[from] std::io::Error),

    #[error("quinn connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("quinn connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("write stream error: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("read stream error: {0}")]
    Read(#[from] quinn::ReadExactError),

    #[error("stream already closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),

    #[error("frame larger than {MAX_FRAME_BYTES} bytes ({0})")]
    FrameTooLarge(u32),
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// A bidirectional QUIC endpoint.
///
/// Owns the agent's identity and TLS material; both sides of every
/// connection are authenticated with the same Ed25519 keypair. Use
/// [`BoweryEndpoint::dial`] for outbound and [`BoweryEndpoint::accept`] for
/// inbound.
#[derive(Debug, Clone)]
pub struct BoweryEndpoint {
    inner: Endpoint,
    identity: Arc<Identity>,
    fingerprint: Fingerprint,
    material: Arc<TlsMaterial>,
}

impl BoweryEndpoint {
    /// Bind a new endpoint at `addr` (use `0.0.0.0:0` to let the OS pick a
    /// port). The endpoint will both serve incoming peers (using
    /// `client_verifier` to validate them) and dial outgoing ones.
    pub fn bind<R>(
        identity: Arc<Identity>,
        client_verifier: Arc<PinnedCertVerifier<R>>,
        addr: SocketAddr,
    ) -> Result<Self, Error>
    where
        R: FingerprintResolver + 'static,
    {
        let material = Arc::new(tls::build_self_signed_cert(&identity)?);
        let fingerprint = identity.fingerprint();

        let server_config = build_server_config(&material, client_verifier)?;

        let socket = std::net::UdpSocket::bind(addr)?;
        let inner = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self {
            inner,
            identity,
            fingerprint,
            material,
        })
    }

    /// The local fingerprint advertised by this endpoint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The local socket address actually bound. Useful for tests using
    /// ephemeral ports.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// The identity this endpoint is presenting on every handshake.
    pub fn identity(&self) -> &Arc<Identity> {
        &self.identity
    }

    /// Dial a peer at `addr`. The provided `server_verifier` decides which
    /// peers are acceptable (typically constructed via
    /// [`PinnedCertVerifier::expecting`] when dialing a known fingerprint).
    pub async fn dial<R>(
        &self,
        server_verifier: Arc<PinnedCertVerifier<R>>,
        addr: SocketAddr,
    ) -> Result<BoweryConnection, Error>
    where
        R: FingerprintResolver + 'static,
    {
        let client_config = build_client_config(&self.material, server_verifier)?;
        let connecting = self
            .inner
            .connect_with(client_config, addr, "bowery.local")?;
        let connection = connecting.await?;
        Ok(BoweryConnection { inner: connection })
    }

    /// Accept the next inbound connection. Returns `None` when the endpoint
    /// has been closed.
    pub async fn accept(&self) -> Option<Result<BoweryConnection, Error>> {
        let incoming = self.inner.accept().await?;
        Some(match incoming.await {
            Ok(connection) => Ok(BoweryConnection { inner: connection }),
            Err(e) => Err(Error::Connection(e)),
        })
    }

    /// Close the endpoint and all its connections.
    pub async fn close(&self) {
        self.inner.close(0u32.into(), b"bowery shutdown");
        self.inner.wait_idle().await;
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// An authenticated bidirectional QUIC connection.
#[derive(Debug, Clone)]
pub struct BoweryConnection {
    inner: quinn::Connection,
}

impl BoweryConnection {
    /// Send an opaque (already-sealed) envelope on a freshly opened
    /// unidirectional stream. Blocks until the peer has consumed the stream
    /// (or explicitly stopped it), so the caller knows the data was
    /// delivered before dropping the connection.
    pub async fn send_envelope(&self, bytes: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(bytes.len()).map_err(|_| Error::FrameTooLarge(u32::MAX))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(Error::FrameTooLarge(len));
        }
        let mut send = self.inner.open_uni().await?;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(bytes).await?;
        send.finish()?;
        // Wait for the receiver to read to end-of-stream (or stop us).
        // Without this, dropping the Connection right after finish() can
        // race the receiver's read; quinn doesn't guarantee delivery once
        // the underlying Connection is closed.
        let _ = send.stopped().await;
        Ok(())
    }

    /// Read the next envelope from the next inbound unidirectional stream.
    pub async fn recv_envelope(&self) -> Result<Vec<u8>, Error> {
        let mut recv = self.inner.accept_uni().await?;
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);
        if len as usize > MAX_FRAME_BYTES {
            return Err(Error::FrameTooLarge(len));
        }
        let mut buf = vec![0u8; len as usize];
        recv.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Remote socket address.
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// `true` if the underlying QUIC connection has been closed
    /// (either side, any reason). Used by the pool to lazily evict
    /// dead entries before handing them to a caller.
    pub fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    /// Awaits the connection's close. Resolves with the
    /// `ConnectionError` that closed it. Used by the pool's
    /// background watcher tasks.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.inner.closed().await
    }

    /// Stable per-process connection id. Useful in logs to tell
    /// "same connection reused" from "redialled".
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }
}

// ---------------------------------------------------------------------------
// Internal config builders
// ---------------------------------------------------------------------------

/// Build the hardened `TransportConfig` shared by server and client.
///
/// Two connection-level caps:
///
/// - `max_idle_timeout`: connections silent for `QUIC_IDLE_TIMEOUT`
///   are dropped. Without this, a peer that completes the TLS
///   handshake but never sends an envelope holds state forever
///   (slow-loris).
/// - `keep_alive_interval`: keeps legitimate-but-idle connections
///   alive without the operator having to think about it.
///
/// Plus `max_concurrent_uni_streams` to cap per-connection
/// fan-out — the protocol is sequential one-stream-per-envelope so
/// 8 is plenty.
fn hardened_transport_config() -> TransportConfig {
    let mut cfg = TransportConfig::default();
    cfg.max_idle_timeout(Some(
        QUIC_IDLE_TIMEOUT
            .try_into()
            .expect("QUIC_IDLE_TIMEOUT fits in VarInt"),
    ));
    cfg.keep_alive_interval(Some(QUIC_KEEPALIVE_INTERVAL));
    cfg.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    // Defense in depth — bidirectional streams aren't used today, but
    // future protocol additions might. Cap them at the same value.
    cfg.max_concurrent_bidi_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    cfg
}

fn build_server_config<R>(
    material: &Arc<TlsMaterial>,
    client_verifier: Arc<PinnedCertVerifier<R>>,
) -> Result<ServerConfig, Error>
where
    R: FingerprintResolver + 'static,
{
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut rustls_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(Error::Rustls)?
        .with_client_cert_verifier(client_verifier as Arc<dyn ClientCertVerifier>)
        .with_single_cert(vec![material.cert.clone()], material.key.clone_key())?;
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];

    let quic_cfg = QuicServerConfig::try_from(rustls_cfg).map_err(Error::NoQuicCrypto)?;
    let mut server = ServerConfig::with_crypto(Arc::new(quic_cfg));
    server.transport_config(Arc::new(hardened_transport_config()));
    Ok(server)
}

fn build_client_config<R>(
    material: &Arc<TlsMaterial>,
    server_verifier: Arc<PinnedCertVerifier<R>>,
) -> Result<ClientConfig, Error>
where
    R: FingerprintResolver + 'static,
{
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut rustls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(Error::Rustls)?
        .dangerous()
        .with_custom_certificate_verifier(server_verifier as Arc<dyn ServerCertVerifier>)
        .with_client_auth_cert(vec![material.cert.clone()], material.key.clone_key())?;
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];

    let quic_cfg = QuicClientConfig::try_from(rustls_cfg).map_err(Error::NoQuicCrypto)?;
    let mut client = ClientConfig::new(Arc::new(quic_cfg));
    client.transport_config(Arc::new(hardened_transport_config()));
    Ok(client)
}

// ---------------------------------------------------------------------------
// Helper: pin a server name. Quinn requires SNI even when our verifier
// ignores it.
// ---------------------------------------------------------------------------

#[allow(dead_code)] // reserved for future per-peer SNI customization
fn fixed_server_name() -> ServerName<'static> {
    ServerName::try_from("bowery.local").expect("static server name parses")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Sealer, StaticResolver, Verifier};
    use bowery_proto::WhisperPayload;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    #[allow(clippy::similar_names)] // alpha/beta is more obscure than a/b suffixes
    async fn two_endpoints_exchange_signed_heartbeat() {
        let id_alpha = Arc::new(Identity::generate());
        let id_beta = Arc::new(Identity::generate());

        // Each side pins the other.
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

        let endpoint_beta = BoweryEndpoint::bind(id_beta.clone(), accept_verifier_beta, loopback())
            .expect("bind beta");
        let endpoint_alpha =
            BoweryEndpoint::bind(id_alpha.clone(), accept_verifier_alpha, loopback())
                .expect("bind alpha");

        let beta_addr = endpoint_beta.local_addr().unwrap();

        // Beta accepts and reads one envelope.
        let endpoint_beta_clone = endpoint_beta.clone();
        let mut resolver_for_verify = StaticResolver::new();
        resolver_for_verify.insert(id_alpha.verifying_key());
        let envelope_verifier = Verifier::new(resolver_for_verify, id_beta.fingerprint());
        let alpha_fp = id_alpha.fingerprint();

        let beta_task = tokio::spawn(async move {
            let conn = endpoint_beta_clone
                .accept()
                .await
                .expect("incoming")
                .expect("connection ok");
            let bytes = conn.recv_envelope().await.expect("recv");
            let opened = envelope_verifier.open(&bytes).expect("verify");
            assert_eq!(opened.sender, alpha_fp);
            opened
        });

        // Alpha dials beta and sends a signed heartbeat.
        let conn = endpoint_alpha
            .dial(dial_verifier, beta_addr)
            .await
            .expect("dial");

        let sealer = Sealer::new(id_alpha.clone());
        let bytes = sealer.seal_for(&id_beta.fingerprint(), &WhisperPayload::heartbeat("0.0.1"));
        conn.send_envelope(&bytes).await.expect("send");

        let opened = tokio::time::timeout(Duration::from_secs(5), beta_task)
            .await
            .expect("beta_task timeout")
            .expect("beta_task panic");

        match opened.payload.body {
            Some(bowery_proto::Body::Heartbeat(hb)) => {
                assert_eq!(hb.agent_version, "0.0.1");
            }
            other => panic!("unexpected body: {other:?}"),
        }

        endpoint_alpha.close().await;
        endpoint_beta.close().await;
    }

    #[tokio::test]
    #[allow(clippy::similar_names)]
    async fn dial_to_unpinned_peer_fails() {
        let id_alpha = Arc::new(Identity::generate());
        let id_beta = Arc::new(Identity::generate());
        let id_unrelated = Identity::generate();

        // Alpha pins an unrelated key; beta's cert won't match.
        let mut resolver_alpha = StaticResolver::new();
        resolver_alpha.insert(id_unrelated.verifying_key());

        let mut resolver_beta = StaticResolver::new();
        resolver_beta.insert(id_alpha.verifying_key());

        let dial_verifier = Arc::new(PinnedCertVerifier::new(resolver_alpha.clone()));
        let accept_verifier_alpha = Arc::new(PinnedCertVerifier::new(resolver_alpha));
        let accept_verifier_beta = Arc::new(PinnedCertVerifier::new(resolver_beta));

        let endpoint_beta =
            BoweryEndpoint::bind(id_beta, accept_verifier_beta, loopback()).unwrap();
        let endpoint_alpha =
            BoweryEndpoint::bind(id_alpha, accept_verifier_alpha, loopback()).unwrap();

        // Spawn an accept task so the QUIC handshake progresses to the
        // cert-verification stage where it must fail.
        let endpoint_beta_clone = endpoint_beta.clone();
        let _beta_task = tokio::spawn(async move {
            if let Some(incoming) = endpoint_beta_clone.accept().await {
                let _ = incoming;
            }
        });

        let result = endpoint_alpha
            .dial(dial_verifier, endpoint_beta.local_addr().unwrap())
            .await;
        assert!(
            result.is_err(),
            "dial should fail when server cert is unpinned: {result:?}"
        );

        endpoint_alpha.close().await;
        endpoint_beta.close().await;
    }
}
