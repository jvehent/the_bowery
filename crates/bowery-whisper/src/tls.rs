//! TLS layer for the whispering protocol.
//!
//! Bowery uses RFC-7250-style raw-public-key authentication, expressed as
//! self-signed X.509 certificates whose Subject Public Key Info is the
//! agent's Ed25519 verifying key. There is no PKI: peers authenticate each
//! other by SHA-256(pubkey) — the same [`Fingerprint`] used in envelope
//! signatures — looked up against a [`FingerprintResolver`].
//!
//! This module covers:
//! - [`build_self_signed_cert`]: derive a `(cert, key)` pair from an
//!   [`Identity`].
//! - [`extract_pubkey_fingerprint`]: hash a leaf certificate's Ed25519
//!   public key.
//! - [`PinnedCertVerifier`]: a rustls verifier that implements both
//!   `ServerCertVerifier` and `ClientCertVerifier` using fingerprint
//!   pinning instead of chain validation.

use bowery_crypto::{Fingerprint, Identity};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    DigitallySignedStruct, DistinguishedName as RustlsDn, Error as RustlsError, SignatureScheme,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::envelope::FingerprintResolver;

/// DER encoding of the ed25519 OID (`1.3.101.112`).
const ED25519_OID: &[u8] = &[0x2B, 0x65, 0x70];
const ED25519_PUBKEY_LEN: usize = 32;
const CERT_VALIDITY_DAYS: i64 = 365 * 100;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to encode identity to PKCS8: {0}")]
    Pkcs8(String),

    #[error("rcgen error: {0}")]
    Rcgen(String),

    #[error("unsupported certificate algorithm; expected ed25519")]
    UnsupportedAlgorithm,

    #[error("certificate parse failed: {0}")]
    CertParse(String),

    #[error("ed25519 public key has unexpected length: {0}")]
    BadKeyLength(usize),
}

// ---------------------------------------------------------------------------
// Cert generation
// ---------------------------------------------------------------------------

/// A self-signed certificate paired with its private key, ready to feed into
/// rustls.
#[derive(Debug)]
pub struct TlsMaterial {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl TlsMaterial {
    /// SHA-256 fingerprint of the certificate's Ed25519 public key.
    pub fn fingerprint(&self) -> Result<Fingerprint, Error> {
        extract_pubkey_fingerprint(&self.cert)
    }
}

/// Build a self-signed X.509 certificate from the agent's identity.
///
/// The certificate's Subject Public Key is the identity's Ed25519 verifying
/// key. SHA-256 of that pubkey is the same [`Fingerprint`] used elsewhere in
/// the protocol, so a single pinning store covers both envelope signatures
/// and TLS handshakes.
pub fn build_self_signed_cert(identity: &Identity) -> Result<TlsMaterial, Error> {
    let pkcs8_doc = identity
        .signing_key()
        .to_pkcs8_der()
        .map_err(|e| Error::Pkcs8(e.to_string()))?;
    let pkcs8_bytes = pkcs8_doc.as_bytes();

    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8_bytes.to_vec());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &PKCS_ED25519)
        .map_err(|e| Error::Rcgen(e.to_string()))?;

    let mut params = CertificateParams::new(vec!["bowery.local".to_string()])
        .map_err(|e| Error::Rcgen(e.to_string()))?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "bowery");
    params.distinguished_name = name;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(CERT_VALIDITY_DAYS);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Rcgen(e.to_string()))?;

    Ok(TlsMaterial {
        cert: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(pkcs8_der),
    })
}

// ---------------------------------------------------------------------------
// Pubkey extraction
// ---------------------------------------------------------------------------

/// Extract the Ed25519 public key from a leaf certificate and return its
/// SHA-256 fingerprint.
pub fn extract_pubkey_fingerprint(cert: &CertificateDer<'_>) -> Result<Fingerprint, Error> {
    let (_, parsed) =
        X509Certificate::from_der(cert.as_ref()).map_err(|e| Error::CertParse(e.to_string()))?;
    let spki = &parsed.tbs_certificate.subject_pki;
    let alg = spki.algorithm.algorithm.as_bytes();
    if alg != ED25519_OID {
        return Err(Error::UnsupportedAlgorithm);
    }
    let pubkey = spki.subject_public_key.data.as_ref();
    if pubkey.len() != ED25519_PUBKEY_LEN {
        return Err(Error::BadKeyLength(pubkey.len()));
    }
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    Ok(Fingerprint::from_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// rustls verifier shared by both ends of a Bowery handshake.
///
/// Pins by SHA-256(Ed25519 pubkey) and resolves through the caller's
/// [`FingerprintResolver`]. When `expected` is set, the resolved fingerprint
/// must additionally equal that value (used by clients dialing a specific
/// known peer).
pub struct PinnedCertVerifier<R> {
    resolver: R,
    expected: Option<Fingerprint>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl<R> std::fmt::Debug for PinnedCertVerifier<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("expected", &self.expected)
            .finish_non_exhaustive()
    }
}

impl<R> PinnedCertVerifier<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            expected: None,
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }

    pub fn expecting(resolver: R, expected: Fingerprint) -> Self {
        Self {
            expected: Some(expected),
            ..Self::new(resolver)
        }
    }
}

impl<R: FingerprintResolver> PinnedCertVerifier<R> {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), RustlsError> {
        let fp = extract_pubkey_fingerprint(end_entity)
            .map_err(|e| RustlsError::General(format!("bowery cert: {e}")))?;
        if let Some(expected) = self.expected
            && fp != expected
        {
            return Err(RustlsError::General(format!(
                "peer fingerprint {fp} does not match expected {expected}"
            )));
        }
        if self.resolver.resolve(&fp).is_none() {
            return Err(RustlsError::General(format!(
                "peer fingerprint {fp} is not pinned"
            )));
        }
        Ok(())
    }
}

impl<R: FingerprintResolver + 'static> ServerCertVerifier for PinnedCertVerifier<R> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

impl<R: FingerprintResolver + 'static> ClientCertVerifier for PinnedCertVerifier<R> {
    fn root_hint_subjects(&self) -> &[RustlsDn] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::StaticResolver;
    use rustls::pki_types::ServerName;

    fn make_cert(identity: &Identity) -> TlsMaterial {
        build_self_signed_cert(identity).expect("self-signed cert")
    }

    #[test]
    fn cert_fingerprint_matches_identity_fingerprint() {
        let id = Identity::generate();
        let mat = make_cert(&id);
        assert_eq!(mat.fingerprint().unwrap(), id.fingerprint());
    }

    #[test]
    fn extract_pubkey_fingerprint_matches() {
        let id = Identity::generate();
        let mat = make_cert(&id);
        let fp = extract_pubkey_fingerprint(&mat.cert).unwrap();
        assert_eq!(fp, id.fingerprint());
    }

    #[test]
    fn server_verifier_accepts_pinned_cert() {
        let id = Identity::generate();
        let mat = make_cert(&id);
        let mut resolver = StaticResolver::new();
        resolver.insert(id.verifying_key());
        let verifier = PinnedCertVerifier::new(resolver);

        let server_name = ServerName::try_from("bowery.local").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1));
        verifier
            .verify_server_cert(&mat.cert, &[], &server_name, &[], now)
            .expect("pinned cert should verify");
    }

    #[test]
    fn server_verifier_rejects_unpinned_cert() {
        let id = Identity::generate();
        let mat = make_cert(&id);
        let resolver = StaticResolver::new(); // no pins
        let verifier = PinnedCertVerifier::new(resolver);

        let server_name = ServerName::try_from("bowery.local").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1));
        let err = verifier
            .verify_server_cert(&mat.cert, &[], &server_name, &[], now)
            .unwrap_err();
        assert!(format!("{err}").contains("not pinned"));
    }

    #[test]
    fn server_verifier_rejects_when_expected_fingerprint_mismatches() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let mat = make_cert(&id_a);
        let mut resolver = StaticResolver::new();
        resolver.insert(id_a.verifying_key());
        let verifier = PinnedCertVerifier::expecting(resolver, id_b.fingerprint());

        let server_name = ServerName::try_from("bowery.local").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1));
        let err = verifier
            .verify_server_cert(&mat.cert, &[], &server_name, &[], now)
            .unwrap_err();
        assert!(format!("{err}").contains("does not match expected"));
    }

    #[test]
    fn client_verifier_accepts_pinned_cert() {
        let id = Identity::generate();
        let mat = make_cert(&id);
        let mut resolver = StaticResolver::new();
        resolver.insert(id.verifying_key());
        let verifier: PinnedCertVerifier<_> = PinnedCertVerifier::new(resolver);

        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1));
        ClientCertVerifier::verify_client_cert(&verifier, &mat.cert, &[], now)
            .expect("pinned client cert should verify");
    }

    #[test]
    fn rejects_non_ed25519_cert() {
        // Build an RSA-style cert via rcgen and confirm we reject it.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["other".to_string()]).unwrap();
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, "other");
        params.distinguished_name = name;
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().clone();
        let err = extract_pubkey_fingerprint(&cert_der).unwrap_err();
        assert!(matches!(err, Error::UnsupportedAlgorithm));
    }
}
