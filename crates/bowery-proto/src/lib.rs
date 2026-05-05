//! Wire-format messages for The Bowery's whispering protocol.
//!
//! Defined directly via `prost` derive macros (no `protoc` build dep).
//! The corresponding `.proto` IDL is documented in
//! [`DESIGN.md`](../../DESIGN.md) §8.4 and is the source of truth for
//! field tags; the Rust definitions here must stay in sync.
//!
//! Phase 1a populates only [`Heartbeat`]. Other payload variants are
//! defined as empty placeholders and gain fields in later phases.

#![allow(clippy::doc_markdown)]

use prost::Message as ProstMessage;
use prost::Oneof;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// The outer envelope carried by every whisper message.
///
/// Field meanings:
/// - `sender_fingerprint`: SHA-256(verifying_key) of the sender (32 bytes).
/// - `nonce`: per-sender monotonic nonce (used by the receiver's replay guard).
/// - `ts_unix_ms`: send timestamp, ms since Unix epoch (for skew gating).
/// - `payload`: a `WhisperPayload`, encoded with prost. Phase 1a transmits
///   plaintext; Phase 5 wraps this in ChaCha20-Poly1305 ciphertext.
/// - `signature`: Ed25519 signature over a canonical concatenation of the
///   four fields above (see [`crate::CANONICAL_SIG_DOMAIN`]).
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct WhisperEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    pub sender_fingerprint: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub nonce: u64,
    #[prost(uint64, tag = "3")]
    pub ts_unix_ms: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub signature: Vec<u8>,
}

/// Domain-separation prefix for envelope signatures.
///
/// Every signed message is
///   `domain || recipient_fp || sender_fp || nonce_be || ts_be || payload`
/// where `domain` is this constant and both fingerprints are 32 bytes.
/// The prefix prevents cross-protocol signature reuse if Bowery keys
/// are ever loaded into other protocols by mistake.
///
/// **Recipient binding (Phase-8 H1):** including the *recipient*'s
/// fingerprint in the signing input means an envelope signed for
/// host A cannot be replayed against host B — even if both pin the
/// same sender — because B's signing input would be different. The
/// recipient_fp is *not* on the wire (the envelope shape is the
/// same as v1); each receiver supplies its own self-fp when
/// building the signing input. This means a mismatch between what
/// the sender targeted and what the receiver expects surfaces as
/// `BadSignature`, which is the right outcome.
///
/// Bumped from `v1` → `v2` for the recipient-binding change. Any v1
/// peers still running will see `BadSignature` from a v2 receiver
/// (and vice-versa); there's no production fleet to migrate.
pub const CANONICAL_SIG_DOMAIN: &[u8] = b"bowery/whisper/envelope/v2";

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// The inner payload, with one variant per message type.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct WhisperPayload {
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9")]
    pub body: Option<Body>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum Body {
    #[prost(message, tag = "1")]
    Question(Question),
    #[prost(message, tag = "2")]
    Answer(Answer),
    #[prost(message, tag = "3")]
    Alert(Alert),
    #[prost(message, tag = "4")]
    OperatorCommand(OperatorCommand),
    #[prost(message, tag = "5")]
    OperatorResult(OperatorResult),
    #[prost(message, tag = "6")]
    Heartbeat(Heartbeat),
    #[prost(message, tag = "7")]
    NeighborOp(NeighborOp),
    #[prost(message, tag = "8")]
    Subscribe(Subscribe),
    #[prost(message, tag = "9")]
    Alerts(Alerts),
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

/// Liveness ping. Sent at a configurable interval between paired peers.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Heartbeat {
    /// Sender's `bowery-agent` semantic-version string (e.g. `"0.0.1"`).
    #[prost(string, tag = "1")]
    pub agent_version: String,
}

// ---------------------------------------------------------------------------
// Question / Answer — Phase 5 whisper Q&A.
// ---------------------------------------------------------------------------

/// Phase-5 whisper question: "have you seen something matching this
/// tier-1 fingerprint?"
///
/// Tier-1 fingerprints are 64-bit truncations of `SHA256(domain ||
/// tier2_sha256)`; see `bowery_whisper::fingerprint`. They permit
/// collisions by design — peers can confirm or deny a *fuzzy* match
/// without leaking the underlying hash to anyone who hasn't already
/// independently observed it. Tier-2 (the full sha256) is exchanged
/// inside the encrypted whisper envelope only after both sides have
/// agreed the tier-1 hint is worth following up on.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Question {
    /// 16-byte episode id (typically uuid v4) the asker uses to
    /// correlate this question with the verdict that prompted it. We
    /// don't trust it — the asker could re-use it across questions —
    /// but it's a useful aggregation key in operator dashboards.
    #[prost(bytes = "vec", tag = "1")]
    pub episode_id: Vec<u8>,

    /// 8-byte tier-1 fingerprint of the artifact in question.
    #[prost(bytes = "vec", tag = "2")]
    pub tier1_fp: Vec<u8>,

    /// Hard deadline for responses, in milliseconds since the asker's
    /// wall clock. Responders drop this question if their local clock
    /// is past `ttl_ms` (with some skew tolerance applied separately
    /// at envelope-verification time).
    #[prost(uint64, tag = "3")]
    pub ttl_ms: u64,

    /// Optional short human-readable note (kept under 64 bytes by
    /// convention; over-long values may be truncated by responders for
    /// log-bloat reasons). Empty string means "no note".
    #[prost(string, tag = "4")]
    pub note: String,
}

/// Phase-5 whisper answer to a [`Question`]. Echoes the asker's
/// `episode_id` and `tier1_fp` so multiplexed askers can demux without
/// state-tracking, and so a malicious peer can't confuse one query with
/// another by replying out-of-order.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Answer {
    #[prost(bytes = "vec", tag = "1")]
    pub episode_id: Vec<u8>,

    #[prost(bytes = "vec", tag = "2")]
    pub tier1_fp: Vec<u8>,

    /// How many times the responder has independently observed something
    /// matching this tier-1 fingerprint. Zero means "never seen".
    #[prost(uint64, tag = "3")]
    pub seen_count: u64,

    /// First / last seen, milliseconds since unix epoch. Zero if
    /// `seen_count == 0` (no observations).
    #[prost(uint64, tag = "4")]
    pub first_seen_unix_ms: u64,

    #[prost(uint64, tag = "5")]
    pub last_seen_unix_ms: u64,

    /// Optional short note (rationale, role-tag of the responding host,
    /// etc.). Over 256 bytes is truncated by the asker.
    #[prost(string, tag = "6")]
    pub note: String,
}

// ---------------------------------------------------------------------------
// Operator I/O — Phase 6 alerts + subscribe.
// ---------------------------------------------------------------------------

/// A high-suspicion verdict surfaced to an operator. Authored by the
/// agent that observed the episode (`originator_fp`) and either pushed
/// into a per-agent inbox (where roaming operators pick it up via
/// [`Subscribe`]) or, in later phases, replicated into the mesh KV for
/// neighborhood-wide visibility.
///
/// Phase 6a only emits Alerts in response to LLM verdicts; Phase 7 may
/// also emit them for response-engine actions taken.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct Alert {
    /// 32-byte fingerprint of the agent that observed the episode. The
    /// operator-side CLI uses this to know which host to ask follow-up
    /// questions about (a future `bowery hunt` flow).
    #[prost(bytes = "vec", tag = "1")]
    pub originator_fp: Vec<u8>,

    /// Episode id from the analyzer (`bowery_analysis::Verdict::episode_id`),
    /// echoed all the way through. Stable across the alert + any later
    /// operator-issued follow-up commands.
    #[prost(string, tag = "2")]
    pub episode_id: String,

    /// Hex-encoded sha256 of the offending exe, if known. Empty when
    /// the agent couldn't enrich the event with a binary hash.
    #[prost(string, tag = "3")]
    pub exe_sha256_hex: String,

    /// Resolved exe path of the rooting process, if any.
    #[prost(string, tag = "4")]
    pub exe_path: String,

    /// Refined suspicion in `[0, 1]` from the LLM analyzer (or, when
    /// the LLM was bypassed, the pre-filter's aggregated suspicion).
    #[prost(float, tag = "5")]
    pub suspicion: f32,

    /// One- or two-sentence rationale.
    #[prost(string, tag = "6")]
    pub rationale: String,

    /// Action ids the LLM (or the agent's policy) suggested. The
    /// operator side renders these as advisory; nothing is executed
    /// until Phase 7's response engine.
    #[prost(string, repeated, tag = "7")]
    pub suggested_actions: Vec<String>,

    /// Wall-clock time when the alert was authored (ms since unix
    /// epoch). Used by the inbox cursor + retention sweeper.
    #[prost(uint64, tag = "8")]
    pub ts_unix_ms: u64,

    /// Backend label (`mock/echo`, `llama-cpp/qwen3-0.6b`, etc.). Lets
    /// dashboards segment alerts by analyzer when a fleet runs mixed
    /// LLM backends.
    #[prost(string, tag = "9")]
    pub backend: String,
}

/// Operator-issued request to drain the agent's local inbox. Sent on a
/// fresh whisper connection from the operator's CLI; the agent answers
/// with an [`Alerts`] payload on the same connection.
///
/// `since_unix_ms` is the cursor returned by the previous `Alerts`
/// response (or 0 on first connect). The agent returns every
/// not-yet-evicted alert with `ts_unix_ms >= since_unix_ms`.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Subscribe {
    #[prost(uint64, tag = "1")]
    pub since_unix_ms: u64,
    /// Soft cap on the number of alerts the agent should bundle into a
    /// single response. Zero means "no cap; return everything".
    #[prost(uint32, tag = "2")]
    pub max_items: u32,
}

/// Bundle of alerts the agent is returning to a subscribed operator.
///
/// `cursor_unix_ms` is the value the operator should pass as
/// `since_unix_ms` on the next `Subscribe`; it equals the largest
/// `Alert.ts_unix_ms + 1` in `items` (or echoes the request's value
/// when `items` is empty).
#[derive(Clone, PartialEq, ProstMessage)]
pub struct Alerts {
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<Alert>,
    #[prost(uint64, tag = "2")]
    pub cursor_unix_ms: u64,
}

// ---------------------------------------------------------------------------
// Operator commands — Phase 6b.
//
// `OperatorCommand` carries a typed `command` oneof so each variant has
// its own schema. New commands are added by extending the oneof, never
// by smuggling free-form strings — this keeps every command's input
// surface visible at code-review time. `request_id` is the asker's
// correlation token; the responder echoes it in `OperatorResult`.
// ---------------------------------------------------------------------------

// Drop the `Eq` derive on messages whose oneof contains nested oneofs —
// prost's Oneof types are `PartialEq` only (some payloads may carry
// floats in future variants). Matches the shape of `WhisperPayload`.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct OperatorCommand {
    /// Caller-chosen correlation id. Echoed in [`OperatorResult`] so the
    /// CLI can match concurrent requests.
    #[prost(string, tag = "1")]
    pub request_id: String,
    /// Per-command deadline in milliseconds. The agent enforces this on
    /// the handler side (e.g. as a wall-clock timeout on the osquery
    /// subprocess) and the CLI uses it to size its receive timeout.
    #[prost(uint32, tag = "2")]
    pub timeout_ms: u32,
    /// Phase-9 final-1: when non-empty, this command is being
    /// forwarded by a relay on behalf of an original operator.
    /// The bytes are the operator's *original* signed
    /// `WhisperEnvelope` (encoded via prost). The peer verifies
    /// the inner envelope under its own `[operators]` set,
    /// extracts the original operator's fingerprint as
    /// `inner.sender`, and uses *that* identity (not the relay's)
    /// as both the authority for the command and the recipient
    /// for sealed `SqlChunk` responses.
    ///
    /// Cycle prevention: when this field is non-empty, the peer
    /// rejects any inner command with `fanout = true`. Combined
    /// with the relay always forwarding `fanout = false`, this
    /// caps fan-out at one hop without trusting the relay.
    ///
    /// Backward compat: empty bytes preserve the slice-6 shape;
    /// the receiver uses today's "sender must be in `[operators]`"
    /// gate.
    #[prost(bytes = "vec", tag = "3")]
    pub forwarded_from_operator: Vec<u8>,
    /// One of the typed command bodies.
    #[prost(oneof = "OperatorCommandBody", tags = "10, 11")]
    pub command: Option<OperatorCommandBody>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum OperatorCommandBody {
    /// Run a SQL query against a host-installed `sysquery` binary
    /// (subprocess wrapper, see `bowery-sysquery`). Surface is the
    /// binary's own table set — typically broader than the native
    /// Bowery tables but pulled in via subprocess. Read-only by
    /// design; the agent additionally rejects any query containing
    /// forbidden keywords (Phase 6b polish — start permissive,
    /// tighten later).
    #[prost(message, tag = "10")]
    Sysquery(SysqueryQuery),
    /// Run a SQL query against the agent's native Phase-9 SQL
    /// surface (`bowery-sql`). The response is *streamed*: the
    /// agent emits one or more `SqlChunk` envelopes (each in its
    /// own unidirectional QUIC stream, all with the same
    /// `request_id`) terminated by either a chunk with `end =
    /// true` or an `Error` body. Operator-side decoder loops on
    /// `recv_envelope` until it sees the terminal frame.
    #[prost(message, tag = "11")]
    Sql(SqlQuery),
}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct SysqueryQuery {
    /// SQL string. Subject to per-agent allow-list policy at handler
    /// time; the agent may refuse any query the local config doesn't
    /// permit.
    #[prost(string, tag = "1")]
    pub sql: String,
}

/// Phase-9 final-1: operator-signed delegation that authorises a
/// relay to forward a `SqlQuery` to its pinned peers.
///
/// Carried inside [`OperatorCommand::forwarded_from_operator`]
/// (encoded via prost). The peer verifies:
///
/// 1. The signature over `signing_input(operator_fp, ts_unix_ms,
///    request_id, command_digest)` against the operator's pubkey
///    (must be in the peer's `[operators]` set).
/// 2. `request_id` matches the outer `OperatorCommand.request_id`.
/// 3. `command_digest = SHA-256(prost-encoded
///    OperatorCommandBody)` matches the actual outer command.
/// 4. `ts_unix_ms` is within the same skew window as the envelope
///    layer.
///
/// On success the peer treats `operator_fp` as the authority for
/// the command and seals every `SqlChunk` response for it (rather
/// than for the relay it received the envelope from). The relay
/// forwards peer envelope bytes verbatim — F-1 / F-2 / F-3
/// closure: the relay can drop peer chunks but cannot fabricate
/// or tamper with their contents.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct OperatorAuthorization {
    /// 32-byte fingerprint of the original operator. The peer
    /// looks this up in its `[operators]` resolver.
    #[prost(bytes = "vec", tag = "1")]
    pub operator_fp: Vec<u8>,
    /// Authorisation timestamp, ms since UNIX epoch. Subject to
    /// the same skew check as envelope `ts_unix_ms`.
    #[prost(uint64, tag = "2")]
    pub ts_unix_ms: u64,
    /// Echoes the outer `OperatorCommand.request_id` so the peer
    /// can confirm the authorisation matches the command it's
    /// processing.
    #[prost(string, tag = "3")]
    pub request_id: String,
    /// SHA-256 of the prost-encoded `OperatorCommandBody` the
    /// peer will execute. Binds the authorisation to a specific
    /// command — the relay can't substitute a different SQL
    /// string under an authorisation issued for some other
    /// query.
    #[prost(bytes = "vec", tag = "4")]
    pub command_digest: Vec<u8>,
    /// Ed25519 signature over `OPERATOR_AUTHORIZATION_DOMAIN ||
    /// operator_fp || ts_be || request_id_len_be || request_id ||
    /// command_digest`.
    #[prost(bytes = "vec", tag = "5")]
    pub signature: Vec<u8>,
}

/// Domain-separation prefix for [`OperatorAuthorization`]
/// signatures. Bumped if the canonical input ever changes.
pub const OPERATOR_AUTHORIZATION_DOMAIN: &[u8] = b"bowery/operator-authorization/v1";

impl OperatorAuthorization {
    /// Build the canonical bytes that the operator's Ed25519 key
    /// signs over. Mirror this layout in [`Self::verify`].
    pub fn signing_input(
        operator_fp: &[u8; 32],
        ts_unix_ms: u64,
        request_id: &str,
        command_digest: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            OPERATOR_AUTHORIZATION_DOMAIN.len() + 32 + 8 + 4 + request_id.len() + 32,
        );
        buf.extend_from_slice(OPERATOR_AUTHORIZATION_DOMAIN);
        buf.extend_from_slice(operator_fp);
        buf.extend_from_slice(&ts_unix_ms.to_be_bytes());
        let req_len = u32::try_from(request_id.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&req_len.to_be_bytes());
        buf.extend_from_slice(request_id.as_bytes());
        buf.extend_from_slice(command_digest);
        buf
    }
}

/// Phase-9 SQL command body. See [`OperatorCommandBody::Sql`].
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct SqlQuery {
    /// SQL string evaluated against the agent's native table set
    /// (see `bowery-tables`). No allow-list — every Phase-9 table
    /// is read-only over `procfs`/`sysfs`/`/etc`, so an arbitrary
    /// SELECT exposes only what the agent already publishes via
    /// other channels.
    #[prost(string, tag = "1")]
    pub sql: String,
    /// Phase-9 slice 7: when true, the dialled agent acts as a
    /// **relay** — it runs the query locally *and* dispatches it
    /// to its pinned peers, multiplexing every peer's chunks back
    /// over the same operator connection. When false, only the
    /// directly-dialled agent runs the query (slice-6 shape).
    ///
    /// Cycle prevention: the relay always sends `fanout = false`
    /// to peers, so a peer never recurses. Operators set this to
    /// `true` for one-hop fan-out.
    #[prost(bool, tag = "2")]
    pub fanout: bool,
    /// Optional explicit peer-fingerprint filter for fanout. Each
    /// entry is a 32-byte fingerprint. Empty = every pinned peer
    /// the relay has in `KnownNeighbors`. Ignored when `fanout =
    /// false`.
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub peers: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, ProstMessage)]
pub struct OperatorResult {
    /// Echo of [`OperatorCommand::request_id`].
    #[prost(string, tag = "1")]
    pub request_id: String,
    /// One of the typed result bodies. Distinct from a top-level
    /// `error` field so a future "always populated alongside the
    /// concrete result" pattern (e.g. structured warnings) can
    /// extend cleanly.
    #[prost(oneof = "OperatorResultBody", tags = "10, 11, 12")]
    pub result: Option<OperatorResultBody>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum OperatorResultBody {
    /// Successful execution of a `Sysquery` command. Schema is
    /// the wrapped binary's JSON output as a string.
    #[prost(message, tag = "10")]
    Sysquery(SysqueryResult),
    /// The handler refused or failed the command. Always populated
    /// when the agent could parse the request but declined to run
    /// it (policy denial, subprocess failure, timeout, etc.). For
    /// "I couldn't even decode the envelope" the asker sees a
    /// transport-level error, not this.
    #[prost(message, tag = "11")]
    Error(OperatorError),
    /// One chunk of a streaming SQL response. Multiple `SqlChunk`
    /// envelopes share the same `request_id`. The first chunk
    /// carries `columns`; subsequent chunks leave it empty. The
    /// final chunk has `end = true` (and may also carry rows).
    #[prost(message, tag = "12")]
    SqlChunk(SqlChunk),
}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct SysqueryResult {
    /// JSON array — the raw stdout of the wrapped binary called
    /// with `--json <sql>`. Operator-side tooling parses this with
    /// `serde_json::Value`; keeping it as a string here means we
    /// don't have to model every column type in protobuf.
    #[prost(string, tag = "1")]
    pub json: String,
    /// Wrapped binary's exit status (0 = success, non-zero =
    /// handler fell back without a structured reason).
    #[prost(int32, tag = "2")]
    pub exit_code: i32,
}

/// One chunk of a streaming SQL response. See
/// [`OperatorResultBody::SqlChunk`] for the framing protocol.
///
/// Empty rows + `end = true` is a valid terminator (used when the
/// query produced no rows but still completed successfully). An
/// error mid-stream is signalled by sending an `Error` body
/// instead of a further `SqlChunk`; the operator-side decoder
/// must accept either as a stream terminator.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct SqlChunk {
    /// Column names — populated only on the first chunk *per
    /// agent*. In fan-out mode, every distinct agent's first chunk
    /// carries column names; subsequent chunks from the same agent
    /// leave it empty.
    #[prost(string, repeated, tag = "1")]
    pub columns: Vec<String>,
    /// Row batch. Each row's `values` length matches `columns`
    /// length from the first chunk that carried them.
    #[prost(message, repeated, tag = "2")]
    pub rows: Vec<SqlRow>,
    /// Terminator flag *for this agent's stream*. In single-agent
    /// (non-fanout) mode, this is the stream terminator full-stop.
    /// In fan-out mode, the relay multiplexes per-peer streams and
    /// emits one chunk with `end = true` per peer (including
    /// itself); the operator-side decoder counts EOFs against the
    /// expected peer set.
    #[prost(bool, tag = "3")]
    pub end: bool,
    /// Phase-9 slice 7: 32-byte fingerprint of the agent that
    /// produced this chunk. Populated on the relay path so the
    /// operator can attribute rows. Empty in single-agent mode —
    /// the operator infers attribution from the connection's
    /// pinned fingerprint.
    #[prost(bytes = "vec", tag = "4")]
    pub agent_fp: Vec<u8>,
}

/// One row in a SQL response chunk.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct SqlRow {
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<SqlValue>,
}

/// One typed cell in a `SqlRow`. Mirrors the five SQLite storage
/// classes exactly (NULL, INTEGER, REAL, TEXT, BLOB). Empty
/// `value` means SQL NULL — prost can't distinguish "field not
/// set" from "null integer = 0", so we use the absence of the
/// oneof to mean NULL.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct SqlValue {
    #[prost(oneof = "SqlValueKind", tags = "1, 2, 3, 4")]
    pub value: Option<SqlValueKind>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum SqlValueKind {
    #[prost(int64, tag = "1")]
    Integer(i64),
    #[prost(double, tag = "2")]
    Real(f64),
    #[prost(string, tag = "3")]
    Text(String),
    #[prost(bytes, tag = "4")]
    Blob(Vec<u8>),
}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct OperatorError {
    /// Stable, programmatic error tag — `"policy_denied"`,
    /// `"timeout"`, `"unsupported_command"`, `"handler_error"`.
    #[prost(string, tag = "1")]
    pub kind: String,
    /// Human-readable detail. Operators see this verbatim; never
    /// embed paths or other host-specific data the operator
    /// shouldn't know.
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct NeighborOp {}

// ---------------------------------------------------------------------------
// Bloom advert — published to the mesh KV (chitchat), not via envelope.
// ---------------------------------------------------------------------------

/// A periodic "what tier-1 fingerprints have I seen" advert, gossiped
/// through the mesh KV. Encoded as protobuf for compactness and
/// schema-evolution; the KV value is base64'd by the mesh layer if
/// needed for transport.
///
/// Privacy trade-off: this leaks a coarse view of every host's
/// observation set in the public KV. Two mitigations:
/// 1. Tier-1 fingerprints are 64-bit and intentionally collidable.
/// 2. Bloom filters add a second layer of indistinguishability — a
///    "yes" set-membership in the filter is consistent with collisions
///    on top of collisions.
///
/// Tier-2 (the full sha256) only travels through the encrypted whisper
/// envelope, after both sides agree the tier-1 hint is worth chasing.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct BloomAdvert {
    /// Monotonic epoch counter. Receivers keep only the highest epoch
    /// from any given peer; lower-epoch adverts are stale.
    #[prost(uint64, tag = "1")]
    pub epoch: u64,

    /// Filter size in bits. Must equal `bits.len() * 8`.
    #[prost(uint32, tag = "2")]
    pub bit_count: u32,

    /// Number of hash positions per insert. Bounded at sender side; the
    /// receiver should reject impossibly large values.
    #[prost(uint32, tag = "3")]
    pub k: u32,

    /// Raw filter bytes (length = `bit_count / 8`).
    #[prost(bytes = "vec", tag = "4")]
    pub bits: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

impl WhisperPayload {
    pub fn heartbeat(agent_version: impl Into<String>) -> Self {
        Self {
            body: Some(Body::Heartbeat(Heartbeat {
                agent_version: agent_version.into(),
            })),
        }
    }

    pub fn question(q: Question) -> Self {
        Self {
            body: Some(Body::Question(q)),
        }
    }

    pub fn answer(a: Answer) -> Self {
        Self {
            body: Some(Body::Answer(a)),
        }
    }

    pub fn alert(a: Alert) -> Self {
        Self {
            body: Some(Body::Alert(a)),
        }
    }

    pub fn subscribe(s: Subscribe) -> Self {
        Self {
            body: Some(Body::Subscribe(s)),
        }
    }

    pub fn alerts(a: Alerts) -> Self {
        Self {
            body: Some(Body::Alerts(a)),
        }
    }

    pub fn operator_command(c: OperatorCommand) -> Self {
        Self {
            body: Some(Body::OperatorCommand(c)),
        }
    }

    pub fn operator_result(r: OperatorResult) -> Self {
        Self {
            body: Some(Body::OperatorResult(r)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_roundtrip() {
        let original = WhisperPayload::heartbeat("0.0.1");
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        assert_eq!(original, decoded);
        match decoded.body {
            Some(Body::Heartbeat(hb)) => assert_eq!(hb.agent_version, "0.0.1"),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn question_roundtrip() {
        let q = Question {
            episode_id: vec![0xab; 16],
            tier1_fp: vec![0xcd; 8],
            ttl_ms: 60_000,
            note: "binary scored 0.83".into(),
        };
        let original = WhisperPayload::question(q.clone());
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::Question(got)) => assert_eq!(got, q),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn answer_roundtrip() {
        let a = Answer {
            episode_id: vec![0xab; 16],
            tier1_fp: vec![0xcd; 8],
            seen_count: 3,
            first_seen_unix_ms: 1_700_000_000_000,
            last_seen_unix_ms: 1_700_000_300_000,
            note: "common across web tier".into(),
        };
        let original = WhisperPayload::answer(a.clone());
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::Answer(got)) => assert_eq!(got, a),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn alert_roundtrip() {
        let alert = Alert {
            originator_fp: vec![0xaa; 32],
            episode_id: "ep-7".into(),
            exe_sha256_hex: "abcdef".repeat(8),
            exe_path: "/tmp/payload".into(),
            suspicion: 0.92,
            rationale: "writable-path exec".into(),
            suggested_actions: vec!["alert".into(), "kill_process".into()],
            ts_unix_ms: 1_730_000_000_000,
            backend: "mock/echo".into(),
        };
        let original = WhisperPayload::alert(alert.clone());
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::Alert(got)) => assert_eq!(got, alert),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn subscribe_and_alerts_roundtrip() {
        let sub = Subscribe {
            since_unix_ms: 1_700_000_000_000,
            max_items: 100,
        };
        let bytes = WhisperPayload::subscribe(sub.clone()).encode_to_vec();
        match WhisperPayload::decode(bytes.as_slice()).unwrap().body {
            Some(Body::Subscribe(got)) => assert_eq!(got, sub),
            other => panic!("unexpected body: {other:?}"),
        }

        let resp = Alerts {
            items: vec![Alert {
                originator_fp: vec![1; 32],
                episode_id: "x".into(),
                exe_sha256_hex: "deadbeef".into(),
                exe_path: "/x".into(),
                suspicion: 0.5,
                rationale: "y".into(),
                suggested_actions: vec![],
                ts_unix_ms: 7,
                backend: "test".into(),
            }],
            cursor_unix_ms: 8,
        };
        let bytes = WhisperPayload::alerts(resp.clone()).encode_to_vec();
        match WhisperPayload::decode(bytes.as_slice()).unwrap().body {
            Some(Body::Alerts(got)) => assert_eq!(got, resp),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn bloom_advert_roundtrip() {
        let advert = BloomAdvert {
            epoch: 7,
            bit_count: 1024,
            k: 6,
            bits: vec![0xff; 128],
        };
        let bytes = advert.encode_to_vec();
        let decoded = BloomAdvert::decode(bytes.as_slice()).unwrap();
        assert_eq!(advert, decoded);
    }

    #[test]
    fn sql_chunk_roundtrip_streams_typed_values() {
        // Build a chunk that exercises every SqlValueKind variant
        // plus a NULL (None oneof) — the wire format must round-
        // trip all five SQLite storage classes losslessly.
        let row1 = SqlRow {
            values: vec![
                SqlValue {
                    value: Some(SqlValueKind::Integer(42)),
                },
                SqlValue {
                    value: Some(SqlValueKind::Text("hello".into())),
                },
                SqlValue { value: None }, // NULL
            ],
        };
        let row2 = SqlRow {
            values: vec![
                SqlValue {
                    value: Some(SqlValueKind::Real(2.5)),
                },
                SqlValue {
                    value: Some(SqlValueKind::Blob(vec![0xde, 0xad, 0xbe, 0xef])),
                },
                SqlValue { value: None },
            ],
        };
        let chunk = SqlChunk {
            columns: vec!["a".into(), "b".into(), "c".into()],
            rows: vec![row1, row2],
            end: true,
            agent_fp: vec![0x42; 32],
        };
        let result = OperatorResult {
            request_id: "req-1".into(),
            result: Some(OperatorResultBody::SqlChunk(chunk.clone())),
        };
        let bytes = WhisperPayload::operator_result(result).encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::OperatorResult(r)) => {
                assert_eq!(r.request_id, "req-1");
                match r.result {
                    Some(OperatorResultBody::SqlChunk(got)) => assert_eq!(got, chunk),
                    other => panic!("unexpected result body: {other:?}"),
                }
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn sql_query_command_roundtrip() {
        let cmd = OperatorCommand {
            request_id: "q-7".into(),
            timeout_ms: 5_000,
            forwarded_from_operator: Vec::new(),
            command: Some(OperatorCommandBody::Sql(SqlQuery {
                sql: "SELECT pid FROM processes LIMIT 5".into(),
                fanout: false,
                peers: Vec::new(),
            })),
        };
        let bytes = WhisperPayload::operator_command(cmd.clone()).encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::OperatorCommand(got)) => assert_eq!(got, cmd),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn empty_envelope_roundtrip() {
        let env = WhisperEnvelope {
            sender_fingerprint: vec![0u8; 32],
            nonce: 42,
            ts_unix_ms: 1_700_000_000_000,
            payload: WhisperPayload::heartbeat("0.0.1").encode_to_vec(),
            signature: vec![0u8; 64],
        };
        let bytes = env.encode_to_vec();
        let decoded = WhisperEnvelope::decode(bytes.as_slice()).unwrap();
        assert_eq!(env, decoded);
    }
}
