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

    /// Neighbourhood corroboration for this episode, when a whisper Q&A
    /// round ran. `None` on alerts that never whisper (file-watch hits,
    /// YARA matches) and on the first alert for an episode — the round
    /// starts *after* the initial alert is emitted, so confirmation
    /// arrives as a second, superseding alert for the same `episode_id`.
    #[prost(message, optional, tag = "10")]
    pub confirmation: Option<AlertConfirmation>,
}

/// Outcome of asking role-similar peers about an episode's binary.
///
/// Polarity matters and is easy to get backwards: a peer answering
/// `seen_count > 0` means "I have this binary in my baseline too", which
/// argues the binary is a normal fleet artifact — *less* suspicious. So
/// confirmation is driven by `peers_unseen`: a quorum of neighbours that
/// have **never** seen it makes the binary anomalous for this fleet.
/// `peers_seen` is reported alongside rather than folded in, so an
/// operator can tell "nobody has this" from "everybody has this" instead
/// of being handed a single opaque number.
#[derive(Clone, Copy, PartialEq, Eq, ProstMessage)]
pub struct AlertConfirmation {
    /// Peers actually dialled this round (after role-similarity ranking
    /// and the bloom pre-filter).
    #[prost(uint32, tag = "1")]
    pub peers_asked: u32,
    /// Replied "never seen it" — the evidence that confirms.
    #[prost(uint32, tag = "2")]
    pub peers_unseen: u32,
    /// Replied "seen it", with a count. Argues the binary is common.
    #[prost(uint32, tag = "3")]
    pub peers_seen: u32,
    /// Timed out or failed to dial. Never counts toward a quorum —
    /// silence is not evidence.
    #[prost(uint32, tag = "4")]
    pub peers_no_reply: u32,
    /// The threshold in force when this verdict was computed, so an
    /// operator reading an old alert knows what "confirmed" meant then.
    #[prost(uint32, tag = "5")]
    pub quorum: u32,
    /// `peers_unseen >= quorum`.
    #[prost(bool, tag = "6")]
    pub confirmed: bool,
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
    /// True on the final chunk of a response. A large inbox is split
    /// across several sub-frame-sized `Alerts` envelopes so none exceeds
    /// the transport frame cap — a single oversized frame is rejected,
    /// which would silently deliver *zero* alerts. The operator reads
    /// `Alerts` envelopes until it sees `end = true`; only the final
    /// chunk's `cursor_unix_ms` is authoritative.
    #[prost(bool, tag = "3")]
    pub end: bool,
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
    /// the handler side (e.g. as a SQL wall-clock timeout) and the CLI
    /// uses it to size its receive timeout.
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
    /// rejects any inner **`Sql`** command with `fanout = true`.
    /// Combined with the relay always forwarding `fanout = false`,
    /// this caps SQL fan-out at one hop without trusting the relay.
    ///
    /// [`YaraPush`] is deliberately exempt: rule distribution is
    /// meant to reach the whole mesh, so it is bounded by its own
    /// `ttl` hop counter plus a per-agent `(operator_fp,
    /// request_id)` seen-set instead of a one-hop cap.
    ///
    /// Backward compat: empty bytes preserve the slice-6 shape;
    /// the receiver uses today's "sender must be in `[operators]`"
    /// gate.
    #[prost(bytes = "vec", tag = "3")]
    pub forwarded_from_operator: Vec<u8>,
    /// One of the typed command bodies.
    #[prost(oneof = "OperatorCommandBody", tags = "11, 12, 13")]
    pub command: Option<OperatorCommandBody>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum OperatorCommandBody {
    /// Run a SQL query against the agent's native Phase-9 SQL
    /// surface (`bowery-sql`). The response is *streamed*: the
    /// agent emits one or more `SqlChunk` envelopes (each in its
    /// own unidirectional QUIC stream, all with the same
    /// `request_id`) terminated by either a chunk with `end =
    /// true` or an `Error` body. Operator-side decoder loops on
    /// `recv_envelope` until it sees the terminal frame.
    #[prost(message, tag = "11")]
    Sql(SqlQuery),
    /// Distribute a YARA rule file to the agent, scan the given
    /// targets with it, and (when `fanout`) propagate it onward
    /// through the mesh. The response is a `YaraReport` per
    /// reporting agent, terminated the same way SQL chunks are.
    #[prost(message, tag = "12")]
    YaraPush(YaraPush),
    /// Deliver an operator-signed [`Revocation`] to the agent and, when
    /// `fanout`, propagate it onward through the mesh.
    ///
    /// Unlike every other command body, the payload here is
    /// *self-authenticating*: the revocation carries its own operator
    /// signature, so a receiving agent verifies it directly instead of
    /// trusting the delegation chain that carried it. A relaying peer
    /// can therefore drop a revocation but cannot forge one.
    #[prost(message, tag = "13")]
    RevokePush(RevokePush),
}

/// See [`OperatorCommandBody::RevokePush`].
#[derive(Clone, PartialEq, ProstMessage)]
pub struct RevokePush {
    /// Prost-encoded [`Revocation`].
    #[prost(bytes = "vec", tag = "1")]
    pub revocation: Vec<u8>,
    /// When true, forward to pinned peers (subject to `ttl`).
    #[prost(bool, tag = "2")]
    pub fanout: bool,
    /// Remaining hops. Each forwarding agent decrements it and stops at
    /// zero — a structural bound on amplification, independent of the
    /// natural termination that comes from the revocation store (a
    /// re-seen revocation is not new, so it is not forwarded).
    #[prost(uint32, tag = "3")]
    pub ttl: u32,
}

/// One agent's response to a [`RevokePush`].
///
/// The flags are deliberately not collapsed into an enum: they are
/// independent facts an operator needs separately — a report can be
/// `accepted` *and* `already_known` (converged) or `accepted` and
/// `evicted` (it was actively trusted here until now).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, PartialEq, ProstMessage)]
pub struct RevokeReport {
    /// Reporting agent. Empty on the fan-out completion terminator.
    #[prost(bytes = "vec", tag = "1")]
    pub agent_fp: Vec<u8>,
    /// The revocation verified and is now in force on this agent.
    #[prost(bool, tag = "2")]
    pub accepted: bool,
    /// Already held — reported separately from `accepted` because it is
    /// what tells an operator the fleet has converged rather than that
    /// the push is still spreading.
    #[prost(bool, tag = "3")]
    pub already_known: bool,
    /// Whether the target was pinned here and has now been evicted.
    #[prost(bool, tag = "4")]
    pub evicted: bool,
    #[prost(string, tag = "5")]
    pub error: String,
    #[prost(bool, tag = "6")]
    pub end: bool,
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

/// Distribute + run a YARA rule file. See
/// [`OperatorCommandBody::YaraPush`].
///
/// The rule bytes travel inside the signed `OperatorCommand`, so every
/// hop re-verifies the *original operator's* signature over the exact
/// command (see [`OperatorAuthorization`]): a relaying agent can drop a
/// rule but cannot forge or alter one.
///
/// Size: the whole envelope must fit the transport frame cap (64 KiB),
/// so `rules` is bounded well below that — the agent rejects an
/// oversized push with a `rule_too_large` error rather than letting the
/// stream tear down.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct YaraPush {
    /// Content address of `rules` (lowercase hex SHA-256). Used as the
    /// on-disk filename and the `bowery_yara_rules` primary key, so the
    /// same rule pushed twice doesn't duplicate.
    #[prost(string, tag = "1")]
    pub rule_id: String,
    /// The raw YARA source. Compiled on receipt; a rule that fails to
    /// compile is rejected and never stored.
    #[prost(bytes = "vec", tag = "2")]
    pub rules: Vec<u8>,
    /// Absolute paths (files or directories) to scan on this agent.
    /// Empty = store the rule without scanning.
    #[prost(string, repeated, tag = "3")]
    pub targets: Vec<String>,
    /// When true, forward this push to pinned peers (subject to `ttl`).
    #[prost(bool, tag = "4")]
    pub fanout: bool,
    /// Remaining hops. Each forwarding agent decrements it and stops at
    /// zero — the structural bound on mesh amplification, independent of
    /// the `(operator_fp, request_id)` seen-set that prevents cycles.
    #[prost(uint32, tag = "5")]
    pub ttl: u32,
}

/// One agent's YARA scan result. See [`OperatorResultBody::YaraReport`].
///
/// Framing mirrors `SqlChunk`: one report per contributing agent, and in
/// fan-out mode the relay emits a final terminator report with an empty
/// `agent_fp` once every peer has finished.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct YaraReport {
    /// Fingerprint of the reporting agent. Operators should prefer the
    /// authenticated envelope sender for attribution; this field is a
    /// rendering convenience. Empty + `end = true` is the fan-out
    /// completion terminator.
    #[prost(bytes = "vec", tag = "1")]
    pub agent_fp: Vec<u8>,
    /// Content address of the rule this report is about.
    #[prost(string, tag = "2")]
    pub rule_id: String,
    /// Every match this agent found.
    #[prost(message, repeated, tag = "3")]
    pub matches: Vec<YaraMatch>,
    /// How many files were scanned (after caps were applied).
    #[prost(uint32, tag = "4")]
    pub scanned: u32,
    /// Non-fatal problems (unreadable paths, per-file timeouts, caps
    /// hit). A fatal failure is reported as an `Error` body instead.
    #[prost(string, repeated, tag = "5")]
    pub errors: Vec<String>,
    /// Terminator flag for this agent's stream.
    #[prost(bool, tag = "6")]
    pub end: bool,
}

/// A single YARA rule match.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct YaraMatch {
    /// The matching rule's identifier from the YARA source.
    #[prost(string, tag = "1")]
    pub rule_name: String,
    /// Path of the file that matched.
    #[prost(string, tag = "2")]
    pub path: String,
    /// Tags declared on the matching rule.
    #[prost(string, repeated, tag = "3")]
    pub tags: Vec<String>,
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
    #[prost(oneof = "OperatorResultBody", tags = "11, 12, 13, 14")]
    pub result: Option<OperatorResultBody>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum OperatorResultBody {
    /// The handler refused or failed the command. Always populated
    /// when the agent could parse the request but declined to run
    /// it (policy denial, handler error, timeout, etc.). For
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
    /// One agent's YARA scan result. Multiple `YaraReport` envelopes
    /// share the same `request_id` in fan-out mode (one per agent),
    /// terminated by a report with an empty `agent_fp` and `end = true`.
    #[prost(message, tag = "13")]
    YaraReport(YaraReport),
    /// One agent's response to a `RevokePush`, framed like `YaraReport`.
    #[prost(message, tag = "14")]
    RevokeReport(RevokeReport),
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

// ---------------------------------------------------------------------------
// Phase-3 mesh trust: membership grants and revocations.
// ---------------------------------------------------------------------------

/// Domain separator for [`MembershipGrant`] signatures. Distinct from
/// every other signing domain so a signature minted for one purpose can
/// never be replayed as another.
pub const MEMBERSHIP_GRANT_DOMAIN: &[u8] = b"bowery/mesh/membership-grant/v1";

/// Domain separator for [`Revocation`] signatures.
pub const REVOCATION_DOMAIN: &[u8] = b"bowery/mesh/revocation/v1";

/// An operator's signed statement that a given agent belongs in a given
/// mesh cluster.
///
/// This is what replaces trust-on-first-use. Under TOFU any host that
/// can reach the gossip port during the bootstrap window becomes a
/// permanently trusted mesh member — and gossip is plain unauthenticated
/// UDP, so "can reach the port" is the entire admission control. A grant
/// moves that decision to a key the agent already trusts: agents are
/// configured with operator public keys (`[operators] pubkeys_b64`), so
/// a grant is verifiable offline by every agent with no new trust root
/// and no enrollment round trip.
///
/// **`agent_fp` binds the grant to one identity.** Without it a grant
/// harvested off the wire (it is published in plaintext gossip KV, and
/// is meant to be) could be replayed by any key at all. Verification
/// must check it against the fingerprint of the peer actually gossiping.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct MembershipGrant {
    /// Fingerprint of the agent identity this grant admits.
    #[prost(bytes = "vec", tag = "1")]
    pub agent_fp: Vec<u8>,
    /// Mesh cluster this grant is valid for. Checked against the
    /// agent's own `[mesh] cluster_id`, so a grant for a staging fleet
    /// can't admit a peer into production.
    #[prost(string, tag = "2")]
    pub cluster_id: String,
    #[prost(uint64, tag = "3")]
    pub issued_unix_ms: u64,
    /// Expiry. `0` means no expiry — appropriate for long-lived
    /// infrastructure, but an expiring grant limits the blast radius of
    /// a leaked operator key.
    #[prost(uint64, tag = "4")]
    pub expires_unix_ms: u64,
    /// Fingerprint of the operator key that signed this grant. Selects
    /// which configured operator key to verify against.
    #[prost(bytes = "vec", tag = "5")]
    pub operator_fp: Vec<u8>,
    /// Ed25519 signature over [`MembershipGrant::signing_input`].
    #[prost(bytes = "vec", tag = "6")]
    pub sig: Vec<u8>,
}

impl MembershipGrant {
    /// Bytes an operator signs. Length-prefixes `cluster_id` so a grant
    /// for cluster `"ab"` can't be reinterpreted as one for `"a"` with
    /// different trailing fields.
    #[must_use]
    pub fn signing_input(
        agent_fp: &[u8; 32],
        cluster_id: &str,
        issued_unix_ms: u64,
        expires_unix_ms: u64,
        operator_fp: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            MEMBERSHIP_GRANT_DOMAIN.len() + 32 + 4 + cluster_id.len() + 8 + 8 + 32,
        );
        buf.extend_from_slice(MEMBERSHIP_GRANT_DOMAIN);
        buf.extend_from_slice(agent_fp);
        let len = u32::try_from(cluster_id.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(cluster_id.as_bytes());
        buf.extend_from_slice(&issued_unix_ms.to_be_bytes());
        buf.extend_from_slice(&expires_unix_ms.to_be_bytes());
        buf.extend_from_slice(operator_fp);
        buf
    }

    /// This grant's own signing input.
    #[must_use]
    pub fn to_signing_input(&self) -> Option<Vec<u8>> {
        let agent: [u8; 32] = self.agent_fp.as_slice().try_into().ok()?;
        let operator: [u8; 32] = self.operator_fp.as_slice().try_into().ok()?;
        Some(Self::signing_input(
            &agent,
            &self.cluster_id,
            self.issued_unix_ms,
            self.expires_unix_ms,
            &operator,
        ))
    }
}

/// An operator's signed statement that an agent is no longer trusted.
///
/// TOFU has no exit: once pinned, a peer stays a full mesh member for
/// the life of the pin store, so a compromised host keeps answering
/// whisper questions and receiving distributed rules forever. A
/// revocation is the exit.
///
/// Revocations are deliberately *unconditional and permanent* once seen:
/// there is no un-revoke, because an attacker who can make an agent
/// forget a revocation has undone the containment. Re-admitting a
/// rebuilt host means giving it a new identity key.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct Revocation {
    #[prost(bytes = "vec", tag = "1")]
    pub agent_fp: Vec<u8>,
    #[prost(string, tag = "2")]
    pub cluster_id: String,
    #[prost(uint64, tag = "3")]
    pub issued_unix_ms: u64,
    /// Free-text operator note, carried for the audit trail.
    #[prost(string, tag = "4")]
    pub reason: String,
    #[prost(bytes = "vec", tag = "5")]
    pub operator_fp: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub sig: Vec<u8>,
}

impl Revocation {
    #[must_use]
    pub fn signing_input(
        agent_fp: &[u8; 32],
        cluster_id: &str,
        issued_unix_ms: u64,
        reason: &str,
        operator_fp: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            REVOCATION_DOMAIN.len() + 32 + 4 + cluster_id.len() + 8 + 4 + reason.len() + 32,
        );
        buf.extend_from_slice(REVOCATION_DOMAIN);
        buf.extend_from_slice(agent_fp);
        let len = u32::try_from(cluster_id.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(cluster_id.as_bytes());
        buf.extend_from_slice(&issued_unix_ms.to_be_bytes());
        let rlen = u32::try_from(reason.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&rlen.to_be_bytes());
        buf.extend_from_slice(reason.as_bytes());
        buf.extend_from_slice(operator_fp);
        buf
    }

    #[must_use]
    pub fn to_signing_input(&self) -> Option<Vec<u8>> {
        let agent: [u8; 32] = self.agent_fp.as_slice().try_into().ok()?;
        let operator: [u8; 32] = self.operator_fp.as_slice().try_into().ok()?;
        Some(Self::signing_input(
            &agent,
            &self.cluster_id,
            self.issued_unix_ms,
            &self.reason,
            &operator,
        ))
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
            confirmation: Some(AlertConfirmation {
                peers_asked: 5,
                peers_unseen: 4,
                peers_seen: 1,
                peers_no_reply: 0,
                quorum: 2,
                confirmed: true,
            }),
        };
        let original = WhisperPayload::alert(alert.clone());
        let bytes = original.encode_to_vec();
        let decoded = WhisperPayload::decode(bytes.as_slice()).unwrap();
        match decoded.body {
            Some(Body::Alert(got)) => assert_eq!(got, alert),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    /// An agent still running the previous build emits alerts with no
    /// field 10. Decoding one must yield `confirmation: None` rather than
    /// failing — a mixed-version fleet is the normal state during a
    /// rollout, and a decode error would drop that agent's alerts
    /// entirely.
    #[test]
    fn alert_without_confirmation_field_still_decodes() {
        let mut legacy = Alert {
            originator_fp: vec![0xbb; 32],
            episode_id: "ep-legacy".into(),
            exe_sha256_hex: "ab".repeat(32),
            exe_path: "/usr/bin/legacy".into(),
            suspicion: 0.7,
            rationale: "old agent".into(),
            suggested_actions: vec!["alert".into()],
            ts_unix_ms: 1_730_000_000_001,
            backend: "old/backend".into(),
            confirmation: None,
        };
        // `None` encodes to no tag-10 bytes at all, which is exactly the
        // wire image an older agent produces.
        let bytes = legacy.encode_to_vec();
        assert!(
            !bytes.windows(1).any(|w| w == [0x52]),
            "tag 10 (LEN) must be absent from the legacy wire image"
        );
        let decoded = Alert::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.confirmation, None);
        legacy.confirmation = None;
        assert_eq!(decoded, legacy);
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
                confirmation: None,
            }],
            cursor_unix_ms: 8,
            end: true,
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
