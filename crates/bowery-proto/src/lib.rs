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
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13")]
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
    // Tags 10 and 11 are retired. They carried `ConnectionQuery` /
    // `ConnectionAnswer`, the single-purpose ancestors of the
    // corroboration pair below, and must never be reused: an agent
    // still running that build would decode a tag-10 field as a
    // connection query and answer it under the old rules. Skipping to
    // 12/13 instead makes the mismatch a clean "unknown field →
    // `body: None` → ignored" on both sides.
    #[prost(message, tag = "12")]
    CorroborationQuery(CorroborationQuery),
    #[prost(message, tag = "13")]
    CorroborationAnswer(CorroborationAnswer),
}

impl Body {
    /// Stable discriminator name, for log lines and "unexpected body"
    /// errors.
    ///
    /// It lives here, next to the variants, because it had drifted into
    /// three identical copies across the transport, the Q&A module, and
    /// the agent's stream dispatcher — each of which had to be found and
    /// updated every time a variant was added.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Question(_) => "Question",
            Self::Answer(_) => "Answer",
            Self::Alert(_) => "Alert",
            Self::OperatorCommand(_) => "OperatorCommand",
            Self::OperatorResult(_) => "OperatorResult",
            Self::Heartbeat(_) => "Heartbeat",
            Self::NeighborOp(_) => "NeighborOp",
            Self::Subscribe(_) => "Subscribe",
            Self::Alerts(_) => "Alerts",
            Self::CorroborationQuery(_) => "CorroborationQuery",
            Self::CorroborationAnswer(_) => "CorroborationAnswer",
        }
    }
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

/// One key/value pair. The unit of a [`CorroborationQuery`]'s subject
/// and a [`CorroborationAnswer`]'s evidence.
///
/// Untyped on purpose. The whole point of the corroboration messages is
/// that the transport, the round engine, and the alert path never learn
/// what any particular detection is *about* — only the handler
/// registered for a `kind` interprets these, so adding a new kind of
/// suspicion touches no shared code and needs no wire change.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct Attribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

impl Attribute {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Look a key up in a subject/evidence list. First match wins;
/// duplicates are the sender's problem, not the reader's.
#[must_use]
pub fn attribute<'a>(attrs: &'a [Attribute], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.key == key)
        .map(|a| a.value.as_str())
}

/// What a peer says about an observation someone else made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Corroboration {
    /// Never sent deliberately. It is the proto3 default, so it is what
    /// a garbled, truncated, or older-build answer decodes to — and the
    /// asker must treat it exactly like `Refused`. Reading a zero as a
    /// denial would let a decoding bug anywhere in the fleet
    /// manufacture alerts.
    Unspecified = 0,
    /// "Yes, that was me." Any evidence the responder can attach — the
    /// process behind it, when it happened — rides in `evidence`.
    Corroborated = 1,
    /// "I looked, and I have no record of it." The alarming answer, and
    /// the only one that counts toward a quorum.
    Denied = 2,
    /// "I will not answer": out of policy, or the local data needed to
    /// answer honestly is unavailable. Deliberately distinct from
    /// `Denied`, because "I won't say" and "it didn't happen" mean
    /// opposite things about the asker's suspicion.
    Refused = 3,
}

/// "Can anyone corroborate what I just saw?" — the asker half of a
/// cross-host corroboration round.
///
/// The observations worth whispering about share a shape: they are
/// unremarkable on the host that sees them and only become evidence
/// when a second host agrees or disagrees. Lateral movement is the
/// motivating example — an inbound SSH is normal, an outbound SSH is
/// normal, but an inbound connection that *no host in the fleet admits
/// making* is not — and it is deliberately not the only one this
/// message can carry.
///
/// # Kinds, and why the wire stays dumb
///
/// `kind` selects the handler on both ends. Everything specific to a
/// detection lives in `subject`, which this layer never inspects. A new
/// kind of suspicion is a new handler registration, not a proto change,
/// so the security-critical parts — envelope signing, recipient
/// binding, replay and skew gating, rate limiting, the quorum rule —
/// are written once and inherited rather than reimplemented per
/// detection.
///
/// # The privacy constraint is per-kind, and is not optional
///
/// A generic "ask a peer about its history" message is a generic
/// enumeration primitive unless every handler constrains what may be
/// asked. Each responder is required to enforce a rule that limits a
/// query to facts the asker already knows — the connection handler, for
/// instance, requires the named address to be the **asker's own**, as
/// the responder's own view of the mesh reports it, so a peer only ever
/// learns about traffic it was already party to.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct CorroborationQuery {
    /// Correlates the answer with the question. Echoed back verbatim.
    #[prost(string, tag = "1")]
    pub query_id: String,
    /// Handler selector, e.g. `net.inbound_connect`. An unknown kind is
    /// refused, never guessed at.
    #[prost(string, tag = "2")]
    pub kind: String,
    /// Absolute deadline (ms since unix epoch), matching `Question`'s
    /// encoding. Past it the responder drops the query rather than
    /// answering something the asker can no longer correlate.
    #[prost(uint64, tag = "3")]
    pub deadline_unix_ms: u64,
    /// Inclusive search window. Clamped by the responder regardless of
    /// what is asked for, so a query cannot become a full-history scan.
    #[prost(uint64, tag = "4")]
    pub window_start_unix_ms: u64,
    #[prost(uint64, tag = "5")]
    pub window_end_unix_ms: u64,
    /// The observation itself, interpreted only by the `kind`'s handler.
    #[prost(message, repeated, tag = "6")]
    pub subject: Vec<Attribute>,
}

/// The responder half of [`CorroborationQuery`].
///
/// [`Corroboration::Denied`] is the interesting answer: the peer that
/// should know about this has no record of it. For a connection that
/// means either its agent is not seeing what it should — blind,
/// tampered with, or newly compromised — or the source address was
/// spoofed. Both are worth waking someone for, and neither is visible
/// from one host.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct CorroborationAnswer {
    #[prost(string, tag = "1")]
    pub query_id: String,
    /// Echoed from the query. The asker checks it: an answer about a
    /// different kind than was asked is discarded rather than tallied.
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(enumeration = "Corroboration", tag = "3")]
    pub outcome: i32,
    /// Populated on [`Corroboration::Corroborated`]. For a connection
    /// this is the process attribution the accepting host can never
    /// derive on its own.
    #[prost(message, repeated, tag = "4")]
    pub evidence: Vec<Attribute>,
    /// Why, when the outcome is [`Corroboration::Refused`]. Operator
    /// text only — the asker branches on `outcome`, never on this.
    #[prost(string, tag = "5")]
    pub reason: String,
}

impl CorroborationAnswer {
    /// Decoded outcome, with anything unrecognised folded into
    /// [`Corroboration::Unspecified`] — which every caller must already
    /// handle as "told me nothing", so a future peer sending an outcome
    /// this build has never heard of degrades to silence rather than to
    /// a denial.
    #[must_use]
    pub fn corroboration(&self) -> Corroboration {
        Corroboration::try_from(self.outcome).unwrap_or(Corroboration::Unspecified)
    }
}

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

    /// Set when the responder declined rather than looked — it has
    /// observed too little for "I have never seen it" to mean anything.
    ///
    /// This field exists because of a failure observed on a live fleet.
    /// Two agents were running with no working event source, so their
    /// baselines were empty, so they answered `seen_count: 0` to every
    /// question ever asked. Since a quorum of "never seen it" is exactly
    /// what confirms an alert, **every** alert on their neighbour was
    /// being quorum-confirmed by two hosts that had never observed
    /// anything at all — including `/usr/bin/ssh`.
    ///
    /// `seen_count: 0` conflates two opposite claims: *"I watch this
    /// fleet and your binary is not part of it"* and *"I am not
    /// watching"*. Only the first is evidence. A responder that cannot
    /// make the first claim honestly must say so here, and an asker must
    /// never count a refusal toward a quorum.
    ///
    /// Empty means the responder actually looked. Older peers have no
    /// such field, so they decode to empty and are counted as having
    /// looked — which is the pre-existing behaviour, not a regression,
    /// and is why upgrading responders matters more than upgrading
    /// askers.
    #[prost(string, tag = "7")]
    pub refused: String,
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

    /// Everything an operator needs to judge the alert without logging
    /// in: full command line, uid, working directory, the process
    /// ancestry, and what the process had open.
    ///
    /// Untyped key/value rather than named fields, reusing
    /// [`Attribute`], because what is worth attaching differs per
    /// detection — an exec alert wants the ancestry, a file alert wants
    /// the writing process — and the alert path should not gain a field
    /// every time a detection wants to say something new.
    ///
    /// **Attacker-influenced, all of it.** A command line is whatever
    /// somebody chose to run. Renderers sanitise and cap it, and say so
    /// to the reader.
    #[prost(message, repeated, tag = "11")]
    pub context: Vec<Attribute>,

    /// The detection that produced this alert, e.g.
    /// `cred.read_netrc` or `lineage.service_spawned_shell`.
    ///
    /// Every alert has one. For an exec that cleared the threshold on
    /// baseline rarity alone the answer is `baseline.rarity` — a score
    /// rather than a rule table entry, and named so rather than left
    /// blank.
    ///
    /// Added because the id was previously recoverable only by
    /// *parsing* it back out of `episode_id` (which encodes it for file
    /// findings and not for exec ones) or by reading it out of the
    /// rationale prose. Nothing structured carried it, so `bowery_alerts`
    /// could not answer "which rule produced these" and an operator had
    /// nothing to point at when saying a finding is benign.
    ///
    /// A **superseding** alert carries the rule of the episode it
    /// refines, not a rule of its own: an LLM re-scoring a
    /// `lineage.service_spawned_shell` episode is still that finding.
    #[prost(string, tag = "12")]
    pub rule_id: String,
}

/// What the neighbourhood said when asked about an alert.
///
/// One shape serves both whisper rounds, because they ask the same
/// question in different words: *does anyone else have a record of
/// this?* For a binary that is "have you seen this executable"; for a
/// connection it is "did you make this connection". In both, a peer
/// answering **no** is the evidence that confirms.
///
/// Polarity matters and is easy to get backwards. A peer that *does*
/// have a record argues the observation is ordinary — a binary the
/// fleet runs everywhere, a connection somebody really did make — so it
/// counts *against* the alert. Confirmation is therefore driven by
/// `peers_unseen`. The counts are reported side by side rather than
/// folded into one number so an operator can tell "nobody has this"
/// from "everybody has this".
#[derive(Clone, Copy, PartialEq, Eq, ProstMessage)]
pub struct AlertConfirmation {
    /// Peers actually asked this round.
    #[prost(uint32, tag = "1")]
    pub peers_asked: u32,
    /// Replied "I have no record of it" — the evidence that confirms.
    #[prost(uint32, tag = "2")]
    pub peers_unseen: u32,
    /// Replied "I do have a record of it". Argues the observation is
    /// ordinary.
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
    /// Answered, but declined to say — the query was out of policy for
    /// them, or they lacked the local data to answer honestly. Held
    /// apart from `peers_no_reply` because a refusal is a *reachable,
    /// working* peer choosing not to answer, which is worth seeing; it
    /// is kept out of `peers_unseen` because "I won't say" is not "it
    /// didn't happen".
    #[prost(uint32, tag = "7")]
    pub peers_refused: u32,
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
    #[prost(oneof = "OperatorCommandBody", tags = "11, 12, 13, 14")]
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
    /// Deliver an operator-signed [`AlertSilence`] and, when `fanout`,
    /// propagate it onward.
    ///
    /// Self-authenticating like [`OperatorCommandBody::RevokePush`], and
    /// for a sharper reason: this payload *stops* findings, so a relay
    /// that could forge one could blind the fleet by relaying. Each hop
    /// verifies the operator signature itself.
    #[prost(message, tag = "14")]
    SilencePush(SilencePush),
}

/// See [`OperatorCommandBody::SilencePush`].
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct SilencePush {
    /// Prost-encoded [`AlertSilence`], carrying its own signature.
    #[prost(bytes = "vec", tag = "1")]
    pub silence: Vec<u8>,
    /// Remaining hops. Clamped by the receiving agent, so one push
    /// cannot be handed an unbounded budget.
    #[prost(uint32, tag = "2")]
    pub ttl: u32,
    /// Propagate to pinned peers as well as applying locally.
    #[prost(bool, tag = "3")]
    pub fanout: bool,
}

/// One agent's response to a [`SilencePush`], framed like
/// [`RevokeReport`].
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct SilenceReport {
    /// Reporting agent. Empty on the fan-out completion terminator.
    #[prost(bytes = "vec", tag = "1")]
    pub agent_fp: Vec<u8>,
    /// Verified and now in force here.
    #[prost(bool, tag = "2")]
    pub accepted: bool,
    /// Already held. Reported apart from `accepted` because it is what
    /// tells an operator the fleet has converged rather than that the
    /// push is still spreading.
    #[prost(bool, tag = "3")]
    pub already_known: bool,
    /// Why it was refused, in the agent's own words. Named rather than
    /// generic: an operator whose silence did not take needs to know
    /// whether it was the signature, the cluster, or the expiry.
    #[prost(string, tag = "4")]
    pub error: String,
    #[prost(bool, tag = "5")]
    pub end: bool,
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
    #[prost(oneof = "OperatorResultBody", tags = "11, 12, 13, 14, 15")]
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
    /// One agent's response to a `SilencePush`, framed like
    /// `RevokeReport`.
    #[prost(message, tag = "15")]
    SilenceReport(SilenceReport),
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

    #[must_use]
    pub fn corroboration_query(q: CorroborationQuery) -> Self {
        Self {
            body: Some(Body::CorroborationQuery(q)),
        }
    }

    #[must_use]
    pub fn corroboration_answer(a: CorroborationAnswer) -> Self {
        Self {
            body: Some(Body::CorroborationAnswer(a)),
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

/// Domain separator for [`LogReport`] signatures.
pub const LOG_REPORT_DOMAIN: &[u8] = b"bowery/mesh/log-report/v1";

/// An agent's signed statement of how much history its event log holds.
///
/// Published into the gossip KV so neighbours remember it. Root on a
/// host can delete that host's log, and nothing local survives to say it
/// existed — a verifier only sees what remains, so a log truncated to
/// nothing looks exactly like an agent installed a minute ago. It does
/// not look that way to a peer who already wrote the number down.
///
/// **Signed, because gossip is plain unauthenticated UDP.** Anyone who
/// can reach the port can publish a KV value, so an unsigned report
/// would let an attacker either forge a huge sequence number for a host
/// they are about to clear, or accuse a healthy peer of rolling back.
/// The signature is checked against the fingerprint of the peer actually
/// gossiping, exactly as [`MembershipGrant`] is.
///
/// **`host_fp` binds the report to one identity** for the same reason a
/// grant carries one: a report harvested off the wire is published in
/// plaintext and meant to be, and without the binding it could be
/// replayed under any key.
#[derive(Clone, PartialEq, ProstMessage)]
pub struct LogReport {
    /// Fingerprint of the agent whose log this describes.
    #[prost(bytes = "vec", tag = "1")]
    pub host_fp: Vec<u8>,
    /// Highest sequence number the event log has ever assigned. Rises
    /// only: it survives a restart, and retention prunes old rows
    /// without reissuing numbers.
    #[prost(uint64, tag = "2")]
    pub highest_seq: u64,
    /// When the reporting host stamped this. Lets a receiver ignore a
    /// stale value redelivered after a newer one, which eventually
    /// consistent gossip will do.
    #[prost(uint64, tag = "3")]
    pub reported_unix_ms: u64,
    /// Ed25519 signature over [`LogReport::signing_input`].
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
}

impl LogReport {
    /// The bytes a report's signature covers.
    #[must_use]
    pub fn signing_input_for(
        host_fp: &[u8; 32],
        highest_seq: u64,
        reported_unix_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(LOG_REPORT_DOMAIN.len() + 32 + 8 + 8);
        buf.extend_from_slice(LOG_REPORT_DOMAIN);
        buf.extend_from_slice(host_fp);
        buf.extend_from_slice(&highest_seq.to_be_bytes());
        buf.extend_from_slice(&reported_unix_ms.to_be_bytes());
        buf
    }

    /// This report's own signing input, or `None` if `host_fp` is not a
    /// fingerprint.
    #[must_use]
    pub fn signing_input(&self) -> Option<Vec<u8>> {
        let fp: [u8; 32] = self.host_fp.as_slice().try_into().ok()?;
        Some(Self::signing_input_for(
            &fp,
            self.highest_seq,
            self.reported_unix_ms,
        ))
    }
}

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

/// Domain separator for [`AlertSilence`] signatures.
pub const ALERT_SILENCE_DOMAIN: &[u8] = b"bowery/mesh/alert-silence/v1";

/// An operator's signed statement that a shape of alert is benign.
///
/// Every other signed object here *adds* something an agent will act on.
/// This one takes something away, and it is the only record in the system
/// whose effect is to make findings stop reaching a human. Read
/// `DESIGN-ALERT-SILENCING.md` §4 before extending it.
///
/// **Self-authenticating**, exactly as [`Revocation`] is: the record
/// carries its own operator signature, so a relaying peer can drop a
/// silence but never forge one, and every hop verifies it independently
/// rather than trusting whoever handed it over.
///
/// **An empty match field is a wildcard, and a record with every match
/// field empty covers nothing.** That is enforced in
/// `bowery_analysis::silence`, deliberately at the point of use rather
/// than only at the point of signing — a guard that lives with the
/// signer is a guard an unsigned bug walks past.
#[derive(Clone, PartialEq, Eq, ProstMessage)]
pub struct AlertSilence {
    /// Stable content id over the match spec, so re-issuing the same
    /// judgement replaces it instead of stacking another.
    #[prost(string, tag = "1")]
    pub id: String,
    /// Mesh cluster this applies to, checked against the agent's own
    /// `[mesh] cluster_id` so a staging silence cannot quiet production.
    #[prost(string, tag = "2")]
    pub cluster_id: String,

    /// Detection to silence. Empty matches any.
    #[prost(string, tag = "3")]
    pub rule_id: String,
    /// Lowercase hex SHA-256 of the binary. Empty matches any — which
    /// the CLI refuses to sign without an explicit flag, because a
    /// silence that does not name a binary is inherited by whatever an
    /// attacker puts at the path it does name.
    #[prost(string, tag = "4")]
    pub exe_sha256_hex: String,
    /// Subject path — the binary for an exec finding, the file touched
    /// for a file finding. Empty matches any.
    #[prost(string, tag = "5")]
    pub exe_path: String,
    /// Fingerprint of the only host that should honour this. Empty means
    /// fleet-wide.
    #[prost(bytes = "vec", tag = "6")]
    pub host_fp: Vec<u8>,

    /// Suspicion multiplier in thousandths: `0` silences, `1000` leaves
    /// the score alone and only counts matches.
    ///
    /// An integer rather than a float because this value is covered by a
    /// signature. Two encodings of the same float would sign
    /// differently, and comparing signed floats for equality is a
    /// question nobody should have to answer about an audit record.
    #[prost(uint32, tag = "7")]
    pub weight_permille: u32,
    /// Why the operator judged it benign. Required by the CLI — the
    /// audit trail is most of the point.
    #[prost(string, tag = "8")]
    pub reason: String,

    #[prost(uint64, tag = "9")]
    pub issued_unix_ms: u64,
    /// Mandatory upstream. An unbounded silence is a permanent blind
    /// spot, so nothing here can express "never expires".
    #[prost(uint64, tag = "10")]
    pub expires_unix_ms: u64,

    #[prost(bytes = "vec", tag = "11")]
    pub operator_fp: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub sig: Vec<u8>,
}

impl AlertSilence {
    /// Full weight, as permille.
    pub const FULL_WEIGHT: u32 = 1000;

    /// The bytes this record's signature covers, or `None` when
    /// `operator_fp` is not a fingerprint.
    ///
    /// Every field that changes what gets suppressed is in here. A field
    /// left out of the signing input is a field a relay could rewrite,
    /// so widening the match spec later means widening this too — the
    /// only field deliberately excluded is `sig` itself.
    ///
    /// Takes `&self` rather than the eleven fields separately, which is
    /// also the natural minting flow: build the record with an empty
    /// `sig`, sign this, then fill it in.
    #[must_use]
    pub fn to_signing_input(&self) -> Option<Vec<u8>> {
        let operator: [u8; 32] = self.operator_fp.as_slice().try_into().ok()?;
        let mut buf = Vec::with_capacity(ALERT_SILENCE_DOMAIN.len() + 256);
        buf.extend_from_slice(ALERT_SILENCE_DOMAIN);
        // Every variable-length field is length-prefixed, so no two
        // different specs can produce the same bytes by shifting a
        // boundary — `("a", "bc")` must not sign the same as `("ab", "c")`.
        for field in [
            self.id.as_bytes(),
            self.cluster_id.as_bytes(),
            self.rule_id.as_bytes(),
            self.exe_sha256_hex.as_bytes(),
            self.exe_path.as_bytes(),
            self.host_fp.as_slice(),
            self.reason.as_bytes(),
        ] {
            let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(field);
        }
        buf.extend_from_slice(&self.weight_permille.to_be_bytes());
        buf.extend_from_slice(&self.issued_unix_ms.to_be_bytes());
        buf.extend_from_slice(&self.expires_unix_ms.to_be_bytes());
        buf.extend_from_slice(&operator);
        Some(buf)
    }

    // The content id is derived by `bowery_analysis::silence::SilenceSpec::id`,
    // which owns the spec semantics and the hash. This crate stays a
    // wire-format crate with no dependency beyond prost.
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

    /// A silence must survive the wire unchanged, and its signing input
    /// must cover every field that decides what gets suppressed.
    #[test]
    fn an_alert_silence_round_trips_and_signs_over_everything_that_matters() {
        let base = AlertSilence {
            id: "sil-0123456789abcdef".into(),
            cluster_id: "prod".into(),
            rule_id: "cred.read_netrc".into(),
            exe_sha256_hex: "8353a512".into(),
            exe_path: "/home/j/.netrc".into(),
            host_fp: vec![0xaa; 32],
            weight_permille: 300,
            reason: "git reads its own netrc".into(),
            issued_unix_ms: 1_000,
            expires_unix_ms: 2_000,
            operator_fp: vec![0xbb; 32],
            sig: vec![0xcc; 64],
        };
        let bytes = base.encode_to_vec();
        let decoded = AlertSilence::decode(bytes.as_slice()).expect("decodes");
        assert_eq!(decoded, base);

        let input = base.to_signing_input().expect("signable");
        // Changing any field that affects what is suppressed must change
        // the bytes being signed. A field left out here is a field a
        // relay could rewrite without breaking the signature.
        for mutated in [
            AlertSilence {
                id: "sil-other".into(),
                ..base.clone()
            },
            AlertSilence {
                cluster_id: "staging".into(),
                ..base.clone()
            },
            AlertSilence {
                rule_id: "cred.read_aws".into(),
                ..base.clone()
            },
            AlertSilence {
                exe_sha256_hex: "deadbeef".into(),
                ..base.clone()
            },
            AlertSilence {
                exe_path: "/etc/shadow".into(),
                ..base.clone()
            },
            AlertSilence {
                host_fp: vec![0xdd; 32],
                ..base.clone()
            },
            AlertSilence {
                weight_permille: 0,
                ..base.clone()
            },
            AlertSilence {
                reason: "different".into(),
                ..base.clone()
            },
            AlertSilence {
                issued_unix_ms: 9,
                ..base.clone()
            },
            AlertSilence {
                expires_unix_ms: 9,
                ..base.clone()
            },
            AlertSilence {
                operator_fp: vec![0xee; 32],
                ..base.clone()
            },
        ] {
            assert_ne!(
                mutated.to_signing_input().expect("signable"),
                input,
                "a change to this field did not change the signed bytes"
            );
        }

        // The signature itself is excluded, or signing would be circular.
        let resigned = AlertSilence {
            sig: vec![0x11; 64],
            ..base.clone()
        };
        assert_eq!(resigned.to_signing_input().expect("signable"), input);
    }

    /// Length prefixes, so no two different specs can produce the same
    /// signed bytes by shifting a field boundary.
    #[test]
    fn silence_field_boundaries_cannot_be_shifted() {
        let a = AlertSilence {
            rule_id: "a".into(),
            exe_sha256_hex: "bc".into(),
            operator_fp: vec![0; 32],
            ..Default::default()
        };
        let b = AlertSilence {
            rule_id: "ab".into(),
            exe_sha256_hex: "c".into(),
            operator_fp: vec![0; 32],
            ..Default::default()
        };
        assert_ne!(a.to_signing_input(), b.to_signing_input());
    }

    /// Domains keep a signature minted for one purpose from verifying as
    /// another. A silence is the one record whose misuse turns detection
    /// off, so this matters more here than anywhere else.
    #[test]
    fn the_silence_domain_is_distinct_from_every_other() {
        let domains = [
            ALERT_SILENCE_DOMAIN,
            REVOCATION_DOMAIN,
            MEMBERSHIP_GRANT_DOMAIN,
            OPERATOR_AUTHORIZATION_DOMAIN,
            LOG_REPORT_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in domains.iter().skip(i + 1) {
                assert_ne!(a, b);
                // Nor may one be a prefix of another: a length-prefixed
                // body after a prefix-colliding domain could otherwise
                // be reinterpreted.
                assert!(!a.starts_with(b) && !b.starts_with(a), "{a:?} vs {b:?}");
            }
        }
    }

    /// An operator fingerprint that is not 32 bytes cannot be signed
    /// over, and must refuse rather than pad.
    #[test]
    fn a_malformed_operator_fingerprint_is_not_signable() {
        let bad = AlertSilence {
            operator_fp: vec![0xaa; 31],
            ..Default::default()
        };
        assert!(bad.to_signing_input().is_none());
    }
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
            refused: String::new(),
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
            rule_id: "cred.read_netrc".into(),
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
                peers_refused: 0,
                quorum: 2,
                confirmed: true,
            }),
            context: Vec::new(),
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
            rule_id: "cred.read_netrc".into(),
            episode_id: "ep-legacy".into(),
            exe_sha256_hex: "ab".repeat(32),
            exe_path: "/usr/bin/legacy".into(),
            suspicion: 0.7,
            rationale: "old agent".into(),
            suggested_actions: vec!["alert".into()],
            ts_unix_ms: 1_730_000_000_001,
            backend: "old/backend".into(),
            confirmation: None,
            context: Vec::new(),
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
                rule_id: "cred.read_netrc".into(),
                episode_id: "x".into(),
                exe_sha256_hex: "deadbeef".into(),
                exe_path: "/x".into(),
                suspicion: 0.5,
                rationale: "y".into(),
                suggested_actions: vec![],
                ts_unix_ms: 7,
                backend: "test".into(),
                confirmation: None,
                context: Vec::new(),
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
