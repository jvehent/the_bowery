//! `bowery exec` — send typed [`OperatorCommand`]s to an agent.
//!
//! Phase 6b. Mirrors the dial / seal / wait pattern from
//! [`crate::alerts`] — the operator-key authenticates the request,
//! the agent's pinned fingerprint authenticates the response. The
//! only differences:
//!
//! - The outbound envelope carries `OperatorCommand` instead of
//!   `Subscribe`.
//! - The inbound envelope carries `OperatorResult` (with a typed
//!   per-command body) instead of `Alerts`.
//! - One round-trip per invocation; no follow mode.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bowery_crypto::{Fingerprint, Identity};
use bowery_proto::{
    Body, OperatorCommand, OperatorCommandBody, OperatorResultBody, SqlChunk, SqlQuery, SqlRow,
    SqlValueKind, WhisperPayload,
};

use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::BoweryEndpoint;
use bowery_whisper::{Sealer, StaticResolver, Verifier};
use clap::ValueEnum;
use ed25519_dalek::VerifyingKey;

/// Output format for the streamed SQL rows.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum SqlFormat {
    /// Tab-separated values, one row per line. Streams.
    Tsv,
    /// One JSON object per row, column-name array on first line.
    /// Streams.
    Json,
    /// Aligned ASCII table. Buffered — emitted on stream close.
    Table,
}

impl std::fmt::Display for SqlFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tsv => "tsv",
            Self::Json => "json",
            Self::Table => "table",
        })
    }
}

/// Send a single Phase-9 SQL query and stream the rows back into
/// the caller-provided `sink`. Each chunk envelope arrives on its
/// own QUIC stream; the loop terminates on the first chunk with
/// `end = true` (single-agent mode) or on connection close (fanout
/// mode). The exchange-level deadline is the operator-supplied
/// timeout plus a small slack — the agent enforces its own timeout
/// server-side and is the authority on "how long before this query
/// is killed".
///
/// `sink` is `&mut dyn SqlSink` so callers can pick the rendering:
/// [`make_stdout_sink`] for the CLI, [`CollectSink`] for the
/// ncurses console.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn sql(
    operator_key: PathBuf,
    target_addr: SocketAddr,
    target_fp_hex: String,
    target_pubkey_b64: String,
    peer_pubkeys_b64: Vec<String>,
    sql: String,
    timeout: Duration,
    fanout: bool,
    verbose_whisper: bool,
    sink: &mut dyn SqlSink,
) -> Result<()> {
    let mut trace = WhisperTrace::new(verbose_whisper);
    let identity = Arc::new(
        Identity::load(&operator_key)
            .with_context(|| format!("loading operator key from {}", operator_key.display()))?,
    );

    let target_fp = parse_fingerprint(&target_fp_hex)?;
    let target_vk = parse_verifying_key(&target_pubkey_b64)?;
    let mut resolver = StaticResolver::new();
    let inserted_fp = resolver.insert(target_vk);
    if inserted_fp != target_fp {
        bail!("target_pubkey_b64 fingerprint {inserted_fp} doesn't match --agent-fp {target_fp}");
    }
    // Phase-9 final-1 + final-8: with fanout=true, peers seal
    // their chunks directly for us. The resolver needs each peer's
    // pubkey to verify them. Two sources, in priority order:
    //
    //   1. Operator-side peer manifest at ~/.bowery/peers.toml
    //      (auto-loaded; bowery peers add/list/remove manages it).
    //   2. Explicit --peer-pubkey-b64 flags on the command line
    //      (operator can extend a one-off query without persisting).
    //
    // Peers absent from both surfaces will surface as
    // `BadSignature` envelope-verify errors — visible failure mode
    // rather than silent drop.
    if fanout
        && let Ok(manifest_path) = crate::peers::default_path()
        && let Ok(manifest) = crate::peers::Manifest::load(&manifest_path)
    {
        // fingerprint-hex → operator-assigned name, so fan-out output can
        // show a readable agent name beside each row's fingerprint.
        let mut agent_names: HashMap<String, String> = HashMap::new();
        for peer in &manifest.peers {
            let vk = parse_verifying_key(&peer.pubkey_b64)
                .with_context(|| format!("decoding peer manifest entry {} pubkey", peer.name))?;
            resolver.insert(vk);
            agent_names.insert(peer.fp.to_ascii_lowercase(), peer.name.clone());
        }
        trace.set_names(agent_names.clone());
        sink.set_agent_names(agent_names);
    }
    for b64 in &peer_pubkeys_b64 {
        let vk = parse_verifying_key(b64)
            .with_context(|| format!("parsing --peer-pubkey-b64 {b64:?}"))?;
        resolver.insert(vk);
    }
    let resolver = Arc::new(resolver);

    // Bind the client socket to the unspecified address, NOT loopback, so
    // the kernel selects the correct source interface per destination:
    // loopback for a local target, `tailscale0` for a tailnet peer, `eth0`
    // for a LAN host. A `127.0.0.1`-bound socket can only reach locally
    // deliverable addresses, so it silently strands every remote dial
    // (the packets never egress) — the target's own tailnet IP happens to
    // be local on that host, which is why a self-dial deceptively works.
    // Match the target's address family so an IPv6 tailnet address works.
    let bind_addr: SocketAddr = if target_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let endpoint = BoweryEndpoint::bind(identity.clone(), accept_verifier, bind_addr)
        .context("binding operator-side endpoint")?;

    let operator_fp = identity.fingerprint();
    let sealer = Sealer::new(identity.clone());
    let envelope_verifier = Verifier::new(resolver.clone(), operator_fp);

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), target_fp));
    let conn = endpoint
        .dial(dial_verifier, target_addr)
        .await
        .with_context(|| format!("dialing agent at {target_addr}"))?;

    let request_id = format!("op-{}", current_unix_ms());
    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);

    // Phase-9 final-1: when fanout is requested, sign an
    // OperatorAuthorization that the relay can forward to peers.
    // The peer verifies the operator's signature against its
    // [operators] set — no relay-as-operator trust required.
    let body = OperatorCommandBody::Sql(SqlQuery {
        sql,
        fanout,
        peers: Vec::new(),
    });
    let forwarded = if fanout {
        let auth =
            bowery_whisper::forwarding::sign_operator_authorization(&identity, &request_id, &body);
        prost::Message::encode_to_vec(&auth)
    } else {
        Vec::new()
    };
    let authorized = !forwarded.is_empty();
    let cmd = OperatorCommand {
        forwarded_from_operator: forwarded,
        request_id: request_id.clone(),
        timeout_ms,
        command: Some(body),
    };
    trace.sent_query(&target_fp.to_string(), &request_id, fanout, authorized);
    let outbound = sealer.seal_for(&target_fp, &WhisperPayload::operator_command(cmd));

    let exchange_timeout = timeout + Duration::from_secs(2);
    let exchange = async {
        conn.send_envelope(&outbound)
            .await
            .context("sending OperatorCommand")?;

        // In fan-out mode the relay multiplexes per-peer streams,
        // each terminated with its own `end = true`; we keep
        // reading until the connection closes (the relay drops it
        // after all peers finished). In single-agent mode we stop
        // on the first `end = true`. We index column lists per
        // agent_fp so each peer's first chunk's column names
        // survive across that peer's batches.
        let mut columns_by_agent: HashMap<Vec<u8>, Vec<String>> = HashMap::new();
        let mut last_columns: Vec<String> = Vec::new();
        loop {
            let recv = conn.recv_envelope().await;
            let bytes = match recv {
                Ok(b) => b,
                Err(e) => {
                    if fanout {
                        // Connection close terminates the fan-out
                        // stream — the relay's done with peers.
                        trace.note(&format!("relay closed the connection ({e})"));
                        trace.summary();
                        return Ok::<(), anyhow::Error>(());
                    }
                    return Err(anyhow::Error::from(e).context("awaiting SqlChunk envelope"));
                }
            };
            let opened = envelope_verifier
                .open(&bytes)
                .context("verifying SqlChunk envelope")?;
            // The authenticated envelope sender — the identity whose key
            // sealed this chunk. Trust THIS, never the self-declared
            // `chunk.agent_fp`: in fan-out every peer's key is in our
            // resolver, so `agent_fp` is attacker-settable but the envelope
            // signature is not.
            let sender = opened.sender;
            let result = match opened.payload.body {
                Some(Body::OperatorResult(r)) => r,
                other => bail!("agent replied with unexpected body: {other:?}"),
            };
            if result.request_id != request_id {
                bail!(
                    "agent echoed request_id={:?}, expected {:?}",
                    result.request_id,
                    request_id
                );
            }
            match result.result {
                Some(OperatorResultBody::SqlChunk(chunk)) => {
                    let SqlChunk {
                        columns: chunk_cols,
                        rows,
                        end,
                        agent_fp: declared_fp,
                    } = chunk;
                    // Fan-out completion terminator: an empty-agent_fp,
                    // end=true chunk — but ONLY honored from the relay we
                    // dialled (`sender == target_fp`). The relay seals the
                    // terminator with its own identity, so this holds for the
                    // legitimate one; a compromised fan-out peer cannot forge
                    // a terminator to truncate the fleet-wide result stream
                    // (previously the shape alone ended the loop).
                    if is_fanout_terminator(fanout, end, &declared_fp, sender, target_fp) {
                        trace.note("relay sent the fan-out terminator; all peers finished");
                        trace.summary();
                        return Ok::<(), anyhow::Error>(());
                    }
                    trace.chunk(
                        &sender.to_string(),
                        &hex_fp(&declared_fp),
                        rows.len(),
                        chunk_cols.len(),
                        end,
                        bytes.len(),
                    );
                    // Attribute rows to the authenticated sender, not the
                    // self-declared agent_fp, so a peer cannot stamp another
                    // host's fingerprint onto fabricated rows.
                    let agent_fp = sender.as_bytes().to_vec();
                    let columns: Vec<String> = if chunk_cols.is_empty() {
                        columns_by_agent
                            .get(&agent_fp)
                            .cloned()
                            .unwrap_or_else(|| last_columns.clone())
                    } else {
                        columns_by_agent.insert(agent_fp.clone(), chunk_cols.clone());
                        last_columns.clone_from(&chunk_cols);
                        chunk_cols
                    };
                    sink.header(&columns);
                    for row in rows {
                        sink.row(&columns, &agent_fp, &row);
                    }
                    if end && !fanout {
                        trace.summary();
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                Some(OperatorResultBody::Error(e)) => {
                    trace.note(&format!(
                        "error from {}: {} ({})",
                        trace.label(&sender.to_string()),
                        e.message,
                        e.kind
                    ));
                    eprintln!("agent refused query: {} ({})", e.message, e.kind);
                    bail!("sql query failed: {}", e.kind);
                }
                Some(OperatorResultBody::RevokeReport(_)) => {
                    bail!("agent replied with a RevokeReport to a SQL request");
                }
                Some(OperatorResultBody::YaraReport(_)) => {
                    // Wrong result type for this request — the agent
                    // echoed our request_id with a YARA body. Treat as a
                    // protocol error rather than silently ignoring it.
                    bail!("agent replied with a YaraReport to a SQL request");
                }
                None => bail!("agent returned an OperatorResult with no body"),
            }
        }
    };
    let outcome = tokio::time::timeout(exchange_timeout, exchange).await;
    drop(conn);
    endpoint.close().await;
    match outcome {
        Ok(Ok(())) => {
            sink.finish();
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => bail!("sql query timed out after {exchange_timeout:?}"),
    }
}

/// Output sink for SQL rows. Streaming sinks (`tsv`, `json`) print
/// directly in `header`/`row`; the buffered `table` sink defers
/// every print until `finish` so it can compute column widths.
///
/// Public so the ncurses console can plug in [`CollectSink`] (which
/// stashes rows in memory for ratatui rendering) instead of writing
/// to stdout.
pub trait SqlSink: Send {
    fn header(&mut self, columns: &[String]);
    fn row(&mut self, columns: &[String], agent_fp: &[u8], row: &SqlRow);
    fn finish(&mut self);
    /// Provide fingerprint-hex → operator-assigned name (from the peer
    /// manifest) so fan-out output can show a readable agent name beside
    /// the raw fingerprint. Default no-op — the ncurses console's
    /// [`CollectSink`] renders attribution itself.
    fn set_agent_names(&mut self, _names: HashMap<String, String>) {}
}

/// Resolve an agent fingerprint to its operator-assigned name from the
/// peer manifest, for fan-out output. Falls back to `"?"` when the
/// fingerprint isn't in `~/.bowery/peers.toml` (the full fingerprint is
/// still shown in the adjacent `_agent_fp` column).
fn agent_name_for(names: &HashMap<String, String>, agent_fp: &[u8]) -> String {
    names
        .get(&hex_fp(agent_fp))
        .cloned()
        .unwrap_or_else(|| "?".to_string())
}

// ---------------------------------------------------------------------------
// Whisper trace (`--verbose-whisper`)
// ---------------------------------------------------------------------------

/// Narrates the envelopes a fan-out query exchanges.
///
/// Fan-out is the one operator path where "it returned fewer rows than I
/// expected" has several very different causes — a peer that never
/// replied, a peer that replied with an error, a relay that closed
/// early — and the normal output cannot tell them apart. This makes the
/// exchange visible without changing it.
///
/// Everything goes to **stderr**, so `bowery exec sql --fanout … >
/// results.tsv` still produces a clean file.
#[derive(Debug)]
pub struct WhisperTrace {
    enabled: bool,
    started: std::time::Instant,
    names: HashMap<String, String>,
    /// Rows attributed to each authenticated sender, for the summary.
    rows_by_sender: HashMap<String, usize>,
    order: Vec<String>,
}

impl WhisperTrace {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            started: std::time::Instant::now(),
            names: HashMap::new(),
            rows_by_sender: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn set_names(&mut self, names: HashMap<String, String>) {
        self.names = names;
    }

    fn label(&self, fp_hex: &str) -> String {
        let short: String = fp_hex.chars().take(12).collect();
        self.names
            .get(fp_hex)
            .map_or_else(|| short.clone(), |n| format!("{n} ({short})"))
    }

    fn ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    fn say(&self, arrow: &str, msg: &str) {
        if self.enabled {
            eprintln!("[whisper {:>6}ms] {arrow} {msg}", self.ms());
        }
    }

    pub fn sent_query(&self, relay: &str, request_id: &str, fanout: bool, authorized: bool) {
        self.say(
            "-->",
            &format!(
                "OperatorCommand::Sql to {} request_id={request_id} fanout={fanout}{}",
                self.label(relay),
                if authorized {
                    " +OperatorAuthorization"
                } else {
                    ""
                }
            ),
        );
    }

    pub fn chunk(
        &mut self,
        sender_hex: &str,
        declared_hex: &str,
        rows: usize,
        columns: usize,
        end: bool,
        bytes: usize,
    ) {
        if !self.rows_by_sender.contains_key(sender_hex) {
            self.order.push(sender_hex.to_string());
        }
        *self
            .rows_by_sender
            .entry(sender_hex.to_string())
            .or_insert(0) += rows;
        self.say(
            "<--",
            &format!(
                "SqlChunk from {} rows={rows} cols={columns} end={end} {bytes}B",
                self.label(sender_hex)
            ),
        );
        // The one thing worth shouting about. Rows are attributed to the
        // envelope signer, never to this self-declared field, so a
        // mismatch is a peer *trying* to stamp another host's identity
        // onto its rows — defeated, but worth seeing.
        if !declared_hex.is_empty() && declared_hex != sender_hex {
            eprintln!(
                "[whisper {:>6}ms] !!! chunk claims agent_fp={} but was signed by {} \
                 — attributed to the signer",
                self.ms(),
                self.label(declared_hex),
                self.label(sender_hex)
            );
        }
    }

    pub fn note(&self, msg: &str) {
        self.say("   ", msg);
    }

    /// Final accounting: who answered, and with how much.
    pub fn summary(&self) {
        if !self.enabled {
            return;
        }
        eprintln!(
            "[whisper {:>6}ms] --- {} agent(s) reported",
            self.ms(),
            self.order.len()
        );
        for fp in &self.order {
            eprintln!(
                "[whisper        ]     {} rows={}",
                self.label(fp),
                self.rows_by_sender.get(fp).copied().unwrap_or(0)
            );
        }
    }
}

/// Construct the right stdout-rendering sink for the operator CLI's
/// `--format` flag.
pub fn make_stdout_sink(format: SqlFormat, fanout: bool) -> Box<dyn SqlSink> {
    match format {
        SqlFormat::Tsv => Box::new(TsvSink {
            printed_header: false,
            fanout,
            agent_names: HashMap::new(),
        }),
        SqlFormat::Json => Box::new(JsonSink {
            printed_header: false,
            fanout,
            agent_names: HashMap::new(),
        }),
        SqlFormat::Table => Box::new(TableSink {
            columns: Vec::new(),
            rows: Vec::new(),
            fanout,
            agent_names: HashMap::new(),
        }),
    }
}

/// One row collected from the wire — used by [`CollectSink`].
#[derive(Debug, Clone)]
pub struct CollectedRow {
    /// Fingerprint of the agent that produced this row. Empty for
    /// single-agent mode.
    pub agent_fp: Vec<u8>,
    /// The row's columnar values, in the order declared by the
    /// matching [`CollectSink::columns`] entry.
    pub values: Vec<bowery_proto::SqlValue>,
}

/// In-memory sink — accumulates the column header (set on the first
/// chunk; subsequent chunks reuse it) and every row. Used by the
/// ncurses console so it can paint the table after the stream
/// closes.
#[derive(Debug, Default)]
pub struct CollectSink {
    /// Column names. Set from the first chunk that declares them;
    /// kept stable for the rest of the stream.
    pub columns: Vec<String>,
    pub rows: Vec<CollectedRow>,
}

impl SqlSink for CollectSink {
    fn header(&mut self, columns: &[String]) {
        if self.columns.is_empty() {
            self.columns = columns.to_vec();
        }
    }
    fn row(&mut self, _columns: &[String], agent_fp: &[u8], row: &SqlRow) {
        self.rows.push(CollectedRow {
            agent_fp: agent_fp.to_vec(),
            values: row.values.clone(),
        });
    }
    fn finish(&mut self) {}
}

struct TsvSink {
    printed_header: bool,
    fanout: bool,
    agent_names: HashMap<String, String>,
}

impl SqlSink for TsvSink {
    fn set_agent_names(&mut self, names: HashMap<String, String>) {
        self.agent_names = names;
    }

    fn header(&mut self, columns: &[String]) {
        if self.printed_header || columns.is_empty() {
            return;
        }
        let mut head: Vec<String> =
            Vec::with_capacity(columns.len() + 2 * usize::from(self.fanout));
        if self.fanout {
            head.push("_agent_name".to_string());
            head.push("_agent_fp".to_string());
        }
        head.extend(columns.iter().cloned());
        println!("{}", head.join("\t"));
        self.printed_header = true;
    }

    fn row(&mut self, _columns: &[String], agent_fp: &[u8], row: &SqlRow) {
        let mut cells: Vec<String> =
            Vec::with_capacity(row.values.len() + 2 * usize::from(self.fanout));
        if self.fanout {
            cells.push(agent_name_for(&self.agent_names, agent_fp));
            cells.push(hex_fp(agent_fp));
        }
        cells.extend(row.values.iter().map(value_to_text));
        println!("{}", cells.join("\t"));
    }

    fn finish(&mut self) {}
}

struct JsonSink {
    printed_header: bool,
    fanout: bool,
    agent_names: HashMap<String, String>,
}

impl SqlSink for JsonSink {
    fn set_agent_names(&mut self, names: HashMap<String, String>) {
        self.agent_names = names;
    }

    fn header(&mut self, columns: &[String]) {
        if self.printed_header || columns.is_empty() {
            return;
        }
        let escaped: Vec<String> = columns
            .iter()
            .map(|c| format!("\"{}\"", escape_json_string(c)))
            .collect();
        println!("[{}]", escaped.join(","));
        self.printed_header = true;
    }

    fn row(&mut self, columns: &[String], agent_fp: &[u8], row: &SqlRow) {
        let mut parts: Vec<String> =
            Vec::with_capacity(row.values.len() + 2 * usize::from(self.fanout));
        if self.fanout {
            parts.push(format!(
                "\"_agent_name\":\"{}\"",
                escape_json_string(&agent_name_for(&self.agent_names, agent_fp))
            ));
            parts.push(format!("\"_agent_fp\":\"{}\"", hex_fp(agent_fp)));
        }
        for (i, v) in row.values.iter().enumerate() {
            let key = columns.get(i).map_or("", String::as_str);
            parts.push(format!(
                "\"{}\":{}",
                escape_json_string(key),
                value_to_json(v)
            ));
        }
        println!("{{{}}}", parts.join(","));
    }

    fn finish(&mut self) {}
}

/// Buffered ASCII-table sink. Holds the full result set in memory
/// so it can compute column widths before printing. Don't use
/// against multi-million-row queries — the `tsv` / `json` modes
/// stream and stay constant-memory.
struct TableSink {
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
    fanout: bool,
    agent_names: HashMap<String, String>,
}

impl SqlSink for TableSink {
    fn set_agent_names(&mut self, names: HashMap<String, String>) {
        self.agent_names = names;
    }

    fn header(&mut self, columns: &[String]) {
        if !self.columns.is_empty() || columns.is_empty() {
            return;
        }
        if self.fanout {
            self.columns.push("_agent_name".to_string());
            self.columns.push("_agent_fp".to_string());
        }
        self.columns.extend(columns.iter().cloned());
    }

    fn row(&mut self, _columns: &[String], agent_fp: &[u8], row: &SqlRow) {
        let mut cells: Vec<String> =
            Vec::with_capacity(row.values.len() + 2 * usize::from(self.fanout));
        if self.fanout {
            cells.push(agent_name_for(&self.agent_names, agent_fp));
            cells.push(hex_fp(agent_fp));
        }
        cells.extend(row.values.iter().map(value_to_text));
        self.rows.push(cells);
    }

    fn finish(&mut self) {
        if self.columns.is_empty() {
            return;
        }
        // Compute per-column max width across header + body.
        let mut widths: Vec<usize> = self.columns.iter().map(|c| c.chars().count()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.chars().count());
                }
            }
        }
        let pad = |s: &str, w: usize| {
            let n = s.chars().count();
            let pad = w.saturating_sub(n);
            format!("{s}{}", " ".repeat(pad))
        };
        let sep: String = widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("-+-");

        let header_row: String = self
            .columns
            .iter()
            .zip(widths.iter())
            .map(|(c, w)| pad(c, *w))
            .collect::<Vec<_>>()
            .join(" | ");
        println!("{header_row}");
        println!("{sep}");
        for row in &self.rows {
            let line: String = row
                .iter()
                .zip(widths.iter())
                .map(|(c, w)| pad(c, *w))
                .collect::<Vec<_>>()
                .join(" | ");
            println!("{line}");
        }
        println!("({} rows)", self.rows.len());
    }
}

fn hex_fp(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn value_to_text(v: &bowery_proto::SqlValue) -> String {
    match &v.value {
        None => String::new(),
        Some(SqlValueKind::Integer(i)) => i.to_string(),
        Some(SqlValueKind::Real(f)) => f.to_string(),
        Some(SqlValueKind::Text(s)) => s.clone(),
        Some(SqlValueKind::Blob(b)) => format!("<{} bytes>", b.len()),
    }
}

fn value_to_json(v: &bowery_proto::SqlValue) -> String {
    match &v.value {
        None => "null".to_string(),
        Some(SqlValueKind::Integer(i)) => i.to_string(),
        Some(SqlValueKind::Real(f)) => {
            // JSON disallows NaN/Inf; emit null for those.
            if f.is_finite() {
                f.to_string()
            } else {
                "null".to_string()
            }
        }
        Some(SqlValueKind::Text(s)) => format!("\"{}\"", escape_json_string(s)),
        Some(SqlValueKind::Blob(b)) => format!("\"<{} bytes>\"", b.len()),
    }
}

fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn parse_fingerprint(s: &str) -> Result<Fingerprint> {
    if s.len() != 64 {
        bail!("fingerprint must be 64 hex chars (got {})", s.len());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow!("invalid hex at byte {i}: {e}"))?;
    }
    Ok(Fingerprint::from_bytes(bytes))
}

fn parse_verifying_key(b64: &str) -> Result<VerifyingKey> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    let bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| anyhow!("base64 decode: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("verifying key is {} bytes; expected 32", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid Ed25519 pubkey: {e}"))
}

/// Minimal JSON string escaper — only used for the `--json` envelope
/// shape, where the only attacker-controlled string is the operator's
/// own `request_id` (we generated it). Keeps the dep graph free of a
/// full `serde_json` import for this one use.
fn escape_json_string(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Push a YARA rule to an agent, scan the given targets, and print each
/// reporting agent's results.
///
/// Mirrors [`sql`]'s dial → seal → send → read-until-terminator shape,
/// including the same two integrity rules learned there: attribute a
/// report by the **authenticated envelope sender** (never a self-declared
/// field), and honor the fan-out terminator only from the relay we
/// dialled — otherwise one compromised peer could truncate the fleet's
/// results or impersonate another host.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn yara(
    operator_key: PathBuf,
    target_addr: SocketAddr,
    target_fp_hex: String,
    target_pubkey_b64: String,
    peer_pubkeys_b64: Vec<String>,
    rules_path: PathBuf,
    targets: Vec<String>,
    timeout: Duration,
    fanout: bool,
    ttl: u32,
) -> Result<()> {
    use bowery_proto::YaraPush;
    // Fail here with a clear message rather than letting an oversized
    // envelope tear down the QUIC stream with no explanation.
    const MAX_RULE_BYTES: usize = 48 * 1024;

    let rules = std::fs::read(&rules_path)
        .with_context(|| format!("reading rule file {}", rules_path.display()))?;
    if rules.len() > MAX_RULE_BYTES {
        bail!(
            "rule file is {} bytes; the transport frame cap allows about {} \
             (split the rules across several pushes)",
            rules.len(),
            MAX_RULE_BYTES
        );
    }
    let rule_id = sha256_hex(&rules);

    let identity = Arc::new(
        Identity::load(&operator_key)
            .with_context(|| format!("loading operator key from {}", operator_key.display()))?,
    );
    let target_fp = parse_fingerprint(&target_fp_hex)?;
    let target_vk = parse_verifying_key(&target_pubkey_b64)?;
    let mut resolver = StaticResolver::new();
    let inserted_fp = resolver.insert(target_vk);
    if inserted_fp != target_fp {
        bail!("target_pubkey_b64 fingerprint {inserted_fp} doesn't match --agent-fp {target_fp}");
    }
    // Propagating agents seal their reports for us directly, so we need
    // their pubkeys to verify — same manifest the SQL fan-out uses.
    let mut agent_names: HashMap<String, String> = HashMap::new();
    if let Ok(manifest_path) = crate::peers::default_path()
        && let Ok(manifest) = crate::peers::Manifest::load(&manifest_path)
    {
        for peer in &manifest.peers {
            if let Ok(vk) = parse_verifying_key(&peer.pubkey_b64) {
                resolver.insert(vk);
                agent_names.insert(peer.fp.to_ascii_lowercase(), peer.name.clone());
            }
        }
    }
    for b64 in &peer_pubkeys_b64 {
        let vk = parse_verifying_key(b64)
            .with_context(|| format!("parsing --peer-pubkey-b64 {b64:?}"))?;
        resolver.insert(vk);
    }
    let resolver = Arc::new(resolver);

    let bind_addr: SocketAddr = if target_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let endpoint = BoweryEndpoint::bind(identity.clone(), accept_verifier, bind_addr)
        .context("binding operator-side endpoint")?;
    let operator_fp = identity.fingerprint();
    let sealer = Sealer::new(identity.clone());
    let envelope_verifier = Verifier::new(resolver.clone(), operator_fp);
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), target_fp));
    let conn = endpoint
        .dial(dial_verifier, target_addr)
        .await
        .with_context(|| format!("dialing agent at {target_addr}"))?;

    let request_id = format!("op-{}", current_unix_ms());
    let target_count = targets.len();
    let body = OperatorCommandBody::YaraPush(YaraPush {
        rule_id: rule_id.clone(),
        rules,
        targets,
        fanout,
        ttl,
    });
    // Always sign an authorization: unlike SQL, a YARA push can travel
    // several hops, and every agent it reaches verifies this signature.
    let auth =
        bowery_whisper::forwarding::sign_operator_authorization(&identity, &request_id, &body);
    let cmd = OperatorCommand {
        forwarded_from_operator: prost::Message::encode_to_vec(&auth),
        request_id: request_id.clone(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        command: Some(body),
    };
    let outbound = sealer.seal_for(&target_fp, &WhisperPayload::operator_command(cmd));

    println!("pushing rule {} ({target_count} target(s))", &rule_id[..16]);
    let exchange_timeout = timeout + Duration::from_secs(2);
    let exchange = async {
        conn.send_envelope(&outbound)
            .await
            .context("sending YaraPush")?;
        let mut reporting = 0usize;
        let mut total_matches = 0usize;
        loop {
            let bytes = match conn.recv_envelope().await {
                Ok(b) => b,
                Err(e) => {
                    if fanout {
                        break; // connection closed ends a fan-out stream
                    }
                    return Err(anyhow::Error::from(e).context("awaiting YaraReport"));
                }
            };
            let opened = envelope_verifier
                .open(&bytes)
                .context("verifying YaraReport envelope")?;
            let sender = opened.sender;
            let result = match opened.payload.body {
                Some(Body::OperatorResult(r)) => r,
                other => bail!("agent replied with unexpected body: {other:?}"),
            };
            if result.request_id != request_id {
                bail!("agent echoed request_id {:?}", result.request_id);
            }
            match result.result {
                Some(OperatorResultBody::YaraReport(rep)) => {
                    // Fan-out terminator, honored only from the relay.
                    if fanout && rep.end && rep.agent_fp.is_empty() && sender == target_fp {
                        break;
                    }
                    let name = agent_name_for(&agent_names, sender.as_bytes());
                    reporting += 1;
                    total_matches += rep.matches.len();
                    println!(
                        "{name} ({}): {} match(es), {} file(s) scanned",
                        &sender.to_string()[..16],
                        rep.matches.len(),
                        rep.scanned
                    );
                    for m in &rep.matches {
                        println!("    MATCH {} :: {}", m.rule_name, m.path);
                    }
                    for e in &rep.errors {
                        println!("    note: {e}");
                    }
                    if rep.end && !fanout {
                        break;
                    }
                }
                Some(OperatorResultBody::Error(e)) => {
                    eprintln!("agent refused push: {} ({})", e.message, e.kind);
                    bail!("yara push failed: {}", e.kind);
                }
                Some(OperatorResultBody::SqlChunk(_) | OperatorResultBody::RevokeReport(_)) => {
                    bail!("agent replied with an unexpected body to a YARA request");
                }
                None => bail!("agent returned an OperatorResult with no body"),
            }
        }
        println!("{reporting} agent(s) reported, {total_matches} total match(es)");
        Ok::<(), anyhow::Error>(())
    };
    let outcome = tokio::time::timeout(exchange_timeout, exchange).await;
    drop(conn);
    endpoint.close().await;
    match outcome {
        Ok(r) => r,
        Err(_) => bail!("yara push timed out after {exchange_timeout:?}"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Whether a received chunk is the fan-out completion terminator — an
/// empty declared `agent_fp` with `end = true`, which the relay sends to
/// signal "all peers done". Honored ONLY when it comes from the relay we
/// dialled (`sender == target_fp`), because the relay seals the terminator
/// with its own identity. A compromised fan-out peer's key is in our
/// resolver (so its envelopes verify), but binding the terminator to the
/// authenticated sender stops it from forging one to truncate the
/// fleet-wide result stream.
fn is_fanout_terminator(
    fanout: bool,
    end: bool,
    declared_fp: &[u8],
    sender: Fingerprint,
    target_fp: Fingerprint,
) -> bool {
    fanout && end && declared_fp.is_empty() && sender == target_fp
}

/// Push an operator-signed revocation to an agent and, with `fanout`,
/// through the mesh.
///
/// Mirrors [`yara`]'s transport exactly. The difference is what carries
/// the authority: the revocation is signed over its own fields, so every
/// agent it reaches verifies it directly rather than trusting the chain
/// of peers that relayed it. The `OperatorAuthorization` here only
/// authorises the *relaying*, not the revocation's contents.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one linear exchange, mirrors `yara`
pub async fn revoke_push(
    operator_key: PathBuf,
    target_addr: SocketAddr,
    target_fp_hex: String,
    target_pubkey_b64: String,
    peer_pubkeys_b64: Vec<String>,
    revocation_b64: String,
    timeout: Duration,
    fanout: bool,
    ttl: u32,
) -> Result<()> {
    use base64::Engine as _;
    use bowery_proto::RevokePush;

    let revocation = base64::prelude::BASE64_STANDARD
        .decode(revocation_b64.trim())
        .context("decoding revocation (expected base64 from `bowery trust revoke`)")?;
    // Decode locally so an operator typo fails here with a clear message
    // rather than as a rejection from every agent in the fleet.
    let decoded = <bowery_proto::Revocation as prost::Message>::decode(revocation.as_slice())
        .context("revocation is not a valid Revocation message")?;
    let target_agent = hex_lower(&decoded.agent_fp);

    let identity = Arc::new(
        Identity::load(&operator_key)
            .with_context(|| format!("loading operator key from {}", operator_key.display()))?,
    );
    let target_fp = parse_fingerprint(&target_fp_hex)?;
    let target_vk = parse_verifying_key(&target_pubkey_b64)?;
    let mut resolver = StaticResolver::new();
    let inserted_fp = resolver.insert(target_vk);
    if inserted_fp != target_fp {
        bail!("target_pubkey_b64 fingerprint {inserted_fp} doesn't match --agent-fp {target_fp}");
    }
    let mut agent_names: HashMap<String, String> = HashMap::new();
    if let Ok(manifest_path) = crate::peers::default_path()
        && let Ok(manifest) = crate::peers::Manifest::load(&manifest_path)
    {
        for peer in &manifest.peers {
            if let Ok(vk) = parse_verifying_key(&peer.pubkey_b64) {
                resolver.insert(vk);
                agent_names.insert(peer.fp.to_ascii_lowercase(), peer.name.clone());
            }
        }
    }
    // Propagating agents seal their reports for us directly, so we need
    // their pubkeys to verify — same manifest the SQL fan-out uses.
    for b64 in &peer_pubkeys_b64 {
        let vk = parse_verifying_key(b64)
            .with_context(|| format!("parsing --peer-pubkey-b64 {b64:?}"))?;
        resolver.insert(vk);
    }
    let resolver = Arc::new(resolver);

    let bind_addr: SocketAddr = if target_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let accept_verifier = Arc::new(PinnedCertVerifier::new(resolver.clone()));
    let endpoint = BoweryEndpoint::bind(identity.clone(), accept_verifier, bind_addr)
        .context("binding operator-side endpoint")?;
    let operator_fp = identity.fingerprint();
    let sealer = Sealer::new(identity.clone());
    let envelope_verifier = Verifier::new(resolver.clone(), operator_fp);
    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(resolver.clone(), target_fp));
    let conn = endpoint
        .dial(dial_verifier, target_addr)
        .await
        .with_context(|| format!("dialing agent at {target_addr}"))?;

    let request_id = format!("op-{}", current_unix_ms());
    let body = OperatorCommandBody::RevokePush(RevokePush {
        revocation,
        fanout,
        ttl,
    });
    let auth =
        bowery_whisper::forwarding::sign_operator_authorization(&identity, &request_id, &body);
    let cmd = OperatorCommand {
        forwarded_from_operator: prost::Message::encode_to_vec(&auth),
        request_id: request_id.clone(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        command: Some(body),
    };
    let outbound = sealer.seal_for(&target_fp, &WhisperPayload::operator_command(cmd));

    println!(
        "revoking {} (reason: {})",
        &target_agent[..16],
        decoded.reason
    );
    let exchange_timeout = timeout + Duration::from_secs(2);
    let exchange = async {
        conn.send_envelope(&outbound)
            .await
            .context("sending RevokePush")?;
        let mut applied = 0usize;
        let mut already = 0usize;
        loop {
            let bytes = match conn.recv_envelope().await {
                Ok(b) => b,
                Err(e) => {
                    if fanout {
                        break;
                    }
                    return Err(anyhow::Error::from(e).context("awaiting RevokeReport"));
                }
            };
            let opened = envelope_verifier
                .open(&bytes)
                .context("verifying RevokeReport envelope")?;
            let sender = opened.sender;
            let result = match opened.payload.body {
                Some(Body::OperatorResult(r)) => r,
                other => bail!("agent replied with unexpected body: {other:?}"),
            };
            if result.request_id != request_id {
                bail!("agent echoed request_id {:?}", result.request_id);
            }
            match result.result {
                Some(OperatorResultBody::RevokeReport(rep)) => {
                    // Terminator honoured only from the dialled relay,
                    // so a peer can't truncate the fleet's replies.
                    if fanout && rep.end && rep.agent_fp.is_empty() && sender == target_fp {
                        break;
                    }
                    let name = agent_name_for(&agent_names, sender.as_bytes());
                    let short = &sender.to_string()[..16];
                    if rep.error.is_empty() {
                        if rep.already_known {
                            already += 1;
                        } else {
                            applied += 1;
                        }
                        println!(
                            "{name} ({short}): {}{}",
                            if rep.already_known {
                                "already held"
                            } else {
                                "APPLIED"
                            },
                            if rep.evicted { ", peer evicted" } else { "" }
                        );
                    } else {
                        println!("{name} ({short}): REFUSED — {}", rep.error);
                    }
                    if rep.end && !fanout {
                        break;
                    }
                }
                Some(OperatorResultBody::Error(e)) => {
                    eprintln!("agent refused push: {} ({})", e.message, e.kind);
                    bail!("revoke push failed: {}", e.kind);
                }
                other => bail!("agent replied with an unexpected result body: {other:?}"),
            }
        }
        println!("{applied} agent(s) newly applied, {already} already held");
        Ok::<(), anyhow::Error>(())
    };
    let outcome = tokio::time::timeout(exchange_timeout, exchange).await;
    drop(conn);
    endpoint.close().await;
    match outcome {
        Ok(r) => r,
        Err(_) => bail!("revoke push timed out after {exchange_timeout:?}"),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_terminator_only_honored_from_relay() {
        let relay = Fingerprint::from_bytes([1u8; 32]);
        let peer = Fingerprint::from_bytes([2u8; 32]);

        // The relay's own empty-agent_fp end chunk ends the fan-out stream.
        assert!(is_fanout_terminator(true, true, &[], relay, relay));

        // A compromised fan-out peer CANNOT forge a terminator to truncate
        // the fleet-wide result stream: same shape, but sender != the relay.
        assert!(!is_fanout_terminator(true, true, &[], peer, relay));

        // A non-empty agent_fp is a data chunk, never a terminator.
        assert!(!is_fanout_terminator(true, true, &[7u8; 32], relay, relay));

        // end=false is never a terminator.
        assert!(!is_fanout_terminator(true, false, &[], relay, relay));

        // Single-agent mode never uses the terminator sentinel.
        assert!(!is_fanout_terminator(false, true, &[], relay, relay));
    }

    #[test]
    fn agent_name_resolves_from_manifest_else_question_mark() {
        let mut names = HashMap::new();
        names.insert("aa".repeat(32), "web-1".to_string()); // 64-char fp hex
        // Known fingerprint → operator-assigned name.
        assert_eq!(agent_name_for(&names, &[0xaau8; 32]), "web-1");
        // Unknown fingerprint → "?" (the raw fp is still shown alongside).
        assert_eq!(agent_name_for(&names, &[0xbbu8; 32]), "?");
    }
}
