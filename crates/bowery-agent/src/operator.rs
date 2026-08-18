//! The operator-facing side of the agent: who may talk to it, and what
//! they may ask.
//!
//! Split out of `agent.rs` alongside [`crate::pipeline`]. Where the
//! pipeline is everything that happens to an *event*, this is everything
//! that happens to a *request* — the QUIC accept loop, the per-stream
//! dispatch, and the handlers behind each operator command: SQL with
//! mesh fan-out, YARA rule distribution, revocation propagation, and the
//! whisper Q&A responder.
//!
//! Grouped because they share a trust boundary rather than a data type.
//! Every function here runs on bytes that arrived over the network, and
//! each one is responsible for establishing who sent them before acting:
//! an operator signature checked against the configured keys, or a peer
//! fingerprint checked against the pin store. That is a different kind
//! of care from the pipeline's, and keeping the two apart makes it
//! harder to lose track of which one you are writing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bowery_baseline::Baseline;
use bowery_crypto::Fingerprint;
use bowery_mesh::PeerInfo;
use bowery_proto::{Body, WhisperPayload};
use bowery_whisper::FingerprintResolver;
use bowery_whisper::fingerprint::{TIER1_LEN, Tier1Fingerprint};
use bowery_whisper::known_neighbors::KnownNeighbors;
use bowery_whisper::tls::PinnedCertVerifier;
use bowery_whisper::transport::{BoweryConnection, BoweryEndpoint};
use bowery_whisper::{Sealer, StaticResolver, Verifier};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::agent::{
    AgentEvent, MAX_REVOKE_TTL, OperatorCommandRouter, RateLimit, RelayContext, ResolverArc,
    RevocationContext, SQL_CHUNK_ROW_LIMIT, YaraContext, command_body_digest, encode_row,
    respond_to_subscribe, run_peer_yara_push, send_chunk, send_revoke_report, send_sql_error,
    send_yara_report,
};
use crate::corroboration::ResponderRegistry;
use crate::inbox::{AlertInbox, current_unix_ms};

#[allow(clippy::too_many_arguments)] // wiring kept explicit at the call site
/// The long-lived state every inbound request is served from.
///
/// `spawn_accept_task` and `handle_connection` took eleven and twelve
/// parameters respectively, differing only in whether the first was an
/// endpoint or an already-accepted connection. Everything else was the
/// same list, restated — and `sealer` alone appeared in fourteen
/// signatures across this module.
///
/// Held once and cloned per connection. Every field is an `Arc` or a
/// small handle, so a clone costs a refcount.
#[derive(Clone)]
pub(crate) struct ServerContext {
    pub operators: Arc<StaticResolver>,
    pub sealer: Arc<Sealer>,
    pub baseline: Arc<Baseline>,
    pub inbox: Arc<AlertInbox>,
    pub op_router: Arc<OperatorCommandRouter>,
    pub events_tx: broadcast::Sender<AgentEvent>,
    pub qa_rate_limit: Arc<RateLimit>,
    pub responders: Arc<ResponderRegistry>,
    pub coverage_bar: crate::whisper_qa::CoverageBar,
}

impl std::fmt::Debug for ServerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerContext").finish_non_exhaustive()
    }
}

pub(crate) fn spawn_accept_task(
    endpoint: BoweryEndpoint,
    resolver: ResolverArc,
    ctx: ServerContext,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let self_fp = ctx.sealer.fingerprint();
        let envelope_verifier = Arc::new(Verifier::new(resolver, self_fp));
        loop {
            tokio::select! {
                accept = endpoint.accept() => {
                    let Some(connection_result) = accept else { break };
                    match connection_result {
                        Ok(conn) => {
                            tokio::spawn(handle_connection(
                                conn,
                                envelope_verifier.clone(),
                                ctx.clone(),
                            ));
                        }
                        Err(e) => warn!(error = %e, "accept failed"),
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

/// Spawn the per-connection accept loops. Run two parallel readers:
///
/// - **Uni stream loop.** Heartbeats, `Subscribe`, and `OperatorCommand`
///   land here. Responses go back via fresh outbound uni streams.
/// - **Bi stream loop (slice 3).** Whisper `Question` lands here.
///   The reply rides the same bidi stream so it doesn't race the
///   uni-loop's `accept_uni` for delivery.
///
/// Splitting the two readers means a pooled connection can receive
/// peer-initiated whispers without the dialler's bi-loop racing its
/// own `ask()` for the response — they use disjoint Quinn streams.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connection(
    conn: BoweryConnection,
    verifier: Arc<Verifier<ResolverArc>>,
    ctx: ServerContext,
) {
    let uni = tokio::spawn(handle_uni_stream_loop(
        conn.clone(),
        verifier.clone(),
        ctx.clone(),
    ));
    let bi = tokio::spawn(handle_bi_stream_loop(conn, verifier, ctx));
    let _ = tokio::join!(uni, bi);
}

async fn handle_uni_stream_loop(
    conn: BoweryConnection,
    verifier: Arc<Verifier<ResolverArc>>,
    ctx: ServerContext,
) {
    while let Ok(bytes) = conn.recv_envelope().await {
        match verifier.open(&bytes) {
            Ok(env) => {
                info!(sender = %env.sender, nonce = env.nonce, "received envelope");
                let _ = ctx.events_tx.send(AgentEvent::EnvelopeReceived {
                    sender: env.sender,
                    nonce: env.nonce,
                });
                match env.payload.body {
                    Some(Body::Question(_)) => {
                        // Slice 3: questions ride bidi streams now. A
                        // Question on a uni stream is a stale-protocol
                        // peer or an oversight; log and ignore.
                        warn!(
                            sender = %env.sender,
                            "received whisper Question on uni stream; ignoring (Q&A is bidi)"
                        );
                    }
                    Some(Body::Subscribe(s)) => {
                        if ctx.operators.resolve(&env.sender).is_none() {
                            warn!(
                                sender = %env.sender,
                                "rejecting Subscribe from non-operator sender"
                            );
                            continue;
                        }
                        if let Err(e) = respond_to_subscribe(
                            &conn,
                            &ctx.sealer,
                            &ctx.inbox,
                            env.sender,
                            s,
                            &ctx.events_tx,
                        )
                        .await
                        {
                            warn!(sender = %env.sender, error = %e, "Subscribe response failed");
                        }
                    }
                    Some(Body::OperatorCommand(c)) => {
                        let is_direct_operator = ctx.operators.resolve(&env.sender).is_some();
                        let is_relay_forward = !c.forwarded_from_operator.is_empty();
                        if !is_direct_operator && !is_relay_forward {
                            warn!(
                                sender = %env.sender,
                                "rejecting OperatorCommand from non-operator sender"
                            );
                            continue;
                        }
                        if let Err(e) = respond_to_operator_command(
                            &conn,
                            ctx.sealer.clone(),
                            env.sender,
                            c,
                            &ctx.op_router,
                            &ctx.operators,
                            &ctx.events_tx,
                        )
                        .await
                        {
                            warn!(sender = %env.sender, error = %e, "OperatorCommand response failed");
                        }
                    }
                    _ => {
                        // Heartbeat / other bodies: nothing to do beyond
                        // emitting EnvelopeReceived above.
                    }
                }
            }
            Err(e) => warn!(error = %e, "envelope verification failed"),
        }
    }
}

#[allow(clippy::too_many_arguments)] // keeps the wiring explicit at the call site
async fn handle_bi_stream_loop(
    conn: BoweryConnection,
    verifier: Arc<Verifier<ResolverArc>>,
    ctx: ServerContext,
) {
    loop {
        let Ok((bytes, reply)) = conn.accept_request().await else {
            break;
        };
        let env = match verifier.open(&bytes) {
            Ok(env) => env,
            Err(e) => {
                warn!(error = %e, "bidi envelope verification failed");
                continue;
            }
        };
        info!(sender = %env.sender, nonce = env.nonce, "received bi envelope");
        let _ = ctx.events_tx.send(AgentEvent::EnvelopeReceived {
            sender: env.sender,
            nonce: env.nonce,
        });
        match env.payload.body {
            Some(Body::CorroborationQuery(q)) => {
                // Same bucket as Q&A: this costs an indexed lookup, but
                // it is still peer-triggered work.
                if !ctx.qa_rate_limit.try_acquire(&env.sender) {
                    warn!(sender = %env.sender, "corroboration rate limit exceeded; shedding");
                    continue;
                }
                // The dispatcher is kind-agnostic on purpose: adding a
                // detection registers a handler and changes nothing
                // here, so the rate limit, the shape checks, and the
                // envelope crypto are inherited rather than
                // reimplemented per kind.
                let Some(answer) = ctx.responders.dispatch(env.sender, &q).await else {
                    continue; // expired; the asker has already given up
                };
                let outbound = ctx
                    .sealer
                    .seal_for(&env.sender, &WhisperPayload::corroboration_answer(answer));
                if let Err(e) = reply.send(&outbound).await {
                    warn!(sender = %env.sender, error = %e, "corroboration response failed");
                }
            }
            Some(Body::Question(q)) => {
                // Check the budget before the O(ctx.baseline) scan, not after.
                if !ctx.qa_rate_limit.try_acquire(&env.sender) {
                    warn!(sender = %env.sender, "whisper Q&A rate limit exceeded; shedding");
                    continue;
                }
                if let Err(e) = respond_to_question(
                    reply,
                    &ctx.sealer,
                    &ctx.baseline,
                    env.sender,
                    q,
                    ctx.coverage_bar,
                )
                .await
                {
                    warn!(sender = %env.sender, error = %e, "whisper Q&A response failed");
                }
            }
            other => {
                warn!(
                    sender = %env.sender,
                    body = ?other.as_ref().map(Body::kind_name),
                    "unexpected body on bi stream; ignoring"
                );
            }
        }
    }
}

async fn respond_to_question(
    reply: bowery_whisper::transport::Reply,
    sealer: &Sealer,
    baseline: &Arc<Baseline>,
    asker: Fingerprint,
    question: bowery_proto::Question,
    coverage_bar: crate::whisper_qa::CoverageBar,
) -> Result<(), bowery_whisper::transport::Error> {
    if question.tier1_fp.len() != TIER1_LEN {
        warn!(
            len = question.tier1_fp.len(),
            "received question with invalid tier1_fp length; ignoring"
        );
        // Drop `reply` without sending — Quinn resets the stream and
        // the asker observes a transport error / timeout.
        return Ok(());
    }
    // `ttl_ms` is an absolute deadline (see `qa::ttl_deadline_ms`). An
    // expired question is work whose answer nobody is still waiting for
    // — the other responder path (`qa.rs`) already drops these, and not
    // doing so here left a free way to buy baseline scans with stale
    // replayed-shaped traffic.
    let now_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX);
    if now_ms > question.ttl_ms {
        debug!(
            sender = %asker,
            now_ms,
            ttl_ms = question.ttl_ms,
            "dropping expired whisper question"
        );
        return Ok(());
    }

    let mut fp_bytes = [0u8; TIER1_LEN];
    fp_bytes.copy_from_slice(&question.tier1_fp);
    let target = Tier1Fingerprint::from_bytes(fp_bytes);

    let baseline = baseline.clone();
    let knowledge = match tokio::task::spawn_blocking(move || {
        crate::whisper_qa::local_knowledge(&baseline, target, coverage_bar)
    })
    .await
    {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "baseline scan task panicked");
            return Ok(());
        }
    };

    // Refusing is the whole point of the coverage check: a host that has
    // observed nothing must not answer "never seen it", because a quorum
    // of those is what confirms an alert on the asker.
    let answer = match knowledge {
        crate::whisper_qa::LocalKnowledge::Observed(sighting) => bowery_proto::Answer {
            episode_id: question.episode_id,
            tier1_fp: question.tier1_fp,
            seen_count: sighting.seen_count,
            first_seen_unix_ms: sighting.first_seen_unix_ms,
            last_seen_unix_ms: sighting.last_seen_unix_ms,
            note: String::new(),
            refused: String::new(),
        },
        crate::whisper_qa::LocalKnowledge::Insufficient { binaries, age } => {
            debug!(
                sender = %asker,
                binaries,
                age_secs = age.as_secs(),
                min_binaries = coverage_bar.min_binaries,
                min_age_secs = coverage_bar.min_age.as_secs(),
                "declining a whisper question: too little observed to answer honestly"
            );
            bowery_proto::Answer {
                episode_id: question.episode_id,
                tier1_fp: question.tier1_fp,
                note: String::new(),
                refused: format!(
                    "observed {binaries} binaries over {}h; too little to say whether this is rare",
                    age.as_secs() / 3600
                ),
                ..Default::default()
            }
        }
    };
    let outbound = sealer.seal_for(&asker, &WhisperPayload::answer(answer));
    reply.send(&outbound).await
}

/// Phase-6b operator-command dispatch.
///
/// The envelope-level operator gate has already passed by the time
/// we get here (`handle_connection` rejects non-operators upstream).
/// This function:
///
/// 1. Decodes the typed command body. An empty `command` field
///    surfaces as `unsupported_command` so the operator's CLI sees
///    the wire-level mismatch rather than a silent timeout.
/// 2. Dispatches to the per-command handler (`Sql` against the
///    native engine; future commands add new arms).
/// 3. Builds an [`OperatorResult`] echoing the `request_id`, seals
///    it back to the operator, and emits an event.
///
/// New commands are added by extending the match — never by
/// smuggling free-form strings, so each command's surface stays
/// visible at code-review time.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // wiring kept explicit
async fn respond_to_operator_command(
    conn: &BoweryConnection,
    sealer: Arc<Sealer>,
    sender: Fingerprint,
    cmd: bowery_proto::OperatorCommand,
    op_router: &OperatorCommandRouter,
    operators: &Arc<StaticResolver>,
    events_tx: &broadcast::Sender<AgentEvent>,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::OperatorCommandBody;

    let request_id = cmd.request_id.clone();
    let command_kind = match cmd.command.as_ref() {
        Some(OperatorCommandBody::Sql(_)) => "sql",
        Some(OperatorCommandBody::YaraPush(_)) => "yara_push",
        Some(OperatorCommandBody::RevokePush(_)) => "revoke_push",
        None => "<empty>",
    };

    // Phase-9 final-1: resolve the *effective* operator. Two cases:
    //
    // 1. Direct operator dial: envelope sender is in [operators];
    //    forwarded_from_operator may be set or empty (the operator
    //    pre-signs an authorisation when it wants the relay to fan
    //    out). The effective operator is the envelope sender; the
    //    authorisation field is parsed only to validate it.
    //
    // 2. Relay-forwarded: envelope sender is a pinned peer (NOT in
    //    [operators]) and forwarded_from_operator MUST be set. We
    //    verify the operator's signature, recompute the
    //    command_digest, and use the operator_fp from the
    //    authorisation as the effective operator. Sealed responses
    //    flow back to that operator, not to the relay.
    let is_direct_operator = operators.resolve(&sender).is_some();
    let operator = match resolve_effective_operator(&cmd, &request_id, operators, sender) {
        Ok(fp) => fp,
        Err(reason) => {
            warn!(
                sender = %sender,
                request_id = %request_id,
                reason,
                "rejecting OperatorCommand: forwarded_from_operator failed verification"
            );
            return send_sql_error(
                conn,
                &sealer,
                &sender,
                &request_id,
                "forwarding_invalid",
                reason,
            )
            .await;
        }
    };

    // Cycle prevention: only the originally-dialled relay (which
    // received the command directly from a configured operator)
    // may fan out. A relay-forwarded command (i.e. one whose
    // envelope sender is NOT in [operators]) requesting further
    // fanout is rejected — that's a malicious relay trying to
    // multi-hop amplify.
    if !is_direct_operator
        && let Some(OperatorCommandBody::Sql(q)) = &cmd.command
        && q.fanout
    {
        warn!(
            sender = %sender,
            request_id = %request_id,
            "rejecting forwarded SqlQuery with fanout=true (cycle prevention)"
        );
        return send_sql_error(
            conn,
            &sealer,
            &sender,
            &request_id,
            "policy_denied",
            "forwarded SqlQuery may not request fanout (one-hop cap)",
        )
        .await;
    }
    // Clamp the operator's requested timeout to our configured cap.
    // The operator can ask for less; they can't ask for more.
    let requested = Duration::from_millis(u64::from(cmd.timeout_ms));
    let effective_timeout = requested
        .min(op_router.max_timeout)
        .max(Duration::from_millis(100));
    info!(
        operator = %operator,
        request_id = %request_id,
        kind = command_kind,
        requested_ms = cmd.timeout_ms,
        effective_ms = u64::try_from(effective_timeout.as_millis()).unwrap_or(u64::MAX),
        "operator command received"
    );

    // Revocation delivery + propagation. Placed before the other
    // bodies because it is the only command whose payload authorises
    // itself: the revocation carries an operator signature over its own
    // fields, so a relaying peer can drop it but cannot forge one.
    if let Some(OperatorCommandBody::RevokePush(p)) = &cmd.command {
        let Some(rev_ctx) = op_router.revocation.clone() else {
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "policy_denied",
                "revocation handling is not enabled on this agent",
            )
            .await;
        };
        if p.fanout && is_direct_operator && !op_router.fanout_rate_limit.try_acquire(&operator) {
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "rate_limited",
                "fan-out bucket empty for this operator; back off and retry",
            )
            .await;
        }
        // Clamp the hop budget so one push can't be handed an unbounded
        // one, same as YARA.
        let capped = bowery_proto::RevokePush {
            ttl: p.ttl.min(MAX_REVOKE_TTL),
            ..p.clone()
        };
        let outcome = handle_revoke_push(
            conn,
            &sealer,
            operator,
            &request_id,
            &capped,
            &cmd.forwarded_from_operator,
            &rev_ctx,
            op_router.relay.as_ref(),
            effective_timeout,
        )
        .await;
        let _ = events_tx.send(AgentEvent::OperatorCommandHandled {
            operator,
            request_id,
            kind: command_kind,
        });
        return outcome;
    }

    // YARA rule distribution. Like SQL it streams its own responses;
    // unlike SQL it may propagate multiple hops (bounded by ttl + the
    // seen-set) because a detection rule is meant to reach the fleet.
    if let Some(OperatorCommandBody::YaraPush(p)) = &cmd.command {
        let Some(yara_ctx) = op_router.yara.clone() else {
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "policy_denied",
                "yara rule distribution is not enabled on this agent",
            )
            .await;
        };
        // Rate-limit the entry-point push the same way as fan-out SQL:
        // one operator shouldn't be able to flood the mesh with pushes.
        if p.fanout && is_direct_operator && !op_router.fanout_rate_limit.try_acquire(&operator) {
            warn!(
                operator = %operator,
                request_id = %request_id,
                "rate-limiting yara push: operator bucket empty"
            );
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "rate_limited",
                "fan-out bucket empty for this operator; back off and retry",
            )
            .await;
        }
        // Clamp the operator's requested TTL to this agent's cap, so a
        // single push can't be given an unbounded hop budget.
        let capped = bowery_proto::YaraPush {
            ttl: p.ttl.min(yara_ctx.config.max_ttl),
            ..p.clone()
        };
        let outcome = handle_yara_push(
            conn,
            &sealer,
            operator,
            &request_id,
            &capped,
            &cmd.forwarded_from_operator,
            &yara_ctx,
            op_router.relay.as_ref(),
            effective_timeout,
            events_tx,
        )
        .await;
        let _ = events_tx.send(AgentEvent::OperatorCommandHandled {
            operator,
            request_id,
            kind: command_kind,
        });
        return outcome;
    }

    // SQL is special-cased: it streams multiple chunked envelopes
    // back over the same connection. Other variants build a single
    // OperatorResultBody and fall through to the unified send below.
    if let Some(OperatorCommandBody::Sql(q)) = &cmd.command {
        let sql_engine = op_router.sql.clone();
        // SECURITY-AUDIT-PHASE9 F-4: per-operator-fp rate limit
        // on fan-out queries. Only applied to the entry-point
        // relay (is_direct_operator), not to forwarded peers
        // (their fanout=true is rejected upstream by cycle
        // prevention; their fanout=false bypasses the limiter).
        if q.fanout && is_direct_operator && !op_router.fanout_rate_limit.try_acquire(&operator) {
            warn!(
                operator = %operator,
                request_id = %request_id,
                "rate-limiting fan-out: operator bucket empty"
            );
            return send_sql_error(
                conn,
                &sealer,
                &operator,
                &request_id,
                "rate_limited",
                "fan-out bucket empty for this operator; back off and retry",
            )
            .await;
        }
        let relay = if q.fanout {
            op_router.relay.clone()
        } else {
            None
        };
        let outcome = stream_sql_response(
            conn,
            &sealer,
            operator,
            &request_id,
            sql_engine.as_ref(),
            &q.sql,
            q.fanout,
            &q.peers,
            &cmd.forwarded_from_operator,
            relay.as_ref(),
            effective_timeout,
        )
        .await;
        let _ = events_tx.send(AgentEvent::OperatorCommandHandled {
            operator,
            request_id,
            kind: command_kind,
        });
        return outcome;
    }

    // The `Sql` body is the only command kind; everything is
    // returned above. An empty `command` falls through here.
    send_sql_error(
        conn,
        &sealer,
        &operator,
        &request_id,
        "unsupported_command",
        "OperatorCommand.command is empty",
    )
    .await?;
    let _ = events_tx.send(AgentEvent::OperatorCommandHandled {
        operator,
        request_id,
        kind: command_kind,
    });
    Ok(())
}

/// Drive the streaming SQL response. On success, emits one or
/// more `OperatorResult { SqlChunk }` envelopes (each with `end =
/// true` per agent contributing rows); on failure, emits a single
/// `OperatorResult { Error }` and stops. Each envelope is sealed
/// independently for the operator and rides its own QUIC stream.
///
/// In fan-out mode (`fanout = true` and `relay = Some`), the
/// relay also dispatches the query to its pinned peers in
/// parallel and multiplexes their chunks back to the operator,
/// rewriting each chunk's `agent_fp` to the peer's fingerprint so
/// the operator can attribute rows. Cycle prevention: the relay
/// always sends `fanout = false` to peers.
#[allow(clippy::too_many_arguments)] // wiring kept explicit
async fn stream_sql_response(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    sql_engine: Option<&Arc<bowery_sql::Sql>>,
    sql: &str,
    fanout: bool,
    peer_filter: &[Vec<u8>],
    forwarded_authorization: &[u8],
    relay: Option<&Arc<RelayContext>>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::SqlChunk;

    let Some(engine) = sql_engine else {
        return send_sql_error(
            conn,
            sealer,
            &operator,
            request_id,
            "policy_denied",
            "SQL engine not configured on this agent",
        )
        .await;
    };

    let self_fp = sealer.fingerprint();

    // -- Phase 1: stream the relay's own rows. --
    let rows = match engine.query(sql, timeout).await {
        Ok(rows) => rows,
        Err(e) => {
            let kind = match &e {
                bowery_sql::SqlError::Timeout(_) => "timeout",
                bowery_sql::SqlError::RowCapExceeded { .. } => "row_cap_exceeded",
                bowery_sql::SqlError::Sqlite(_) => "sql_error",
                _ => "handler_error",
            };
            return send_sql_error(conn, sealer, &operator, request_id, kind, &e.to_string()).await;
        }
    };

    let columns: Vec<String> = rows
        .first()
        .map(|r| r.columns.iter().map(|(name, _)| name.clone()).collect())
        .unwrap_or_default();

    // Always populate `agent_fp = self_fp`. With Phase-9 final-1
    // e2e signing, peer chunks are sealed for the operator
    // directly, so the operator can also recover attribution
    // from `envelope.sender` and is encouraged to cross-check.
    // We still set the chunk-level field so:
    //   - the operator-side decoder doesn't have to plumb
    //     envelope.sender into the chunk struct, and
    //   - tests + CLI can render attribution without a
    //     verifier-roundtrip.
    let agent_fp_bytes = self_fp.as_bytes().to_vec();

    if rows.is_empty() {
        let chunk = SqlChunk {
            columns,
            rows: Vec::new(),
            end: true,
            agent_fp: agent_fp_bytes.clone(),
        };
        send_chunk(conn, sealer, &operator, request_id, chunk).await?;
    } else {
        let mut sent = 0usize;
        while sent < rows.len() {
            let take = SQL_CHUNK_ROW_LIMIT.min(rows.len() - sent);
            let batch = &rows[sent..sent + take];
            let proto_rows: Vec<bowery_proto::SqlRow> = batch.iter().map(encode_row).collect();
            let chunk_columns = if sent == 0 {
                columns.clone()
            } else {
                Vec::new()
            };
            let end = sent + take == rows.len();
            let chunk = SqlChunk {
                columns: chunk_columns,
                rows: proto_rows,
                end,
                agent_fp: agent_fp_bytes.clone(),
            };
            send_chunk(conn, sealer, &operator, request_id, chunk).await?;
            sent += take;
        }
    }

    // -- Phase 2: fan-out to peers (if requested + relay-capable). --
    //
    // No relay context (mesh disabled / no peers) silently collapses
    // to local-only — the operator still got the local rows; just no
    // extra peer streams. The operator can distinguish via the
    // per-chunk agent_fp set.
    if fanout && let Some(relay) = relay {
        relay_to_peers(
            conn,
            sealer,
            operator,
            request_id,
            sql,
            peer_filter,
            forwarded_authorization,
            relay,
            timeout,
        )
        .await?;
    }

    // -- Phase 3: fan-out completion terminator. --
    //
    // In fan-out mode the operator can't know how many peers will reply,
    // so it reads until it sees this explicit end marker: a chunk with an
    // empty `agent_fp` and `end = true`. No real chunk ever has an empty
    // agent_fp — the relay stamps its own 32-byte fingerprint and every
    // peer stamps its own — so the sentinel is unambiguous. We send it
    // whenever fan-out was requested (even with zero peers, or with the
    // relay disabled), which is what makes an empty-peer fan-out return
    // immediately instead of hanging until the operator's exchange
    // timeout. Single-agent mode never sends it (the operator stops on
    // the first `end && !fanout`).
    if fanout {
        let terminator = SqlChunk {
            columns: Vec::new(),
            rows: Vec::new(),
            end: true,
            agent_fp: Vec::new(),
        };
        send_chunk(conn, sealer, &operator, request_id, terminator).await?;
    }
    Ok(())
}

/// Handle an operator `YaraPush`: store the rule, scan the requested
/// targets, alert on matches, report back, and (when asked) propagate the
/// push onward through the mesh.
///
/// Ordering matters. The seen-set is consulted **first** so a push that
/// has already been handled is dropped whole — no re-store, no re-scan,
/// and crucially no re-forward. That's what terminates propagation in a
/// cyclic pinned-peer graph; the `ttl` hop counter is the independent
/// structural backstop.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_yara_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    push: &bowery_proto::YaraPush,
    forwarded_authorization: &[u8],
    yara: &Arc<YaraContext>,
    relay: Option<&Arc<RelayContext>>,
    timeout: Duration,
    events_tx: &broadcast::Sender<AgentEvent>,
) -> Result<(), bowery_whisper::transport::Error> {
    let self_fp = sealer.fingerprint();
    let operator_hex = operator.to_string();

    // --- Loop prevention. Must come before any work or forwarding. ---
    if !yara.seen.check_and_record(&operator_hex, request_id) {
        debug!(
            operator = %operator,
            request_id,
            rule = %push.rule_id,
            "dropping already-seen yara push (propagation loop cut)"
        );
        // Still terminate the operator's stream cleanly.
        return send_yara_report(
            conn,
            sealer,
            &operator,
            request_id,
            bowery_proto::YaraReport {
                agent_fp: self_fp.as_bytes().to_vec(),
                rule_id: push.rule_id.clone(),
                matches: Vec::new(),
                scanned: 0,
                errors: vec!["already handled (duplicate push)".to_string()],
                end: true,
            },
        )
        .await;
    }

    // --- Store. Idempotent + content-verified. ---
    let mut errors: Vec<String> = Vec::new();
    if push.rules.len() > yara.config.max_rule_bytes {
        return send_sql_error(
            conn,
            sealer,
            &operator,
            request_id,
            "rule_too_large",
            &format!(
                "rule is {} bytes; this agent's cap is {}",
                push.rules.len(),
                yara.config.max_rule_bytes
            ),
        )
        .await;
    }
    match yara.store.store(
        &push.rule_id,
        &push.rules,
        &operator_hex,
        request_id,
        current_unix_ms() / 1000,
    ) {
        Ok(true) => info!(rule = %push.rule_id, operator = %operator, "yara rule stored"),
        Ok(false) => debug!(rule = %push.rule_id, "yara rule already stored"),
        Err(e) => {
            return send_sql_error(
                conn,
                sealer,
                &operator,
                request_id,
                "rule_rejected",
                &e.to_string(),
            )
            .await;
        }
    }

    // --- Scan. CPU-heavy: bounded by a semaphore, run off the async
    // runtime, and capped by config. ---
    let mut matches: Vec<bowery_proto::YaraMatch> = Vec::new();
    let mut scanned: u32 = 0;
    if push.targets.is_empty() {
        debug!(rule = %push.rule_id, "no scan targets; stored only");
    } else {
        let permit = yara.scan_permits.clone().acquire_owned().await;
        if permit.is_err() {
            errors.push("scan semaphore closed".to_string());
        } else {
            let source = String::from_utf8_lossy(&push.rules).into_owned();
            let targets: Vec<PathBuf> = push.targets.iter().map(PathBuf::from).collect();
            let limits = bowery_yara::ScanLimits {
                max_file_bytes: yara.config.max_file_bytes,
                max_files: yara.config.max_files_per_scan,
                max_depth: yara.config.max_depth,
            };
            let secs = i32::try_from(timeout.as_secs()).unwrap_or(i32::MAX).max(1);
            let scan = tokio::task::spawn_blocking(move || {
                let rules = bowery_yara::Rules::compile(&source)?;
                let mut agg = bowery_yara::ScanOutcome::default();
                for t in targets {
                    let out = rules.scan_path(&t, limits, secs);
                    agg.matches.extend(out.matches);
                    agg.scanned += out.scanned;
                    agg.errors.extend(out.errors);
                }
                Ok::<_, bowery_yara::YaraError>(agg)
            })
            .await;
            match scan {
                Ok(Ok(out)) => {
                    scanned = out.scanned;
                    errors.extend(out.errors);
                    for m in out.matches {
                        matches.push(bowery_proto::YaraMatch {
                            rule_name: m.rule_name,
                            path: m.path.display().to_string(),
                            tags: m.tags,
                        });
                    }
                }
                // A rule that won't compile, or an engine-less build, is
                // reported rather than failing the whole push — the rule
                // is still stored and propagated.
                Ok(Err(e)) => errors.push(e.to_string()),
                Err(e) => errors.push(format!("scan task failed: {e}")),
            }
        }
    }

    // --- Alert on every match, so a hit reaches the operator's inbox
    // even if they aren't watching this command's response. ---
    for m in &matches {
        let alert = crate::alert_builder::AlertBuilder::new(
            yara.originator_fp,
            "yara",
            "yara.match",
            format!("yara-{}-{}", push.rule_id, current_unix_ms()),
            1.0,
            format!("yara rule `{}` matched {}", m.rule_name, m.path),
        )
        .subject(m.path.clone())
        .build();
        let episode_id = alert.episode_id.clone();
        warn!(rule = %m.rule_name, path = %m.path, "YARA MATCH");
        let appended = yara.inbox.append(alert);
        if appended.stored() {
            let _ = events_tx.send(AgentEvent::AlertEmitted {
                episode_id,
                suspicion: 1.0,
            });
        }
    }

    // --- Report this agent's own result. ---
    send_yara_report(
        conn,
        sealer,
        &operator,
        request_id,
        bowery_proto::YaraReport {
            agent_fp: self_fp.as_bytes().to_vec(),
            rule_id: push.rule_id.clone(),
            matches,
            scanned,
            errors,
            end: true,
        },
    )
    .await?;

    // --- Propagate. Unlike SQL fan-out (one hop), a rule is meant to
    // reach the whole mesh, so forwarding is bounded by ttl rather than
    // by "have I been forwarded already". ---
    if push.fanout
        && push.ttl > 0
        && let Some(relay) = relay
    {
        relay_yara_push(
            conn,
            sealer,
            operator,
            request_id,
            push,
            forwarded_authorization,
            relay,
            timeout,
        )
        .await?;
    }

    // Fan-out completion terminator (empty agent_fp), mirroring the SQL
    // path so the operator's read loop ends promptly rather than waiting
    // out its timeout.
    if push.fanout {
        send_yara_report(
            conn,
            sealer,
            &operator,
            request_id,
            bowery_proto::YaraReport {
                agent_fp: Vec::new(),
                rule_id: push.rule_id.clone(),
                matches: Vec::new(),
                scanned: 0,
                errors: Vec::new(),
                end: true,
            },
        )
        .await?;
    }
    Ok(())
}

/// Forward a YARA push to every pinned peer, decrementing `ttl`, and pipe
/// each peer's sealed reports back to the operator verbatim.
///
/// Peers seal their reports for the *operator*, not for us, so a relaying
/// agent can drop a report but cannot forge or read one.
#[allow(clippy::too_many_arguments)]
async fn relay_yara_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    push: &bowery_proto::YaraPush,
    forwarded_authorization: &[u8],
    relay: &Arc<RelayContext>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    let peers: Vec<PeerInfo> = relay
        .peers_watcher
        .borrow()
        .clone()
        .into_iter()
        .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
        .filter(|p| p.fingerprint != sealer.fingerprint())
        .collect();
    if peers.is_empty() {
        return Ok(());
    }

    let (bytes_tx, mut bytes_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut join_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    // Each hop sees one less TTL; the push that reaches ttl == 0 stops.
    let onward = bowery_proto::YaraPush {
        rule_id: push.rule_id.clone(),
        rules: push.rules.clone(),
        targets: push.targets.clone(),
        fanout: true,
        ttl: push.ttl.saturating_sub(1),
    };

    for peer in peers {
        let bytes_tx = bytes_tx.clone();
        let endpoint = relay.endpoint.clone();
        let kn = relay.known_neighbors.clone();
        let sealer_clone = sealer.clone();
        let request_id = request_id.to_string();
        let auth = forwarded_authorization.to_vec();
        let onward = onward.clone();
        join_set.spawn(async move {
            run_peer_yara_push(
                endpoint,
                kn,
                &sealer_clone,
                peer,
                auth,
                onward,
                &request_id,
                timeout,
                bytes_tx,
            )
            .await;
        });
    }
    drop(bytes_tx);

    let drain: Result<(), bowery_whisper::transport::Error> = async {
        while let Some(bytes) = bytes_rx.recv().await {
            conn.send_envelope(&bytes).await?;
        }
        Ok(())
    }
    .await;

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}
    let _ = operator; // attribution is carried by each peer's own sealing
    drain
}

/// Phase-9 slice 7: dispatch the query to every selected pinned
/// peer in parallel, multiplexing their chunks back to the
/// operator. Each peer's chunks have their `agent_fp` rewritten
/// to the peer's fingerprint before forwarding so the operator
/// can attribute rows.
///
/// Per-peer failures (dial failed, peer error, peer timeout) are
/// surfaced as a synthetic terminal chunk for that peer with no
/// rows — the operator still sees the EOF and knows that peer
/// didn't contribute. We don't propagate per-peer errors as a
/// stream-wide failure; the relay best-efforts every peer
/// independently.
#[allow(clippy::too_many_arguments)]
async fn relay_to_peers(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    sql: &str,
    peer_filter: &[Vec<u8>],
    forwarded_authorization: &[u8],
    relay: &Arc<RelayContext>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    use bowery_proto::{OperatorError, SqlChunk};

    // Snapshot the current peer set; turn the filter (if any) into
    // a HashSet of fingerprints for O(1) membership checks.
    let peers: Vec<PeerInfo> = relay.peers_watcher.borrow().clone();
    let peers: Vec<PeerInfo> = if peer_filter.is_empty() {
        peers
            .into_iter()
            .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
            .filter(|p| p.fingerprint != sealer.fingerprint())
            .collect()
    } else {
        let mut wanted: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::with_capacity(peer_filter.len());
        for fp in peer_filter {
            if let Ok(arr) = <[u8; 32]>::try_from(fp.as_slice()) {
                wanted.insert(arr);
            }
        }
        peers
            .into_iter()
            .filter(|p| wanted.contains(p.fingerprint.as_bytes()))
            .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
            .filter(|p| p.fingerprint != sealer.fingerprint())
            .collect()
    };

    if peers.is_empty() {
        return Ok(());
    }

    // Spawn one task per peer onto a JoinSet so we can abort the
    // whole batch if the operator disconnects (SECURITY-AUDIT-PHASE9
    // F-16). The channel now carries opaque envelope **bytes** —
    // peers seal `SqlChunk` directly for the operator (Phase-9
    // final-1 / F-1), so the relay forwards them verbatim.
    let (bytes_tx, mut bytes_rx) =
        mpsc::channel::<(Fingerprint, Result<Vec<u8>, OperatorError>)>(64);
    let per_peer_timeout = timeout;
    let mut join_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    for peer in peers {
        let bytes_tx = bytes_tx.clone();
        let endpoint = relay.endpoint.clone();
        let kn = relay.known_neighbors.clone();
        let sealer_clone = sealer.clone();
        let sql = sql.to_string();
        let request_id = request_id.to_string();
        let auth = forwarded_authorization.to_vec();
        join_set.spawn(async move {
            run_peer_query(
                endpoint,
                kn,
                &sealer_clone,
                peer,
                auth,
                &sql,
                &request_id,
                per_peer_timeout,
                bytes_tx,
            )
            .await;
        });
    }
    drop(bytes_tx); // close the channel so bytes_rx ends when all peers finish

    // Drain peer envelope bytes; forward verbatim to operator. On
    // per-peer error, synthesise a relay-signed terminal chunk so
    // the operator still sees the EOF. If the operator-side send
    // fails (operator dropped), abort every peer task.
    let drain_outcome: Result<(), bowery_whisper::transport::Error> = async {
        while let Some((peer_fp, outcome)) = bytes_rx.recv().await {
            if let Ok(bytes) = outcome {
                // Peer sealed this for the operator's fp; the
                // operator's verifier will check it. We just
                // ship the bytes through.
                conn.send_envelope(&bytes).await?;
            } else {
                // Synthesise a relay-signed terminal chunk for
                // the failed peer. agent_fp is informational;
                // the operator can detect "this came from the
                // relay, not the peer" because the envelope is
                // signed by the relay rather than the peer.
                let chunk = SqlChunk {
                    columns: Vec::new(),
                    rows: Vec::new(),
                    end: true,
                    agent_fp: peer_fp.as_bytes().to_vec(),
                };
                send_chunk(conn, sealer, &operator, request_id, chunk).await?;
            }
        }
        Ok(())
    }
    .await;

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}
    drain_outcome
}

/// One peer's leg of the fan-out. Dials the peer, sends an
/// `OperatorCommand { forwarded_from_operator, … }`, reads
/// **opaque** envelope bytes back, and forwards them through
/// `chunk_tx`. Each envelope is sealed by the peer for the
/// *original operator's* fingerprint, so the relay cannot
/// verify the signature — only operator-side verification can.
/// The relay still peeks into the inner `WhisperPayload`
/// (plaintext per Phase-1a wire format) to detect end-of-stream
/// per peer.
///
/// On dial / send failure, an `OperatorError` is enqueued so the
/// multiplexer can emit a synthetic EOF chunk to the operator
/// (sealed by the relay — operators see a labelled "this peer
/// failed" rather than silence).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_peer_query(
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: &Arc<Sealer>,
    peer: PeerInfo,
    forwarded_authorization: Vec<u8>,
    sql: &str,
    request_id: &str,
    timeout: Duration,
    bytes_tx: mpsc::Sender<(Fingerprint, Result<Vec<u8>, bowery_proto::OperatorError>)>,
) {
    use bowery_proto::{
        Body, OperatorCommand, OperatorCommandBody, OperatorError, OperatorResultBody, SqlQuery,
        WhisperEnvelope,
    };
    use prost::Message as _;

    let peer_fp = peer.fingerprint;
    let cmd = OperatorCommand {
        request_id: request_id.to_string(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        forwarded_from_operator: forwarded_authorization,
        command: Some(OperatorCommandBody::Sql(SqlQuery {
            sql: sql.to_string(),
            fanout: false, // cycle prevention
            peers: Vec::new(),
        })),
    };
    let outbound = sealer.seal_for(&peer_fp, &WhisperPayload::operator_command(cmd));

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer_fp));
    let conn = match endpoint.dial(dial_verifier, peer.whisper_addr).await {
        Ok(c) => c,
        Err(e) => {
            warn!(peer = %peer_fp, error = %e, "fanout dial failed");
            let _ = bytes_tx
                .send((
                    peer_fp,
                    Err(OperatorError {
                        kind: "dial_failed".into(),
                        message: e.to_string(),
                    }),
                ))
                .await;
            return;
        }
    };
    if let Err(e) = conn.send_envelope(&outbound).await {
        warn!(peer = %peer_fp, error = %e, "fanout send failed");
        let _ = bytes_tx
            .send((
                peer_fp,
                Err(OperatorError {
                    kind: "send_failed".into(),
                    message: e.to_string(),
                }),
            ))
            .await;
        return;
    }

    let exchange = async {
        loop {
            let bytes = conn
                .recv_envelope()
                .await
                .map_err(|e| format!("recv: {e}"))?;
            // Peek at the envelope just enough to (a) verify the
            // sender claim and (b) detect end-of-stream. The
            // signature is *not* verified here — it's sealed for
            // the original operator, not the relay. Operator-side
            // verification is the authoritative integrity check.
            let env = WhisperEnvelope::decode(bytes.as_slice())
                .map_err(|e| format!("envelope decode: {e}"))?;
            if env.sender_fingerprint.as_slice() != peer_fp.as_bytes().as_slice() {
                return Err(format!(
                    "envelope sender mismatch: peer {peer_fp} responded with sender_fingerprint {:x?}",
                    env.sender_fingerprint
                ));
            }
            let payload = WhisperPayload::decode(env.payload.as_slice())
                .map_err(|e| format!("payload decode: {e}"))?;
            let is_end_of_stream = matches!(
                &payload.body,
                Some(Body::OperatorResult(r))
                    if matches!(
                        &r.result,
                        Some(OperatorResultBody::SqlChunk(c)) if c.end
                    ) || matches!(&r.result, Some(OperatorResultBody::Error(_)))
            );
            if bytes_tx.send((peer_fp, Ok(bytes))).await.is_err() {
                return Ok(());
            }
            if is_end_of_stream {
                return Ok(());
            }
        }
    };
    let outcome: Result<Result<(), String>, tokio::time::error::Elapsed> =
        tokio::time::timeout(timeout + Duration::from_secs(2), exchange).await;
    if let Err(_) | Ok(Err(_)) = outcome {
        let (kind, message) = match outcome {
            Err(_) => ("timeout", format!("peer {peer_fp} timed out")),
            Ok(Err(e)) => ("peer_error", e),
            _ => unreachable!(),
        };
        let _ = bytes_tx
            .send((
                peer_fp,
                Err(OperatorError {
                    kind: kind.into(),
                    message,
                }),
            ))
            .await;
    }
}

/// Phase-9 final-1: resolve the effective operator for an
/// `OperatorCommand`. Returns either the envelope sender (for
/// direct operator dials) or the operator embedded in a verified
/// `forwarded_from_operator` authorisation. Errors back-propagate
/// as `&'static str` reasons so the caller can surface them in a
/// structured `OperatorError`.
fn resolve_effective_operator(
    cmd: &bowery_proto::OperatorCommand,
    request_id: &str,
    operators: &Arc<StaticResolver>,
    sender: Fingerprint,
) -> Result<Fingerprint, &'static str> {
    use prost::Message as _;

    if cmd.forwarded_from_operator.is_empty() {
        return Ok(sender);
    }
    let auth = bowery_proto::OperatorAuthorization::decode(cmd.forwarded_from_operator.as_slice())
        .map_err(|_| "forwarded_from_operator decode failed")?;
    if auth.operator_fp.len() != 32 {
        return Err("forwarded_from_operator: bad operator_fp length");
    }
    if auth.command_digest.len() != 32 {
        return Err("forwarded_from_operator: bad command_digest length");
    }
    if auth.signature.len() != 64 {
        return Err("forwarded_from_operator: bad signature length");
    }
    if auth.request_id != request_id {
        return Err("forwarded_from_operator: request_id mismatch");
    }
    let mut operator_fp_arr = [0u8; 32];
    operator_fp_arr.copy_from_slice(&auth.operator_fp);
    let operator_fp = Fingerprint::from_bytes(operator_fp_arr);

    // Operator must be in [operators] to authorise a query.
    let Some(vk) = operators.resolve(&operator_fp) else {
        return Err("forwarded_from_operator: operator not in [operators]");
    };

    // Bind authorisation to the actual command we're about to run:
    // peer recomputes SHA-256 of the encoded OperatorCommandBody and
    // compares against the digest signed by the operator. A relay
    // can't substitute a different SQL string under an authorisation
    // issued for some other query.
    let body = cmd
        .command
        .as_ref()
        .ok_or("forwarded_from_operator: empty command")?;
    let actual_digest = command_body_digest(body);
    if actual_digest.as_slice() != auth.command_digest.as_slice() {
        return Err("forwarded_from_operator: command_digest mismatch");
    }

    // ts_unix_ms skew check: same window envelopes use (5 minutes).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let skew = now.abs_diff(auth.ts_unix_ms);
    if skew > 5 * 60 * 1000 {
        return Err("forwarded_from_operator: ts_unix_ms outside skew window");
    }

    let mut digest_arr = [0u8; 32];
    digest_arr.copy_from_slice(&auth.command_digest);
    let signing_input = bowery_proto::OperatorAuthorization::signing_input(
        &operator_fp_arr,
        auth.ts_unix_ms,
        &auth.request_id,
        &digest_arr,
    );
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&auth.signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    if vk.verify_strict(&signing_input, &sig).is_err() {
        return Err("forwarded_from_operator: signature verification failed");
    }
    Ok(operator_fp)
}

/// Apply an operator-signed revocation and, when asked, spread it.
///
/// The security argument here is different from every other command, and
/// simpler: the payload is **self-authenticating**. A `Revocation`
/// carries its own operator signature over its own fields, so this agent
/// verifies it directly rather than trusting whoever relayed it. A
/// compromised peer can therefore *drop* a revocation in transit — it
/// cannot forge one, and cannot use the relay path to eject healthy
/// agents. Dropping is the residual risk, which is why
/// `bowery_revocations` is queryable fleet-wide: convergence is checked,
/// not assumed.
///
/// Propagation terminates on the store rather than on a separate
/// seen-set: revocations are permanent, so a re-received one is not new
/// and is not forwarded. `ttl` remains as an independent structural
/// bound.
#[allow(clippy::too_many_arguments)]
async fn handle_revoke_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    operator: Fingerprint,
    request_id: &str,
    push: &bowery_proto::RevokePush,
    forwarded_authorization: &[u8],
    ctx: &Arc<RevocationContext>,
    relay: Option<&Arc<RelayContext>>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    let self_fp = sealer.fingerprint();
    let mut report = bowery_proto::RevokeReport {
        agent_fp: self_fp.as_bytes().to_vec(),
        end: true,
        ..Default::default()
    };

    let decoded = <bowery_proto::Revocation as prost::Message>::decode(push.revocation.as_slice());
    let mut is_new = false;
    match decoded {
        Err(e) => report.error = format!("undecodable revocation: {e}"),
        Ok(revocation) => {
            let ops = ctx.operators.clone();
            let resolve = move |fp: &Fingerprint| ops.resolve(fp);
            match bowery_whisper::mesh_trust::verify_revocation(
                &revocation,
                &ctx.cluster_id,
                &resolve,
            ) {
                Err(e) => {
                    warn!(sender = %operator, error = %e, "rejecting unverifiable revocation");
                    report.error = e.to_string();
                }
                Ok(target) => match ctx.store.insert(target, &revocation) {
                    Err(e) => report.error = format!("persisting revocation: {e}"),
                    Ok(new) => {
                        is_new = new;
                        report.accepted = true;
                        report.already_known = !new;
                        // Evict immediately rather than waiting for the
                        // next gossip tick: the window between "we know
                        // this peer is compromised" and "we stop
                        // trusting it" should be as close to zero as the
                        // code can make it.
                        report.evicted = ctx.known_neighbors.unpin(&target).unwrap_or(false);
                        if new {
                            warn!(
                                target = %target,
                                reason = %revocation.reason,
                                evicted = report.evicted,
                                "revocation applied"
                            );
                        }
                    }
                },
            }
        }
    }

    send_revoke_report(conn, sealer, &operator, request_id, report).await?;

    // Forward only what we hadn't already seen — that is what makes a
    // flood converge instead of echoing around the mesh forever.
    if push.fanout
        && push.ttl > 0
        && is_new
        && let Some(relay) = relay
    {
        relay_revoke_push(
            conn,
            sealer,
            request_id,
            push,
            forwarded_authorization,
            relay,
            timeout,
        )
        .await?;
    }

    if push.fanout {
        send_revoke_report(
            conn,
            sealer,
            &operator,
            request_id,
            bowery_proto::RevokeReport {
                agent_fp: Vec::new(),
                end: true,
                ..Default::default()
            },
        )
        .await?;
    }
    Ok(())
}

/// Forward a revocation to every pinned peer with `ttl` decremented,
/// piping their sealed reports back to the operator verbatim.
async fn relay_revoke_push(
    conn: &BoweryConnection,
    sealer: &Arc<Sealer>,
    request_id: &str,
    push: &bowery_proto::RevokePush,
    forwarded_authorization: &[u8],
    relay: &Arc<RelayContext>,
    timeout: Duration,
) -> Result<(), bowery_whisper::transport::Error> {
    let peers: Vec<PeerInfo> = relay
        .peers_watcher
        .borrow()
        .clone()
        .into_iter()
        .filter(|p| relay.known_neighbors.resolve(&p.fingerprint).is_some())
        .filter(|p| p.fingerprint != sealer.fingerprint())
        .collect();
    if peers.is_empty() {
        return Ok(());
    }

    let (bytes_tx, mut bytes_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut join_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let onward = bowery_proto::RevokePush {
        revocation: push.revocation.clone(),
        fanout: true,
        ttl: push.ttl.saturating_sub(1),
    };

    for peer in peers {
        let bytes_tx = bytes_tx.clone();
        let endpoint = relay.endpoint.clone();
        let kn = relay.known_neighbors.clone();
        let sealer_clone = sealer.clone();
        let request_id = request_id.to_string();
        let auth = forwarded_authorization.to_vec();
        let onward = onward.clone();
        join_set.spawn(async move {
            run_peer_revoke_push(
                endpoint,
                kn,
                &sealer_clone,
                peer,
                auth,
                onward,
                &request_id,
                timeout,
                bytes_tx,
            )
            .await;
        });
    }
    drop(bytes_tx);

    let drain: Result<(), bowery_whisper::transport::Error> = async {
        while let Some(bytes) = bytes_rx.recv().await {
            conn.send_envelope(&bytes).await?;
        }
        Ok(())
    }
    .await;

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}
    drain
}

#[allow(clippy::too_many_arguments)]
async fn run_peer_revoke_push(
    endpoint: BoweryEndpoint,
    kn: Arc<KnownNeighbors>,
    sealer: &Arc<Sealer>,
    peer: PeerInfo,
    forwarded_authorization: Vec<u8>,
    push: bowery_proto::RevokePush,
    request_id: &str,
    timeout: Duration,
    bytes_tx: mpsc::Sender<Vec<u8>>,
) {
    use bowery_proto::{OperatorCommand, OperatorCommandBody, WhisperEnvelope};
    use prost::Message as _;

    let peer_fp = peer.fingerprint;
    let cmd = OperatorCommand {
        request_id: request_id.to_string(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        forwarded_from_operator: forwarded_authorization,
        command: Some(OperatorCommandBody::RevokePush(push)),
    };
    let outbound = sealer.seal_for(&peer_fp, &WhisperPayload::operator_command(cmd));

    let dial_verifier = Arc::new(PinnedCertVerifier::expecting(kn, peer_fp));
    let Ok(conn) = endpoint.dial(dial_verifier, peer.whisper_addr).await else {
        warn!(peer = %peer_fp, "revocation propagation dial failed");
        return;
    };
    if conn.send_envelope(&outbound).await.is_err() {
        warn!(peer = %peer_fp, "revocation propagation send failed");
        return;
    }

    let pump = async {
        loop {
            let Ok(bytes) = conn.recv_envelope().await else {
                return;
            };
            let Ok(env) = WhisperEnvelope::decode(bytes.as_slice()) else {
                return;
            };
            if env.sender_fingerprint.as_slice() != peer_fp.as_bytes().as_slice() {
                warn!(peer = %peer_fp, "revocation propagation sender mismatch");
                return;
            }
            if bytes_tx.send(bytes).await.is_err() {
                return;
            }
        }
    };
    let _ = tokio::time::timeout(timeout, pump).await;
}
