//! Bounded inference queue with shed-newest backpressure.
//!
//! The agent enqueues an [`AnalysisContext`] when the Phase 3 verdict
//! crosses an LLM-invocation threshold. A worker task pulls from the
//! queue and runs the configured [`LlmAnalyzer`]. If the queue is full
//! when a new request arrives, the **new** request is rejected and the
//! caller receives [`ShedReason::QueueFull`]. This gives the LLM a hard
//! upper bound on per-event latency tax: even a slow model can't gum
//! up the rest of the pipeline.
//!
//! **Tradeoff vs. shed-oldest:** an attacker who can produce a steady
//! stream of decoy submissions fills the queue, and any genuinely
//! suspicious verdict that arrives after the flood is silently shed.
//! Mitigations to add later (Phase-9): a high-priority lane for
//! `suspicion >= 0.95` verdicts that bypasses the regular bounded
//! channel; per-source rate limits on the upstream pipeline; or a
//! true ring-buffered shed-oldest implementation (which `tokio::mpsc`
//! doesn't support natively).

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::backend::{LlmAnalyzer, LlmVerdict};
use crate::context::AnalysisContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShedReason {
    /// Backlog was full when this request arrived; the new request
    /// was dropped (the worker keeps draining what it already has).
    QueueFull,
    /// Worker took longer than the per-request deadline; the request
    /// was abandoned.
    Deadline,
}

#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Maximum number of pending requests. New requests beyond this drop
    /// the oldest pending request.
    pub capacity: usize,
    /// Per-request deadline. When exceeded, the worker abandons the
    /// request and emits a shed event.
    pub per_request_deadline: Duration,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            capacity: 32,
            per_request_deadline: Duration::from_secs(10),
        }
    }
}

/// Outcome the worker emits per request. `episode_id` is taken verbatim
/// from the input context's `pre_verdict` so callers can route the
/// result back to whoever submitted it.
///
/// `Verdict` carries the original `AnalysisContext` back so downstream
/// consumers (e.g. the agent's alert-emission path) can build a
/// refined record without having to maintain a sidecar map keyed by
/// `episode_id`. The clone is cheap — `AnalysisContext` is at most a
/// few hundred bytes per request.
#[derive(Debug)]
pub enum InferenceOutcome {
    Verdict {
        episode_id: String,
        ctx: Box<AnalysisContext>,
        verdict: Box<LlmVerdict>,
    },
    Failed {
        episode_id: String,
        error: String,
    },
    Shed {
        episode_id: String,
        reason: ShedReason,
    },
}

/// Lifecycle handle for the inference worker.
#[derive(Debug)]
pub struct InferenceQueue {
    submitter: Submitter,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

/// Clonable submission handle. Multiple callers may submit concurrently.
#[derive(Debug, Clone)]
pub struct Submitter {
    submit_tx: mpsc::Sender<AnalysisContext>,
}

impl Submitter {
    /// Submit a request. Returns `Err(QueueFull)` if the worker is
    /// backed up; the caller can either drop the work or back off.
    pub fn submit(&self, ctx: AnalysisContext) -> Result<(), ShedReason> {
        match self.submit_tx.try_send(ctx) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("inference queue full; shedding new request");
                Err(ShedReason::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("inference queue closed");
                Err(ShedReason::QueueFull)
            }
        }
    }
}

impl InferenceQueue {
    pub fn start(
        analyzer: Arc<dyn LlmAnalyzer>,
        cfg: &QueueConfig,
        outcomes: mpsc::Sender<InferenceOutcome>,
    ) -> Self {
        let (submit_tx, submit_rx) = mpsc::channel::<AnalysisContext>(cfg.capacity);
        let submit_rx = Arc::new(Mutex::new(submit_rx));
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let per_request_deadline = cfg.per_request_deadline;
        let worker = tokio::spawn(async move {
            loop {
                let next = {
                    let mut rx = submit_rx.lock().await;
                    tokio::select! {
                        item = rx.recv() => item,
                        _ = shutdown_rx.changed() => None,
                    }
                };
                let Some(ctx) = next else { break };

                let episode_id = ctx.pre_verdict.episode_id.clone();
                let result =
                    tokio::time::timeout(per_request_deadline, analyzer.analyze(&ctx)).await;
                let outcome = match result {
                    Ok(Ok(v)) => InferenceOutcome::Verdict {
                        episode_id,
                        ctx: Box::new(ctx),
                        verdict: Box::new(v),
                    },
                    Ok(Err(e)) => InferenceOutcome::Failed {
                        episode_id,
                        error: e.to_string(),
                    },
                    Err(_) => InferenceOutcome::Shed {
                        episode_id,
                        reason: ShedReason::Deadline,
                    },
                };
                if outcomes.send(outcome).await.is_err() {
                    break;
                }
            }
        });

        Self {
            submitter: Submitter { submit_tx },
            shutdown_tx,
            worker: Some(worker),
        }
    }

    /// Clone a submission handle for use elsewhere.
    pub fn submitter(&self) -> Submitter {
        self.submitter.clone()
    }

    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.worker.take() {
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{MockLlmAnalyzer, MockMode};
    use bowery_analysis::{BinaryScore, Verdict};

    fn ctx(suspicion: f32) -> AnalysisContext {
        AnalysisContext::new(Verdict {
            episode_id: "ep-x".into(),
            suspicion,
            score: BinaryScore {
                value: suspicion,
                baseline_seen_count: 0,
                reason: "t".into(),
            },
            rule_hits: Vec::new(),
        })
    }

    #[tokio::test]
    async fn worker_processes_submitted_requests() {
        let analyzer = Arc::new(MockLlmAnalyzer::new(MockMode::Echo));
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let q = InferenceQueue::start(analyzer, &QueueConfig::default(), out_tx);
        let submitter = q.submitter();

        submitter.submit(ctx(0.9)).unwrap();
        submitter.submit(ctx(0.8)).unwrap();

        for _ in 0..2 {
            let outcome = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
                .await
                .expect("timed out")
                .expect("outcome");
            assert!(matches!(outcome, InferenceOutcome::Verdict { .. }));
        }
        q.shutdown().await;
    }

    #[tokio::test]
    async fn deadline_sheds_long_running_inference() {
        // Wrap the mock so we can artificially slow it down.
        struct SlowAnalyzer;
        #[async_trait::async_trait]
        impl LlmAnalyzer for SlowAnalyzer {
            async fn analyze(
                &self,
                _ctx: &AnalysisContext,
            ) -> Result<crate::backend::LlmVerdict, crate::backend::LlmError> {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(crate::backend::LlmVerdict {
                    suspicion: 0.0,
                    rationale: "slow".into(),
                    suggested_actions: Vec::new(),
                    whisper_query: String::new(),
                    backend: "slow".into(),
                })
            }
            fn name(&self) -> &'static str {
                "slow"
            }
        }

        let analyzer = Arc::new(SlowAnalyzer);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let cfg = QueueConfig {
            capacity: 4,
            per_request_deadline: Duration::from_millis(50),
        };
        let q = InferenceQueue::start(analyzer, &cfg, out_tx);
        let submitter = q.submitter();

        submitter.submit(ctx(0.9)).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("timed out")
            .expect("outcome");
        assert!(
            matches!(
                outcome,
                InferenceOutcome::Shed {
                    reason: ShedReason::Deadline,
                    ..
                }
            ),
            "got {outcome:?}"
        );
        q.shutdown().await;
    }

    #[tokio::test]
    async fn failing_analyzer_yields_failed_outcome() {
        let analyzer = Arc::new(MockLlmAnalyzer::new(MockMode::Failing));
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let q = InferenceQueue::start(analyzer, &QueueConfig::default(), out_tx);
        let submitter = q.submitter();

        submitter.submit(ctx(0.9)).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("timed out")
            .expect("outcome");
        assert!(matches!(outcome, InferenceOutcome::Failed { .. }));
        q.shutdown().await;
    }
}
