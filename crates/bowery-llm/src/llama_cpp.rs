//! llama.cpp-backed LLM analyzer (Qwen3-0.6B by default).
//!
//! Loaded behind the `llama-cpp` feature so default builds stay free of
//! the C++ build dependency. Uses [`llama_cpp_2`] under the hood.
//!
//! Threading model: llama.cpp's `LlamaModel` and `LlamaContext` are not
//! `Send`. We park them on a single dedicated OS thread, communicating
//! via tokio channels: callers `await` a oneshot response while the
//! worker runs inference synchronously. This keeps the tokio runtime
//! unblocked even when a single inference call takes seconds.
//!
//! Resource expectations (Qwen3-0.6B `Q4_K_M`):
//! - Disk: ~400 MB GGUF
//! - RAM: ~600 MB resident
//! - CPU: ~50–200 tok/s on a modern `x86_64` core
//!
//! Phase 4b ships only the CPU path. CUDA/Vulkan offload is a knob on
//! [`LlamaCppConfig::n_gpu_layers`] but the corresponding llama-cpp-2
//! features aren't wired here — that's a follow-up.

use std::num::NonZeroU32;
use std::path::PathBuf;

use async_trait::async_trait;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::backend::{LlmAnalyzer, LlmError, LlmVerdict};
use crate::context::AnalysisContext;
use crate::parse::parse_verdict;
use crate::prompt::PromptStyle;

/// Backend tag embedded in [`LlmVerdict::backend`] for log/audit purposes.
const BACKEND_TAG: &str = "llama-cpp/qwen3-0.6b";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlamaCppConfig {
    /// Path to the Qwen3-0.6B GGUF file. The agent's `[llm.llama_cpp]
    /// model_path` knob feeds this.
    pub model_path: PathBuf,
    /// Context window in tokens. 4096 covers our prompt (~500 tokens) +
    /// generous headroom for context expansion in later phases.
    pub n_ctx: u32,
    /// CPU threads for the matmul kernels. 0 → llama.cpp's default
    /// (typically `min(physical_cores, 4)`).
    pub n_threads: i32,
    /// GPU layers to offload (0 = pure CPU). Phase 4b ignores this on
    /// CPU-only builds; reserved for the GPU follow-up.
    pub n_gpu_layers: u32,
    /// Maximum response length in tokens. Bowery's prompt asks for a
    /// short JSON object; 256 is plenty.
    pub max_tokens: usize,
    /// Sampling temperature. Lower = more deterministic. JSON output
    /// benefits from low temperature.
    pub temperature: f32,
}

impl Default for LlamaCppConfig {
    fn default() -> Self {
        Self {
            model_path: PathBuf::from("/var/lib/bowery/models/qwen3-0.6b-instruct-q4_k_m.gguf"),
            n_ctx: 4096,
            n_threads: 0,
            n_gpu_layers: 0,
            max_tokens: 256,
            temperature: 0.2,
        }
    }
}

/// llama.cpp-backed analyzer. Holds a worker thread that owns the model.
pub struct LlamaCppAnalyzer {
    request_tx: mpsc::Sender<Request>,
    backend_tag: String,
    max_tokens: usize,
}

/// Hard cap on requests in flight between the analyzer and its dedicated
/// llama.cpp thread. The upstream `InferenceQueue` already bounds + sheds
/// at its own capacity, so under the queue's single-worker contract this
/// channel only ever holds one request at a time. The bound exists as
/// defense-in-depth: any future code path that calls `analyze()` directly
/// (tests, debug tooling, multi-worker queues) cannot grow this channel
/// without bound and exhaust memory.
const REQUEST_CHANNEL_DEPTH: usize = 32;

impl std::fmt::Debug for LlamaCppAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlamaCppAnalyzer")
            .field("backend_tag", &self.backend_tag)
            .finish_non_exhaustive()
    }
}

struct Request {
    prompt: String,
    max_tokens: usize,
    responder: oneshot::Sender<Result<String, LlmError>>,
}

impl LlamaCppAnalyzer {
    /// Initialise the backend, load the model, and spawn the worker.
    /// Returns once the worker is ready to accept requests.
    pub async fn new(config: LlamaCppConfig) -> Result<Self, LlmError> {
        info!(model = %config.model_path.display(), "loading Qwen3 GGUF (this is slow)");

        let (request_tx, mut request_rx) = mpsc::channel::<Request>(REQUEST_CHANNEL_DEPTH);
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), LlmError>>();

        let max_tokens = config.max_tokens;
        let cfg = config.clone();
        std::thread::Builder::new()
            .name("bowery-llm-worker".to_string())
            .spawn(move || {
                let worker = match Worker::new(&cfg) {
                    Ok(w) => {
                        let _ = ready_tx.send(Ok(()));
                        w
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                debug!("LLM worker ready");
                while let Some(req) = request_rx.blocking_recv() {
                    let response = worker.run(&req.prompt, req.max_tokens);
                    if req.responder.send(response).is_err() {
                        debug!("LLM client dropped its responder before we replied");
                    }
                }
                info!("LLM worker shutting down");
            })
            .map_err(|e| LlmError::ModelNotLoaded(format!("spawn worker: {e}")))?;

        ready_rx
            .await
            .map_err(|_| LlmError::ModelNotLoaded("worker exited before ready".into()))??;

        Ok(Self {
            request_tx,
            backend_tag: BACKEND_TAG.to_string(),
            max_tokens,
        })
    }
}

#[async_trait]
impl LlmAnalyzer for LlamaCppAnalyzer {
    async fn analyze(&self, ctx: &AnalysisContext) -> Result<LlmVerdict, LlmError> {
        let prompt = PromptStyle::Qwen3Chat.render(ctx);
        let (responder, response_rx) = oneshot::channel();
        // Honor `LlamaCppConfig.max_tokens` instead of hardcoding 256.
        // try_send (not send().await) so backpressure surfaces as
        // BadResponse rather than blocking the caller — the upstream
        // queue already runs us single-worker, so Full here would mean
        // a concurrent direct caller is racing.
        self.request_tx
            .try_send(Request {
                prompt,
                max_tokens: self.max_tokens,
                responder,
            })
            .map_err(|_| LlmError::Cancelled)?;
        let raw = response_rx.await.map_err(|_| LlmError::Cancelled)??;
        parse_verdict(&raw, &self.backend_tag)
    }

    fn name(&self) -> &str {
        &self.backend_tag
    }
}

// ---------------------------------------------------------------------------
// Worker — runs on its own thread, owns the model + backend.
// ---------------------------------------------------------------------------

struct Worker {
    backend: LlamaBackend,
    model: LlamaModel,
    ctx_params: LlamaContextParams,
}

impl Worker {
    fn new(config: &LlamaCppConfig) -> Result<Self, LlmError> {
        let backend = LlamaBackend::init().map_err(|e| LlmError::ModelNotLoaded(e.to_string()))?;
        let model_params = LlamaModelParams::default().with_n_gpu_layers(config.n_gpu_layers);
        let model = LlamaModel::load_from_file(&backend, &config.model_path, &model_params)
            .map_err(|e| LlmError::ModelNotLoaded(e.to_string()))?;
        let n_ctx = NonZeroU32::new(config.n_ctx).unwrap_or(NonZeroU32::new(2048).unwrap());
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(Some(n_ctx))
            .with_n_threads(config.n_threads);
        Ok(Self {
            backend,
            model,
            ctx_params,
        })
    }

    // llama.cpp uses i32 for batch indices and token positions; usize→i32
    // casts are safe at the magnitudes we operate at (n_ctx ≤ 4096, max
    // tokens ≤ 256 in our config).
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn run(&self, prompt: &str, max_tokens: usize) -> Result<String, LlmError> {
        let mut ctx = self
            .model
            .new_context(&self.backend, self.ctx_params.clone())
            .map_err(|e| LlmError::Inference(format!("new_context: {e}")))?;

        let tokens = self
            .model
            .str_to_token(prompt, AddBos::Always)
            .map_err(|e| LlmError::Inference(format!("tokenize: {e}")))?;

        if tokens.is_empty() {
            return Err(LlmError::Inference("empty tokenisation".into()));
        }

        // Feed the prompt into the context.
        let prompt_len = tokens.len();
        let mut batch = LlamaBatch::new(prompt_len.max(512), 1);
        let last_idx = (prompt_len - 1) as i32;
        for (i, token) in tokens.into_iter().enumerate() {
            let i = i as i32;
            batch
                .add(token, i, &[0], i == last_idx)
                .map_err(|e| LlmError::Inference(format!("batch.add prompt: {e}")))?;
        }
        ctx.decode(&mut batch)
            .map_err(|e| LlmError::Inference(format!("decode prompt: {e}")))?;

        let mut sampler = LlamaSampler::greedy();
        // Accumulate raw bytes from token_to_piece — UTF-8 sequences can
        // span multiple tokens, so we can't decode per-token safely.
        let mut output_bytes: Vec<u8> = Vec::with_capacity(max_tokens * 4);
        let mut n_cur = batch.n_tokens();
        let max_total = (prompt_len + max_tokens) as i32;

        while n_cur < max_total {
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(token);
            if self.model.is_eog_token(token) {
                break;
            }
            // Args: token, max_bytes, render_special, vocab_id_override.
            // 64 bytes covers any single Qwen3 piece; `false` means
            // "don't render <|special|> tokens as their text form".
            let piece = self
                .model
                .token_to_piece_bytes(token, 64, false, None)
                .map_err(|e| LlmError::Inference(format!("token_to_piece_bytes: {e}")))?;
            output_bytes.extend_from_slice(&piece);

            batch.clear();
            batch
                .add(token, n_cur, &[0], true)
                .map_err(|e| LlmError::Inference(format!("batch.add token: {e}")))?;
            ctx.decode(&mut batch)
                .map_err(|e| LlmError::Inference(format!("decode token: {e}")))?;
            n_cur += 1;
        }

        // Lossy is correct here: the model can emit malformed UTF-8 if it
        // truncates mid-codepoint at max_tokens. We'd rather get the
        // best-effort string than fail the verdict.
        let response = String::from_utf8_lossy(&output_bytes).into_owned();
        if response.is_empty() {
            warn!("LLM produced empty response");
        }
        Ok(response)
    }
}

impl Drop for LlamaCppAnalyzer {
    fn drop(&mut self) {
        // Closing the request channel signals the worker to exit.
        // Nothing else to do; the OS thread joins on next runtime
        // shutdown via its own drop.
        debug!("dropping LlamaCppAnalyzer");
    }
}

// ---------------------------------------------------------------------------
// Tests — only compile-checked here. Real inference tests need a model
// file and live in the agent's integration-test layer (or are run
// manually on the VM via xtest).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_sensible() {
        let cfg = LlamaCppConfig::default();
        assert!(cfg.n_ctx >= 2048);
        assert!(cfg.max_tokens > 0);
        assert!(cfg.temperature > 0.0 && cfg.temperature <= 1.0);
    }

    /// We can't load a model in unit tests (no GGUF on the test host),
    /// but we can at least confirm the config serialises round-trip
    /// so config files don't silently drift.
    #[test]
    fn config_roundtrips_through_json() {
        let cfg = LlamaCppConfig::default();
        let s = serde_json::to_string(&cfg).unwrap();
        let parsed: LlamaCppConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.model_path, cfg.model_path);
        assert_eq!(parsed.n_ctx, cfg.n_ctx);
    }
}
