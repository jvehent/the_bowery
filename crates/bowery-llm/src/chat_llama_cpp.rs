//! `llama.cpp`-backed [`Chat`] for the operator console — same
//! worker-thread architecture as [`crate::llama_cpp::LlamaCppAnalyzer`]
//! but tailored to multi-turn free-form chat (Gemma 4 by default).
//!
//! This module is gated behind the `llama-cpp` feature so consoles
//! that don't want the C++ build dep stay lean.

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

use crate::backend::LlmError;
use crate::chat::{Chat, ChatMessage, render_gemma_prompt};

/// Backend tag embedded in [`Chat::name`] for log/audit purposes.
const BACKEND_TAG: &str = "llama-cpp/gemma-4";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlamaCppChatConfig {
    /// Path to the Gemma 4 GGUF file (or any other GGUF that uses
    /// the `<start_of_turn>` chat template).
    pub model_path: PathBuf,
    /// Context window in tokens. Gemma 4 E2B supports 128K but we
    /// default to 8K which fits the schema-grounded chat prompt
    /// comfortably and keeps RAM usage bounded.
    pub n_ctx: u32,
    /// CPU threads. 0 → llama.cpp's default.
    pub n_threads: i32,
    /// GPU layers to offload (0 = pure CPU).
    pub n_gpu_layers: u32,
    /// Maximum response length per turn.
    pub max_tokens: usize,
    /// Sampling temperature. Slightly higher than the analyzer's
    /// (0.2) since chat replies benefit from a touch of variety.
    pub temperature: f32,
}

impl Default for LlamaCppChatConfig {
    fn default() -> Self {
        // Operator-side default — workstation home dir, not the agent's
        // /var/lib path.
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        Self {
            model_path: PathBuf::from(home).join(".bowery/models/gemma-4-e2b-it-q4_k_m.gguf"),
            n_ctx: 8192,
            n_threads: 0,
            n_gpu_layers: 0,
            max_tokens: 512,
            temperature: 0.4,
        }
    }
}

/// Holds a worker thread that owns the model. Same architecture as
/// the analyzer's worker — the two could share a thread later, but
/// they're built for different prompt families and we keep them
/// independent for now so the analyzer's tight JSON loop isn't
/// affected by chat-style sampling decisions.
pub struct LlamaCppChat {
    request_tx: mpsc::Sender<Request>,
    backend_tag: String,
    max_tokens: usize,
}

impl std::fmt::Debug for LlamaCppChat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlamaCppChat")
            .field("backend_tag", &self.backend_tag)
            .finish_non_exhaustive()
    }
}

const REQUEST_CHANNEL_DEPTH: usize = 8;

struct Request {
    prompt: String,
    max_tokens: usize,
    responder: oneshot::Sender<Result<String, LlmError>>,
}

impl LlamaCppChat {
    /// Initialise the backend, load the model, and spawn the worker.
    /// Returns once the worker is ready to accept requests.
    pub async fn new(config: LlamaCppChatConfig) -> Result<Self, LlmError> {
        info!(model = %config.model_path.display(), "loading Gemma 4 GGUF for chat");

        let (request_tx, mut request_rx) = mpsc::channel::<Request>(REQUEST_CHANNEL_DEPTH);
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), LlmError>>();

        let max_tokens = config.max_tokens;
        let cfg = config.clone();
        std::thread::Builder::new()
            .name("bowery-chat-worker".to_string())
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
                debug!("chat worker ready");
                while let Some(req) = request_rx.blocking_recv() {
                    let response = worker.run(&req.prompt, req.max_tokens);
                    if req.responder.send(response).is_err() {
                        debug!("chat client dropped its responder before we replied");
                    }
                }
                info!("chat worker shutting down");
            })
            .map_err(|e| LlmError::ModelNotLoaded(format!("spawn chat worker: {e}")))?;

        ready_rx
            .await
            .map_err(|_| LlmError::ModelNotLoaded("chat worker exited before ready".into()))??;

        Ok(Self {
            request_tx,
            backend_tag: BACKEND_TAG.to_string(),
            max_tokens,
        })
    }
}

#[async_trait]
impl Chat for LlamaCppChat {
    async fn complete(&self, messages: &[ChatMessage]) -> Result<String, LlmError> {
        let prompt = render_gemma_prompt(messages);
        let (responder, response_rx) = oneshot::channel();
        self.request_tx
            .try_send(Request {
                prompt,
                max_tokens: self.max_tokens,
                responder,
            })
            .map_err(|_| LlmError::Cancelled)?;
        let raw = response_rx.await.map_err(|_| LlmError::Cancelled)??;
        Ok(strip_gemma_end_marker(&raw))
    }

    fn name(&self) -> &str {
        &self.backend_tag
    }
}

/// Trim Gemma's `<end_of_turn>` if the model emitted it explicitly.
/// llama.cpp greedy sampling stops at EOG which usually catches it,
/// but some quants emit the literal string.
fn strip_gemma_end_marker(s: &str) -> String {
    s.trim_end_matches('\n')
        .trim_end_matches("<end_of_turn>")
        .trim_end_matches('\n')
        .to_string()
}

// ---------------------------------------------------------------------------
// Worker — owns the model, runs on its own OS thread.
// ---------------------------------------------------------------------------

struct Worker {
    backend: LlamaBackend,
    model: LlamaModel,
    ctx_params: LlamaContextParams,
}

impl Worker {
    fn new(config: &LlamaCppChatConfig) -> Result<Self, LlmError> {
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
        let mut output_bytes: Vec<u8> = Vec::with_capacity(max_tokens * 4);
        let mut n_cur = batch.n_tokens();
        let max_total = (prompt_len + max_tokens) as i32;

        while n_cur < max_total {
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(token);
            if self.model.is_eog_token(token) {
                break;
            }
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

        let response = String::from_utf8_lossy(&output_bytes).into_owned();
        if response.is_empty() {
            warn!("chat backend produced empty response");
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_sensible() {
        let cfg = LlamaCppChatConfig::default();
        assert!(cfg.n_ctx >= 2048);
        assert!(cfg.max_tokens > 0);
        assert!(cfg.temperature > 0.0 && cfg.temperature <= 1.0);
    }

    #[test]
    fn config_roundtrips_through_json() {
        let cfg = LlamaCppChatConfig::default();
        let s = serde_json::to_string(&cfg).unwrap();
        let parsed: LlamaCppChatConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.model_path, cfg.model_path);
        assert_eq!(parsed.n_ctx, cfg.n_ctx);
    }

    #[test]
    fn end_marker_stripped() {
        assert_eq!(strip_gemma_end_marker("hello<end_of_turn>"), "hello");
        assert_eq!(strip_gemma_end_marker("hello<end_of_turn>\n"), "hello");
        assert_eq!(strip_gemma_end_marker("hello"), "hello");
    }
}
