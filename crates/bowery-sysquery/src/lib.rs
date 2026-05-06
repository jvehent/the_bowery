//! Subprocess wrapper for the Phase-6b operator command path that
//! shells out to a host-installed query binary.
//!
//! The binary's expected contract is "accept a SQL string on the
//! command line and emit JSON on stdout". The agent doesn't care
//! which implementation the operator points it at — historically
//! this was the upstream osquery interactive shell, but Bowery's
//! native Phase-9 SQL surface (see `bowery-sql` / `bowery-tables`)
//! is the primary path. This crate exists for the deployment cases
//! where the operator wants the wider third-party-table surface
//! available alongside the native Bowery tables.
//!
//! ## When to enable sysquery
//!
//! Sysquery is **disabled by default** (`[sysquery] enabled =
//! false` in `agent.toml`). Operators turn it on per-host when
//! they have established osquery query libraries or need a
//! third-party table the native engine doesn't have. For
//! day-to-day investigation, the native engine is the right
//! choice — see `crates/bowery-sql` and
//! `IMPLEMENTATION.md` § 22.10 for the comparison matrix.
//!
//! Differences from the native engine an operator should know:
//!
//! - **No fan-out.** `bowery exec sysquery` hits exactly one
//!   agent. Cross-host hunts go through `bowery exec sql --fanout`
//!   instead. There's no plan to add fan-out for sysquery —
//!   operators wanting that should write a `bowery-tables` table.
//! - **No streaming.** Output is the wrapped binary's full JSON
//!   blob, returned in a single `OperatorResultBody::Sysquery`
//!   envelope. Capped at 16 MiB stdout/stderr each.
//! - **Slower cold start.** ~50–200 ms for an `osqueryi`
//!   subprocess vs. <5 ms for the in-process native engine.
//! - **Larger trust boundary.** The operator's SQL goes to a
//!   third-party binary that runs as the agent. The native
//!   engine has a SELECT-only `set_authorizer` and pure-Rust
//!   table impls under our review; the wrapped binary's safety
//!   is whatever upstream ships.
//!
//! ## What this crate does
//!
//! - Locates a query binary at a caller-supplied path.
//! - Runs a single SQL query under a wall-clock timeout, capturing
//!   stdout / stderr / exit code.
//! - Hardens the subprocess: no extensions, no audit subscribers,
//!   no remote control, no persistent database. The operator's SQL
//!   keeps the full read-only host-introspection surface but can't
//!   load extensions or write anywhere.
//! - Kills the subprocess on drop (the agent's request might time
//!   out, the operator might disconnect, the agent might shut
//!   down — none of those should leave a query-runner orphan
//!   running indefinitely).
//!
//! ## What this crate does NOT do
//!
//! - Parse the JSON output. Returned verbatim as a `String` so the
//!   operator's tooling owns its schema.
//! - Validate or rewrite the SQL. The agent's request handler may
//!   refuse queries based on a separate allow-list policy; this
//!   crate trusts its caller.
//! - Manage long-running query daemons. We invoke the binary
//!   one-shot intentionally — no persistent state, no extension
//!   sockets to compromise.
//! - Participate in fan-out. `bowery-agent` only invokes this
//!   crate from the operator-direct dispatch arm; relay-forwarded
//!   commands carry `OperatorAuthorization` and route through the
//!   native engine path.

#![warn(unreachable_pub)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout as tokio_timeout;
use tracing::{debug, warn};

/// Cap on captured stdout/stderr per query. Some host-introspection
/// tables (e.g. `process_open_files` on busy hosts) produce large
/// JSON; 16 MiB is well above any sensible operator query and keeps
/// the agent's RAM cost bounded if a malicious operator targets a
/// pathologically expensive table.
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Output of a single subprocess invocation.
#[derive(Debug, Clone)]
pub struct SysqueryOutput {
    /// Raw JSON the binary wrote to stdout. Unparsed.
    pub stdout: String,
    /// Stderr — usually empty on success; carries diagnostic
    /// messages from the underlying binary on syntax errors etc.
    pub stderr: String,
    /// Process exit code. `0` on success.
    pub exit_code: i32,
}

#[derive(Debug, Error)]
pub enum SysqueryError {
    #[error("sysquery binary not found at {0}")]
    BinaryNotFound(PathBuf),

    #[error("sysquery spawn failed: {0}")]
    Spawn(#[source] std::io::Error),

    #[error("sysquery I/O error: {0}")]
    Io(#[source] std::io::Error),

    #[error("sysquery timed out after {0:?}")]
    Timeout(Duration),

    #[error("sysquery output exceeded {limit} bytes")]
    OutputTooLarge { limit: usize },
}

/// Subprocess-backed query runner.
#[derive(Debug, Clone)]
pub struct Sysquery {
    binary_path: PathBuf,
}

impl Sysquery {
    /// Build a runner for the binary at `binary_path`. Returns
    /// `BinaryNotFound` if the path doesn't exist or isn't a file.
    pub fn new(binary_path: impl Into<PathBuf>) -> Result<Self, SysqueryError> {
        let binary_path = binary_path.into();
        if !binary_path.is_file() {
            return Err(SysqueryError::BinaryNotFound(binary_path));
        }
        Ok(Self { binary_path })
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    /// Run `sql` with `--json` output, capped at `timeout` wall-
    /// clock. The subprocess is killed on timeout (and on drop of
    /// the returned future / on caller cancellation, courtesy of
    /// `kill_on_drop`).
    pub async fn run(&self, sql: &str, timeout: Duration) -> Result<SysqueryOutput, SysqueryError> {
        // Hardening flags — narrow the binary to the read-only,
        // single-query path. These flag names match the upstream
        // osquery binary; if you point sysquery at a different
        // binary, adjust accordingly. Each flag's purpose is
        // documented inline.
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("--json")
            // No extensions: the operator's SQL can't auto-load a
            // .so extension that escapes the sandbox.
            .arg("--disable_extensions=true")
            // No audit subscribers / event tables: those write to
            // disk and require persistent state we don't want.
            .arg("--disable_audit=true")
            .arg("--disable_events=true")
            // No persistent database: each invocation is fresh.
            .arg("--database_path=/tmp")
            .arg("--ephemeral=true")
            // Don't read the host's config. We're an operator-driven
            // query runner, not a managed deployment.
            .arg("--config_path=/dev/null")
            // The query itself — last positional, exactly one.
            .arg(sql)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // SIGKILL the subprocess when this Child handle drops,
            // covering caller timeout / cancellation / agent
            // shutdown.
            .kill_on_drop(true);

        debug!(
            binary = %self.binary_path.display(),
            sql_preview = sql.chars().take(80).collect::<String>(),
            "spawning sysquery binary"
        );

        let mut child = cmd.spawn().map_err(SysqueryError::Spawn)?;

        // Take ownership of stdout/stderr handles before awaiting
        // wait_with_output so we can apply our own size cap.
        let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
        let mut stderr_pipe = child.stderr.take().expect("stderr was piped");

        let mut stdout_buf = Vec::with_capacity(8 * 1024);
        let mut stderr_buf = Vec::with_capacity(1024);

        let exchange = async {
            // try_join! returns on the first error and drops the other
            // future. That matters when stdout hits MAX_OUTPUT_BYTES
            // but stderr is still draining — without try_join we'd
            // wait for stderr's EOF (which only comes when the child
            // exits), turning a fast-fail cap into a wait-for-timeout.
            let stdout_fut = read_capped(&mut stdout_pipe, &mut stdout_buf, MAX_OUTPUT_BYTES);
            let stderr_fut = read_capped(&mut stderr_pipe, &mut stderr_buf, MAX_OUTPUT_BYTES);
            tokio::try_join!(stdout_fut, stderr_fut)?;
            let status = child.wait().await.map_err(SysqueryError::Io)?;
            Ok::<_, SysqueryError>(status)
        };

        // Box the inner future so the outer state machine doesn't
        // grow huge — the future captures stack-allocated 8 KiB read
        // chunks, which clippy::large_futures flags above 8 KiB.
        let exchange = Box::pin(exchange);
        let status = match tokio_timeout(timeout, exchange).await {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => {
                // Make sure the child is dead — kill_on_drop covers
                // the timeout case but our own pipe-read errors
                // dropped us out before waitpid completed.
                let _ = child.start_kill();
                return Err(e);
            }
            Err(_) => {
                warn!("sysquery binary exceeded timeout {timeout:?}; killing subprocess");
                let _ = child.start_kill();
                return Err(SysqueryError::Timeout(timeout));
            }
        };

        Ok(SysqueryOutput {
            stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
            // Linux signals (e.g. our SIGKILL on timeout) yield
            // None from `code()`; surface them as a synthetic
            // -signal so the operator sees the failure mode.
            exit_code: status
                .code()
                .or_else(|| {
                    use std::os::unix::process::ExitStatusExt;
                    status.signal().map(|s| -s)
                })
                .unwrap_or(-1),
        })
    }
}

/// Read from `pipe` into `buf` until EOF or the byte cap is hit.
/// Cap exhaustion produces `OutputTooLarge` rather than a partial
/// silent truncation.
async fn read_capped<R>(pipe: &mut R, buf: &mut Vec<u8>, cap: usize) -> Result<(), SysqueryError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut chunk = [0u8; 8192];
    loop {
        let n = pipe.read(&mut chunk).await.map_err(SysqueryError::Io)?;
        if n == 0 {
            return Ok(());
        }
        if buf.len() + n > cap {
            return Err(SysqueryError::OutputTooLarge { limit: cap });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    /// Write a small shim shell script that ignores all its
    /// arguments and runs `body`. Returns its path. Used by tests
    /// to exercise the `run()` pipeline without depending on a real
    /// query binary being installed (and without our hardening
    /// flags being interpreted by the test binary).
    fn make_shim(dir: &std::path::Path, body: &str) -> PathBuf {
        let p = dir.join("shim.sh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).expect("write shim");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
        p
    }

    #[test]
    fn new_rejects_missing_binary() {
        let err = Sysquery::new("/no/such/binary").expect_err("missing path must fail");
        assert!(matches!(err, SysqueryError::BinaryNotFound(_)));
    }

    /// Round-trip the spawn / pipe / wait path against a shim that
    /// emits a known JSON-ish payload on stdout and exits 0.
    #[tokio::test]
    async fn spawn_and_wait_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let shim = make_shim(dir.path(), r#"echo '[{"ok":1}]'"#);
        let runner = Sysquery::new(&shim).expect("shim exists");
        let out = runner
            .run("ignored", Duration::from_secs(2))
            .await
            .expect("run shim");
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains(r#"{"ok":1}"#));
        assert!(out.stderr.is_empty());
    }

    #[tokio::test]
    async fn timeout_kills_long_running_subprocess() {
        let dir = tempfile::tempdir().unwrap();
        // The shim ignores its args (the hardening flags + the SQL
        // string the underlying binary would consume) and just
        // sleeps. Our 100ms timeout triggers the kill path.
        let shim = make_shim(dir.path(), "sleep 5");
        let runner = Sysquery::new(&shim).expect("shim exists");
        let err = runner
            .run("ignored", Duration::from_millis(100))
            .await
            .expect_err("must time out");
        assert!(
            matches!(err, SysqueryError::Timeout(_)),
            "expected Timeout, got {err:?}"
        );
    }

    #[tokio::test]
    async fn output_too_large_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // 32 MiB of zero bytes — well above MAX_OUTPUT_BYTES (16 MiB).
        // dd with bs=1M count=32 produces exactly 32 MiB and exits;
        // we should hit the cap before dd finishes.
        let shim = make_shim(dir.path(), "dd if=/dev/zero bs=1M count=32 2>/dev/null");
        let runner = Sysquery::new(&shim).expect("shim exists");
        let err = runner
            .run("ignored", Duration::from_secs(10))
            .await
            .expect_err("must hit output cap");
        assert!(
            matches!(err, SysqueryError::OutputTooLarge { .. }),
            "expected OutputTooLarge, got {err:?}"
        );
    }
}
