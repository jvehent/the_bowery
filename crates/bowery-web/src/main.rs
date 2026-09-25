//! `bowery-web` — the operator console in a browser.
//!
//! Same flags as `bowery-console`, same data underneath: live queries
//! go through `bowery_cli::exec::sql` over the whisper transport, and
//! alerts come from the operator-side archive, which is the only place
//! that keeps an alert's `context` — and therefore the only place the
//! per-peer whisper verdicts survive. The agent's own `bowery_alerts`
//! table does not carry them.
//!
//! # Why it binds to loopback
//!
//! The listener is unauthenticated by request. This process holds the
//! operator key, so anything that can reach the port can query the
//! fleet, push a silence, and read every alert the archive has. On
//! `127.0.0.1` that is the same boundary as the terminal console —
//! whoever is on the box already has the key. Anywhere else it is a
//! different boundary entirely, so a routable bind has to be asked for
//! explicitly and says so loudly when it happens.
//!
//! # Why the page fetches nothing
//!
//! Every byte of CSS and JavaScript is compiled into the binary. No
//! CDN, no web font, no remote script. Two reasons, the same ones the
//! notification email already follows: an operator investigating a
//! compromise should not be announcing to a third party the moment
//! they opened an alert, and the console has to work on a host with no
//! route to the internet, which is a normal state for the machines
//! this watches.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

mod api;
mod assets;
mod relay;

use relay::Relay;

/// Crate version plus build commit; `-dirty` means uncommitted changes.
const WEB_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BOWERY_GIT_COMMIT"));

#[derive(Parser, Debug)]
#[command(
    version = WEB_VERSION,
    about = "The Bowery operator console, served to a browser",
    long_about = None
)]
struct Args {
    /// Path to the operator identity key.
    #[arg(long, default_value = "~/.bowery/operator.key")]
    operator_key: PathBuf,

    /// `host:port` of the relay agent to dial.
    #[arg(long)]
    agent_addr: String,

    /// Hex fingerprint of the relay agent.
    #[arg(long)]
    agent_fp: String,

    /// Base64 verifying key of the relay agent.
    #[arg(long)]
    agent_pubkey_b64: String,

    /// Mesh cluster id, needed to sign an alert silence.
    #[arg(long)]
    cluster_id: Option<String>,

    /// Per-query timeout. The agent enforces its own stricter cap.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    timeout: Duration,

    /// Address to serve the browser console on.
    ///
    /// Loopback by default, and deliberately: the listener is
    /// unauthenticated, and this process holds the operator key. See
    /// the module docs.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    /// Acknowledge serving an unauthenticated console on a routable
    /// address.
    ///
    /// Without this, a non-loopback `--listen` is refused rather than
    /// quietly obeyed. Anyone who can reach that port gets the fleet.
    #[arg(long)]
    i_understand_this_is_unauthenticated: bool,

    /// Operator-side alert archive. Defaults to `~/.bowery/alerts.db`.
    #[arg(long)]
    archive: Option<PathBuf>,
}

/// Expand a leading `~/`, which clap cannot do for us.
fn expand_home(p: PathBuf) -> Result<PathBuf> {
    let Ok(rest) = p.strip_prefix("~") else {
        return Ok(p);
    };
    let home = std::env::var_os("HOME").context("HOME is not set; pass an absolute path")?;
    Ok(PathBuf::from(home).join(rest))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bowery_web=info".into()),
        )
        .init();

    let args = Args::parse();

    // A routable bind is a different security boundary from loopback,
    // so it is opt-in rather than a flag you can pass by accident.
    if !args.listen.ip().is_loopback() && !args.i_understand_this_is_unauthenticated {
        anyhow::bail!(
            "refusing to serve an unauthenticated console on {} — anything that can reach \
             that port can query the fleet and push silences, because this process holds \
             the operator key. Use a loopback address (and an SSH tunnel to reach it \
             remotely), or pass --i-understand-this-is-unauthenticated if you really mean \
             it.",
            args.listen
        );
    }

    let addr: SocketAddr = args
        .agent_addr
        .parse()
        .with_context(|| format!("--agent-addr {} is not host:port", args.agent_addr))?;

    let archive_path = match args.archive {
        Some(p) => expand_home(p)?,
        None => bowery_cli::archive::default_path()?,
    };

    let relay = Arc::new(Relay {
        operator_key: expand_home(args.operator_key)?,
        addr,
        fp_hex: args.agent_fp,
        pubkey_b64: args.agent_pubkey_b64,
        cluster_id: args.cluster_id,
        timeout: args.timeout,
        archive_path,
        version: WEB_VERSION,
    });

    let app = api::router(relay.clone());
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;

    if args.listen.ip().is_loopback() {
        info!(listen = %args.listen, relay = %relay.addr, "bowery-web ready");
    } else {
        warn!(
            listen = %args.listen,
            "serving an UNAUTHENTICATED console on a routable address; everything that \
             can reach this port holds the operator's authority"
        );
    }
    println!("The Bowery — browser console on http://{}", args.listen);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutting down");
        })
        .await
        .context("serving")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A routable bind is refused unless it was asked for.
    ///
    /// The listener has no authentication at all, and this process can
    /// sign silences for the whole cluster. Binding it to 0.0.0.0 by
    /// typo should not be possible.
    #[test]
    fn the_guard_only_lets_loopback_through_silently() {
        let loopback: SocketAddr = "127.0.0.1:8787".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:8787".parse().unwrap();
        let lan: SocketAddr = "192.168.1.10:8787".parse().unwrap();
        assert!(loopback.ip().is_loopback());
        assert!(!any.ip().is_loopback(), "0.0.0.0 must need the flag");
        assert!(!lan.ip().is_loopback(), "a LAN address must need the flag");
        let v6: SocketAddr = "[::1]:8787".parse().unwrap();
        assert!(v6.ip().is_loopback(), "v6 loopback is loopback too");
    }

    #[test]
    fn a_tilde_path_expands_and_an_absolute_one_is_untouched() {
        // Reads $HOME rather than setting it: `set_var` is unsafe in
        // this edition, and the workspace denies unsafe outright.
        let home = std::env::var("HOME").expect("HOME is set in every environment we run in");
        assert_eq!(
            expand_home(PathBuf::from("~/.bowery/operator.key")).unwrap(),
            PathBuf::from(&home).join(".bowery/operator.key")
        );
        assert_eq!(
            expand_home(PathBuf::from("/etc/bowery/key")).unwrap(),
            PathBuf::from("/etc/bowery/key"),
            "an absolute path must be left alone"
        );
    }
}
