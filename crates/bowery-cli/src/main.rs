//! `bowery` — operator CLI for The Bowery.
//!
//! Phase 0 surface: identity-key management.
//! Phase 2.5 addition: `bowery doctor` host-readiness check.
//! Subsequent phases add `query`, `hunt`, `alerts tail`, `action ...`,
//! `authorization grant`, `model push`, etc.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use bowery_crypto::Identity;
use clap::{Parser, Subcommand};

mod doctor;

#[derive(Parser, Debug)]
#[command(
    name = "bowery",
    version,
    about = "The Bowery operator CLI",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage operator identity keys.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Check whether this host is ready to run a Bowery agent.
    ///
    /// Probes kernel version, BPF-LSM, BTF, bpffs, lsm= cmdline, and
    /// kernel config. Exit code is 0 when ready (warnings allowed) and 1
    /// when one or more checks fail.
    Doctor {
        /// Emit results as JSON instead of human-readable.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum KeyCommand {
    /// Generate a new operator identity key and write it to the given path.
    Generate {
        /// Path to write the new key. Refuses to overwrite an existing file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the fingerprint of an identity key file.
    Fingerprint {
        /// Path to the key file.
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

impl Cli {
    fn run(self) -> Result<ExitCode> {
        match self.command {
            Command::Key(KeyCommand::Generate { out }) => {
                key_generate(&out)?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Key(KeyCommand::Fingerprint { path }) => {
                key_fingerprint(&path)?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Doctor { json } => doctor_cmd(json),
        }
    }
}

fn key_generate(path: &PathBuf) -> Result<()> {
    let identity = Identity::generate();
    identity
        .save(path)
        .with_context(|| format!("writing identity to {}", path.display()))?;
    println!("wrote identity to {}", path.display());
    println!("fingerprint: {}", identity.fingerprint());
    Ok(())
}

fn key_fingerprint(path: &PathBuf) -> Result<()> {
    let identity = Identity::load(path)
        .with_context(|| format!("loading identity from {}", path.display()))?;
    println!("{}", identity.fingerprint());
    Ok(())
}

fn doctor_cmd(json: bool) -> Result<ExitCode> {
    let report = doctor::run();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        doctor::print_human(&report);
    }
    Ok(match report.verdict {
        doctor::Verdict::Ready => ExitCode::SUCCESS,
        doctor::Verdict::NotReady => ExitCode::FAILURE,
    })
}
