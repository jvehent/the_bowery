//! `bowery` — operator CLI for The Bowery.
//!
//! Phase 0 surface: key management only (`bowery key generate`,
//! `bowery key fingerprint`). Subsequent phases add `query`, `hunt`,
//! `alerts tail`, `action ...`, `authorization grant`, `model push`, etc.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use bowery_crypto::Identity;
use clap::{Parser, Subcommand};

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
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

impl Cli {
    fn run(self) -> Result<()> {
        match self.command {
            Command::Key(KeyCommand::Generate { out }) => key_generate(&out),
            Command::Key(KeyCommand::Fingerprint { path }) => key_fingerprint(&path),
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
