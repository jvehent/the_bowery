//! `:command` palette — the keyboard-driven actions that aren't
//! tied to a particular pane. Modeled on vim/Helix.
//!
//! C-2 ships a small set:
//!
//! - `:connect <fp> [<host:port>]` — switch the current relay.
//! - `:quit` — exit cleanly.
//!
//! Future slices add `:export`, `:reload-peers`, `:doctor remote`,
//! `:save query <name>`, etc.

#[derive(Debug, Clone)]
pub(crate) enum PaletteCommand {
    Connect {
        target: String,
        addr: Option<String>,
    },
    Quit,
    /// `:peers add <name> <fp_hex> <pubkey_b64>`
    PeersAdd {
        name: String,
        fp: String,
        pubkey_b64: String,
    },
    /// `:peers remove <fp_hex>`
    PeersRemove {
        fp: String,
    },
    /// `:peers reload` — re-read `~/.bowery/peers.toml` from disk.
    PeersReload,
    /// `:export query <path>` — dump the Query pane's last result
    /// to `<path>` as one JSON object per row.
    ExportQuery {
        path: String,
    },
}

impl PaletteCommand {
    pub(crate) fn parse(line: &str) -> Result<Self, String> {
        let trimmed = line.trim_start_matches(':').trim();
        let mut parts = trimmed.split_whitespace();
        let head = parts.next().unwrap_or("");
        match head {
            "connect" => {
                let target = parts
                    .next()
                    .ok_or_else(|| "usage: :connect <fp_hex> [<host:port>]".to_string())?
                    .to_string();
                let addr = parts.next().map(str::to_string);
                Ok(Self::Connect { target, addr })
            }
            "quit" | "q" => Ok(Self::Quit),
            "peers" => {
                let sub = parts
                    .next()
                    .ok_or_else(|| "usage: :peers {add|remove|reload}".to_string())?;
                match sub {
                    "reload" => Ok(Self::PeersReload),
                    "add" => {
                        let name = parts
                            .next()
                            .ok_or_else(|| {
                                "usage: :peers add <name> <fp> <pubkey_b64>".to_string()
                            })?
                            .to_string();
                        let fp = parts
                            .next()
                            .ok_or_else(|| {
                                "usage: :peers add <name> <fp> <pubkey_b64>".to_string()
                            })?
                            .to_string();
                        let pubkey_b64 = parts
                            .next()
                            .ok_or_else(|| {
                                "usage: :peers add <name> <fp> <pubkey_b64>".to_string()
                            })?
                            .to_string();
                        Ok(Self::PeersAdd {
                            name,
                            fp,
                            pubkey_b64,
                        })
                    }
                    "remove" => {
                        let fp = parts
                            .next()
                            .ok_or_else(|| "usage: :peers remove <fp>".to_string())?
                            .to_string();
                        Ok(Self::PeersRemove { fp })
                    }
                    other => Err(format!("unknown :peers verb: {other}")),
                }
            }
            "export" => {
                let what = parts
                    .next()
                    .ok_or_else(|| "usage: :export query <path>".to_string())?;
                if what != "query" {
                    return Err(format!("unknown :export target: {what}"));
                }
                let path = parts
                    .next()
                    .ok_or_else(|| "usage: :export query <path>".to_string())?
                    .to_string();
                Ok(Self::ExportQuery { path })
            }
            other => Err(format!("unknown command: :{other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quit() {
        assert!(matches!(
            PaletteCommand::parse(":quit").unwrap(),
            PaletteCommand::Quit
        ));
        assert!(matches!(
            PaletteCommand::parse("q").unwrap(),
            PaletteCommand::Quit
        ));
    }

    #[test]
    fn parse_connect_with_addr() {
        let cmd = PaletteCommand::parse(":connect ab12 10.0.0.5:9902").unwrap();
        match cmd {
            PaletteCommand::Connect { target, addr } => {
                assert_eq!(target, "ab12");
                assert_eq!(addr, Some("10.0.0.5:9902".into()));
            }
            other => panic!("expected connect, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown() {
        let err = PaletteCommand::parse(":xyz").unwrap_err();
        assert!(err.contains("unknown command"));
    }
}
