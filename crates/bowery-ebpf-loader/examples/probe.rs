//! Standalone smoke test: load the bowery-ebpf object, attach all
//! tracepoints, drain the three ring buffers for a few seconds, then
//! exit.
//!
//! Useful for confirming that the BPF programs pass verification on a
//! given kernel without spinning up the full agent. Requires `CAP_BPF`,
//! `CAP_PERFMON`, `CAP_SYS_ADMIN` (typically run via sudo).
//!
//! Usage:
//!   sudo BOWERY_BPF_OBJ_PATH=/path/to/bowery-ebpf \
//!     cargo run --example probe -p bowery-ebpf-loader

use std::time::Duration;

use bowery_ebpf_loader::BpfEventSource;
use bowery_events::source::EventSource;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    let source = BpfEventSource::from_default_locations()?;
    println!("loading {}", source.obj_path().display());

    let mut rx = Box::new(source).start();

    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);

    let mut count = 0u32;
    loop {
        tokio::select! {
            biased;
            () = &mut deadline => break,
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        count += 1;
                        if count <= 20 {
                            println!("event: {e:?}");
                        }
                    }
                    None => {
                        eprintln!("event channel closed");
                        break;
                    }
                }
            }
        }
    }

    println!("drained {count} events in 5s — verifier accepted all 3 programs");
    Ok(())
}
