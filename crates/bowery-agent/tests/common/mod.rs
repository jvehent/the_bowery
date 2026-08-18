//! Shared fixtures for the agent's integration tests.
//!
//! Included per test binary rather than linked, so each one sees only
//! what it uses; hence the `dead_code`/`unreachable_pub` allowances.
//!
//! Every test here starts a real agent, which binds a real gossip socket.
//! Handing out ports for that turned out to be worth doing once, and
//! carefully — see [`reserve_udp_port`].

#![allow(unreachable_pub)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};

/// `127.0.0.1:0` — an address the OS is free to complete.
#[allow(dead_code)]
pub fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// Ports are handed out from this base upward.
///
/// Above the usual privileged and service ranges, and below the default
/// Linux ephemeral range (32768+) so the kernel's own allocations for
/// unrelated sockets do not land on top of ours.
const PORT_BASE: u16 = 20_000;
/// How many ports one test process may use.
const SLICE_WIDTH: u16 = 400;
/// How many disjoint slices exist. `SLICES * SLICE_WIDTH` must stay
/// below the ephemeral range.
const SLICES: u16 = 30;

/// Where this process's slice starts. Keyed on the pid so two test
/// binaries running at once cannot draw the same port.
fn slice_base() -> u16 {
    #[allow(clippy::cast_possible_truncation)]
    let slice = (std::process::id() % u32::from(SLICES)) as u16;
    PORT_BASE + slice * SLICE_WIDTH
}

/// Next offset within this process's slice.
static NEXT_OFFSET: AtomicU16 = AtomicU16::new(0);

/// A UDP port for an agent's gossip socket.
///
/// The obvious implementation — bind `:0`, read the port, drop the
/// socket — hands the OS back a port that anything may take before the
/// agent binds it. That race failed `cargo test --workspace` roughly one
/// run in three, always as `failed to bind to 127.0.0.1:NNNNN/UDP for
/// gossip`, and never when the same test ran alone: a dozen test
/// binaries start agents at the same moment, and the window is the few
/// milliseconds between reserving and starting.
///
/// The window cannot be closed while the port is handed over as a
/// number, so this removes the *collisions* instead. Each test process
/// draws from its own slice of the port range, keyed on its pid, and
/// each call within a process takes the next offset in that slice. The
/// binaries that were colliding therefore cannot; the bind below is what
/// skips a port some unrelated process already holds.
#[allow(dead_code)]
pub fn reserve_udp_port() -> SocketAddr {
    let base = slice_base();
    for _ in 0..SLICE_WIDTH {
        let offset = NEXT_OFFSET.fetch_add(1, Ordering::Relaxed) % SLICE_WIDTH;
        let port = base + offset;
        // Bound and dropped purely to prove the port is free right now.
        // Nothing else in this process will ask for it again until the
        // counter wraps, by which time the agent holds it.
        if let Ok(sock) = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            return sock.local_addr().expect("local_addr");
        }
    }
    panic!("no free UDP port in this process's slice starting at {base}");
}
