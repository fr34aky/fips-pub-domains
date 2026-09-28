//! Client I/O for fips-pubdom: everything `pubdom-core` deliberately does not
//! do. Three adapters and the orchestration that ties them to the policy:
//!
//! - [`mesh`]: step 3 over the mesh, behind [`MeshDns`] — the desktop uses a
//!   kernel socket, the phone plugs in its smoltcp stack.
//! - [`txt`]: the legacy `_fips-dns` TXT lookup over hickory, one resolver
//!   per upstream so that agreement between them can be counted.
//! - [`relay`]: claims from Nostr relays (public and mesh), and publishing.
//! - [`pins`]: the JSON pin file shared by every platform.
//! - [`resolver`]: `lookup(query) → answer | passthrough | fail`.
//!
//! No `cfg(target_os)` here (docs/platforms.md).

pub mod config;
pub mod mesh;
pub mod pins;
pub mod relay;
pub mod resolver;
pub mod txt;

pub use config::{Config, ProdResolver};
pub use mesh::{KernelMeshDns, MeshDns};
pub use pins::FilePinStore;
pub use relay::RelayClient;
pub use resolver::{LookupResult, Resolver, ResolverConfig};
pub use txt::TxtVerifier;

/// Unix seconds now — the one clock this crate reads.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// After a failed `recv_from`/`accept` in a serving loop: a per-peer error
/// (a reset, an aborted handshake — Windows reports a closed client port on
/// the next UDP receive) is retried at once; anything else (EMFILE, a
/// vanished interface) is likely to persist, so the loop pauses instead of
/// spinning.
pub async fn after_socket_error(e: &std::io::Error, what: &str) {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted | ConnectionRefused | Interrupted | WouldBlock
        | TimedOut => tracing::debug!(error = %e, "{what} failed"),
        _ => {
            tracing::warn!(error = %e, "{what} failed");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
