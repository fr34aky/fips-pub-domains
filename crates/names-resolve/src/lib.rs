//! Client I/O for fips-names: everything `names-core` deliberately does not
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
//! No `cfg(target_os)` here (docs/plan-platforms.md §1).

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
