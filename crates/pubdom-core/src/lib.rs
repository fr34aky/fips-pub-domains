//! Policy core for resolving public domain names over fips.
//!
//! Everything here is pure: parsing of Nostr events and DNS records, the
//! verification precedence, pinning, and the synthesis of DNS answers. No
//! sockets, no clocks, no files except the pin store behind a trait. The
//! I/O adapters live in `pubdom-resolve`; the phone (fips2go) and the desktop
//! daemon plug their own transports into that crate and share this one.
//!
//! Spec: `docs/spec.md`.

pub mod cache;
pub mod claim;
pub mod domain;
pub mod identity;
pub mod pins;
pub mod policy;
pub mod synth;
pub mod txt;

pub use claim::{Attestation, Claim, Event, ZoneRecord};
pub use identity::Npub;
pub use pins::{Binding, MemoryPinStore, Method, PinStore};
pub use policy::{Decision, Outcome, PinChange, Reason, TxtLookup};

/// Nostr kinds. Placeholders until registered (spec §3, `docs/nip.md`).
pub const KIND_CLAIM: u16 = 37197;
pub const KIND_ATTESTATION: u16 = 37198;
pub const KIND_ZONE: u16 = 37199;

/// The DNS name under a domain that carries the verifier record (spec §4).
pub const TXT_LABEL: &str = "_fips-dns";

/// Service name in the claim's `service` tag and default port of the
/// domain's fips DNS server (spec §6.1).
pub const SERVICE_DNS: &str = "fips-dns";
pub const DEFAULT_SERVER_PORT: u16 = 5355;

/// Events dated further in the future than this are ignored (spec §8).
pub const MAX_FUTURE_SECS: u64 = 600;

/// How old a witness's verification may be and still count (spec §3.2):
/// a decommissioned witness's last word must not bind a retired server
/// forever. Witnesses re-attest daily; a month covers a long outage.
pub const ATTESTATION_MAX_AGE_SECS: u64 = 30 * 86_400;

/// TTL of answers synthesized for applications (spec §7).
pub const ANSWER_TTL_SECS: u32 = 30;

/// TTL imposed on a legacy answer handed out because the lookup overran its
/// budget (docs/architecture.md, budgets). The lookup finishes in the
/// background and caches its decision; the application's resolver must ask
/// again soon rather than keep the legacy address for the upstream's TTL
/// (a parked wildcard's 300 s was enough to look like "always legacy").
pub const OVERRUN_TTL_SECS: u32 = 5;

/// The TTL cap a host puts on the legacy answer for a name that is over
/// fips but whose servers are unreachable right now (the resolver's
/// `Unavailable { retry_in }`): until the next attempt, and at least
/// [`OVERRUN_TTL_SECS`]. One definition for every host, so the daemon and
/// the phone cap alike.
pub fn unavailable_ttl(retry_in: std::time::Duration) -> u32 {
    u32::try_from(retry_in.as_secs())
        .unwrap_or(u32::MAX)
        .max(OVERRUN_TTL_SECS)
}
