//! Policy core for resolving public domain names over fips.
//!
//! Everything here is pure: parsing of Nostr events and DNS records, the
//! verification precedence, pinning, and the synthesis of DNS answers. No
//! sockets, no clocks, no files except the pin store behind a trait. The
//! I/O adapters live in `names-resolve`; the phone (fips2go) and the desktop
//! daemon plug their own transports into that crate and share this one.
//!
//! Spec: `docs/domain-binding.md`.

pub mod cache;
pub mod claim;
pub mod domain;
pub mod identity;
pub mod pins;
pub mod policy;
pub mod synth;
pub mod txt;

pub use claim::{Claim, Event, ZoneRecord};
pub use identity::Npub;
pub use pins::{Binding, MemoryPinStore, Method, PinStore};
pub use policy::{Decision, Outcome, PinUpdate, Reason, TxtLookup};

/// Nostr kinds. Placeholders until registered (spec §3, `docs/nip-draft.md`).
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

/// TTL of answers synthesized for applications (spec §7).
pub const ANSWER_TTL_SECS: u32 = 30;
