//! Bindings and the pin store (spec §5.4, §8 rollback).
//!
//! A binding is `domain → server npub:port`, tagged with how it was verified
//! and when. The store also remembers the newest `created_at` seen per
//! (kind, author, domain) so a relay cannot roll an event back.
//!
//! The trait is synchronous on purpose: the phone's DNS proxy is a blocking
//! per-query thread, and the daemon can afford a short lock. Implementations
//! with real files live in `pubdom-resolve`; [`MemoryPinStore`] is for tests
//! and as the in-memory layer of a file store.

use crate::identity::Npub;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// How a binding was verified, weakest first. A pinned binding is replaced
/// only by a verification of equal or stronger method (spec §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    /// Used with the explicit "unverified" marker only; never pinned.
    Unverified,
    /// At least *k* trusted witnesses attested it (phase 3).
    Attested,
    /// Unsigned DNS answer from a single resolver (phones often have one).
    DnsSingle,
    /// Unsigned DNS, two or more independent resolvers agreed.
    Dns,
    /// DNSSEC-validated — by this node, or from the proof in the claim.
    Dnssec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub domain: String,
    pub npub: Npub,
    pub port: u16,
    pub method: Method,
    /// Unix seconds of the verification this binding rests on.
    pub verified_at: u64,
}

impl Binding {
    pub fn server_addr(&self) -> std::net::SocketAddrV6 {
        std::net::SocketAddrV6::new(self.npub.fips_address(), self.port, 0, 0)
    }
}

/// Key of the anti-rollback table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SeenKey {
    pub kind: u16,
    pub author: Npub,
    pub domain: String,
}

pub trait PinStore: Send + Sync {
    fn get(&self, domain: &str) -> Option<Binding>;
    /// Returns whether anything changed (a file store saves only then).
    fn put(&self, binding: Binding) -> bool;
    fn forget(&self, domain: &str) -> bool;
    fn list(&self) -> Vec<Binding>;
    /// Newest `created_at` seen for this (kind, author, domain).
    fn newest_seen(&self, key: &SeenKey) -> Option<u64>;
    /// Record `created_at` if newer than what was seen; whether it was.
    fn note_seen(&self, key: SeenKey, created_at: u64) -> bool;
}

/// Serializable snapshot of a store — the on-disk shape shared by every
/// platform (docs/platforms.md), so pins can be copied between
/// machines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinSnapshot {
    #[serde(default)]
    pub pins: Vec<Binding>,
    #[serde(default)]
    pub seen: Vec<(SeenKey, u64)>,
}

#[derive(Default)]
pub struct MemoryPinStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    pins: HashMap<String, Binding>,
    seen: HashMap<SeenKey, u64>,
}

impl MemoryPinStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snap: PinSnapshot) -> Self {
        let inner = Inner {
            pins: snap
                .pins
                .into_iter()
                .map(|b| (b.domain.clone(), b))
                .collect(),
            seen: snap.seen.into_iter().collect(),
        };
        Self {
            inner: Mutex::new(inner),
        }
    }

    pub fn snapshot(&self) -> PinSnapshot {
        let g = self.inner.lock().unwrap();
        let mut pins: Vec<Binding> = g.pins.values().cloned().collect();
        pins.sort_by(|a, b| a.domain.cmp(&b.domain));
        let mut seen: Vec<(SeenKey, u64)> = g.seen.iter().map(|(k, v)| (k.clone(), *v)).collect();
        seen.sort_by(|a, b| {
            (&a.0.domain, a.0.kind, &a.0.author).cmp(&(&b.0.domain, b.0.kind, &b.0.author))
        });
        PinSnapshot { pins, seen }
    }
}

impl PinStore for MemoryPinStore {
    fn get(&self, domain: &str) -> Option<Binding> {
        self.inner.lock().unwrap().pins.get(domain).cloned()
    }

    fn put(&self, binding: Binding) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.pins.get(&binding.domain) == Some(&binding) {
            return false;
        }
        g.pins.insert(binding.domain.clone(), binding);
        true
    }

    fn forget(&self, domain: &str) -> bool {
        self.inner.lock().unwrap().pins.remove(domain).is_some()
    }

    fn list(&self) -> Vec<Binding> {
        self.snapshot().pins
    }

    fn newest_seen(&self, key: &SeenKey) -> Option<u64> {
        self.inner.lock().unwrap().seen.get(key).copied()
    }

    fn note_seen(&self, key: SeenKey, created_at: u64) -> bool {
        let mut g = self.inner.lock().unwrap();
        let e = g.seen.entry(key).or_insert(0);
        if created_at > *e {
            *e = created_at;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(domain: &str, method: Method) -> Binding {
        Binding {
            domain: domain.into(),
            npub: Npub::from_bytes([1; 32]),
            port: 5355,
            method,
            verified_at: 10,
        }
    }

    #[test]
    fn methods_order_by_strength() {
        assert!(Method::Dnssec > Method::Dns);
        assert!(Method::Dns > Method::DnsSingle);
        assert!(Method::DnsSingle > Method::Attested);
        assert!(Method::Attested > Method::Unverified);
    }

    #[test]
    fn store_round_trips_through_snapshot() {
        let s = MemoryPinStore::new();
        s.put(b("example.org", Method::Dnssec));
        let key = SeenKey {
            kind: 37197,
            author: Npub::from_bytes([1; 32]),
            domain: "example.org".into(),
        };
        assert!(s.note_seen(key.clone(), 5));
        assert!(!s.note_seen(key.clone(), 3), "only moves forward");
        assert_eq!(s.newest_seen(&key), Some(5));
        assert!(
            !s.put(b("example.org", Method::Dnssec)),
            "unchanged pin reports no change"
        );
        let snap = s.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: PinSnapshot = serde_json::from_str(&json).unwrap();
        let s2 = MemoryPinStore::from_snapshot(back);
        assert_eq!(
            s2.get("example.org"),
            Some(b("example.org", Method::Dnssec))
        );
        assert_eq!(s2.newest_seen(&key), Some(5));
        s2.forget("example.org");
        assert!(s2.list().is_empty());
        assert!(json.contains("\"dnssec\""), "kebab-case methods on disk");
    }

    #[test]
    fn server_addr_is_the_fips_address() {
        let x = b("example.org", Method::Dns);
        assert_eq!(x.server_addr().ip(), &x.npub.fips_address());
        assert_eq!(x.server_addr().port(), 5355);
    }
}
