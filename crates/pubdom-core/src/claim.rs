//! Nostr events of this protocol (spec §3, `docs/nip.md`): the claim
//! (kind 37197) and the zone record (kind 37199), parsed from a transport-
//! neutral [`Event`]. Signature checking is the relay client's job
//! (nostr-sdk verifies on receipt); here we only trust `pubkey`.

use crate::domain::{is_claimable, is_valid_zone_label, normalize};
use crate::identity::Npub;
use crate::{DEFAULT_SERVER_PORT, KIND_CLAIM, KIND_ZONE, SERVICE_DNS};
use serde::{Deserialize, Serialize};

/// The parts of a Nostr event this crate looks at. `pubdom-resolve` converts
/// from `nostr::Event`; tests build it directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub kind: u16,
    /// Author, 64 hex characters.
    pub pubkey: String,
    pub created_at: u64,
    pub tags: Vec<Vec<String>>,
}

/// Limits enforced before anything is cached (spec §8).
pub const MAX_TAGS: usize = 300;
pub const MAX_ZONE_NAMES: usize = 256;
pub const MAX_DNSSEC_B64: usize = 16 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClaimError {
    #[error("kind {0} is not a claim")]
    Kind(u16),
    #[error("invalid author pubkey")]
    Author,
    #[error("missing or invalid d tag")]
    Domain,
    #[error("d is a public suffix or not registrable")]
    PublicSuffix,
    #[error("no usable service tag")]
    Service,
    #[error("too many tags")]
    TooLarge,
}

/// Kind 37197: "`author` serves `domain`'s fips DNS on `port`".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub author: Npub,
    pub domain: String,
    pub port: u16,
    pub created_at: u64,
    /// The `dnssec` tag verbatim (base64 RFC 9102 chain), verified in phase 2.
    pub dnssec: Option<String>,
}

impl Claim {
    pub fn parse(ev: &Event) -> Result<Self, ClaimError> {
        if ev.kind != KIND_CLAIM {
            return Err(ClaimError::Kind(ev.kind));
        }
        if ev.tags.len() > MAX_TAGS {
            return Err(ClaimError::TooLarge);
        }
        let author = Npub::from_hex(&ev.pubkey).map_err(|_| ClaimError::Author)?;
        let d = tag_value(&ev.tags, "d").ok_or(ClaimError::Domain)?;
        let domain = normalize(d).ok_or(ClaimError::Domain)?;
        if domain != d {
            // `d` must already be canonical: lowercase, no trailing dot.
            return Err(ClaimError::Domain);
        }
        if !is_claimable(&domain) {
            return Err(ClaimError::PublicSuffix);
        }
        let port = ev
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "service" && t[1] == SERVICE_DNS)
            .map(|t| match t.get(2) {
                Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0),
                None => Some(DEFAULT_SERVER_PORT),
            })
            .next()
            .ok_or(ClaimError::Service)?
            .ok_or(ClaimError::Service)?;
        let dnssec = tag_value(&ev.tags, "dnssec")
            .filter(|s| !s.is_empty() && s.len() <= MAX_DNSSEC_B64)
            .map(str::to_owned);
        Ok(Self {
            author,
            domain,
            port,
            created_at: ev.created_at,
            dnssec,
        })
    }

    /// The tags of a claim for `domain` — what the server publishes.
    pub fn tags(domain: &str, port: u16, dnssec: Option<&str>) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["d".into(), domain.into()],
            vec!["service".into(), SERVICE_DNS.into(), port.to_string()],
        ];
        if let Some(chain) = dnssec {
            tags.push(vec!["dnssec".into(), chain.into()]);
        }
        tags
    }
}

/// What a zone maps a label to (spec §3.3, §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// Served by this node.
    Node(Npub),
    /// The author itself (`self` in the event, the common single-node case).
    Author,
    /// Explicitly not over fips, even under a wildcard (`legacy`).
    Legacy,
}

/// Kind 37199: the names under a domain, for resolving while the server
/// itself is unreachable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRecord {
    pub author: Npub,
    pub domain: String,
    pub created_at: u64,
    /// (label, target); label `*` is the wildcard, `@` the apex.
    pub names: Vec<(String, Target)>,
}

impl ZoneRecord {
    pub fn parse(ev: &Event) -> Result<Self, ClaimError> {
        if ev.kind != KIND_ZONE {
            return Err(ClaimError::Kind(ev.kind));
        }
        if ev.tags.len() > MAX_TAGS {
            return Err(ClaimError::TooLarge);
        }
        let author = Npub::from_hex(&ev.pubkey).map_err(|_| ClaimError::Author)?;
        let d = tag_value(&ev.tags, "d").ok_or(ClaimError::Domain)?;
        let domain = normalize(d).ok_or(ClaimError::Domain)?;
        if domain != d || !is_claimable(&domain) {
            return Err(ClaimError::PublicSuffix);
        }
        let mut names = Vec::new();
        for t in ev.tags.iter().filter(|t| t.len() == 3 && t[0] == "name") {
            let label = t[1].to_ascii_lowercase();
            if label != "@" && !is_valid_zone_label(&label) {
                continue; // one bad label does not poison the zone
            }
            let target = match t[2].as_str() {
                "self" => Target::Author,
                "legacy" => Target::Legacy,
                s => match Npub::parse_any(s) {
                    Ok(n) => Target::Node(n),
                    Err(_) => continue,
                },
            };
            names.push((label, target));
            if names.len() > MAX_ZONE_NAMES {
                return Err(ClaimError::TooLarge);
            }
        }
        Ok(Self {
            author,
            domain,
            created_at: ev.created_at,
            names,
        })
    }

    /// Resolve `label` (relative, see `domain::relative_label`) to a node,
    /// applying the wildcard. `None` = not over fips.
    pub fn lookup(&self, label: &str) -> Option<Npub> {
        let exact = self.names.iter().find(|(l, _)| l == label);
        let entry = exact.or_else(|| self.names.iter().find(|(l, _)| l == "*"))?;
        match &entry.1 {
            Target::Node(n) => Some(*n),
            Target::Author => Some(self.author),
            Target::Legacy => None,
        }
    }
}

fn tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const DEMO_HEX: &str =
        "e138b9afc2f1f3e18646ab576dc15cb261ab580f4e720ed240ffe64fec619581";

    pub(crate) fn claim_event(domain: &str, port: &str) -> Event {
        Event {
            kind: KIND_CLAIM,
            pubkey: DEMO_HEX.into(),
            created_at: 1_790_000_000,
            tags: vec![
                vec!["d".into(), domain.into()],
                vec!["service".into(), "fips-dns".into(), port.into()],
            ],
        }
    }

    #[test]
    fn parses_a_claim() {
        let c = Claim::parse(&claim_event("example.org", "5355")).unwrap();
        assert_eq!(c.domain, "example.org");
        assert_eq!(c.port, 5355);
        assert_eq!(c.author.to_hex(), DEMO_HEX);
        assert_eq!(c.dnssec, None);
        assert_eq!(
            Claim::tags("example.org", 5355, None),
            claim_event("example.org", "5355").tags
        );
    }

    #[test]
    fn rejects_bad_claims() {
        let mut e = claim_event("example.org", "5355");
        e.kind = 1;
        assert_eq!(Claim::parse(&e).unwrap_err(), ClaimError::Kind(1));
        assert_eq!(
            Claim::parse(&claim_event("ch", "5355")).unwrap_err(),
            ClaimError::PublicSuffix
        );
        assert_eq!(
            Claim::parse(&claim_event("Example.org", "5355")).unwrap_err(),
            ClaimError::Domain
        );
        assert_eq!(
            Claim::parse(&claim_event("example.org.", "5355")).unwrap_err(),
            ClaimError::Domain
        );
        assert_eq!(
            Claim::parse(&claim_event("example.org", "0")).unwrap_err(),
            ClaimError::Service
        );
        let mut e = claim_event("example.org", "5355");
        e.tags[1][1] = "fips-http".into();
        assert_eq!(Claim::parse(&e).unwrap_err(), ClaimError::Service);
        let mut e = claim_event("example.org", "5355");
        e.pubkey = "zz".into();
        assert_eq!(Claim::parse(&e).unwrap_err(), ClaimError::Author);
        let mut e = claim_event("example.org", "5355");
        e.tags
            .extend(std::iter::repeat_n(vec!["x".to_string()], MAX_TAGS));
        assert_eq!(Claim::parse(&e).unwrap_err(), ClaimError::TooLarge);
    }

    #[test]
    fn service_without_port_means_default() {
        let mut e = claim_event("example.org", "5355");
        e.tags[1].pop();
        assert_eq!(Claim::parse(&e).unwrap().port, DEFAULT_SERVER_PORT);
    }

    #[test]
    fn zone_record_lookup_with_wildcard_self_and_legacy() {
        let other = Npub::from_bytes([9u8; 32]);
        let ev = Event {
            kind: KIND_ZONE,
            pubkey: DEMO_HEX.into(),
            created_at: 1,
            tags: vec![
                vec!["d".into(), "example.org".into()],
                vec!["name".into(), "WWW".into(), "legacy".into()],
                vec!["name".into(), "git".into(), other.to_string()],
                vec!["name".into(), "bad label!".into(), "self".into()],
                vec!["name".into(), "*".into(), "self".into()],
            ],
        };
        let z = ZoneRecord::parse(&ev).unwrap();
        assert_eq!(z.names.len(), 3);
        assert_eq!(z.lookup("www"), None, "legacy beats the wildcard");
        assert_eq!(z.lookup("git"), Some(other));
        assert_eq!(z.lookup("anything"), Some(z.author));
        assert_eq!(z.lookup("@"), Some(z.author));
    }
}
