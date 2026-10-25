//! Nostr events of this protocol (spec §3, `docs/nip.md`): the claim
//! (kind 37197), the attestation (37198) and the zone record (37199),
//! parsed from a transport-neutral [`Event`]. Signature checking is the
//! relay client's job (nostr-sdk verifies on receipt); here we only trust
//! `pubkey`.
//!
//! A claim binds its author to a domain in a *role* named by its `service`
//! tag. [`Claim`] is the `fips-dns` role this crate resolves; the generic
//! [`ServiceClaim`] is for the other roles the same verification covers
//! (`fips-ca`, the certificate issuer of fips-pub-pki).

use crate::domain::{is_claimable, is_valid_zone_label, normalize};
use crate::identity::Npub;
use crate::pins::Method;
use crate::{DEFAULT_SERVER_PORT, KIND_ATTESTATION, KIND_CLAIM, KIND_ZONE, SERVICE_DNS};
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
    #[error("missing or invalid p tag")]
    Server,
    #[error("method is neither dnssec nor dns")]
    Method,
    #[error("missing or invalid verified_at tag")]
    VerifiedAt,
}

/// Kind 37197 for any role: "`author` plays `service` for `domain`"
/// (spec §3.1). The port is present for a service that listens somewhere
/// (`fips-dns`) and absent for a role that does not (`fips-ca`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceClaim {
    pub author: Npub,
    pub domain: String,
    pub service: String,
    pub port: Option<u16>,
    pub created_at: u64,
    /// The `dnssec` tag for this role, verbatim (base64 RFC 9102 chain for
    /// the `_<service>.<domain>` TXT RRset), verified in phase 2. A chain
    /// proves one record, so a claim carries one tag per role it wants
    /// proven; the tag's third element names the role, absent meaning
    /// `fips-dns`.
    pub dnssec: Option<String>,
}

impl ServiceClaim {
    /// The claim's `service` tag for `service`, or `ClaimError::Service`
    /// when the event carries none for it (a claim may carry several, one
    /// per role the author plays). A port given but unusable (`0`, not a
    /// number) is the same error: a broken tag must not pass as "no port".
    /// The `dnssec` tag taken is the one for this role; another role's
    /// chain could only fail to verify, so it is not offered.
    pub fn parse(ev: &Event, service: &str) -> Result<Self, ClaimError> {
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
        let tag = ev
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "service" && t[1] == service)
            .ok_or(ClaimError::Service)?;
        let port = match tag.get(2) {
            Some(p) => Some(
                p.parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or(ClaimError::Service)?,
            ),
            None => None,
        };
        let dnssec = ev
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "dnssec")
            .find(|t| role_of(t) == service)
            .map(|t| t[1].as_str())
            .filter(|s| !s.is_empty() && s.len() <= MAX_DNSSEC_B64)
            .map(str::to_owned);
        Ok(Self {
            author,
            domain,
            service: service.to_string(),
            port,
            created_at: ev.created_at,
            dnssec,
        })
    }

    /// The tags of a claim for `domain` in the role `service` — what the
    /// author publishes. `port` for a service that listens.
    pub fn tags(
        domain: &str,
        service: &str,
        port: Option<u16>,
        dnssec: Option<&str>,
    ) -> Vec<Vec<String>> {
        let mut service_tag = vec!["service".to_string(), service.to_string()];
        if let Some(p) = port {
            service_tag.push(p.to_string());
        }
        let mut tags = vec![vec!["d".into(), domain.into()], service_tag];
        if let Some(chain) = dnssec {
            let mut tag = vec!["dnssec".to_string(), chain.to_string()];
            if service != SERVICE_DNS {
                tag.push(service.to_string());
            }
            tags.push(tag);
        }
        tags
    }
}

/// The role a `p` or `dnssec` tag's optional third element names; absent
/// or empty, `fips-dns` — the tags as published before roles existed.
fn role_of(tag: &[String]) -> &str {
    match tag.get(2).map(String::as_str) {
        Some("") | None => SERVICE_DNS,
        Some(role) => role,
    }
}

/// Kind 37197: "`author` serves `domain`'s fips DNS on `port`" — the
/// `fips-dns` role of [`ServiceClaim`], port defaulting to 5355.
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
        let c = ServiceClaim::parse(ev, SERVICE_DNS)?;
        Ok(Self {
            author: c.author,
            domain: c.domain,
            port: c.port.unwrap_or(DEFAULT_SERVER_PORT),
            created_at: c.created_at,
            dnssec: c.dnssec,
        })
    }

    /// The tags of a claim for `domain` — what the server publishes.
    pub fn tags(domain: &str, port: u16, dnssec: Option<&str>) -> Vec<Vec<String>> {
        ServiceClaim::tags(domain, SERVICE_DNS, Some(port), dnssec)
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

    /// The tags of a zone record for `domain` — what the server publishes.
    /// `names` are (label, target) as in [`ZoneRecord::names`].
    pub fn tags(domain: &str, names: &[(String, Target)]) -> Vec<Vec<String>> {
        let mut tags = vec![vec!["d".into(), domain.into()]];
        for (label, target) in names {
            let value = match target {
                Target::Node(n) => n.to_string(),
                Target::Author => "self".into(),
                Target::Legacy => "legacy".into(),
            };
            tags.push(vec!["name".into(), label.clone(), value]);
        }
        tags
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

/// Kind 37198: "`witness` verified, while online, that `servers` serve
/// `domain`" (spec §3.2). Worth only the trust the reader places in the
/// witness: the resolver reads attestations from its configured witnesses
/// and from nobody else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub witness: Npub,
    pub domain: String,
    /// The servers the witness verified, one `p` tag each; a witness that
    /// verified a domain with redundant servers names them all. A `p` tag's
    /// optional third element names the service the key was verified for;
    /// absent means `fips-dns`. Only those are servers.
    pub servers: Vec<Npub>,
    /// The `p` tags for other services, as (service, key): a witness has
    /// one attestation per domain (addressable by `d`), so whoever
    /// re-publishes it for one service must carry the others along or
    /// erase them. The resolver ignores these.
    pub others: Vec<(String, Npub)>,
    /// How the witness verified: `Dnssec` or `Dns` (several resolvers). A
    /// single resolver's say is not worth attesting.
    pub method: Method,
    /// The witness's own verification time; `created_at` is the event's.
    pub verified_at: u64,
    pub created_at: u64,
}

impl Attestation {
    pub fn parse(ev: &Event) -> Result<Self, ClaimError> {
        if ev.kind != KIND_ATTESTATION {
            return Err(ClaimError::Kind(ev.kind));
        }
        if ev.tags.len() > MAX_TAGS {
            return Err(ClaimError::TooLarge);
        }
        let witness = Npub::from_hex(&ev.pubkey).map_err(|_| ClaimError::Author)?;
        let d = tag_value(&ev.tags, "d").ok_or(ClaimError::Domain)?;
        let domain = normalize(d).ok_or(ClaimError::Domain)?;
        if domain != d {
            return Err(ClaimError::Domain);
        }
        if !is_claimable(&domain) {
            return Err(ClaimError::PublicSuffix);
        }
        let mut servers: Vec<Npub> = Vec::new();
        let mut others: Vec<(String, Npub)> = Vec::new();
        for t in ev.tags.iter().filter(|t| t.len() >= 2 && t[0] == "p") {
            let npub = Npub::from_hex(&t[1]).map_err(|_| ClaimError::Server)?;
            match role_of(t) {
                SERVICE_DNS => {
                    if !servers.contains(&npub) {
                        servers.push(npub);
                    }
                }
                service => {
                    let entry = (service.to_string(), npub);
                    if !others.contains(&entry) {
                        others.push(entry);
                    }
                }
            }
        }
        if servers.is_empty() && others.is_empty() {
            return Err(ClaimError::Server);
        }
        let method = match tag_value(&ev.tags, "method") {
            Some("dnssec") => Method::Dnssec,
            Some("dns") => Method::Dns,
            _ => return Err(ClaimError::Method),
        };
        let verified_at = tag_value(&ev.tags, "verified_at")
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(ClaimError::VerifiedAt)?;
        Ok(Self {
            witness,
            domain,
            servers,
            others,
            method,
            verified_at,
            created_at: ev.created_at,
        })
    }

    /// The tags of an attestation — what a witness publishes. `method`
    /// below `Dns` is written as `dns`; the publisher refuses it first
    /// (`pubdom_resolve::relay::publish_attestation`).
    pub fn tags(
        domain: &str,
        servers: &[Npub],
        method: Method,
        verified_at: u64,
    ) -> Vec<Vec<String>> {
        Self::tags_with(domain, servers, &[], method, verified_at)
    }

    /// [`Attestation::tags`] carrying `others` — the (service, key) entries
    /// of other services, kept from the witness's previous attestation so
    /// re-attesting the servers does not erase them. An entry whose
    /// service is `fips-dns` or empty *is* a server entry (that is how
    /// the parser reads it back) and is written as one, once.
    pub fn tags_with(
        domain: &str,
        servers: &[Npub],
        others: &[(String, Npub)],
        method: Method,
        verified_at: u64,
    ) -> Vec<Vec<String>> {
        let is_dns = |service: &String| service.is_empty() || service == SERVICE_DNS;
        let mut tags = vec![vec!["d".into(), domain.into()]];
        let mut written: Vec<Npub> = Vec::new();
        for s in servers.iter().chain(
            others
                .iter()
                .filter(|(service, _)| is_dns(service))
                .map(|(_, key)| key),
        ) {
            if !written.contains(s) {
                written.push(*s);
                tags.push(vec!["p".into(), s.to_hex()]);
            }
        }
        for (service, key) in others.iter().filter(|(service, _)| !is_dns(service)) {
            tags.push(vec!["p".into(), key.to_hex(), service.clone()]);
        }
        let method = match method {
            Method::Dnssec => "dnssec",
            _ => "dns",
        };
        tags.push(vec!["method".into(), method.into()]);
        tags.push(vec!["verified_at".into(), verified_at.to_string()]);
        tags
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
        assert_eq!(
            ServiceClaim::parse(&e, SERVICE_DNS).unwrap().port,
            None,
            "the generic claim reports what the tag says"
        );
    }

    #[test]
    fn a_role_without_a_port_parses_and_a_claim_may_carry_several() {
        // The issuer of fips-pub-pki: `service` with no port, and a
        // chain per role — each proves one record.
        let mut e = claim_event("example.org", "5355");
        e.tags
            .push(vec!["service".into(), crate::SERVICE_CA.into()]);
        e.tags.push(vec!["dnssec".into(), "AAAA".into()]);
        e.tags
            .push(vec!["dnssec".into(), "BBBB".into(), "fips-ca".into()]);
        let ca = ServiceClaim::parse(&e, crate::SERVICE_CA).unwrap();
        assert_eq!(
            (ca.service.as_str(), ca.port, ca.dnssec.as_deref()),
            ("fips-ca", None, Some("BBBB"))
        );
        assert_eq!(ca.author.to_hex(), DEMO_HEX);
        // The same event still is the DNS claim it was, with its own chain.
        let dns = Claim::parse(&e).unwrap();
        assert_eq!((dns.port, dns.dnssec.as_deref()), (5355, Some("AAAA")));
        // Tag order does not matter, and an explicit `fips-dns` third
        // element is the plain tag.
        e.tags.swap(3, 4);
        e.tags[4].push("fips-dns".into());
        assert_eq!(Claim::parse(&e).unwrap().dnssec.as_deref(), Some("AAAA"));
        assert_eq!(
            ServiceClaim::parse(&e, "fips-ca")
                .unwrap()
                .dnssec
                .as_deref(),
            Some("BBBB")
        );
        // A chain for the wrong role is no chain: it could only fail.
        e.tags.retain(|t| t[0] != "dnssec" || t[1] != "BBBB");
        assert_eq!(ServiceClaim::parse(&e, "fips-ca").unwrap().dnssec, None);
        // A role the event does not carry.
        assert_eq!(
            ServiceClaim::parse(&e, "fips-http").unwrap_err(),
            ClaimError::Service
        );
        // A port given but broken is not "no port".
        let mut bad = claim_event("example.org", "5355");
        bad.tags
            .push(vec!["service".into(), "fips-ca".into(), "x".into()]);
        assert_eq!(
            ServiceClaim::parse(&bad, "fips-ca").unwrap_err(),
            ClaimError::Service
        );
        // The builder round-trips, with and without a port, and writes
        // the role on the chain of every role but `fips-dns`.
        let tags = ServiceClaim::tags("example.org", "fips-ca", None, Some("BBBB"));
        assert_eq!(tags[1], vec!["service".to_string(), "fips-ca".to_string()]);
        assert_eq!(tags[2], vec!["dnssec", "BBBB", "fips-ca"]);
        let again = ServiceClaim::parse(
            &Event {
                tags,
                ..claim_event("example.org", "5355")
            },
            "fips-ca",
        )
        .unwrap();
        assert_eq!(again, ca);
        assert_eq!(
            ServiceClaim::tags("example.org", "fips-dns", Some(5355), Some("AAAA")),
            Claim::tags("example.org", 5355, Some("AAAA"))
        );
        assert_eq!(
            Claim::tags("example.org", 5355, Some("AAAA"))[2],
            vec!["dnssec", "AAAA"],
            "the DNS claim's tag is as it always was"
        );
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
        // The builder round-trips through the parser.
        let again = ZoneRecord::parse(&Event {
            tags: ZoneRecord::tags(&z.domain, &z.names),
            ..ev.clone()
        })
        .unwrap();
        assert_eq!(again.names, z.names);
        assert_eq!(z.lookup("www"), None, "legacy beats the wildcard");
        assert_eq!(z.lookup("git"), Some(other));
        assert_eq!(z.lookup("anything"), Some(z.author));
        assert_eq!(z.lookup("@"), Some(z.author));
    }

    #[test]
    fn attestation_round_trip_and_limits() {
        let w = Npub::from_bytes([9; 32]);
        let s1 = Npub::from_bytes([1; 32]);
        let s2 = Npub::from_bytes([2; 32]);
        let ev = Event {
            kind: KIND_ATTESTATION,
            pubkey: w.to_hex(),
            created_at: 50,
            tags: Attestation::tags("example.org", &[s1, s2, s1], Method::Dnssec, 40),
        };
        let a = Attestation::parse(&ev).unwrap();
        assert_eq!(a.witness, w);
        assert_eq!(a.servers, vec![s1, s2], "a repeated p tag counts once");
        assert!(a.others.is_empty());
        assert_eq!(
            (a.method, a.verified_at, a.created_at),
            (Method::Dnssec, 40, 50)
        );
        let mut bad = ev.clone();
        bad.tags.retain(|t| t[0] != "p");
        assert_eq!(Attestation::parse(&bad), Err(ClaimError::Server));
        let mut bad = ev.clone();
        bad.tags.iter_mut().find(|t| t[0] == "method").unwrap()[1] = "dns-single".into();
        assert_eq!(Attestation::parse(&bad), Err(ClaimError::Method));
        let mut bad = ev.clone();
        bad.tags.retain(|t| t[0] != "verified_at");
        assert_eq!(Attestation::parse(&bad), Err(ClaimError::VerifiedAt));
        let mut bad = ev;
        bad.kind = KIND_CLAIM;
        assert_eq!(Attestation::parse(&bad), Err(ClaimError::Kind(KIND_CLAIM)));
    }

    #[test]
    fn a_p_tag_for_another_service_is_not_a_server() {
        let w = Npub::from_bytes([9; 32]);
        let server = Npub::from_bytes([1; 32]);
        let issuer = Npub::from_bytes([2; 32]);
        let others = vec![("fips-ca".to_string(), issuer)];
        let ev = Event {
            kind: KIND_ATTESTATION,
            pubkey: w.to_hex(),
            created_at: 50,
            tags: Attestation::tags_with("example.org", &[server], &others, Method::Dns, 40),
        };
        let a = Attestation::parse(&ev).unwrap();
        assert_eq!(a.servers, vec![server], "the issuer key serves nothing");
        assert_eq!(a.others, others, "but is carried along");
        // An explicit `fips-dns` third element is a server too.
        let mut explicit = ev.clone();
        explicit.tags[1].push("fips-dns".into());
        assert_eq!(Attestation::parse(&explicit).unwrap().servers, vec![server]);
        // A witness that vouches for the issuer only: a valid attestation
        // with no servers, which the resolver's ingest then drops.
        let mut ca_only = ev;
        ca_only.tags.remove(1);
        let a = Attestation::parse(&ca_only).unwrap();
        assert!(a.servers.is_empty());
        assert_eq!(a.others.len(), 1);
        // The builder mirrors the parser: an "other" entry for `fips-dns`
        // or with an empty role is a server entry, written once.
        let sneaky = vec![
            ("".to_string(), server),
            ("fips-dns".to_string(), issuer),
            ("fips-ca".to_string(), issuer),
        ];
        let tags = Attestation::tags_with("example.org", &[server], &sneaky, Method::Dns, 40);
        let p: Vec<&Vec<String>> = tags.iter().filter(|t| t[0] == "p").collect();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0], &vec!["p".to_string(), server.to_hex()]);
        assert_eq!(p[1], &vec!["p".to_string(), issuer.to_hex()]);
        assert_eq!(
            p[2],
            &vec!["p".to_string(), issuer.to_hex(), "fips-ca".to_string()]
        );
        let a = Attestation::parse(&Event { tags, ..ca_only }).unwrap();
        assert_eq!(a.servers, vec![server, issuer]);
        assert_eq!(a.others, vec![("fips-ca".to_string(), issuer)]);
    }
}
