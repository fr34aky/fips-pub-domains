//! Claims and zone records from Nostr relays (spec §3, §5.5), and
//! publishing them.
//!
//! Two relay sets: the node's public relays, and "mesh relays" — relays on
//! fips nodes, `ws://<npub>.fips:port`, reachable without Internet. Online,
//! both sets are asked, but only after a TXT hit (the privacy gate, spec
//! §8); offline, the mesh set first. fips exposes no generic event fetch,
//! so this is our own small nostr-sdk client.

use nostr_sdk::prelude::*;
use pubdom_core::claim::{Event as CoreEvent, Target, ZoneRecord};
use pubdom_core::{Claim, KIND_CLAIM, KIND_ZONE, Npub};
use std::time::Duration;

/// Which relays a fetch may touch (spec §8, the privacy gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayScope {
    /// After a TXT hit: the domain already opted in via DNS, so both sets.
    AfterHit,
    /// Offline: mesh relays first, then the public ones in case a path exists.
    Offline,
    /// Online but the legacy DNS did not answer: only relays the user runs
    /// or chose on the mesh — a public relay must never learn of a domain
    /// that DNS has not vouched for.
    MeshOnly,
}

pub struct RelayClient {
    public: Option<Client>,
    mesh: Option<Client>,
    timeout: Duration,
}

impl RelayClient {
    /// Clients are created connected-lazily: `connect()` returns at once and
    /// relays that are unreachable simply never answer within `timeout`.
    pub async fn new(public: &[String], mesh: &[String], timeout: Duration) -> Self {
        Self {
            public: make(public).await,
            mesh: make(mesh).await,
            timeout,
        }
    }

    /// Claims for `domain` (kind 37197, `d=<domain>`). Online, both relay
    /// sets are asked at once — a domain's claim may live only on a relay
    /// inside the mesh, and the privacy gate is about *when* relays are
    /// asked (after a TXT hit), not which. Offline, the mesh relays first;
    /// the public ones are tried afterwards in case a path exists.
    /// Signatures are verified by the pool.
    pub async fn fetch_claims(&self, domain: &str, scope: RelayScope) -> Vec<CoreEvent> {
        self.fetch(KIND_CLAIM, domain, None, scope).await
    }

    /// The zone record (kind 37199) for `domain` by its server (spec §3.3).
    /// One author's claims for `domain` — a server looking for its own,
    /// which other keys' claims must not crowd out of the result.
    pub async fn fetch_claims_by(
        &self,
        domain: &str,
        author: &Npub,
        scope: RelayScope,
    ) -> Vec<CoreEvent> {
        self.fetch(KIND_CLAIM, domain, Some(author), scope).await
    }

    pub async fn fetch_zone(
        &self,
        domain: &str,
        author: &Npub,
        scope: RelayScope,
    ) -> Vec<CoreEvent> {
        self.fetch(KIND_ZONE, domain, Some(author), scope).await
    }

    async fn fetch(
        &self,
        kind: u16,
        domain: &str,
        author: Option<&Npub>,
        scope: RelayScope,
    ) -> Vec<CoreEvent> {
        let mut filter = Filter::new()
            .kind(Kind::from(kind))
            .identifier(domain)
            .limit(32);
        if let Some(a) = author
            && let Ok(pk) = PublicKey::from_hex(&a.to_hex())
        {
            filter = filter.author(pk);
        }
        match scope {
            RelayScope::AfterHit => {
                let (a, b) = futures::join!(
                    fetch_one(self.public.as_ref(), &filter, self.timeout),
                    fetch_one(self.mesh.as_ref(), &filter, self.timeout),
                );
                let mut out = a;
                out.extend(b);
                out
            }
            RelayScope::MeshOnly => fetch_one(self.mesh.as_ref(), &filter, self.timeout).await,
            RelayScope::Offline => {
                for client in self.mesh.iter().chain(self.public.iter()) {
                    let out = fetch_one(Some(client), &filter, self.timeout).await;
                    if !out.is_empty() {
                        return out;
                    }
                }
                Vec::new()
            }
        }
    }

    pub async fn shutdown(&self) {
        for c in self.public.iter().chain(self.mesh.iter()) {
            c.disconnect().await;
        }
    }
}

async fn fetch_one(client: Option<&Client>, filter: &Filter, timeout: Duration) -> Vec<CoreEvent> {
    let Some(client) = client else {
        return Vec::new();
    };
    match client.fetch_events(filter.clone(), timeout).await {
        Ok(events) => events.into_iter().map(convert).collect(),
        Err(e) => {
            tracing::debug!(error = %e, "relay fetch failed");
            Vec::new()
        }
    }
}

async fn make(urls: &[String]) -> Option<Client> {
    if urls.is_empty() {
        return None;
    }
    let client = Client::default();
    let mut any = false;
    for u in urls {
        match client.add_relay(u).await {
            Ok(_) => any = true,
            Err(e) => tracing::warn!(relay = u, error = %e, "ignoring relay"),
        }
    }
    if !any {
        return None;
    }
    client.connect().await;
    Some(client)
}

fn convert(ev: Event) -> CoreEvent {
    CoreEvent {
        kind: ev.kind.as_u16(),
        pubkey: ev.pubkey.to_hex(),
        created_at: ev.created_at.as_secs(),
        tags: ev.tags.iter().map(|t| t.clone().to_vec()).collect(),
    }
}

/// Publish a claim for `domain` signed with `keys` to `relays`. Addressable:
/// a later claim replaces the earlier one on conforming relays. Returns the
/// relays that accepted it.
pub async fn publish_claim(
    keys: Keys,
    relays: &[String],
    domain: &str,
    port: u16,
    dnssec: Option<&str>,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    publish(
        keys,
        relays,
        KIND_CLAIM,
        Claim::tags(domain, port, dnssec),
        timeout,
    )
    .await
}

/// Publish the zone record (kind 37199) for `domain`: the names it serves,
/// so clients can resolve them while the server itself is unreachable.
pub async fn publish_zone(
    keys: Keys,
    relays: &[String],
    domain: &str,
    names: &[(String, Target)],
    timeout: Duration,
) -> Result<Vec<String>, String> {
    publish(
        keys,
        relays,
        KIND_ZONE,
        ZoneRecord::tags(domain, names),
        timeout,
    )
    .await
}

async fn publish(
    keys: Keys,
    relays: &[String],
    kind: u16,
    tags: Vec<Vec<String>>,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    let client = Client::builder().signer(keys).build();
    for u in relays {
        client.add_relay(u).await.map_err(|e| format!("{u}: {e}"))?;
    }
    // Wait for the connections: `connect()` returns at once and a send
    // before the handshake is "relay not connected".
    client.connect().await;
    client.wait_for_connection(timeout).await;
    let builder = EventBuilder::new(Kind::from(kind), "").tags(parse_tags(tags)?);
    let out = tokio::time::timeout(timeout, client.send_event_builder(builder))
        .await
        .map_err(|_| "timed out publishing".to_string())?
        .map_err(|e| e.to_string())?;
    let ok: Vec<String> = out.success.iter().map(|u| u.to_string()).collect();
    for (u, why) in &out.failed {
        tracing::warn!(relay = %u, kind, reason = %why, "relay rejected the event");
    }
    client.disconnect().await;
    if ok.is_empty() {
        return Err(format!("no relay accepted the kind {kind} event"));
    }
    Ok(ok)
}

fn parse_tags(tags: Vec<Vec<String>>) -> Result<Vec<Tag>, String> {
    tags.into_iter()
        .map(|t| Tag::parse(t).map_err(|e| e.to_string()))
        .collect()
}

/// The claim event as JSON without sending it — for `--dry-run` and for
/// operators who publish through other tooling.
pub fn claim_event_json(
    keys: &Keys,
    domain: &str,
    port: u16,
    dnssec: Option<&str>,
) -> Result<String, String> {
    signed_json(keys, KIND_CLAIM, Claim::tags(domain, port, dnssec))
}

/// The zone record as JSON without sending it.
pub fn zone_event_json(
    keys: &Keys,
    domain: &str,
    names: &[(String, Target)],
) -> Result<String, String> {
    signed_json(keys, KIND_ZONE, ZoneRecord::tags(domain, names))
}

fn signed_json(keys: &Keys, kind: u16, tags: Vec<Vec<String>>) -> Result<String, String> {
    let ev = EventBuilder::new(Kind::from(kind), "")
        .tags(parse_tags(tags)?)
        .sign_with_keys(keys)
        .map_err(|e| e.to_string())?;
    ev.try_as_pretty_json().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_claim_parses_back_through_core() {
        let keys = Keys::generate();
        let json = claim_event_json(&keys, "example.org", 5355, None).unwrap();
        let ev = Event::from_json(&json).unwrap();
        ev.verify().unwrap();
        let core = convert(ev);
        let claim = Claim::parse(&core).unwrap();
        assert_eq!(claim.domain, "example.org");
        assert_eq!(claim.port, 5355);
        assert_eq!(claim.author.to_hex(), keys.public_key().to_hex());
    }

    #[test]
    fn signed_zone_record_parses_back_through_core() {
        let keys = Keys::generate();
        let names = vec![
            ("www".to_string(), Target::Author),
            ("mail".to_string(), Target::Legacy),
        ];
        let json = zone_event_json(&keys, "example.org", &names).unwrap();
        let ev = Event::from_json(&json).unwrap();
        ev.verify().unwrap();
        let z = ZoneRecord::parse(&convert(ev)).unwrap();
        assert_eq!(z.names, names);
        assert_eq!(z.lookup("www"), Some(z.author));
        assert_eq!(z.lookup("mail"), None);
    }
}
