//! Claims from Nostr relays (spec §3, §5.5), and publishing them.
//!
//! Two relay sets: the node's public relays, and "mesh relays" — relays on
//! fips nodes, `ws://[fd…]:port`, reachable without Internet. Online, only
//! the public set is asked and only after a TXT hit (the privacy gate,
//! spec §8); offline, the mesh set first. fips exposes no generic event
//! fetch, so this is our own small nostr-sdk client.

use pubdom_core::claim::Event as CoreEvent;
use pubdom_core::{Claim, KIND_CLAIM};
use nostr_sdk::prelude::*;
use std::time::Duration;

/// Which relays a claim fetch may touch (spec §8, the privacy gate).
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
        Self { public: make(public).await, mesh: make(mesh).await, timeout }
    }

    /// Claims for `domain` (kind 37197, `d=<domain>`). Online, both relay
    /// sets are asked at once — a domain's claim may live only on a relay
    /// inside the mesh, and the privacy gate is about *when* relays are
    /// asked (after a TXT hit), not which. Offline, the mesh relays first;
    /// the public ones are tried afterwards in case a path exists.
    /// Signatures are verified by the pool.
    pub async fn fetch_claims(&self, domain: &str, scope: RelayScope) -> Vec<CoreEvent> {
        let filter = Filter::new().kind(Kind::from(KIND_CLAIM)).identifier(domain).limit(32);
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
    let Some(client) = client else { return Vec::new() };
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
    let client = Client::builder().signer(keys).build();
    for u in relays {
        client.add_relay(u).await.map_err(|e| format!("{u}: {e}"))?;
    }
    client.connect().await;
    let tags: Vec<Tag> = Claim::tags(domain, port, dnssec)
        .into_iter()
        .map(|t| Tag::parse(t).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let builder = EventBuilder::new(Kind::from(KIND_CLAIM), "").tags(tags);
    let out = tokio::time::timeout(timeout, client.send_event_builder(builder))
        .await
        .map_err(|_| "timed out publishing".to_string())?
        .map_err(|e| e.to_string())?;
    let ok: Vec<String> = out.success.iter().map(|u| u.to_string()).collect();
    for (u, why) in &out.failed {
        tracing::warn!(relay = %u, reason = %why, "relay rejected the claim");
    }
    client.disconnect().await;
    if ok.is_empty() {
        return Err("no relay accepted the claim".into());
    }
    Ok(ok)
}

/// The claim event as JSON without sending it — for `--dry-run` and for
/// operators who publish through other tooling.
pub fn claim_event_json(keys: &Keys, domain: &str, port: u16, dnssec: Option<&str>) -> Result<String, String> {
    let tags: Vec<Tag> = Claim::tags(domain, port, dnssec)
        .into_iter()
        .map(|t| Tag::parse(t).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let ev = EventBuilder::new(Kind::from(KIND_CLAIM), "")
        .tags(tags)
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
}
