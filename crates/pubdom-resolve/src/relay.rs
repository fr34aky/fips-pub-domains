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

    /// The zone record (kind 37199) for `domain` by its server (spec §3.3).
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
                let relays: Vec<Relay> = relays_of(self.public.as_ref())
                    .await
                    .into_iter()
                    .chain(relays_of(self.mesh.as_ref()).await)
                    .collect();
                fetch_from(relays, &filter, self.timeout).await
            }
            RelayScope::MeshOnly => {
                fetch_from(relays_of(self.mesh.as_ref()).await, &filter, self.timeout).await
            }
            RelayScope::Offline => {
                for client in self.mesh.iter().chain(self.public.iter()) {
                    let out =
                        fetch_from(relays_of(Some(client)).await, &filter, self.timeout).await;
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

/// How much longer the other relays get once one has delivered a claim.
/// A pool-wide fetch waits for every relay to send EOSE or time out, and a
/// relay that has gone quiet (a half-dead public relay, a mesh relay whose
/// path is being rebuilt) made every cold lookup pay the whole timeout —
/// on the phone, most of its budget. Long enough for a relay on the mesh
/// (a few hundred ms behind a public one) to still be heard.
const GRACE: Duration = Duration::from_millis(750);

async fn relays_of(client: Option<&Client>) -> Vec<Relay> {
    match client {
        Some(c) => c.relays().await.into_values().collect(),
        None => Vec::new(),
    }
}

/// Every relay asked at once, each on its own subscription, and the results
/// gathered as they come: once one relay has answered with events, the rest
/// get [`GRACE`], then the fetch returns with what it has. A relay that is
/// not connected fails at once and counts for nothing.
async fn fetch_from(relays: Vec<Relay>, filter: &Filter, timeout: Duration) -> Vec<CoreEvent> {
    let fetches = relays.into_iter().map(|relay| {
        let filter = filter.clone();
        async move {
            relay
                .fetch_events(filter, timeout, ReqExitPolicy::ExitOnEOSE)
                .await
                .map(|events| events.into_iter().map(convert).collect::<Vec<_>>())
                .map_err(
                    |e| tracing::debug!(relay = %relay.url(), error = %e, "relay fetch failed"),
                )
        }
    });
    gather(futures::stream::FuturesUnordered::from_iter(fetches), GRACE).await
}

/// The gathering rule, apart from nostr-sdk so it can be tested: results
/// in completion order; the first non-empty one starts the grace clock.
async fn gather<S, E>(mut results: S, grace: Duration) -> Vec<CoreEvent>
where
    S: futures::Stream<Item = Result<Vec<CoreEvent>, E>> + Unpin,
{
    use futures::StreamExt;
    let mut out = Vec::new();
    let mut deadline: Option<tokio::time::Instant> = None;
    loop {
        let next = results.next();
        let item = match deadline {
            Some(d) => match tokio::time::timeout_at(d, next).await {
                Ok(item) => item,
                Err(_) => break,
            },
            None => next.await,
        };
        match item {
            None => break,
            Some(Ok(events)) => {
                if !events.is_empty() && deadline.is_none() {
                    deadline = Some(tokio::time::Instant::now() + grace);
                }
                out.extend(events);
            }
            Some(Err(_)) => {}
        }
    }
    out
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

    use futures::stream::FuturesUnordered;
    use std::future::Future;
    use std::pin::Pin;

    fn ev(n: u64) -> CoreEvent {
        CoreEvent {
            kind: KIND_CLAIM,
            pubkey: format!("{n:064x}"),
            created_at: n,
            tags: Vec::new(),
        }
    }

    type Fetch = Pin<Box<dyn Future<Output = Result<Vec<CoreEvent>, ()>> + Send>>;

    fn after(ms: u64, result: Result<Vec<CoreEvent>, ()>) -> Fetch {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            result
        })
    }

    #[tokio::test]
    async fn gather_returns_a_grace_after_the_first_claim_not_after_the_slowest_relay() {
        let fetches: FuturesUnordered<Fetch> = [
            after(10, Ok(vec![ev(1)])),
            after(40, Ok(vec![ev(2)])),
            after(5, Err(())),
            after(5_000, Ok(vec![ev(3)])),
        ]
        .into_iter()
        .collect();
        let started = std::time::Instant::now();
        let out = gather(fetches, Duration::from_millis(200)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "did not wait for the quiet relay"
        );
        let mut got: Vec<u64> = out.iter().map(|e| e.created_at).collect();
        got.sort();
        assert_eq!(
            got,
            vec![1, 2],
            "the fast relays' claims, in whatever order they came"
        );
    }

    #[tokio::test]
    async fn gather_waits_for_a_late_claim_when_the_fast_relays_have_none() {
        // Empty answers (a relay that never saw the domain) do not start
        // the clock: the only relay holding the claim may be the slow one.
        let fetches: FuturesUnordered<Fetch> =
            [after(5, Ok(Vec::new())), after(300, Ok(vec![ev(9)]))]
                .into_iter()
                .collect();
        let out = gather(fetches, Duration::from_millis(50)).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].created_at, 9);
    }

    #[tokio::test]
    async fn gather_with_no_relays_is_empty_at_once() {
        let fetches: FuturesUnordered<Fetch> = FuturesUnordered::new();
        assert!(gather(fetches, Duration::from_secs(5)).await.is_empty());
    }
}
