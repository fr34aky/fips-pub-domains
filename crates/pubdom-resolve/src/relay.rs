//! Claims and zone records from Nostr relays (spec §3, §5.5), and
//! publishing them.
//!
//! Two relay sets: the node's public relays, and "mesh relays" — relays on
//! fips nodes, `ws://<npub>.fips:port`, reachable without Internet. Online,
//! both sets are asked, but only after a TXT hit (the privacy gate, spec
//! §8); offline, the mesh set first. fips exposes no generic event fetch,
//! so this is our own small nostr-sdk client.

use nostr_sdk::prelude::*;
use pubdom_core::claim::{Attestation, Event as CoreEvent, Target, ZoneRecord};
use pubdom_core::{Claim, KIND_ATTESTATION, KIND_CLAIM, KIND_ZONE, Method, Npub};
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
    /// Both sets, every relay heard out: for a publisher that must see the
    /// whole set (a witness attesting the domain's servers), not a lookup
    /// racing a budget.
    Full,
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
        self.fetch(KIND_CLAIM, domain, &[], scope).await
    }

    /// Attestations (kind 37198, spec §3.2) for `domain` by `witnesses`:
    /// the filter names the authors, so nobody else's reach the client —
    /// and it is sent to the mesh relays only, whatever `scope` the claims
    /// used: the list of whom a user trusts is not for a public relay to
    /// learn. A witness therefore publishes to a relay on the mesh. Empty
    /// `witnesses` fetches nothing.
    pub async fn fetch_attestations(
        &self,
        domain: &str,
        witnesses: &[Npub],
        _scope: RelayScope,
    ) -> Vec<CoreEvent> {
        if witnesses.is_empty() {
            return Vec::new();
        }
        let filter = Self::filter(KIND_ATTESTATION, domain, witnesses);
        fetch_from(
            relays_of(self.mesh.as_ref()).await,
            &filter,
            self.timeout,
            None,
        )
        .await
    }

    /// Every attestation for `domain`, whoever published it, from every
    /// relay heard out: the serving node's own view of who vouches for it
    /// (the server's `attestations` command). A resolver never uses this —
    /// it reads its configured witnesses and nobody else.
    ///
    /// Without an author list the per-relay limit is the only bound, so
    /// it is wide: a resolver's fetch may take the newest 32 of its
    /// witnesses', but here 32 strangers' events must not push a real
    /// witness's out. Once a relay has answered, the rest get a grace
    /// period rather than the whole timeout: a dead relay in the list
    /// must not make every listing wait it out.
    pub async fn fetch_attestations_by_anyone(&self, domain: &str) -> Vec<CoreEvent> {
        let filter = Self::filter(KIND_ATTESTATION, domain, &[]).limit(500);
        let relays: Vec<Relay> = relays_of(self.public.as_ref())
            .await
            .into_iter()
            .chain(relays_of(self.mesh.as_ref()).await)
            .collect();
        fetch_from(relays, &filter, self.timeout, Some(GRACE)).await
    }

    fn filter(kind: u16, domain: &str, authors: &[Npub]) -> Filter {
        let mut filter = Filter::new()
            .kind(Kind::from(kind))
            .identifier(domain)
            .limit(32);
        let keys: Vec<PublicKey> = authors
            .iter()
            .filter_map(|a| PublicKey::from_hex(&a.to_hex()).ok())
            .collect();
        if !keys.is_empty() {
            filter = filter.authors(keys);
        }
        filter
    }

    /// One author's claims for `domain` — a server looking for its own,
    /// which other keys' claims must not crowd out of the result.
    pub async fn fetch_claims_by(
        &self,
        domain: &str,
        author: &Npub,
        scope: RelayScope,
    ) -> Vec<CoreEvent> {
        self.fetch(KIND_CLAIM, domain, std::slice::from_ref(author), scope)
            .await
    }

    /// The zone record (kind 37199) for `domain` by its server (spec §3.3).
    pub async fn fetch_zone(
        &self,
        domain: &str,
        author: &Npub,
        scope: RelayScope,
    ) -> Vec<CoreEvent> {
        self.fetch(KIND_ZONE, domain, std::slice::from_ref(author), scope)
            .await
    }

    /// `authors` empty: anyone's.
    async fn fetch(
        &self,
        kind: u16,
        domain: &str,
        authors: &[Npub],
        scope: RelayScope,
    ) -> Vec<CoreEvent> {
        let filter = Self::filter(kind, domain, authors);
        match scope {
            // Online, the TXT record names the server: a claim set short of
            // a slow relay's costs at most that relay's say until the next
            // TXT TTL, so the fast relays set the pace.
            RelayScope::AfterHit | RelayScope::Full => {
                let relays: Vec<Relay> = relays_of(self.public.as_ref())
                    .await
                    .into_iter()
                    .chain(relays_of(self.mesh.as_ref()).await)
                    .collect();
                let grace = match scope {
                    RelayScope::Full => None,
                    _ => Some(GRACE),
                };
                fetch_from(relays, &filter, self.timeout, grace).await
            }
            // Without the TXT record the claims alone decide, and a conflict
            // is only visible with every relay heard: no grace.
            RelayScope::MeshOnly => {
                fetch_from(
                    relays_of(self.mesh.as_ref()).await,
                    &filter,
                    self.timeout,
                    None,
                )
                .await
            }
            RelayScope::Offline => {
                for client in self.mesh.iter().chain(self.public.iter()) {
                    let out =
                        fetch_from(relays_of(Some(client)).await, &filter, self.timeout, None)
                            .await;
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

/// How much longer the other relays get once one has delivered a claim
/// (after a TXT hit). A pool-wide fetch waits for every relay to send EOSE
/// or time out, and a relay that has gone quiet (a half-dead public relay,
/// a mesh relay whose path is being rebuilt) made every cold lookup pay the
/// whole timeout — on the phone, most of its budget. Long enough for a
/// relay on the mesh (a few hundred ms behind a public one) to be heard.
const GRACE: Duration = Duration::from_millis(750);

async fn relays_of(client: Option<&Client>) -> Vec<Relay> {
    match client {
        Some(c) => c.relays().await.into_values().collect(),
        None => Vec::new(),
    }
}

/// Every relay asked at once, each on its own subscription, and the results
/// gathered as they come. With `grace`, once one relay has answered with
/// events the rest get that long, then the fetch returns with what it has;
/// without, every relay is heard out (EOSE or `timeout`). A relay nostr-sdk
/// has given up on fails at once and counts for nothing; one still
/// connecting holds its REQ until it connects or the timeout passes. What
/// a relay delivered before dropping the connection is kept.
async fn fetch_from(
    relays: Vec<Relay>,
    filter: &Filter,
    timeout: Duration,
    grace: Option<Duration>,
) -> Vec<CoreEvent> {
    use futures::StreamExt;
    let fetches = relays.into_iter().map(|relay| {
        let filter = filter.clone();
        async move {
            let mut stream = relay
                .stream_events(filter, timeout, ReqExitPolicy::ExitOnEOSE)
                .await
                .map_err(|e| tracing::debug!(relay = %relay.url(), error = %e, "relay not asked"))?;
            let mut events = Vec::new();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => events.push(convert(ev)),
                    Err(e) => {
                        tracing::debug!(relay = %relay.url(), error = %e, "relay stream ended early");
                        break;
                    }
                }
            }
            Ok::<Vec<CoreEvent>, ()>(events)
        }
    });
    gather(futures::stream::FuturesUnordered::from_iter(fetches), grace).await
}

/// The gathering rule, apart from nostr-sdk so it can be tested: results
/// in completion order, an event seen on several relays kept once, and
/// with `grace` the first non-empty result starts the clock.
async fn gather<S, E>(mut results: S, grace: Option<Duration>) -> Vec<CoreEvent>
where
    S: futures::Stream<Item = Result<Vec<CoreEvent>, E>> + Unpin,
{
    use futures::StreamExt;
    let mut out: Vec<CoreEvent> = Vec::new();
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
                if !events.is_empty()
                    && deadline.is_none()
                    && let Some(g) = grace
                {
                    deadline = Some(tokio::time::Instant::now() + g);
                }
                for e in events {
                    if !out.contains(&e) {
                        out.push(e);
                    }
                }
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
/// a later claim replaces the earlier one on conforming relays. Returns
/// which relays accepted it and which refused, with their reasons.
pub async fn publish_claim(
    keys: Keys,
    relays: &[String],
    domain: &str,
    port: u16,
    dnssec: Option<&str>,
    timeout: Duration,
) -> Result<Outcome, String> {
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
) -> Result<Outcome, String> {
    publish(
        keys,
        relays,
        KIND_ZONE,
        ZoneRecord::tags(domain, names),
        timeout,
    )
    .await
}

/// Publish an attestation (kind 37198, spec §3.2) that `servers` serve
/// `domain`, verified by `method` at `verified_at`, signed with the
/// witness's `keys`. Addressable per (witness, domain): the newest replaces
/// the earlier one, so a witness re-attests the whole server set. `method`
/// must be `Dnssec` or `Dns`: a single resolver's say is not attested.
pub async fn publish_attestation(
    keys: Keys,
    relays: &[String],
    domain: &str,
    servers: &[Npub],
    method: Method,
    verified_at: u64,
    timeout: Duration,
) -> Result<Outcome, String> {
    attestable(method)?;
    publish(
        keys,
        relays,
        KIND_ATTESTATION,
        Attestation::tags(domain, servers, method, verified_at),
        timeout,
    )
    .await
}

/// A node key for signing: a file (fips's `fips.key`: 64 hex characters,
/// or 32 raw bytes) or an nsec/hex string. A file that exists but cannot
/// be read is reported as such — the usual cause is not being in the
/// `fips` group — rather than as an invalid key.
pub fn load_keys(spec: &str) -> Result<Keys, String> {
    let path = std::path::Path::new(spec);
    let text = if path.exists() {
        let bytes = std::fs::read(path).map_err(|e| {
            format!(
                "cannot read {spec}: {e} (is this user in the group that owns it, usually `fips`?)"
            )
        })?;
        if bytes.len() == 32 {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        } else {
            String::from_utf8(bytes)
                .map_err(|_| format!("{spec} is neither text nor a 32-byte key"))?
        }
    } else {
        spec.to_string()
    };
    Keys::parse(text.trim()).map_err(|e| {
        format!("key {spec}: {e} (expected fips's key file, an nsec, or 64 hex characters)")
    })
}

/// What a publication came to, per relay, keyed by the URL as configured
/// (nostr-sdk normalises URLs — `ws://host:80` prints as `ws://host` — so
/// the caller's strings are mapped back). `Err` from the publish functions
/// is a setup or timeout failure; a relay refusing is a `rejected` entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub accepted: Vec<String>,
    /// (relay, reason)
    pub rejected: Vec<(String, String)>,
}

impl Outcome {
    pub fn none_accepted(&self) -> bool {
        self.accepted.is_empty()
    }
}

async fn publish(
    keys: Keys,
    relays: &[String],
    kind: u16,
    tags: Vec<Vec<String>>,
    timeout: Duration,
) -> Result<Outcome, String> {
    let client = Client::builder().signer(keys).build();
    for u in relays {
        client.add_relay(u).await.map_err(|e| format!("{u}: {e}"))?;
    }
    // The configured string for each URL as nostr-sdk prints it.
    let configured = |printed: &str| -> String {
        relays
            .iter()
            .find(|u| {
                nostr_sdk::RelayUrl::parse(u)
                    .map(|r| r.to_string() == printed)
                    .unwrap_or(false)
            })
            .cloned()
            .unwrap_or_else(|| printed.to_string())
    };
    // Wait for the connections: `connect()` returns at once and a send
    // before the handshake is "relay not connected".
    client.connect().await;
    client.wait_for_connection(timeout).await;
    let builder = EventBuilder::new(Kind::from(kind), "").tags(parse_tags(tags)?);
    let out = tokio::time::timeout(timeout, client.send_event_builder(builder))
        .await
        .map_err(|_| "timed out publishing".to_string())?
        .map_err(|e| e.to_string())?;
    let outcome = Outcome {
        accepted: out
            .success
            .iter()
            .map(|u| configured(&u.to_string()))
            .collect(),
        rejected: out
            .failed
            .iter()
            .map(|(u, why)| (configured(&u.to_string()), why.to_string()))
            .collect(),
    };
    for (u, why) in &outcome.rejected {
        tracing::warn!(relay = %u, kind, reason = %why, "relay rejected the event");
    }
    client.disconnect().await;
    Ok(outcome)
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

/// The signed attestation as JSON, for tests and `fips-pubdom attest
/// --dry-run`. `method` as for [`publish_attestation`].
pub fn attestation_event_json(
    keys: &Keys,
    domain: &str,
    servers: &[Npub],
    method: Method,
    verified_at: u64,
) -> Result<String, String> {
    attestable(method)?;
    signed_json(
        keys,
        KIND_ATTESTATION,
        Attestation::tags(domain, servers, method, verified_at),
    )
}

fn attestable(method: Method) -> Result<(), String> {
    if method >= Method::Dns {
        Ok(())
    } else {
        Err(format!(
            "{method:?} is not worth attesting: DNSSEC or two agreeing resolvers only"
        ))
    }
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
    fn signed_attestation_parses_back_through_core() {
        let keys = Keys::generate();
        let server = Npub::from_bytes([4; 32]);
        let json =
            attestation_event_json(&keys, "example.org", &[server], Method::Dnssec, 1234).unwrap();
        let ev = Event::from_json(&json).unwrap();
        ev.verify().unwrap();
        let a = Attestation::parse(&convert(ev)).unwrap();
        assert_eq!(a.witness.to_hex(), keys.public_key().to_hex());
        assert_eq!(a.servers, vec![server]);
        assert_eq!((a.method, a.verified_at), (Method::Dnssec, 1234));
        assert!(
            attestation_event_json(&keys, "example.org", &[server], Method::DnsSingle, 1234)
                .is_err(),
            "a single resolver's verification is refused"
        );
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

    fn fetches(list: Vec<Fetch>) -> FuturesUnordered<Fetch> {
        list.into_iter().collect()
    }

    fn ids(out: &[CoreEvent]) -> Vec<u64> {
        let mut got: Vec<u64> = out.iter().map(|e| e.created_at).collect();
        got.sort();
        got
    }

    #[tokio::test(start_paused = true)]
    async fn gather_returns_a_grace_after_the_first_claim_not_after_the_slowest_relay() {
        let started = tokio::time::Instant::now();
        let out = gather(
            fetches(vec![
                after(10, Ok(vec![ev(1)])),
                after(40, Ok(vec![ev(2)])),
                after(5, Err(())),
                after(5_000, Ok(vec![ev(3)])),
            ]),
            Some(Duration::from_millis(200)),
        )
        .await;
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(210),
            "first claim + grace"
        );
        assert_eq!(
            ids(&out),
            vec![1, 2],
            "the fast relays' claims, in whatever order they came"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gather_waits_for_a_late_claim_when_the_fast_relays_have_none() {
        // Empty answers (a relay that never saw the domain) do not start
        // the clock: the only relay holding the claim may be the slow one.
        let out = gather(
            fetches(vec![after(5, Ok(Vec::new())), after(300, Ok(vec![ev(9)]))]),
            Some(Duration::from_millis(50)),
        )
        .await;
        assert_eq!(ids(&out), vec![9]);
    }

    #[tokio::test(start_paused = true)]
    async fn gather_without_grace_hears_every_relay_and_keeps_each_event_once() {
        let started = tokio::time::Instant::now();
        let out = gather(
            fetches(vec![
                after(10, Ok(vec![ev(1), ev(2)])),
                after(2_000, Ok(vec![ev(2), ev(3)])),
            ]),
            None,
        )
        .await;
        assert_eq!(started.elapsed(), Duration::from_millis(2_000));
        assert_eq!(ids(&out), vec![1, 2, 3], "the mirrored claim once");
    }

    #[tokio::test(start_paused = true)]
    async fn gather_with_no_relays_is_empty_at_once() {
        assert!(
            gather(fetches(Vec::new()), Some(Duration::from_secs(5)))
                .await
                .is_empty()
        );
    }
}
