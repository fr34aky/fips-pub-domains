//! `lookup(query) → answer | passthrough`: spec §5 and §7 wired to the
//! adapters, with the budgets of docs/architecture.md.
//!
//! Invariant (spec §7): the only way an application receives a mesh address
//! is a verified (or pinned, or explicitly opted-in unverified) binding
//! **and** a positive step 3 answer **and** a registered, reachable node.
//! Every other outcome is [`LookupResult::Passthrough`] — the legacy path —
//! and never an error of our making.

use crate::mesh::MeshDns;
use crate::relay::{RelayClient, RelayScope};
use crate::txt::TxtVerifier;
use pubdom_core::cache::{self, TtlCache};
use pubdom_core::claim::{Event, ZoneRecord};
use pubdom_core::policy::{self, Decision, Input, NoProofs, PinChange, Reason, TxtLookup};
use pubdom_core::synth::{self, Query, Step3Outcome};
use pubdom_core::{ANSWER_TTL_SECS, Binding, Npub, PinStore, domain};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Where the TXT record comes from — hickory in production, a table in tests.
pub trait TxtSource: Send + Sync {
    fn lookup(&self, domain: &str) -> impl Future<Output = (TxtLookup, Option<u32>)> + Send;
}

/// Where claims and zone records come from — relays in production, a
/// table in tests.
pub trait ClaimSource: Send + Sync {
    fn fetch_claims(
        &self,
        domain: &str,
        scope: RelayScope,
    ) -> impl Future<Output = Vec<Event>> + Send;

    /// The zone record (kind 37199) for `domain` by `author`.
    fn fetch_zone(
        &self,
        domain: &str,
        author: Npub,
        scope: RelayScope,
    ) -> impl Future<Output = Vec<Event>> + Send;
}

impl TxtSource for TxtVerifier {
    async fn lookup(&self, domain: &str) -> (TxtLookup, Option<u32>) {
        TxtVerifier::lookup(self, domain).await
    }
}

impl ClaimSource for RelayClient {
    async fn fetch_claims(&self, domain: &str, scope: RelayScope) -> Vec<Event> {
        RelayClient::fetch_claims(self, domain, scope).await
    }
    async fn fetch_zone(&self, domain: &str, author: Npub, scope: RelayScope) -> Vec<Event> {
        RelayClient::fetch_zone(self, domain, &author, scope).await
    }
}

/// No upstream at all (a mesh-only node): every TXT lookup is unreachable.
pub struct NoTxt;
impl TxtSource for NoTxt {
    async fn lookup(&self, _: &str) -> (TxtLookup, Option<u32>) {
        (TxtLookup::Unreachable, None)
    }
}

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub public_relays: Vec<String>,
    pub mesh_relays: Vec<String>,
    pub dnssec: bool,
    pub allow_unverified_offline: bool,
    pub txt_timeout: Duration,
    pub relay_timeout: Duration,
    pub step3_timeout: Duration,
    pub tcp_timeout: Duration,
    pub register_timeout: Duration,
    /// Budget for the echo to a node other than the domain's server.
    pub reach_timeout: Duration,
    /// A server that did not answer step 3 is skipped for this long after
    /// the first failure, three times as long after each further failure in
    /// a row, up to `server_backoff_max`; then it is tried again.
    pub server_backoff: Duration,
    pub server_backoff_max: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            // More than two: one relay banning an address or being down must
            // not hide every claim, and a publisher rarely reaches all of them.
            public_relays: vec![
                "wss://relay.damus.io".into(),
                "wss://nos.lol".into(),
                "wss://relay.primal.net".into(),
                "wss://relay.nostr.band".into(),
            ],
            mesh_relays: Vec::new(),
            dnssec: true,
            allow_unverified_offline: false,
            txt_timeout: Duration::from_millis(1500),
            relay_timeout: Duration::from_secs(2),
            step3_timeout: Duration::from_secs(1),
            tcp_timeout: Duration::from_secs(3),
            register_timeout: Duration::from_secs(1),
            reach_timeout: Duration::from_millis(1500),
            server_backoff: Duration::from_secs(300),
            server_backoff_max: Duration::from_secs(3 * 3600),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    /// A complete DNS reply for the application.
    Answer(Vec<u8>),
    /// Not over fips: forward to the legacy upstream exactly as before.
    Passthrough,
}

#[derive(Clone)]
enum CachedDecision {
    /// The domain's servers, primary first, and whether the binding is the
    /// opted-in unverified kind.
    Use(Vec<Binding>, bool),
    NotOverFips,
}

/// How long a positive echo — or a step 3 answer from the node itself —
/// counts as proof of reachability.
const REACHABLE_TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
enum CachedStep3 {
    /// The node, and whether it was the server that gave the answer.
    Node(Npub, bool),
    NotOverFips,
}

/// A server that did not answer step 3.
#[derive(Clone, Copy)]
struct Down {
    /// Failures in a row.
    failures: u32,
    /// Skipped until then (unix seconds).
    retry_at: u64,
}

pub struct Resolver<T: TxtSource, C: ClaimSource> {
    cfg: ResolverConfig,
    pins: Arc<dyn PinStore>,
    txt: T,
    claims: C,
    mesh: Arc<dyn MeshDns>,
    online: AtomicBool,
    decisions: TtlCache<String, CachedDecision>,
    step3: TtlCache<String, CachedStep3>,
    registered: TtlCache<Npub, ()>,
    /// Nodes that answered an echo recently (positive, 2 min) or did not
    /// (negative, 30 s): a browser asks A, AAAA and HTTPS for one name, and
    /// each would otherwise wait out the full echo budget.
    reachable: TtlCache<Npub, bool>,
    /// Zone records by domain, for names asked while the domain's servers
    /// are unreachable (spec §3.3, §6). `None` = no server published one.
    zones: TtlCache<String, Option<ZoneRecord>>,
    /// Servers that did not answer step 3: skipped until `retry_at` (a
    /// backoff that grows with the failures in a row), then tried again —
    /// the periodic re-check of a failed server. The entry outlives its
    /// window so the next failure knows the streak; an answer clears it.
    down: TtlCache<Npub, Down>,
    /// Single-flight per domain: a browser's first visit fires A, AAAA and
    /// HTTPS queries at once, and only one of them should pay for the TXT
    /// and relay round trips (and write the pin).
    inflight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<T: TxtSource, C: ClaimSource> Resolver<T, C> {
    pub fn new(
        cfg: ResolverConfig,
        pins: Arc<dyn PinStore>,
        txt: T,
        claims: C,
        mesh: Arc<dyn MeshDns>,
    ) -> Self {
        Self {
            cfg,
            pins,
            txt,
            claims,
            mesh,
            online: AtomicBool::new(true),
            decisions: TtlCache::new(4096),
            step3: TtlCache::new(4096),
            registered: TtlCache::new(1024),
            reachable: TtlCache::new(1024),
            zones: TtlCache::new(1024),
            down: TtlCache::new(1024),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// The TXT source, for the host to swap upstreams at run time.
    pub fn txt(&self) -> &T {
        &self.txt
    }

    /// The network watcher's view: is a legacy upstream expected to answer?
    /// When it does not anyway, the TXT lookup comes back `Unreachable` and
    /// the offline path is taken regardless.
    pub fn set_online(&self, online: bool) {
        if self.online.swap(online, Ordering::Relaxed) != online {
            tracing::info!(online, "network state changed");
            self.decisions.clear();
        }
    }

    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    pub fn pins(&self) -> &dyn PinStore {
        self.pins.as_ref()
    }

    pub fn flush_caches(&self) {
        self.decisions.clear();
        self.step3.clear();
        self.registered.clear();
        self.reachable.clear();
        self.zones.clear();
        self.down.clear();
    }

    /// The whole of spec §5–§7 for one application query.
    pub async fn lookup(&self, query: &[u8]) -> LookupResult {
        let Some(q) = synth::parse_query(query) else {
            return LookupResult::Passthrough;
        };
        // Only the address types go over fips; HTTPS/SVCB are suppressed for
        // bound names (below). Everything else — MX, TXT, SRV, NS … — stays
        // legacy DNS even under a wildcard zone, and costs no TXT or relay
        // round trip.
        if !matches!(
            q.qtype,
            synth::QTYPE_A
                | synth::QTYPE_AAAA
                | synth::QTYPE_ANY
                | synth::QTYPE_CNAME
                | synth::QTYPE_SVCB
                | synth::QTYPE_HTTPS
        ) {
            return LookupResult::Passthrough;
        }
        let candidates = domain::candidates(&q.name);
        if candidates.is_empty() {
            return LookupResult::Passthrough;
        }
        // Longest claim wins (spec §5.2). Offline, a pinned domain is the
        // only thing that can resolve without a relay round trip, so it is
        // taken before relays are asked about longer, unpinned candidates;
        // the pinned server's zone covers its subtree anyway.
        let mut chosen: Option<(String, Vec<Binding>, bool)> = None;
        if !self.is_online()
            && let Some(d) = candidates
                .iter()
                .rev()
                .find(|d| !self.pins.get(d).is_empty())
            && let CachedDecision::Use(b, unverified) = self.decision(d).await
        {
            chosen = Some((d.clone(), b, unverified));
        }
        for d in candidates.iter().rev() {
            if chosen.is_some() {
                break;
            }
            match self.decision(d).await {
                CachedDecision::Use(b, unverified) => {
                    chosen = Some((d.clone(), b, unverified));
                    break;
                }
                CachedDecision::NotOverFips => {}
            }
        }
        let Some((bound_domain, servers, unverified)) = chosen else {
            return LookupResult::Passthrough;
        };
        if servers.is_empty() {
            return LookupResult::Passthrough;
        }
        if unverified {
            tracing::warn!(name = %q.name, domain = %bound_domain, npub = %servers[0].npub, "resolving through an UNVERIFIED binding (opt-in)");
        }
        match self.step3(&q, &servers).await {
            Some(npub) => self.answer(&q, npub),
            None => LookupResult::Passthrough,
        }
    }

    fn answer(&self, q: &Query, npub: Npub) -> LookupResult {
        let ttl = ANSWER_TTL_SECS;
        let bytes = match q.qtype {
            synth::QTYPE_A | synth::QTYPE_AAAA | synth::QTYPE_ANY | synth::QTYPE_CNAME => {
                synth::build_answer(q, npub, ttl)
            }
            // HTTPS/SVCB: a public record could carry address hints for the
            // legacy path. NODATA keeps the mesh the only path.
            _ => synth::build_rcode(q, simple_dns::RCODE::NoError),
        };
        match bytes {
            Some(b) => LookupResult::Answer(b),
            None => LookupResult::Passthrough,
        }
    }

    async fn decision(&self, d: &str) -> CachedDecision {
        if let Some(c) = self.decisions.get(&d.to_string(), crate::now()) {
            return c;
        }
        let lock = self.flight(d);
        let _flight = lock.lock().await;
        let result = match self.decisions.get(&d.to_string(), crate::now()) {
            Some(c) => c, // a concurrent caller already decided
            None => self.decide_uncached(d).await,
        };
        drop(_flight);
        if Arc::strong_count(&lock) == 2 {
            self.inflight.lock().unwrap().remove(d);
        }
        result
    }

    async fn decide_uncached(&self, d: &str) -> CachedDecision {
        let now = crate::now();
        let pins = self.pins.get(d);
        let online = self.is_online();
        let (txt, txt_ttl) = if online {
            self.txt.lookup(d).await
        } else {
            (TxtLookup::Unreachable, None)
        };
        let events = match &txt {
            // The privacy gate (spec §8): relays only after a TXT hit …
            TxtLookup::Hit { .. } => self.claims.fetch_claims(d, RelayScope::AfterHit).await,
            TxtLookup::Miss { .. } | TxtLookup::Disputed => Vec::new(),
            // … or offline, where the claim stands in for the record (§5.5) —
            // unless a pin already answers, which needs no relay at all.
            TxtLookup::Unreachable if !pins.is_empty() => Vec::new(),
            // Believed online but DNS did not answer: a public relay must not
            // learn the domain; relays on the mesh may.
            TxtLookup::Unreachable if online => {
                self.claims.fetch_claims(d, RelayScope::MeshOnly).await
            }
            TxtLookup::Unreachable => self.claims.fetch_claims(d, RelayScope::Offline).await,
        };
        let claims = policy::ingest_claims(self.pins.as_ref(), d, &events, now);
        let is_unreachable = matches!(txt, TxtLookup::Unreachable);
        let disputed = matches!(txt, TxtLookup::Disputed);
        let outcome = policy::decide(Input {
            domain: d,
            pins,
            txt,
            claims: &claims,
            now,
            allow_unverified_offline: self.cfg.allow_unverified_offline,
            proofs: &NoProofs,
        });
        for change in &outcome.changes {
            match change {
                PinChange::Put(b) => {
                    if self.pins.put(b.clone()) {
                        tracing::info!(domain = d, npub = %b.npub, method = ?b.method, "binding verified and pinned");
                    }
                }
                PinChange::Forget(npub) => {
                    tracing::info!(domain = d, %npub, "no longer named by the TXT record: server unpinned");
                    self.pins.forget_server(d, *npub);
                }
            }
        }
        let (cached, ttl) = match outcome.decision {
            Decision::Bound(b) => {
                let ttl = if disputed {
                    cache::TXT_DISPUTED_TTL
                } else {
                    txt_ttl
                        .map(|t| Duration::from_secs(t.into()).min(cache::TXT_HIT_MAX_TTL))
                        .unwrap_or(cache::CLAIM_TTL)
                };
                (CachedDecision::Use(b, false), ttl)
            }
            Decision::Unverified(b) => (CachedDecision::Use(vec![b], true), cache::RELAY_MISS_TTL),
            Decision::NotOverFips(reason) => {
                if reason == Reason::Disputed {
                    tracing::info!(
                        domain = d,
                        "not over fips: upstream resolvers disagree on the TXT record"
                    );
                } else {
                    tracing::debug!(domain = d, ?reason, "not over fips");
                }
                let ttl = match reason {
                    Reason::NoTxt | Reason::PublicSuffix => cache::TXT_MISS_TTL,
                    Reason::Disputed => cache::TXT_DISPUTED_TTL,
                    _ if is_unreachable => cache::RELAY_MISS_TTL,
                    _ => cache::CLAIM_TTL,
                };
                (CachedDecision::NotOverFips, ttl)
            }
        };
        self.decisions.put(d.to_string(), cached.clone(), ttl, now);
        cached
    }

    /// Step 3 (spec §6) plus the reachability rule (spec §7). `None` means
    /// "not over fips" or failure — the caller passes through either way.
    async fn step3(&self, q: &Query, servers: &[Binding]) -> Option<Npub> {
        // Same single-flight as `decision`: one mesh query per name, however
        // many record types the application asks for at once.
        let lock = self.flight(&format!("step3:{}", q.name));
        let _flight = lock.lock().await;
        let result = self.step3_uncached(q, servers).await;
        drop(_flight);
        if Arc::strong_count(&lock) == 2 {
            self.inflight
                .lock()
                .unwrap()
                .remove(&format!("step3:{}", q.name));
        }
        result
    }

    fn flight(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.inflight
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    async fn step3_uncached(&self, q: &Query, servers: &[Binding]) -> Option<Npub> {
        let now = crate::now();
        match self.step3.get(&q.name, now) {
            // Another node: the echo rule applies.
            Some(CachedStep3::Node(n, false)) => return self.deliverable(q, n, false).await,
            // The server answered for itself, which proved it reachable for
            // REACHABLE_TTL. Past that, ask it again rather than ping it —
            // the answer is the proof, and servers may filter echo.
            Some(CachedStep3::Node(n, true)) if self.reachable.get(&n, now) == Some(true) => {
                return self.deliverable(q, n, true).await;
            }
            Some(CachedStep3::NotOverFips) => return None,
            Some(CachedStep3::Node(_, true)) | None => {}
        }
        // Ask the servers in pin order, skipping those in their backoff
        // window (spec §5.3): the primary stays the primary while it
        // answers, and a failed server is retried once its window expires.
        let mut all_skipped = true;
        for (i, server) in servers.iter().enumerate() {
            if self
                .down
                .get(&server.npub, now)
                .is_some_and(|d| now < d.retry_at)
            {
                continue;
            }
            let then = if i + 1 < servers.len() {
                "trying the next"
            } else {
                "no other server; trying its zone record"
            };
            all_skipped = false;
            if !self.ensure_registered(server.npub).await {
                tracing::debug!(npub = %server.npub, "domain server not reachable through the local node");
                self.mark_down(server.npub, crate::now());
                continue;
            }
            match self.ask_server(q, server, now).await {
                Ok(Step3Outcome::Node { npub, ttl }) => {
                    self.down.remove(&server.npub);
                    let now = crate::now();
                    let ttl = Duration::from_secs(ttl.into()).min(cache::STEP3_MAX_TTL);
                    let proven = npub == server.npub;
                    if proven {
                        // The reply proves the node reachable, for as long as
                        // an echo would: the A query that follows the AAAA
                        // must not need an echo the node may filter.
                        self.reachable.put(npub, true, REACHABLE_TTL, now);
                    }
                    self.step3
                        .put(q.name.clone(), CachedStep3::Node(npub, proven), ttl, now);
                    return self.deliverable(q, npub, proven).await;
                }
                Ok(Step3Outcome::NotOverFips) => {
                    self.down.remove(&server.npub);
                    let now = crate::now();
                    self.step3.put(
                        q.name.clone(),
                        CachedStep3::NotOverFips,
                        Duration::from_secs(300),
                        now,
                    );
                    return None;
                }
                Ok(other) => {
                    tracing::info!(name = %q.name, npub = %server.npub, ?other, "domain server failed; {then}");
                    self.mark_down(server.npub, crate::now());
                }
                Err(e) => {
                    tracing::info!(name = %q.name, npub = %server.npub, error = %e, "domain server did not answer; {then}");
                    self.mark_down(server.npub, crate::now());
                }
            }
        }
        if all_skipped {
            tracing::debug!(name = %q.name, "every domain server is in its backoff window");
        }
        self.via_zone_record(q, servers).await
    }

    /// One step 3 exchange with `server`: UDP with one retry, TCP on
    /// truncation.
    async fn ask_server(
        &self,
        q: &Query,
        server: &Binding,
        now: u64,
    ) -> Result<Step3Outcome, String> {
        let msg = synth::build_query(query_id(&q.name, now), &q.name, synth::QTYPE_AAAA)
            .ok_or_else(|| "unbuildable query".to_string())?;
        let id = u16::from_be_bytes([msg[0], msg[1]]);
        let addr = server.server_addr();
        let mesh = self.mesh.clone();
        let (t_udp, t_tcp) = (self.cfg.step3_timeout, self.cfg.tcp_timeout);
        tokio::task::spawn_blocking(move || {
            let reply = match mesh.query_udp(addr, &msg, t_udp) {
                Ok(r) => r,
                // One retry: a mesh path may still be settling.
                Err(_) => mesh
                    .query_udp(addr, &msg, t_udp)
                    .map_err(|e| e.to_string())?,
            };
            let mut out = synth::parse_step3_reply(&reply, id);
            if out == Step3Outcome::Truncated {
                let reply = mesh
                    .query_tcp(addr, &msg, t_tcp)
                    .map_err(|e| e.to_string())?;
                out = synth::parse_step3_reply(&reply, id);
            }
            Ok::<_, String>(out)
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r)
    }

    /// Remember a failed server with a growing backoff.
    fn mark_down(&self, npub: Npub, now: u64) {
        // The streak is forgotten once the entry expires: a server that has
        // not failed for a whole maximum window starts over.
        // Whatever its last answer proved no longer holds: the zone-record
        // fallback must echo it like any other target.
        self.reachable.remove(&npub);
        let prev = self.down.get(&npub, now);
        if prev.is_some_and(|d| now < d.retry_at) {
            // Already marked for this outage by a concurrent lookup of
            // another name: one outage counts once.
            return;
        }
        let failures = prev.map_or(0, |d| d.failures) + 1;
        let window = self
            .cfg
            .server_backoff
            .saturating_mul(3u32.saturating_pow(failures - 1))
            .min(self.cfg.server_backoff_max);
        let down = Down {
            failures,
            retry_at: now + window.as_secs(),
        };
        self.down
            .put(npub, down, window + self.cfg.server_backoff_max, now);
    }

    /// No domain server answered: resolve `q` from a published zone record
    /// instead (spec §3.3, §6) — the newest by any of the domain's servers.
    /// Every target has to answer an echo, since nothing proved any of them
    /// reachable.
    async fn via_zone_record(&self, q: &Query, servers: &[Binding]) -> Option<Npub> {
        let first = servers.first()?;
        let dom = &first.domain;
        let now = crate::now();
        let zone = match self.zones.get(dom, now) {
            Some(z) => z,
            None => {
                // The domain was vouched for when it was pinned, so asking
                // relays about it discloses nothing new (spec §8).
                let scope = if self.is_online() {
                    RelayScope::AfterHit
                } else {
                    RelayScope::Offline
                };
                let mut best: Option<ZoneRecord> = None;
                for server in servers {
                    let events = self.claims.fetch_zone(dom, server.npub, scope).await;
                    if let Some(z) =
                        policy::ingest_zone(self.pins.as_ref(), dom, server.npub, &events, now)
                        && best.as_ref().is_none_or(|b| b.created_at < z.created_at)
                    {
                        best = Some(z);
                    }
                }
                let ttl = if best.is_some() {
                    cache::CLAIM_TTL
                } else {
                    cache::RELAY_MISS_TTL
                };
                self.zones.put(dom.clone(), best.clone(), ttl, now);
                best
            }
        };
        let zone = zone?;
        let label = domain::relative_label(&q.name, dom)?;
        let target = zone.lookup(label)?;
        tracing::info!(name = %q.name, npub = %target, "domain server unreachable; answering from its zone record");
        self.deliverable(q, target, false).await
    }

    /// Register `target` with the local node and, unless `proven` (the
    /// node just answered step 3), require an echo reply.
    async fn deliverable(&self, q: &Query, target: Npub, proven: bool) -> Option<Npub> {
        if !self.ensure_registered(target).await {
            return None;
        }
        if proven || self.ensure_reachable(target).await {
            Some(target)
        } else {
            tracing::info!(name = %q.name, npub = %target, "target node not reachable through the local fips node; using the legacy answer");
            None
        }
    }

    async fn ensure_reachable(&self, npub: Npub) -> bool {
        let now = crate::now();
        if let Some(known) = self.reachable.get(&npub, now) {
            return known;
        }
        let mesh = self.mesh.clone();
        let t = self.cfg.reach_timeout;
        let ok = tokio::task::spawn_blocking(move || mesh.reachable(npub, t))
            .await
            .unwrap_or(false);
        let ttl = if ok {
            REACHABLE_TTL
        } else {
            Duration::from_secs(30)
        };
        self.reachable.put(npub, ok, ttl, now);
        ok
    }

    async fn ensure_registered(&self, npub: Npub) -> bool {
        let now = crate::now();
        if self.registered.get(&npub, now).is_some() {
            return true;
        }
        let mesh = self.mesh.clone();
        let t = self.cfg.register_timeout;
        let ok = tokio::task::spawn_blocking(move || mesh.register(npub, t))
            .await
            .unwrap_or(false);
        if ok {
            self.registered.put(npub, (), Duration::from_secs(240), now);
        }
        ok
    }
}

fn query_id(name: &str, now: u64) -> u16 {
    // Not security-relevant on the mesh (spec §6: the source is
    // authenticated); just distinct across concurrent lookups.
    let mut h: u32 = now as u32;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    (h ^ (h >> 16)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubdom_core::synth::{QTYPE_A, QTYPE_AAAA, build_query, parse_step3_reply, server_reply};
    use pubdom_core::txt::TxtRecord;
    use pubdom_core::{Claim, KIND_CLAIM, MemoryPinStore, Method};
    use std::collections::HashMap;
    use std::net::SocketAddrV6;
    use std::sync::Mutex;

    fn npub(b: u8) -> Npub {
        Npub::from_bytes([b; 32])
    }

    struct FakeTxt(Mutex<HashMap<String, TxtLookup>>);
    impl TxtSource for FakeTxt {
        async fn lookup(&self, domain: &str) -> (TxtLookup, Option<u32>) {
            let r = self.0.lock().unwrap().get(domain).cloned();
            (
                r.unwrap_or(TxtLookup::Miss {
                    method: Method::DnsSingle,
                }),
                Some(300),
            )
        }
    }

    struct FakeClaims(Vec<Event>, Mutex<Vec<(String, RelayScope)>>);
    impl ClaimSource for FakeClaims {
        async fn fetch_claims(&self, domain: &str, scope: RelayScope) -> Vec<Event> {
            self.1.lock().unwrap().push((domain.into(), scope));
            self.0
                .iter()
                .filter(|e| e.kind == KIND_CLAIM && e.tags[0][1] == domain)
                .cloned()
                .collect()
        }
        async fn fetch_zone(&self, domain: &str, author: Npub, scope: RelayScope) -> Vec<Event> {
            self.1
                .lock()
                .unwrap()
                .push((format!("zone:{domain}"), scope));
            self.0
                .iter()
                .filter(|e| {
                    e.kind == pubdom_core::KIND_ZONE
                        && e.tags[0][1] == domain
                        && e.pubkey == author.to_hex()
                })
                .cloned()
                .collect()
        }
    }

    /// A mesh with one domain server (npub 1) serving `www` → self and
    /// `git` → npub 2, and a responder that knows every npub.
    struct FakeMesh {
        queries: Mutex<Vec<SocketAddrV6>>,
        registered: Mutex<Vec<Npub>>,
        echoes: Mutex<Vec<Npub>>,
        unreachable: Vec<Npub>,
        /// Domain servers whose DNS does not answer (the node may still ping).
        down: Vec<Npub>,
    }
    impl MeshDns for FakeMesh {
        fn query_udp(
            &self,
            server: SocketAddrV6,
            msg: &[u8],
            _: Duration,
        ) -> std::io::Result<Vec<u8>> {
            self.queries.lock().unwrap().push(server);
            // Any of the first few npubs may be a server; they all serve the
            // same zone.
            let which = (1..=4).find(|i| npub(*i).fips_address() == *server.ip());
            let which = which.expect("a query to an address that is not a server");
            if self.down.contains(&npub(which)) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no answer",
                ));
            }
            let q = synth::parse_query(msg).unwrap();
            let target = match q.name.as_str() {
                "www.example.org" => Some(npub(1)),
                "git.example.org" => Some(npub(2)),
                _ => None,
            };
            Ok(server_reply(msg, target, 120).unwrap())
        }
        fn query_tcp(&self, _: SocketAddrV6, _: &[u8], _: Duration) -> std::io::Result<Vec<u8>> {
            unreachable!("nothing is truncated here")
        }
        fn register(&self, npub: Npub, _: Duration) -> bool {
            self.registered.lock().unwrap().push(npub);
            true
        }
        fn reachable(&self, npub: Npub, _: Duration) -> bool {
            self.echoes.lock().unwrap().push(npub);
            !self.unreachable.contains(&npub)
        }
    }

    fn claim_event(author: Npub, domain: &str) -> Event {
        Event {
            kind: KIND_CLAIM,
            pubkey: author.to_hex(),
            created_at: crate::now() - 10,
            tags: Claim::tags(domain, 5355, None),
        }
    }

    fn resolver(
        txt: HashMap<String, TxtLookup>,
        claims: Vec<Event>,
        pins: Arc<dyn PinStore>,
        unreachable: Vec<Npub>,
        allow_unverified: bool,
    ) -> (Resolver<FakeTxt, FakeClaims>, Arc<FakeMesh>) {
        let mesh = Arc::new(FakeMesh {
            queries: Mutex::new(vec![]),
            registered: Mutex::new(vec![]),
            echoes: Mutex::new(vec![]),
            unreachable,
            down: vec![],
        });
        let cfg = ResolverConfig {
            allow_unverified_offline: allow_unverified,
            ..Default::default()
        };
        let r = Resolver::new(
            cfg,
            pins,
            FakeTxt(Mutex::new(txt)),
            FakeClaims(claims, Mutex::new(vec![])),
            mesh.clone(),
        );
        (r, mesh)
    }

    fn hit(author: Npub) -> TxtLookup {
        TxtLookup::Hit {
            records: vec![TxtRecord {
                npub: author,
                port: Some(5355),
            }],
            method: Method::Dnssec,
        }
    }

    #[tokio::test]
    async fn online_first_visit_verifies_pins_and_answers_aaaa() {
        let pins: Arc<MemoryPinStore> = Arc::new(MemoryPinStore::new());
        let (r, mesh) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            pins.clone(),
            vec![],
            false,
        );
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        let LookupResult::Answer(a) = r.lookup(&q).await else {
            panic!("expected answer")
        };
        assert_eq!(
            parse_step3_reply(&a, 1),
            Step3Outcome::Node {
                npub: npub(1),
                ttl: ANSWER_TTL_SECS
            }
        );
        let pin = &pins.get("example.org")[0];
        assert_eq!((pin.npub, pin.method), (npub(1), Method::Dnssec));
        assert_eq!(mesh.queries.lock().unwrap().len(), 1);
        // Second lookup of the same name: served from caches, no mesh query.
        let q = build_query(2, "www.example.org", QTYPE_A).unwrap();
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
        assert_eq!(mesh.queries.lock().unwrap().len(), 1);
        // Relays were asked only after the TXT hit, and only online.
        assert_eq!(
            r.claims.1.lock().unwrap().as_slice(),
            &[("example.org".to_string(), RelayScope::AfterHit)]
        );
    }

    #[tokio::test]
    async fn dns_unreachable_while_online_asks_mesh_relays_only() {
        struct Dead;
        impl TxtSource for Dead {
            async fn lookup(&self, _: &str) -> (TxtLookup, Option<u32>) {
                (TxtLookup::Unreachable, None)
            }
        }
        let mesh = Arc::new(FakeMesh {
            queries: Mutex::new(vec![]),
            registered: Mutex::new(vec![]),
            echoes: Mutex::new(vec![]),
            unreachable: vec![],
            down: vec![],
        });
        let r = Resolver::new(
            ResolverConfig::default(),
            Arc::new(MemoryPinStore::new()),
            Dead,
            FakeClaims(vec![], Mutex::new(vec![])),
            mesh,
        );
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        let asked = r.claims.1.lock().unwrap().clone();
        assert!(!asked.is_empty());
        assert!(
            asked.iter().all(|(_, s)| *s == RelayScope::MeshOnly),
            "{asked:?}"
        );
    }

    #[tokio::test]
    async fn concurrent_first_lookups_decide_once() {
        let pins: Arc<MemoryPinStore> = Arc::new(MemoryPinStore::new());
        let (r, mesh) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            pins,
            vec![],
            false,
        );
        let r = Arc::new(r);
        let mut tasks = Vec::new();
        for (i, qt) in [QTYPE_A, QTYPE_AAAA, 65u16].iter().enumerate() {
            let r = r.clone();
            let q = build_query(i as u16 + 1, "www.example.org", *qt).unwrap();
            tasks.push(tokio::spawn(async move { r.lookup(&q).await }));
        }
        for t in tasks {
            assert!(matches!(t.await.unwrap(), LookupResult::Answer(_)));
        }
        assert_eq!(
            r.claims.1.lock().unwrap().len(),
            1,
            "one relay fetch for three concurrent queries"
        );
        assert_eq!(mesh.queries.lock().unwrap().len(), 1, "one step 3 query");
    }

    #[tokio::test]
    async fn no_txt_is_passthrough_and_relays_are_never_asked() {
        let (r, mesh) = resolver(
            HashMap::new(),
            vec![claim_event(npub(1), "example.org")],
            Arc::new(MemoryPinStore::new()),
            vec![],
            false,
        );
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        assert!(r.claims.1.lock().unwrap().is_empty(), "privacy gate");
        assert!(mesh.queries.lock().unwrap().is_empty());
        // Public suffixes and unknown TLDs never even start.
        assert_eq!(
            r.lookup(&build_query(2, "ch", QTYPE_AAAA).unwrap()).await,
            LookupResult::Passthrough
        );
        assert_eq!(
            r.lookup(&build_query(3, "home.fips", QTYPE_AAAA).unwrap())
                .await,
            LookupResult::Passthrough
        );
    }

    #[tokio::test]
    async fn bound_domain_but_name_not_served_is_passthrough() {
        let (r, _) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            Arc::new(MemoryPinStore::new()),
            vec![],
            false,
        );
        let q = build_query(1, "mail.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(
            r.lookup(&q).await,
            LookupResult::Passthrough,
            "NXDOMAIN from step 3 means legacy"
        );
    }

    #[tokio::test]
    async fn unreachable_target_node_is_passthrough() {
        // git → npub 2, which the local node cannot reach.
        let (r, mesh) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            Arc::new(MemoryPinStore::new()),
            vec![npub(2)],
            false,
        );
        let q = build_query(1, "git.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        // The verdict is remembered: the A query that follows does not
        // wait out another echo budget.
        let q = build_query(2, "git.example.org", QTYPE_A).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        assert_eq!(
            mesh.echoes.lock().unwrap().len(),
            1,
            "one echo for two queries"
        );
    }

    #[tokio::test]
    async fn offline_pinned_domain_resolves_without_dns_or_relays() {
        let pins: Arc<MemoryPinStore> = Arc::new(MemoryPinStore::new());
        pins.put(Binding {
            domain: "example.org".into(),
            npub: npub(1),
            port: 5355,
            method: Method::Dns,
            verified_at: 1,
        });
        let (r, _) = resolver(HashMap::new(), vec![], pins, vec![], false);
        r.set_online(false);
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
        assert!(
            r.claims.1.lock().unwrap().is_empty(),
            "pinned offline: no relay round trip at all"
        );
    }

    #[tokio::test]
    async fn offline_unpinned_claim_is_refused_unless_opted_in() {
        let claims = vec![claim_event(npub(1), "example.org")];
        let (r, _) = resolver(
            HashMap::new(),
            claims.clone(),
            Arc::new(MemoryPinStore::new()),
            vec![],
            false,
        );
        r.set_online(false);
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        let asked = r.claims.1.lock().unwrap().clone();
        assert!(
            asked.iter().all(|(_, s)| *s == RelayScope::Offline),
            "offline scope"
        );
        assert!(asked.iter().any(|(d, _)| d == "example.org"));

        let (r, _) = resolver(
            HashMap::new(),
            claims,
            Arc::new(MemoryPinStore::new()),
            vec![],
            true,
        );
        r.set_online(false);
        assert!(
            matches!(r.lookup(&q).await, LookupResult::Answer(_)),
            "opt-in marker path"
        );
    }

    #[tokio::test]
    async fn other_record_types_for_a_bound_name_get_nodata() {
        let (r, _) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            Arc::new(MemoryPinStore::new()),
            vec![],
            false,
        );
        let q = build_query(1, "www.example.org", 65).unwrap(); // HTTPS
        let LookupResult::Answer(a) = r.lookup(&q).await else {
            panic!()
        };
        let p = simple_dns::Packet::parse(&a).unwrap();
        assert!(p.answers.is_empty());
        assert_eq!(p.rcode(), simple_dns::RCODE::NoError);
    }

    fn zone_event(
        author: Npub,
        domain: &str,
        names: &[(&str, pubdom_core::claim::Target)],
    ) -> Event {
        let names: Vec<(String, pubdom_core::claim::Target)> = names
            .iter()
            .map(|(l, t)| (l.to_string(), t.clone()))
            .collect();
        Event {
            kind: pubdom_core::KIND_ZONE,
            pubkey: author.to_hex(),
            created_at: crate::now() - 10,
            tags: pubdom_core::claim::ZoneRecord::tags(domain, &names),
        }
    }

    #[tokio::test]
    async fn server_down_resolves_from_the_zone_record() {
        use pubdom_core::claim::Target;
        let pins: Arc<MemoryPinStore> = Arc::new(MemoryPinStore::new());
        pins.put(Binding {
            domain: "example.org".into(),
            npub: npub(1),
            port: 5355,
            method: Method::Dnssec,
            verified_at: 1,
        });
        let mesh = Arc::new(FakeMesh {
            queries: Mutex::new(vec![]),
            registered: Mutex::new(vec![]),
            echoes: Mutex::new(vec![]),
            unreachable: vec![npub(1)], // the server's node is gone entirely
            down: vec![npub(1)],
        });
        let events = vec![zone_event(
            npub(1),
            "example.org",
            &[
                ("git", Target::Node(npub(2))),
                ("www", Target::Author),
                ("mail", Target::Legacy),
            ],
        )];
        let r = Resolver::new(
            ResolverConfig::default(),
            pins,
            FakeTxt(Mutex::new(HashMap::new())),
            FakeClaims(events, Mutex::new(vec![])),
            mesh.clone(),
        );
        r.set_online(false);
        // git → another node, which answers an echo: over fips.
        let q = build_query(1, "git.example.org", QTYPE_AAAA).unwrap();
        let LookupResult::Answer(a) = r.lookup(&q).await else {
            panic!("git should resolve from the zone record")
        };
        assert_eq!(
            parse_step3_reply(&a, 1),
            Step3Outcome::Node {
                npub: npub(2),
                ttl: ANSWER_TTL_SECS
            }
        );
        assert!(
            mesh.echoes.lock().unwrap().contains(&npub(2)),
            "zone targets must answer an echo"
        );
        // www → the server itself, which is down: legacy.
        let q = build_query(2, "www.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        // mail → legacy by the zone; unknown → not in the zone.
        assert_eq!(
            r.lookup(&build_query(3, "mail.example.org", QTYPE_AAAA).unwrap())
                .await,
            LookupResult::Passthrough
        );
        assert_eq!(
            r.lookup(&build_query(4, "other.example.org", QTYPE_AAAA).unwrap())
                .await,
            LookupResult::Passthrough
        );
        // One relay fetch for the zone, in the offline scope.
        let asked = r.claims.1.lock().unwrap().clone();
        assert_eq!(
            asked
                .iter()
                .filter(|(d, _)| d == "zone:example.org")
                .count(),
            1
        );
        assert!(asked.iter().all(|(_, s)| *s == RelayScope::Offline));
    }

    #[tokio::test]
    async fn nxdomain_from_a_live_server_never_consults_the_zone_record() {
        use pubdom_core::claim::Target;
        let events = vec![
            claim_event(npub(1), "example.org"),
            zone_event(npub(1), "example.org", &[("mail", Target::Node(npub(2)))]),
        ];
        let (r, _) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            events,
            Arc::new(MemoryPinStore::new()),
            vec![],
            false,
        );
        let q = build_query(1, "mail.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(
            r.lookup(&q).await,
            LookupResult::Passthrough,
            "the live server's NXDOMAIN wins"
        );
        assert!(
            !r.claims
                .1
                .lock()
                .unwrap()
                .iter()
                .any(|(d, _)| d.starts_with("zone:"))
        );
    }

    /// Two servers named by the TXT record, both claiming: both are pinned;
    /// when the primary's DNS stops answering, the second one answers, and
    /// the primary is skipped for its backoff window before being retried.
    #[tokio::test]
    async fn redundant_servers_fail_over_and_retry_after_the_backoff() {
        let pins: Arc<MemoryPinStore> = Arc::new(MemoryPinStore::new());
        let two = TxtLookup::Hit {
            records: vec![
                TxtRecord {
                    npub: npub(1),
                    port: Some(5355),
                },
                TxtRecord {
                    npub: npub(2),
                    port: Some(5355),
                },
            ],
            method: Method::Dnssec,
        };
        let mesh = Arc::new(FakeMesh {
            queries: Mutex::new(vec![]),
            registered: Mutex::new(vec![]),
            echoes: Mutex::new(vec![]),
            unreachable: vec![],
            down: vec![npub(1)],
        });
        let cfg = ResolverConfig {
            server_backoff: Duration::from_secs(300),
            ..Default::default()
        };
        let r = Resolver::new(
            cfg,
            pins.clone(),
            FakeTxt(Mutex::new(HashMap::from([(
                "example.org".to_string(),
                two,
            )]))),
            FakeClaims(
                vec![
                    claim_event(npub(1), "example.org"),
                    claim_event(npub(2), "example.org"),
                ],
                Mutex::new(vec![]),
            ),
            mesh.clone(),
        );
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
        let servers = pins.get("example.org");
        assert_eq!(servers.len(), 2, "both named servers are pinned");
        let asked: Vec<SocketAddrV6> = mesh.queries.lock().unwrap().clone();
        assert_eq!(asked.len(), 3, "primary (udp + retry), then the second");
        assert_eq!(asked[0].ip(), &npub(1).fips_address());
        assert_eq!(asked[2].ip(), &npub(2).fips_address());
        // A second name: the primary is in its backoff window and skipped.
        let q = build_query(2, "git.example.org", QTYPE_AAAA).unwrap();
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
        let asked = mesh.queries.lock().unwrap().clone();
        assert_eq!(asked.len(), 4, "one query, straight to the second server");
        assert_eq!(asked[3].ip(), &npub(2).fips_address());
    }

    #[tokio::test]
    async fn a_failed_server_is_retried_once_its_backoff_expires() {
        let pins: Arc<MemoryPinStore> = Arc::new(MemoryPinStore::new());
        pins.put(Binding {
            domain: "example.org".into(),
            npub: npub(1),
            port: 5355,
            method: Method::Dns,
            verified_at: 1,
        });
        pins.put(Binding {
            domain: "example.org".into(),
            npub: npub(2),
            port: 5355,
            method: Method::Dns,
            verified_at: 1,
        });
        let mesh = Arc::new(FakeMesh {
            queries: Mutex::new(vec![]),
            registered: Mutex::new(vec![]),
            echoes: Mutex::new(vec![]),
            unreachable: vec![],
            down: vec![npub(1)],
        });
        // A zero backoff: the window has expired by the next lookup.
        let cfg = ResolverConfig {
            server_backoff: Duration::ZERO,
            ..Default::default()
        };
        let r = Resolver::new(
            cfg,
            pins,
            FakeTxt(Mutex::new(HashMap::new())),
            FakeClaims(vec![], Mutex::new(vec![])),
            mesh.clone(),
        );
        r.set_online(false);
        for (i, name) in ["www.example.org", "git.example.org"].iter().enumerate() {
            let q = build_query(i as u16 + 1, name, QTYPE_AAAA).unwrap();
            assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
        }
        let asked = mesh.queries.lock().unwrap().clone();
        let to_primary = asked
            .iter()
            .filter(|a| a.ip() == &npub(1).fips_address())
            .count();
        assert_eq!(
            to_primary, 4,
            "the primary is tried again (udp + retry) on the second lookup"
        );
    }

    #[test]
    fn backoff_grows_with_failures_in_a_row_and_is_capped() {
        let (r, _) = resolver(
            HashMap::new(),
            vec![],
            Arc::new(MemoryPinStore::new()),
            vec![],
            false,
        );
        // Defaults: 5 min, then three times as long, up to 3 h.
        let mut now = 1_000;
        let mut windows = Vec::new();
        for _ in 0..6 {
            r.mark_down(npub(1), now);
            let d = r.down.get(&npub(1), now).unwrap();
            windows.push(d.retry_at - now);
            // The failed retry happens once the window has passed.
            now = d.retry_at;
        }
        assert_eq!(windows, vec![300, 900, 2700, 8100, 10800, 10800]);
        // Concurrent lookups of other names failing on the same outage
        // count once.
        r.mark_down(npub(1), now - 1);
        assert_eq!(r.down.get(&npub(1), now).unwrap().retry_at, now);
        // An answer clears the streak.
        r.down.remove(&npub(1));
        r.mark_down(npub(1), now);
        assert_eq!(r.down.get(&npub(1), now).unwrap().retry_at - now, 300);
    }

    #[tokio::test]
    async fn the_server_answering_for_itself_needs_no_echo_for_other_types() {
        // The server (npub 1) filters ICMPv6 echo. Its step 3 answer proves
        // it reachable, for the AAAA query and for the A query that follows
        // from the cache — else A would fall back to the public address
        // while AAAA went to the mesh.
        let (r, mesh) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            Arc::new(MemoryPinStore::new()),
            vec![npub(1)],
            false,
        );
        for (id, qtype) in [(1, QTYPE_AAAA), (2, QTYPE_A)] {
            let q = build_query(id, "www.example.org", qtype).unwrap();
            assert!(
                matches!(r.lookup(&q).await, LookupResult::Answer(_)),
                "qtype {qtype}"
            );
        }
        assert!(mesh.echoes.lock().unwrap().is_empty());
        assert_eq!(
            mesh.queries.lock().unwrap().len(),
            1,
            "A came from the cache"
        );
        // Once that proof has lapsed, the server is asked again — not
        // pinged — and answers.
        r.reachable.remove(&npub(1));
        let q = build_query(3, "www.example.org", QTYPE_A).unwrap();
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
        assert!(mesh.echoes.lock().unwrap().is_empty());
        assert_eq!(mesh.queries.lock().unwrap().len(), 2, "re-asked");
        // A server that fails loses its proof: the zone-record fallback
        // must echo it.
        r.mark_down(npub(1), crate::now());
        assert_eq!(r.reachable.get(&npub(1), crate::now()), None);
    }

    #[tokio::test]
    async fn non_address_types_stay_legacy_even_under_a_wildcard() {
        // MX, TXT (SPF/DMARC), SRV … of a bound name go to the public DNS
        // untouched and cost no TXT, relay or mesh round trip.
        let (r, mesh) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            Arc::new(MemoryPinStore::new()),
            vec![],
            false,
        );
        for qtype in [15u16, 16, 33, 2, 6] {
            let q = build_query(1, "www.example.org", qtype).unwrap();
            assert_eq!(
                r.lookup(&q).await,
                LookupResult::Passthrough,
                "qtype {qtype}"
            );
        }
        assert!(r.claims.1.lock().unwrap().is_empty());
        assert!(mesh.queries.lock().unwrap().is_empty());
    }
}
