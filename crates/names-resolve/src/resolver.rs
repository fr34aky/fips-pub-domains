//! `lookup(query) → answer | passthrough`: spec §5 and §7 wired to the
//! adapters, with the budgets of plan-phase1 §6.
//!
//! Invariant (spec §7): the only way an application receives a mesh address
//! is a verified (or pinned, or explicitly opted-in unverified) binding
//! **and** a positive step 3 answer **and** a registered, reachable node.
//! Every other outcome is [`LookupResult::Passthrough`] — the legacy path —
//! and never an error of our making.

use crate::mesh::MeshDns;
use crate::relay::RelayClient;
use crate::txt::TxtVerifier;
use names_core::cache::{self, TtlCache};
use names_core::claim::Event;
use names_core::policy::{self, Decision, Input, NoProofs, PinUpdate, Reason, TxtLookup};
use names_core::synth::{self, Query, Step3Outcome};
use names_core::{ANSWER_TTL_SECS, Binding, Npub, PinStore, domain};
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Where the TXT record comes from — hickory in production, a table in tests.
pub trait TxtSource: Send + Sync {
    fn lookup(&self, domain: &str) -> impl Future<Output = (TxtLookup, Option<u32>)> + Send;
}

/// Where claims come from — relays in production, a table in tests.
pub trait ClaimSource: Send + Sync {
    fn fetch_claims(&self, domain: &str, online: bool) -> impl Future<Output = Vec<Event>> + Send;
}

impl TxtSource for TxtVerifier {
    async fn lookup(&self, domain: &str) -> (TxtLookup, Option<u32>) {
        TxtVerifier::lookup(self, domain).await
    }
}

impl ClaimSource for RelayClient {
    async fn fetch_claims(&self, domain: &str, online: bool) -> Vec<Event> {
        RelayClient::fetch_claims(self, domain, online).await
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
    /// Empty: the system's resolvers.
    pub upstreams: Vec<IpAddr>,
    pub dnssec: bool,
    pub allow_unverified_offline: bool,
    pub txt_timeout: Duration,
    pub relay_timeout: Duration,
    pub step3_timeout: Duration,
    pub tcp_timeout: Duration,
    pub register_timeout: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            public_relays: vec!["wss://relay.damus.io".into(), "wss://nos.lol".into()],
            mesh_relays: Vec::new(),
            upstreams: Vec::new(),
            dnssec: true,
            allow_unverified_offline: false,
            txt_timeout: Duration::from_millis(1500),
            relay_timeout: Duration::from_secs(2),
            step3_timeout: Duration::from_secs(1),
            tcp_timeout: Duration::from_secs(3),
            register_timeout: Duration::from_secs(1),
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
    Use(Binding, bool),
    NotOverFips,
}

#[derive(Clone)]
enum CachedStep3 {
    Node(Npub),
    NotOverFips,
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
}

impl<T: TxtSource, C: ClaimSource> Resolver<T, C> {
    pub fn new(cfg: ResolverConfig, pins: Arc<dyn PinStore>, txt: T, claims: C, mesh: Arc<dyn MeshDns>) -> Self {
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
        }
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
    }

    /// The whole of spec §5–§7 for one application query.
    pub async fn lookup(&self, query: &[u8]) -> LookupResult {
        let Some(q) = synth::parse_query(query) else {
            return LookupResult::Passthrough;
        };
        let candidates = domain::candidates(&q.name);
        if candidates.is_empty() {
            return LookupResult::Passthrough;
        }
        // Longest claim wins (spec §5.2).
        let mut chosen: Option<(String, Binding, bool)> = None;
        for d in candidates.iter().rev() {
            match self.decision(d).await {
                CachedDecision::Use(b, unverified) => {
                    chosen = Some((d.clone(), b, unverified));
                    break;
                }
                CachedDecision::NotOverFips => {}
            }
        }
        let Some((bound_domain, binding, unverified)) = chosen else {
            return LookupResult::Passthrough;
        };
        if unverified {
            tracing::warn!(name = %q.name, domain = %bound_domain, npub = %binding.npub, "resolving through an UNVERIFIED binding (opt-in)");
        }
        match self.step3(&q, &binding).await {
            Some(npub) => self.answer(&q, npub),
            None => LookupResult::Passthrough,
        }
    }

    fn answer(&self, q: &Query, npub: Npub) -> LookupResult {
        let ttl = ANSWER_TTL_SECS;
        let bytes = match q.qtype {
            synth::QTYPE_A | synth::QTYPE_AAAA | synth::QTYPE_ANY | synth::QTYPE_CNAME => synth::build_answer(q, npub, ttl),
            // HTTPS/SVCB and the like: a public record could carry address
            // hints for the legacy path. NODATA keeps the mesh the only path.
            _ => synth::build_rcode(q, simple_dns::RCODE::NoError),
        };
        match bytes {
            Some(b) => LookupResult::Answer(b),
            None => LookupResult::Passthrough,
        }
    }

    async fn decision(&self, d: &str) -> CachedDecision {
        let now = crate::now();
        if let Some(c) = self.decisions.get(&d.to_string(), now) {
            return c;
        }
        let pin = self.pins.get(d);
        let online = self.is_online();
        let (txt, txt_ttl) = if online { self.txt.lookup(d).await } else { (TxtLookup::Unreachable, None) };
        let events = match &txt {
            // The privacy gate (spec §8): relays only after a TXT hit …
            TxtLookup::Hit { .. } => self.claims.fetch_claims(d, true).await,
            TxtLookup::Miss => Vec::new(),
            // … or offline, where the claim stands in for the record (§5.5).
            TxtLookup::Unreachable => self.claims.fetch_claims(d, false).await,
        };
        let claims = policy::ingest_claims(self.pins.as_ref(), d, &events, now);
        let is_unreachable = matches!(txt, TxtLookup::Unreachable);
        let outcome = policy::decide(Input {
            domain: d,
            pin,
            txt,
            claims: &claims,
            now,
            allow_unverified_offline: self.cfg.allow_unverified_offline,
            proofs: &NoProofs,
        });
        match &outcome.pin_update {
            PinUpdate::Keep => {}
            PinUpdate::Put(b) => {
                tracing::info!(domain = d, npub = %b.npub, method = ?b.method, "binding verified and pinned");
                self.pins.put(b.clone());
            }
            PinUpdate::Forget => {
                tracing::info!(domain = d, "TXT record gone: binding unpinned");
                self.pins.forget(d);
            }
        }
        let (cached, ttl) = match outcome.decision {
            Decision::Bound(b) => {
                let ttl = txt_ttl.map(|t| Duration::from_secs(t.into()).min(cache::TXT_HIT_MAX_TTL)).unwrap_or(cache::CLAIM_TTL);
                (CachedDecision::Use(b, false), ttl)
            }
            Decision::Unverified(b) => (CachedDecision::Use(b, true), cache::RELAY_MISS_TTL),
            Decision::NotOverFips(reason) => {
                tracing::debug!(domain = d, ?reason, "not over fips");
                let ttl = match reason {
                    Reason::NoTxt | Reason::PublicSuffix => cache::TXT_MISS_TTL,
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
    async fn step3(&self, q: &Query, binding: &Binding) -> Option<Npub> {
        let now = crate::now();
        let cached = match self.step3.get(&q.name, now) {
            Some(CachedStep3::Node(n)) => Some(n),
            Some(CachedStep3::NotOverFips) => return None,
            None => {
                if !self.ensure_registered(binding.npub).await {
                    tracing::debug!(npub = %binding.npub, "domain server not reachable through the local node");
                    return None;
                }
                let msg = synth::build_query(query_id(&q.name, now), &q.name, synth::QTYPE_AAAA)?;
                let id = u16::from_be_bytes([msg[0], msg[1]]);
                let server = binding.server_addr();
                let mesh = self.mesh.clone();
                let (t_udp, t_tcp) = (self.cfg.step3_timeout, self.cfg.tcp_timeout);
                let outcome = tokio::task::spawn_blocking(move || {
                    let reply = match mesh.query_udp(server, &msg, t_udp) {
                        Ok(r) => r,
                        // One retry: a mesh path may still be settling.
                        Err(_) => mesh.query_udp(server, &msg, t_udp).map_err(|e| e.to_string())?,
                    };
                    let mut out = synth::parse_step3_reply(&reply, id);
                    if out == Step3Outcome::Truncated {
                        let reply = mesh.query_tcp(server, &msg, t_tcp).map_err(|e| e.to_string())?;
                        out = synth::parse_step3_reply(&reply, id);
                    }
                    Ok::<_, String>(out)
                })
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
                match outcome {
                    Ok(Step3Outcome::Node { npub, ttl }) => {
                        let ttl = Duration::from_secs(ttl.into()).min(cache::STEP3_MAX_TTL);
                        self.step3.put(q.name.clone(), CachedStep3::Node(npub), ttl, now);
                        Some(npub)
                    }
                    Ok(Step3Outcome::NotOverFips) => {
                        self.step3.put(q.name.clone(), CachedStep3::NotOverFips, Duration::from_secs(300), now);
                        return None;
                    }
                    Ok(other) => {
                        tracing::debug!(name = %q.name, ?other, "step 3 failed");
                        return None;
                    }
                    Err(e) => {
                        tracing::debug!(name = %q.name, error = %e, "step 3 failed");
                        return None;
                    }
                }
            }
        };
        let target = cached?;
        // The answer names a node; make it routable and, when it is not the
        // server we just talked to, take the registration as the reachability
        // check (spec §7).
        if self.ensure_registered(target).await { Some(target) } else { None }
    }

    async fn ensure_registered(&self, npub: Npub) -> bool {
        let now = crate::now();
        if self.registered.get(&npub, now).is_some() {
            return true;
        }
        let mesh = self.mesh.clone();
        let t = self.cfg.register_timeout;
        let ok = tokio::task::spawn_blocking(move || mesh.register(npub, t)).await.unwrap_or(false);
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
    use names_core::synth::{QTYPE_A, QTYPE_AAAA, build_query, parse_step3_reply, server_reply};
    use names_core::txt::TxtRecord;
    use names_core::{Claim, KIND_CLAIM, MemoryPinStore, Method};
    use std::collections::HashMap;
    use std::net::SocketAddrV6;
    use std::sync::Mutex;

    fn npub(b: u8) -> Npub {
        Npub::from_bytes([b; 32])
    }

    struct FakeTxt(Mutex<HashMap<String, TxtLookup>>);
    impl TxtSource for FakeTxt {
        async fn lookup(&self, domain: &str) -> (TxtLookup, Option<u32>) {
            (self.0.lock().unwrap().get(domain).cloned().unwrap_or(TxtLookup::Miss), Some(300))
        }
    }

    struct FakeClaims(Vec<Event>, Mutex<Vec<(String, bool)>>);
    impl ClaimSource for FakeClaims {
        async fn fetch_claims(&self, domain: &str, online: bool) -> Vec<Event> {
            self.1.lock().unwrap().push((domain.into(), online));
            self.0.iter().filter(|e| e.tags[0][1] == domain).cloned().collect()
        }
    }

    /// A mesh with one domain server (npub 1) serving `www` → self and
    /// `git` → npub 2, and a responder that knows every npub.
    struct FakeMesh {
        queries: Mutex<Vec<SocketAddrV6>>,
        registered: Mutex<Vec<Npub>>,
        unreachable: Vec<Npub>,
    }
    impl MeshDns for FakeMesh {
        fn query_udp(&self, server: SocketAddrV6, msg: &[u8], _: Duration) -> std::io::Result<Vec<u8>> {
            self.queries.lock().unwrap().push(server);
            assert_eq!(server.ip(), &npub(1).fips_address());
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
            !self.unreachable.contains(&npub)
        }
    }

    fn claim_event(author: Npub, domain: &str) -> Event {
        Event { kind: KIND_CLAIM, pubkey: author.to_hex(), created_at: crate::now() - 10, tags: Claim::tags(domain, 5355, None) }
    }

    fn resolver(
        txt: HashMap<String, TxtLookup>,
        claims: Vec<Event>,
        pins: Arc<dyn PinStore>,
        unreachable: Vec<Npub>,
        allow_unverified: bool,
    ) -> (Resolver<FakeTxt, FakeClaims>, Arc<FakeMesh>) {
        let mesh = Arc::new(FakeMesh { queries: Mutex::new(vec![]), registered: Mutex::new(vec![]), unreachable });
        let cfg = ResolverConfig { allow_unverified_offline: allow_unverified, ..Default::default() };
        let r = Resolver::new(cfg, pins, FakeTxt(Mutex::new(txt)), FakeClaims(claims, Mutex::new(vec![])), mesh.clone());
        (r, mesh)
    }

    fn hit(author: Npub) -> TxtLookup {
        TxtLookup::Hit { records: vec![TxtRecord { npub: author, port: Some(5355) }], method: Method::Dnssec }
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
        let LookupResult::Answer(a) = r.lookup(&q).await else { panic!("expected answer") };
        assert_eq!(parse_step3_reply(&a, 1), Step3Outcome::Node { npub: npub(1), ttl: ANSWER_TTL_SECS });
        let pin = pins.get("example.org").unwrap();
        assert_eq!((pin.npub, pin.method), (npub(1), Method::Dnssec));
        assert_eq!(mesh.queries.lock().unwrap().len(), 1);
        // Second lookup of the same name: served from caches, no mesh query.
        let q = build_query(2, "www.example.org", QTYPE_A).unwrap();
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
        assert_eq!(mesh.queries.lock().unwrap().len(), 1);
        // Relays were asked only after the TXT hit, and only online.
        assert_eq!(r.claims.1.lock().unwrap().as_slice(), &[("example.org".to_string(), true)]);
    }

    #[tokio::test]
    async fn no_txt_is_passthrough_and_relays_are_never_asked() {
        let (r, mesh) = resolver(HashMap::new(), vec![claim_event(npub(1), "example.org")], Arc::new(MemoryPinStore::new()), vec![], false);
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        assert!(r.claims.1.lock().unwrap().is_empty(), "privacy gate");
        assert!(mesh.queries.lock().unwrap().is_empty());
        // Public suffixes and unknown TLDs never even start.
        assert_eq!(r.lookup(&build_query(2, "ch", QTYPE_AAAA).unwrap()).await, LookupResult::Passthrough);
        assert_eq!(r.lookup(&build_query(3, "home.fips", QTYPE_AAAA).unwrap()).await, LookupResult::Passthrough);
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
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough, "NXDOMAIN from step 3 means legacy");
    }

    #[tokio::test]
    async fn unreachable_target_node_is_passthrough() {
        // git → npub 2, which the local node cannot reach.
        let (r, _) = resolver(
            HashMap::from([("example.org".to_string(), hit(npub(1)))]),
            vec![claim_event(npub(1), "example.org")],
            Arc::new(MemoryPinStore::new()),
            vec![npub(2)],
            false,
        );
        let q = build_query(1, "git.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
    }

    #[tokio::test]
    async fn offline_pinned_domain_resolves_without_dns_or_relays() {
        let pins: Arc<MemoryPinStore> = Arc::new(MemoryPinStore::new());
        pins.put(Binding { domain: "example.org".into(), npub: npub(1), port: 5355, method: Method::Dns, verified_at: 1 });
        let (r, _) = resolver(HashMap::new(), vec![], pins, vec![], false);
        r.set_online(false);
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)));
    }

    #[tokio::test]
    async fn offline_unpinned_claim_is_refused_unless_opted_in() {
        let claims = vec![claim_event(npub(1), "example.org")];
        let (r, _) = resolver(HashMap::new(), claims.clone(), Arc::new(MemoryPinStore::new()), vec![], false);
        r.set_online(false);
        let q = build_query(1, "www.example.org", QTYPE_AAAA).unwrap();
        assert_eq!(r.lookup(&q).await, LookupResult::Passthrough);
        let asked = r.claims.1.lock().unwrap().clone();
        assert!(asked.iter().all(|(_, online)| !online), "mesh relays asked, offline mode");
        assert!(asked.iter().any(|(d, _)| d == "example.org"));

        let (r, _) = resolver(HashMap::new(), claims, Arc::new(MemoryPinStore::new()), vec![], true);
        r.set_online(false);
        assert!(matches!(r.lookup(&q).await, LookupResult::Answer(_)), "opt-in marker path");
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
        let LookupResult::Answer(a) = r.lookup(&q).await else { panic!() };
        let p = simple_dns::Packet::parse(&a).unwrap();
        assert!(p.answers.is_empty());
        assert_eq!(p.rcode(), simple_dns::RCODE::NoError);
    }
}
