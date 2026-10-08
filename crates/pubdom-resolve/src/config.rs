//! The resolver's configuration file — shared by the daemon and the CLI,
//! and mirrored by the JSON the fips2go app passes to its shim. YAML, all
//! keys optional:
//!
//! ```yaml
//! listen: ["[::1]:5356", "127.0.0.1:5356"]
//! upstreams: ["9.9.9.9", "1.1.1.1"]            # empty: the system's
//! upstreams_from: /run/systemd/resolve/resolv.conf   # re-read periodically
//! dnssec: true
//! plain_probe: true                    # false: validate every "no record" too (needs dnssec)
//! public_relays: ["wss://relay.damus.io", "wss://nos.lol"]
//! mesh_relays: ["ws://npub1….fips:80"]   # by .fips name, never an [fd…] literal:
//!                                        # nostr-sdk mangles bracketed IPv6, and
//!                                        # resolving the name is what registers
//!                                        # the relay's identity with the node
//! responder: "[::1]:5354"                      # fips's .fips responder
//! mesh_bind: "fdd9:…"                          # this node's fips address
//! pins: /var/lib/fips-pubdom/pins.json
//! allow_unverified_offline: false
//! witnesses: ["npub1…", "npub1…"]      # whose attestations count offline (spec §3.2)
//! attestation_threshold: 2             # k: witnesses that must agree; 0 = off
//! budget_ms: 4500
//! control: /run/fips-pubdom/control.sock   # the control socket (fips-ui, `fips-pubdom ctl`); null: none
//! ```

use crate::mesh::KernelMeshDns;
use crate::pins::FilePinStore;
use crate::relay::RelayClient;
use crate::resolver::{Resolver, ResolverConfig};
use crate::txt::TxtVerifier;
use pubdom_core::Npub;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub upstreams: Vec<IpAddr>,
    pub upstreams_from: Option<PathBuf>,
    pub dnssec: bool,
    /// `false`: no plain probe for unpinned domains; every `_fips-dns`
    /// lookup is validated (`ResolverConfig::plain_probe`).
    pub plain_probe: bool,
    pub public_relays: Vec<String>,
    pub mesh_relays: Vec<String>,
    pub responder: SocketAddr,
    pub mesh_bind: Option<Ipv6Addr>,
    pub pins: PathBuf,
    pub allow_unverified_offline: bool,
    /// Witnesses whose attestations (kind 37198) count offline. Nobody
    /// else's are fetched, let alone believed (spec §3.2, §5.1 step 4).
    pub witnesses: Vec<Npub>,
    /// *k*: how many witnesses must attest a server. `0` turns
    /// attestations off even with witnesses configured.
    pub attestation_threshold: usize,
    pub budget_ms: u64,
    /// The control socket (docs/webui.md): status, pins, forget, flush,
    /// log, for fips-ui and `fips-pubdom ctl`. `null` for none. Created
    /// only if its directory exists.
    pub control: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        let d = ResolverConfig::default();
        Self {
            listen: vec![
                "[::1]:5356".parse().unwrap(),
                "127.0.0.1:5356".parse().unwrap(),
            ],
            upstreams: Vec::new(),
            upstreams_from: None,
            dnssec: d.dnssec,
            plain_probe: d.plain_probe,
            public_relays: d.public_relays,
            mesh_relays: d.mesh_relays,
            responder: "[::1]:5354".parse().unwrap(),
            mesh_bind: None,
            pins: PathBuf::from("/var/lib/fips-pubdom/pins.json"),
            allow_unverified_offline: false,
            witnesses: Vec::new(),
            attestation_threshold: d.attestation_threshold,
            budget_ms: 4500,
            control: Some(PathBuf::from("/run/fips-pubdom/control.sock")),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The file's text as the daemon loads it: unknown keys are errors.
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_yaml::from_str(text).map_err(|e| e.to_string())
    }

    /// The configuration as YAML, every key written out — what `validate
    /// config` prints so a tool sees the defaults it did not set.
    pub fn render(&self) -> String {
        serde_yaml::to_string(self).unwrap_or_default()
    }

    /// Load if present, defaults otherwise.
    pub fn load_or_default(path: &Path) -> Result<Self, String> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn budget(&self) -> Duration {
        Duration::from_millis(self.budget_ms)
    }

    /// The upstreams to forward to right now: the configured list, or the
    /// servers named in `upstreams_from` minus ourselves (in full mode the
    /// system's resolver configuration points back at us).
    pub fn current_upstreams(&self) -> Vec<IpAddr> {
        if !self.upstreams.is_empty() {
            return self.upstreams.clone();
        }
        let Some(path) = &self.upstreams_from else {
            return Vec::new();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        let own: Vec<IpAddr> = self.listen.iter().map(|a| a.ip()).collect();
        nameservers(&text)
            .into_iter()
            .filter(|ip| !own.contains(ip) && !ip.is_loopback())
            .collect()
    }

    /// Search domains the system's links carry (the `search` line of
    /// `upstreams_from`). On systemd-resolved a link's search domain is also
    /// a routing domain and the longest match wins, so names under these go
    /// to that link's resolver, not to the daemon — a LAN whose search
    /// domain is a bound domain shadows it entirely.
    pub fn link_search_domains(&self) -> Vec<String> {
        let Some(path) = &self.upstreams_from else {
            return Vec::new();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|l| keyword(l, "search"))
            .flat_map(|rest| rest.split_whitespace().map(str::to_owned))
            // `fips` is fips's own routing domain on its link: by design,
            // and never a bound domain (spec §5.2 rejects unknown TLDs).
            .filter(|d| d != "." && d != "fips")
            .collect()
    }

    pub fn resolver_config(&self) -> ResolverConfig {
        ResolverConfig {
            public_relays: self.public_relays.clone(),
            mesh_relays: self.mesh_relays.clone(),
            dnssec: self.dnssec,
            plain_probe: self.plain_probe,
            allow_unverified_offline: self.allow_unverified_offline,
            witnesses: self.witnesses.clone(),
            attestation_threshold: self.attestation_threshold,
            ..ResolverConfig::default()
        }
    }

    /// The production resolver: hickory + nostr-sdk + kernel sockets + the
    /// pin file. `upstreams` empty means "no legacy DNS": mesh-only node.
    pub async fn build_resolver(&self, upstreams: Vec<IpAddr>) -> Result<ProdResolver, String> {
        let rc = self.resolver_config();
        let txt = MaybeTxt::new(&upstreams, self.dnssec, rc.txt_timeout)?;
        let relays =
            RelayClient::new(&self.public_relays, &self.mesh_relays, rc.relay_timeout).await;
        let pins = FilePinStore::open(&self.pins).map_err(|e| e.to_string())?;
        let mesh = KernelMeshDns::new(self.responder, self.mesh_bind);
        let r = Resolver::new(rc, Arc::new(pins), txt, relays, Arc::new(mesh));
        r.set_online(!upstreams.is_empty());
        Ok(r)
    }
}

pub type ProdResolver = Resolver<MaybeTxt, RelayClient>;

/// `line` with `kw` stripped, if the line is that keyword's as glibc
/// reads resolv.conf: the keyword at the start of the line, followed by
/// a space or tab. An indented line or `nameserverX` is not a keyword
/// line to the system resolver, so it is none to us.
fn keyword<'a>(line: &'a str, kw: &str) -> Option<&'a str> {
    line.strip_prefix(kw)
        .filter(|rest| rest.starts_with([' ', '\t']))
}

/// The `nameserver` entries of a resolv.conf as glibc takes them (keyword
/// rule of [`keyword`], the address ended by whitespace, `;` or `#`, a
/// `%scope` suffix dropped), in order, each once. Loopback and the
/// daemon's own addresses are the caller's business; glibc's cap of three
/// servers is not applied, since the file may be read by resolved or
/// NetworkManager, which have none.
pub fn nameservers(text: &str) -> Vec<IpAddr> {
    collect_nameservers(text.lines().filter_map(|l| keyword(l, "nameserver")))
}

/// The `nameserver` entries as dnsmasq reads its resolv file: tokens
/// split on whitespace, so an indented line counts. For a file whose
/// only reader is dnsmasq.
pub fn nameservers_lenient(text: &str) -> Vec<IpAddr> {
    collect_nameservers(
        text.lines()
            .filter_map(|l| l.trim_start().strip_prefix("nameserver"))
            .filter(|rest| rest.starts_with([' ', '\t'])),
    )
}

fn collect_nameservers<'a>(rests: impl Iterator<Item = &'a str>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in rests
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|s| s.split([';', '#']).next().unwrap_or(""))
        .filter_map(|s| {
            s.split_once('%')
                .map_or(s, |(a, _)| a)
                .parse::<IpAddr>()
                .ok()
        })
    {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// A TXT source that may be absent (mesh-only node, or the system has no
/// resolvers right now) and can be swapped when the upstreams change — a
/// laptop that moves networks must verify against the new resolvers, not
/// keep asking the old ones until they time out.
pub struct MaybeTxt {
    dnssec: bool,
    /// The verifier and what it was built from, under one lock: a change
    /// to either part rebuilds it from both, and a rebuild that fails
    /// leaves all three as they were, so what is reported is what runs.
    parts: std::sync::Mutex<Parts>,
}

struct Parts {
    upstreams: Vec<IpAddr>,
    timeout: Duration,
    verifier: Option<Arc<TxtVerifier>>,
}

impl MaybeTxt {
    pub fn new(upstreams: &[IpAddr], dnssec: bool, timeout: Duration) -> Result<Self, String> {
        let me = Self {
            dnssec,
            parts: std::sync::Mutex::new(Parts {
                upstreams: Vec::new(),
                timeout,
                verifier: None,
            }),
        };
        me.set_upstreams(upstreams)?;
        Ok(me)
    }

    /// Replace the verifier; an empty list means "no legacy DNS" and every
    /// lookup is `Unreachable`. Nothing happens when the list is the same.
    pub fn set_upstreams(&self, upstreams: &[IpAddr]) -> Result<(), String> {
        let mut parts = self.parts.lock().unwrap();
        if parts.upstreams == upstreams && (upstreams.is_empty() || parts.verifier.is_some()) {
            return Ok(());
        }
        let verifier = Self::build(upstreams, self.dnssec, parts.timeout)?;
        parts.upstreams = upstreams.to_vec();
        parts.verifier = verifier;
        Ok(())
    }

    /// How long each upstream's TXT lookup may take before the upstream
    /// counts as unanswering (the verifier allows 200 ms on top). A host
    /// that knows the Internet is gone — the phone, from Android's network
    /// validation — shortens this so a first offline lookup fails into the
    /// mesh path within its budget, instead of skipping the lookup, which
    /// would also skip it on a network that works but was never validated.
    /// Nothing happens when the value is the same.
    pub fn set_timeout(&self, timeout: Duration) -> Result<(), String> {
        let mut parts = self.parts.lock().unwrap();
        if parts.timeout == timeout {
            return Ok(());
        }
        let verifier = Self::build(&parts.upstreams, self.dnssec, timeout)?;
        parts.timeout = timeout;
        parts.verifier = verifier;
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        self.parts.lock().unwrap().timeout
    }

    fn build(
        upstreams: &[IpAddr],
        dnssec: bool,
        timeout: Duration,
    ) -> Result<Option<Arc<TxtVerifier>>, String> {
        if upstreams.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Arc::new(TxtVerifier::new(
                upstreams, dnssec, timeout,
            )?)))
        }
    }

    fn current(&self) -> Option<Arc<TxtVerifier>> {
        self.parts.lock().unwrap().verifier.clone()
    }
}

impl crate::resolver::TxtSource for MaybeTxt {
    async fn lookup(&self, domain: &str) -> (pubdom_core::policy::TxtLookup, Option<u32>) {
        match self.current() {
            Some(t) => t.lookup(domain).await,
            None => (pubdom_core::policy::TxtLookup::Unreachable, None),
        }
    }

    async fn lookup_with(
        &self,
        domain: &str,
        first_denial: &(dyn Fn() + Sync),
    ) -> (pubdom_core::policy::TxtLookup, Option<u32>) {
        match self.current() {
            Some(t) => t.lookup_with(domain, first_denial).await,
            None => (pubdom_core::policy::TxtLookup::Unreachable, None),
        }
    }

    async fn probe(
        &self,
        domain: &str,
        first_denial: &(dyn Fn() + Sync),
    ) -> crate::resolver::Probe {
        match self.current() {
            Some(t) => t.probe(domain, first_denial).await,
            None => crate::resolver::Probe::Unreachable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams_from_filters_ourselves() {
        let dir = std::env::temp_dir().join(format!("fips-pubdom-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("resolv.conf");
        std::fs::write(&f, "# generated\nnameserver ::1\nnameserver 127.0.0.1\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nsearch lan fips\n").unwrap();
        let cfg = Config {
            upstreams_from: Some(f),
            ..Default::default()
        };
        assert_eq!(
            cfg.current_upstreams(),
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap()
            ]
        );
        assert_eq!(cfg.link_search_domains(), vec!["lan"]);
        let cfg = Config::default();
        assert!(cfg.current_upstreams().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn maybe_txt_rebuilds_from_both_parts_when_one_changes() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let t = MaybeTxt::new(&[ip("192.0.2.1")], false, Duration::from_millis(1500)).unwrap();
        let v = t.current().unwrap();
        assert_eq!(
            (v.upstreams(), v.timeout()),
            (vec![ip("192.0.2.1")], Duration::from_millis(1500))
        );
        t.set_timeout(Duration::from_millis(500)).unwrap();
        let v = t.current().unwrap();
        assert_eq!(
            (v.upstreams(), v.timeout()),
            (vec![ip("192.0.2.1")], Duration::from_millis(500)),
            "the verifier carries the new timeout and the old upstreams"
        );
        t.set_upstreams(&[]).unwrap();
        assert!(t.current().is_none());
        t.set_upstreams(&[ip("192.0.2.2")]).unwrap();
        let v = t.current().unwrap();
        assert_eq!(
            (v.upstreams(), v.timeout()),
            (vec![ip("192.0.2.2")], Duration::from_millis(500)),
            "the verifier carries the new upstreams and the kept timeout"
        );
        // An unchanged value is a no-op: the same verifier instance stays.
        t.set_timeout(Duration::from_millis(500)).unwrap();
        assert!(Arc::ptr_eq(&v, &t.current().unwrap()));
        t.set_upstreams(&[ip("192.0.2.2")]).unwrap();
        assert!(Arc::ptr_eq(&v, &t.current().unwrap()));
    }

    #[test]
    fn nameservers_reads_the_file_as_glibc_does() {
        let text = "# c\n  nameserver 10.9.9.9\nnameserver1.2.3.4\nnameserver\t10.0.0.1\nnameserver fe80::1%eth0\nnameserver 10.0.0.1\nnameserver 192.168.1.1#router\nsearch lan\n";
        let got = nameservers(text);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(
            got,
            vec![ip("10.0.0.1"), ip("fe80::1"), ip("192.168.1.1")],
            "indented and glued keywords ignored, repeats once, a #comment cut"
        );
        // dnsmasq's reading takes the indented line too.
        let lenient = nameservers_lenient(text);
        assert_eq!(lenient[0], ip("10.9.9.9"));
        assert_eq!(lenient.len(), 4);
        // The same keyword rule for search: `searchlist` is not `search`.
        assert_eq!(keyword("searchlist lan", "search"), None);
        assert_eq!(keyword("search lan", "search"), Some(" lan"));
    }

    #[test]
    fn yaml_round_trip_and_unknown_keys_rejected() {
        let y = "listen: [\"[::1]:5356\"]\ndnssec: false\nmesh_relays: [\"ws://[fd00::1]:7777\"]\n";
        let c: Config = serde_yaml::from_str(y).unwrap();
        assert!(!c.dnssec);
        assert_eq!(c.listen.len(), 1);
        assert!(serde_yaml::from_str::<Config>("nonsense: 1\n").is_err());
        assert!(Config::parse("nonsense: 1\n").is_err());
        let round: Config = Config::parse(&Config::default().render()).unwrap();
        assert_eq!(round.listen, Config::default().listen);
        let w = Npub::from_bytes([7; 32]);
        let y = format!("witnesses: [\"{w}\"]\nattestation_threshold: 1\n");
        let c: Config = serde_yaml::from_str(&y).unwrap();
        assert_eq!(c.witnesses, vec![w]);
        assert_eq!(c.resolver_config().attestation_threshold, 1);
        assert_eq!(Config::default().attestation_threshold, 2);
        assert!(Config::default().witnesses.is_empty());
        assert!(Config::default().resolver_config().plain_probe);
        let c: Config = serde_yaml::from_str("plain_probe: false\n").unwrap();
        assert!(!c.resolver_config().plain_probe);
    }
}
