//! The resolver's configuration file — shared by the daemon and the CLI,
//! and mirrored by the JSON the fips2go app passes to its shim. YAML, all
//! keys optional:
//!
//! ```yaml
//! listen: ["[::1]:5356", "127.0.0.1:5356"]
//! upstreams: ["9.9.9.9", "1.1.1.1"]            # empty: the system's
//! upstreams_from: /run/systemd/resolve/resolv.conf   # re-read periodically
//! dnssec: true
//! public_relays: ["wss://relay.damus.io", "wss://nos.lol"]
//! mesh_relays: ["ws://npub1….fips:80"]   # by .fips name, never an [fd…] literal:
//!                                        # nostr-sdk mangles bracketed IPv6, and
//!                                        # resolving the name is what registers
//!                                        # the relay's identity with the node
//! responder: "[::1]:5354"                      # fips's .fips responder
//! mesh_bind: "fdd9:…"                          # this node's fips address
//! pins: /var/lib/fips-pubdom/pins.json
//! allow_unverified_offline: false
//! budget_ms: 4500
//! ```

use crate::mesh::KernelMeshDns;
use crate::pins::FilePinStore;
use crate::relay::RelayClient;
use crate::resolver::{Resolver, ResolverConfig};
use crate::txt::TxtVerifier;
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
    pub public_relays: Vec<String>,
    pub mesh_relays: Vec<String>,
    pub responder: SocketAddr,
    pub mesh_bind: Option<Ipv6Addr>,
    pub pins: PathBuf,
    pub allow_unverified_offline: bool,
    pub budget_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        let d = ResolverConfig::default();
        Self {
            listen: vec!["[::1]:5356".parse().unwrap(), "127.0.0.1:5356".parse().unwrap()],
            upstreams: Vec::new(),
            upstreams_from: None,
            dnssec: d.dnssec,
            public_relays: d.public_relays,
            mesh_relays: d.mesh_relays,
            responder: "[::1]:5354".parse().unwrap(),
            mesh_bind: None,
            pins: PathBuf::from("/var/lib/fips-pubdom/pins.json"),
            allow_unverified_offline: false,
            budget_ms: 4500,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Load if present, defaults otherwise.
    pub fn load_or_default(path: &Path) -> Result<Self, String> {
        if path.exists() { Self::load(path) } else { Ok(Self::default()) }
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
        let mut out: Vec<IpAddr> = Vec::new();
        for ip in text
            .lines()
            .filter_map(|l| l.strip_prefix("nameserver"))
            .filter_map(|rest| rest.split_whitespace().next())
            .filter_map(|s| s.split('%').next().unwrap_or(s).parse::<IpAddr>().ok())
            .filter(|ip| !own.contains(ip) && !ip.is_loopback())
        {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        out
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
            .filter_map(|l| l.strip_prefix("search"))
            .flat_map(|rest| rest.split_whitespace().map(str::to_owned))
            // `fips` is fips's own routing domain on its link: by design,
            // and never a bound domain (spec §5.2 rejects unknown TLDs).
            .filter(|d| d != "." && d != "fips")
            .collect()
    }

    pub fn resolver_config(&self, upstreams: Vec<IpAddr>) -> ResolverConfig {
        ResolverConfig {
            public_relays: self.public_relays.clone(),
            mesh_relays: self.mesh_relays.clone(),
            upstreams,
            dnssec: self.dnssec,
            allow_unverified_offline: self.allow_unverified_offline,
            ..ResolverConfig::default()
        }
    }

    /// The production resolver: hickory + nostr-sdk + kernel sockets + the
    /// pin file. `upstreams` empty means "no legacy DNS": mesh-only node.
    pub async fn build_resolver(&self, upstreams: Vec<IpAddr>) -> Result<ProdResolver, String> {
        let rc = self.resolver_config(upstreams.clone());
        let txt = MaybeTxt::new(&upstreams, self.dnssec, rc.txt_timeout)?;
        let relays = RelayClient::new(&self.public_relays, &self.mesh_relays, rc.relay_timeout).await;
        let pins = FilePinStore::open(&self.pins).map_err(|e| e.to_string())?;
        let mesh = KernelMeshDns::new(self.responder, self.mesh_bind);
        let r = Resolver::new(rc, Arc::new(pins), txt, relays, Arc::new(mesh));
        r.set_online(!upstreams.is_empty());
        Ok(r)
    }
}

pub type ProdResolver = Resolver<MaybeTxt, RelayClient>;

/// A TXT source that may be absent (mesh-only node, or the system has no
/// resolvers right now) and can be swapped when the upstreams change — a
/// laptop that moves networks must verify against the new resolvers, not
/// keep asking the old ones until they time out.
pub struct MaybeTxt {
    inner: std::sync::Mutex<Option<Arc<TxtVerifier>>>,
    dnssec: bool,
    timeout: Duration,
}

impl MaybeTxt {
    pub fn new(upstreams: &[IpAddr], dnssec: bool, timeout: Duration) -> Result<Self, String> {
        let me = Self { inner: std::sync::Mutex::new(None), dnssec, timeout };
        me.set_upstreams(upstreams)?;
        Ok(me)
    }

    /// Replace the verifier; an empty list means "no legacy DNS" and every
    /// lookup is `Unreachable`.
    pub fn set_upstreams(&self, upstreams: &[IpAddr]) -> Result<(), String> {
        let v = if upstreams.is_empty() {
            None
        } else {
            Some(Arc::new(TxtVerifier::new(upstreams, self.dnssec, self.timeout)?))
        };
        *self.inner.lock().unwrap() = v;
        Ok(())
    }

    fn current(&self) -> Option<Arc<TxtVerifier>> {
        self.inner.lock().unwrap().clone()
    }
}

impl crate::resolver::TxtSource for MaybeTxt {
    async fn lookup(&self, domain: &str) -> (pubdom_core::policy::TxtLookup, Option<u32>) {
        match self.current() {
            Some(t) => t.lookup(domain).await,
            None => (pubdom_core::policy::TxtLookup::Unreachable, None),
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
        let cfg = Config { upstreams_from: Some(f), ..Default::default() };
        assert_eq!(cfg.current_upstreams(), vec!["192.168.1.1".parse::<IpAddr>().unwrap(), "fe80::1".parse().unwrap()]);
        assert_eq!(cfg.link_search_domains(), vec!["lan"]);
        let cfg = Config::default();
        assert!(cfg.current_upstreams().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn yaml_round_trip_and_unknown_keys_rejected() {
        let y = "listen: [\"[::1]:5356\"]\ndnssec: false\nmesh_relays: [\"ws://[fd00::1]:7777\"]\n";
        let c: Config = serde_yaml::from_str(y).unwrap();
        assert!(!c.dnssec);
        assert_eq!(c.listen.len(), 1);
        assert!(serde_yaml::from_str::<Config>("nonsense: 1\n").is_err());
    }
}
