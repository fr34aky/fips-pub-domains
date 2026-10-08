//! `fips-pubdom-server` — the domain's fips DNS server (spec §6.1) and the
//! publisher of its claim (spec §3.1).
//!
//! Runs on the node that serves the domain, listening on that node's own
//! fips address (UDP and TCP, default port 5355), and answers from a zone
//! file:
//!
//! ```yaml
//! domain: example.org
//! port: 5355            # optional
//! names:
//!   www: self
//!   git: npub1…
//!   mail: legacy        # kept off the mesh even under the wildcard
//!   "*": self
//! ```
//!
//! This is deliberately not fips's own `.fips` responder: that one binds
//! loopback, knows only `.fips`, and drops queries arriving on the mesh
//! interface. Mesh exposure is the point here, so the fips firewall needs a
//! drop-in allowing the port (`packaging/common/fips-pubdom.nft`).

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use nostr_sdk::Keys;
use pubdom_core::claim::{Target, ZoneRecord};
use pubdom_core::domain::{normalize, relative_label};
use pubdom_core::txt::TxtRecord;
use pubdom_core::{DEFAULT_SERVER_PORT, Npub, synth};
use pubdom_resolve::proof;
use pubdom_resolve::relay::{claim_event_json, publish_claim, publish_zone, zone_event_json};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Parser)]
#[command(name = "fips-pubdom-server", version, about)]
struct Cli {
    /// Node key: fips's key file (hex), or an nsec/hex string.
    #[arg(long, global = true, default_value = "/etc/fips/fips.key")]
    key: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Answer step 3 queries for the zones over the mesh.
    Serve {
        /// Configuration file (docs/operators.md); its zones directory is
        /// followed as files come, change and go. Flags given alongside
        /// override it.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Zone file(s); with --config, in addition to the directory.
        #[arg(long, required_unless_present = "config")]
        zone: Vec<PathBuf>,
        /// Address to listen on; default: this node's fips address.
        #[arg(long)]
        bind: Option<Ipv6Addr>,
        /// Answer TTL in seconds (default 300).
        #[arg(long)]
        ttl: Option<u32>,
        /// Also publish the claims at start and every 24 h.
        #[arg(long)]
        publish: bool,
        #[arg(long)]
        relay: Vec<String>,
        #[command(flatten)]
        proof: ProofArgs,
    },
    /// Write a configuration file from the zones directory and the unit's
    /// environment file, for a server set up before there was one.
    Init {
        /// Where the zone files are.
        #[arg(long, default_value = "/etc/fips-pubdom/zones")]
        zones: PathBuf,
        /// The unit's environment file (PUBDOM_SERVER_ARGS=…), if any.
        #[arg(long, default_value = "/etc/fips-pubdom/server.env")]
        env: PathBuf,
        /// The file to write.
        #[arg(long, default_value = "/etc/fips-pubdom/server.yaml")]
        out: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Check a zone file or a configuration file read from stdin, as the
    /// server would load it; prints the normalised form, or the error and
    /// exit status 1. For tooling that writes those files (fips-ui).
    Validate {
        #[command(subcommand)]
        what: Validate,
    },
    /// Sign and publish the claim(s) to relays.
    Publish {
        #[arg(long, required = true)]
        zone: Vec<PathBuf>,
        #[arg(long, required = true)]
        relay: Vec<String>,
        /// Print the signed event instead of sending it.
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        proof: ProofArgs,
    },
    /// Print the legacy DNS TXT record the operator must add (spec §4).
    Txt {
        #[arg(long, required = true)]
        zone: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum Validate {
    /// A zone file.
    Zone,
    /// A server configuration file.
    Config,
}

/// `/etc/fips-pubdom/server.yaml`: everything `serve` takes as flags, as a
/// file the operator — or fips-ui's helper — edits (docs/webui.md).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
struct ServerConfig {
    /// Node key: fips's key file (hex), or an nsec/hex string.
    key: String,
    /// The zones directory: every `*.yaml` in it is served, followed as
    /// files come, change and go.
    zones: PathBuf,
    /// Address to listen on; default: this node's fips address.
    bind: Option<Ipv6Addr>,
    /// The port, for zones that name none; a zone naming another is refused.
    port: u16,
    /// Answer TTL in seconds.
    ttl: u32,
    publish: PublishConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
struct PublishConfig {
    /// Relays the claims and zone records go to; empty: nothing is
    /// published.
    relays: Vec<String>,
    /// Attach the DNSSEC proof to the claim (spec §3.1).
    dnssec_proof: bool,
    /// Resolvers to collect the proof from; empty: the system's, then
    /// 9.9.9.9 and 1.1.1.1.
    dns: Vec<IpAddr>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            key: "/etc/fips/fips.key".into(),
            zones: PathBuf::from("/etc/fips-pubdom/zones"),
            bind: None,
            port: DEFAULT_SERVER_PORT,
            ttl: 300,
            publish: PublishConfig::default(),
        }
    }
}

impl Default for PublishConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            dnssec_proof: true,
            dns: Vec::new(),
        }
    }
}

impl ServerConfig {
    fn parse(text: &str) -> Result<Self> {
        let cfg: Self = serde_yaml::from_str(text)?;
        if cfg.zones.as_os_str().is_empty() {
            bail!("zones: a directory is required");
        }
        for r in &cfg.publish.relays {
            if !(r.starts_with("ws://") || r.starts_with("wss://")) {
                bail!("publish.relays: {r:?} is not a ws:// or wss:// URL");
            }
        }
        Ok(cfg)
    }

    fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        Self::parse(&text).with_context(|| path.display().to_string())
    }

    /// From a pre-configuration-file install: the zones directory as it
    /// is, and `PUBDOM_SERVER_ARGS` from the unit's environment file.
    fn from_env(zones: &Path, env_text: Option<&str>) -> Result<Self> {
        let mut cfg = Self {
            zones: zones.to_path_buf(),
            ..Self::default()
        };
        let Some(text) = env_text else {
            return Ok(cfg);
        };
        let Some(line) = text
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("PUBDOM_SERVER_ARGS="))
        else {
            return Ok(cfg);
        };
        let mut args = shell_words(line).into_iter();
        while let Some(a) = args.next() {
            match a.as_str() {
                "--publish" => {}
                "--relay" => cfg.publish.relays.push(
                    args.next()
                        .ok_or_else(|| anyhow!("--relay without a value"))?,
                ),
                "--no-dnssec-proof" => cfg.publish.dnssec_proof = false,
                "--dns" => cfg.publish.dns.push(
                    args.next()
                        .ok_or_else(|| anyhow!("--dns without a value"))?
                        .parse()
                        .context("--dns")?,
                ),
                "--ttl" => {
                    cfg.ttl = args
                        .next()
                        .ok_or_else(|| anyhow!("--ttl without a value"))?
                        .parse()
                        .context("--ttl")?
                }
                "--bind" => {
                    cfg.bind = Some(
                        args.next()
                            .ok_or_else(|| anyhow!("--bind without a value"))?
                            .parse()
                            .context("--bind")?,
                    )
                }
                other => {
                    if let Some(v) = other.strip_prefix("--relay=") {
                        cfg.publish.relays.push(v.to_string());
                    } else {
                        bail!("PUBDOM_SERVER_ARGS: {other:?} is not a serve flag init knows");
                    }
                }
            }
        }
        Ok(cfg)
    }
}

/// The unit's `PUBDOM_SERVER_ARGS=…` value split as the shell would:
/// whitespace between words, single or double quotes around a word.
fn shell_words(line: &str) -> Vec<String> {
    let line = line.trim();
    let line = line
        .strip_prefix('"')
        .and_then(|l| l.strip_suffix('"'))
        .or_else(|| line.strip_prefix('\'').and_then(|l| l.strip_suffix('\'')))
        .unwrap_or(line);
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// The DNSSEC proof carried in the claim (spec §3.1 `dnssec` tag).
#[derive(clap::Args, Clone)]
struct ProofArgs {
    /// Do not attach a DNSSEC proof to the claim.
    #[arg(long)]
    no_dnssec_proof: bool,
    /// Resolver to collect the proof from (repeatable); default: the
    /// system's, then 9.9.9.9 and 1.1.1.1.
    #[arg(long = "dns")]
    dns: Vec<IpAddr>,
}

/// Builds the proofs, remembering the last good chain per domain: a failed
/// rebuild (a resolver timing out) must not replace a claim whose proof is
/// still valid with one that has none.
struct Prover {
    args: ProofArgs,
    /// This server's key: a chain whose record does not name it is useless.
    author: Npub,
    /// Where this server's own earlier claim can be found after a restart;
    /// empty for a dry run, which must not touch the network beyond DNS.
    relays: Vec<String>,
    last: std::sync::Mutex<std::collections::HashMap<String, (String, u64)>>,
    /// Domains whose record stopped naming this server: its earlier proofs
    /// are evidence for a retired key and are never restored in this
    /// process. (A relay lookup that found nothing is not remembered — the
    /// relays may just not have been reachable yet.)
    no_seed: std::sync::Mutex<std::collections::HashSet<String>>,
}

/// What a publication carries, and when to try again at the latest.
struct Proof {
    chain: Option<String>,
    expires: Option<u64>,
    retry: Duration,
}

impl Prover {
    fn new(args: ProofArgs, author: Npub, relays: Vec<String>) -> Self {
        Self {
            args,
            author,
            relays,
            last: Default::default(),
            no_seed: Default::default(),
        }
    }

    /// The chain of this server's newest claim on the relays, if it carries
    /// a valid proof naming this server: after a restart during a DNS
    /// outage, what keeps the relays' copy from being replaced by a claim
    /// without a proof.
    async fn published_chain(&self, domain: &str) -> Option<(String, u64)> {
        if self.relays.is_empty() || self.no_seed.lock().unwrap().contains(domain) {
            return None;
        }
        let relays =
            pubdom_resolve::RelayClient::new(&self.relays, &[], Duration::from_secs(3)).await;
        let events = relays
            .fetch_claims_by(
                domain,
                &self.author,
                pubdom_resolve::relay::RelayScope::AfterHit,
            )
            .await;
        relays.shutdown().await;
        let claims: Vec<pubdom_core::Claim> = events
            .iter()
            .filter_map(|e| pubdom_core::Claim::parse(e).ok())
            .collect();
        let checker = proof::DnssecProofs::default();
        let now = pubdom_resolve::now();
        own_chain(&claims, self.author, domain, |c| checker.check(c, now).ok())
    }

    async fn proof(&self, domain: &str) -> Proof {
        let day = Duration::from_secs(24 * 3600);
        let hour = Duration::from_secs(3600);
        let none = |retry| Proof {
            chain: None,
            expires: None,
            retry,
        };
        if self.args.no_dnssec_proof {
            return none(day);
        }
        let upstreams = if self.args.dns.is_empty() {
            proof::default_upstreams()
        } else {
            self.args.dns.clone()
        };
        let now = pubdom_resolve::now();
        let e = match proof::build_chain_any(domain, &upstreams, Duration::from_secs(3)).await {
            Ok((_, proven)) if !proven.records.iter().any(|r| r.npub == self.author) => {
                // The live record no longer names this server (a key
                // rotation, or a record for another node). An older proof
                // that did would be evidence for a retired key: publish none.
                self.last.lock().unwrap().remove(domain);
                self.no_seed.lock().unwrap().insert(domain.to_string());
                tracing::warn!(%domain, author = %self.author, "the _fips-dns record does not name this server's key; publishing the claim without a DNSSEC proof");
                // A resolver may still hold the record from before this
                // server was added: look again soon.
                return none(hour);
            }
            Ok((chain, proven)) => {
                self.last
                    .lock()
                    .unwrap()
                    .insert(domain.to_string(), (chain.clone(), proven.expires));
                // Halfway through the remaining validity of the shortest
                // signature, at least an hour and at most a day from now.
                let left = proven.expires.saturating_sub(now);
                return Proof {
                    chain: Some(chain),
                    expires: Some(proven.expires),
                    retry: Duration::from_secs(left / 2).clamp(hour, day),
                };
            }
            Err(e) => e,
        };
        // Collecting failed (a resolver timing out, no Internet): keep the
        // last chain while it has an hour left — from memory, or after a
        // restart from this server's own claim on the relays.
        let cached = self.last.lock().unwrap().get(domain).cloned();
        let last = match cached {
            Some(l) => Some(l),
            None => {
                let seeded = self.published_chain(domain).await;
                if let Some(l) = &seeded {
                    self.last
                        .lock()
                        .unwrap()
                        .insert(domain.to_string(), l.clone());
                }
                seeded
            }
        };
        match last {
            Some((chain, expires)) if expires > now + KEEP_MARGIN => {
                tracing::warn!(%domain, error = %e, "could not refresh the DNSSEC proof; keeping the last one");
                Proof {
                    chain: Some(chain),
                    expires: Some(expires),
                    retry: hour,
                }
            }
            // A zone that had a proof: retry soon. One that never had one
            // is most likely unsigned: daily.
            had => {
                tracing::warn!(%domain, error = %e, "no DNSSEC proof for the claim; clients that never saw the domain online cannot verify it offline");
                none(if had.is_some() { hour } else { day })
            }
        }
    }
}

/// A kept chain is republished only while it has this much validity left.
const KEEP_MARGIN: u64 = 3600;

/// The chain to restore from this server's own claims on the relays, with
/// its expiry: only the newest claim counts (a relay that missed the latest
/// publication must not bring back an older proof — for a key since
/// rotated out, say), and only if `check` accepts its proof.
fn own_chain(
    claims: &[pubdom_core::Claim],
    author: Npub,
    domain: &str,
    check: impl Fn(&pubdom_core::Claim) -> Option<proof::Proven>,
) -> Option<(String, u64)> {
    let newest = claims
        .iter()
        .filter(|c| c.author == author && c.domain == domain)
        .max_by_key(|c| c.created_at)?;
    let chain = newest.dnssec.clone()?;
    let p = check(newest)?;
    Some((chain, p.expires))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneFile {
    domain: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    names: BTreeMap<String, String>,
}

/// A loaded zone: the core's zone-record shape (so the phase-2 kind 37199
/// event is the same data) plus what serving needs.
struct Zone {
    path: PathBuf,
    mtime: Option<SystemTime>,
    port: u16,
    record: ZoneRecord,
}

fn load_zone(path: &Path, author: Npub, default_port: u16) -> Result<Zone> {
    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let mut z = parse_zone(&text, &path.display().to_string(), author, default_port)?;
    z.path = path.to_path_buf();
    z.mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    Ok(z)
}

/// A zone file's text as the server loads it (`validate zone` uses the
/// same function, so what it accepts the server serves).
fn parse_zone(text: &str, label: &str, author: Npub, default_port: u16) -> Result<Zone> {
    let zf: ZoneFile = serde_yaml::from_str(text).with_context(|| label.to_string())?;
    let domain = normalize(&zf.domain).ok_or_else(|| anyhow!("{label}: invalid domain"))?;
    if !pubdom_core::domain::is_claimable(&domain) {
        bail!("{label}: {domain} is a public suffix or not registrable");
    }
    let mut names = Vec::new();
    for (name, target) in &zf.names {
        let name = name.to_ascii_lowercase();
        if name != "@" && !pubdom_core::domain::is_valid_zone_label(&name) {
            bail!("{label}: invalid label {name:?}");
        }
        let target = match target.as_str() {
            "self" => Target::Author,
            "legacy" => Target::Legacy,
            s => Target::Node(Npub::parse_any(s).map_err(|e| anyhow!("{label}: {name}: {e}"))?),
        };
        names.push((name, target));
    }
    Ok(Zone {
        path: PathBuf::new(),
        mtime: None,
        port: zf.port.unwrap_or(default_port),
        record: ZoneRecord {
            author,
            domain,
            created_at: 0,
            names,
        },
    })
}

/// A zone as `validate zone` prints it back: what the server made of it.
fn render_zone(z: &Zone) -> String {
    let mut out = format!("domain: {}\nport: {}\nnames:\n", z.record.domain, z.port);
    for (label, target) in &z.record.names {
        let t = match target {
            Target::Author => "self".to_string(),
            Target::Legacy => "legacy".to_string(),
            Target::Node(n) => n.to_string(),
        };
        out.push_str(&format!("  {label:?}: {t}\n"));
    }
    out
}

/// The node key (see `pubdom_resolve::relay::load_keys`).
fn load_keys(spec: &str) -> Result<Keys> {
    pubdom_resolve::relay::load_keys(spec).map_err(anyhow::Error::msg)
}

fn author_of(keys: &Keys) -> Npub {
    Npub::from_hex(&keys.public_key().to_hex()).expect("nostr pubkey is 32 bytes")
}

struct Zones {
    author: Npub,
    zones: RwLock<Vec<Zone>>,
    /// The directory followed for zones coming and going; `None` when the
    /// zones were named one by one on the command line.
    dir: Option<PathBuf>,
    /// The port this process serves: a zone naming another is refused.
    port: u16,
}

impl Zones {
    /// The directory's `*.yaml` files against what is loaded: new files
    /// are loaded, files gone are dropped, files changed are reloaded (as
    /// `check_reload` does between scans). A file that does not load is
    /// reported and skipped — once, until it changes.
    fn rescan(&self) {
        let Some(dir) = &self.dir else {
            return;
        };
        let mut present: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "yaml") && p.is_file())
                .collect(),
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "cannot read the zones directory");
                return;
            }
        };
        present.sort();
        let gone: Vec<usize> = {
            let g = self.zones.read().unwrap();
            g.iter()
                .enumerate()
                .filter(|(_, z)| {
                    z.path.parent() == Some(dir.as_path()) && !present.contains(&z.path)
                })
                .map(|(i, _)| i)
                .collect()
        };
        for i in gone.into_iter().rev() {
            let z = self.zones.write().unwrap().remove(i);
            tracing::info!(domain = %z.record.domain, zone = %z.path.display(), "zone file removed; no longer served");
        }
        for path in present {
            let known = self.zones.read().unwrap().iter().any(|z| z.path == path);
            if known {
                continue;
            }
            match load_zone(&path, self.author, self.port) {
                Ok(z) if z.port != self.port => {
                    tracing::error!(zone = %path.display(), port = z.port, serving = self.port, "zone names another port than this process serves; skipped");
                }
                Ok(z) => {
                    let dup = self
                        .zones
                        .read()
                        .unwrap()
                        .iter()
                        .any(|o| o.record.domain == z.record.domain);
                    if dup {
                        tracing::error!(zone = %path.display(), domain = %z.record.domain, "a zone for this domain is already loaded from another file; skipped");
                        continue;
                    }
                    tracing::info!(domain = %z.record.domain, names = z.record.names.len(), zone = %path.display(), "zone loaded");
                    self.zones.write().unwrap().push(z);
                }
                Err(e) => {
                    tracing::error!(zone = %path.display(), error = %e, "zone file does not load; skipped");
                }
            }
        }
        self.check_reload();
    }

    /// Reload any zone whose file changed (one stat per query, like fips's
    /// hosts file); a broken edit keeps the last good zone.
    fn check_reload(&self) {
        let stale: Vec<(usize, PathBuf)> = {
            let g = self.zones.read().unwrap();
            g.iter()
                .enumerate()
                .filter(|(_, z)| {
                    std::fs::metadata(&z.path).and_then(|m| m.modified()).ok() != z.mtime
                })
                .map(|(i, z)| (i, z.path.clone()))
                .collect()
        };
        for (i, path) in stale {
            match load_zone(&path, self.author, self.port) {
                Ok(z) => {
                    tracing::info!(zone = %path.display(), "zone reloaded");
                    self.zones.write().unwrap()[i] = z;
                }
                Err(e) => {
                    tracing::error!(zone = %path.display(), error = %e, "zone reload failed; keeping the old one")
                }
            }
        }
    }

    fn lookup(&self, qname: &str) -> Option<Npub> {
        let g = self.zones.read().unwrap();
        // Longest matching zone wins.
        let mut best: Option<(&Zone, &str)> = None;
        for z in g.iter() {
            if let Some(label) = relative_label(qname, &z.record.domain)
                && best.is_none_or(|(b, _)| z.record.domain.len() > b.record.domain.len())
            {
                best = Some((z, label));
            }
        }
        let (z, label) = best?;
        z.record.lookup(label)
    }
}

fn reply(zones: &Zones, query: &[u8], ttl: u32) -> Option<Vec<u8>> {
    zones.check_reload();
    let q = synth::parse_query(query)?;
    let target = zones.lookup(&q.name);
    tracing::debug!(name = %q.name, target = ?target.map(|n| n.to_string()), "query");
    synth::server_reply(query, target, ttl)
}

async fn serve(zones: Arc<Zones>, bind: SocketAddrV6, ttl: u32) -> Result<()> {
    let udp = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind udp {bind}"))?;
    let tcp = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind tcp {bind}"))?;
    tracing::info!(%bind, "serving");
    let z_udp = zones.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = match udp.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    pubdom_resolve::after_socket_error(&e, "receive").await;
                    continue;
                }
            };
            if let Some(r) = reply(&z_udp, &buf[..n], ttl) {
                let _ = udp.send_to(&r, from).await;
            }
        }
    });
    let tcp_task = tokio::spawn(async move {
        loop {
            let (mut s, _) = match tcp.accept().await {
                Ok(v) => v,
                Err(e) => {
                    pubdom_resolve::after_socket_error(&e, "accept").await;
                    continue;
                }
            };
            let z = zones.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(10), async {
                    let mut hdr = [0u8; 2];
                    s.read_exact(&mut hdr).await?;
                    let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
                    s.read_exact(&mut q).await?;
                    if let Some(r) = reply(&z, &q, ttl) {
                        s.write_all(&(r.len() as u16).to_be_bytes()).await?;
                        s.write_all(&r).await?;
                    }
                    Ok::<_, std::io::Error>(())
                })
                .await;
            });
        }
    });
    let _ = tokio::try_join!(udp_task, tcp_task);
    Ok(())
}

/// The claim and the zone record for every zone (spec §3.1, §3.3): the
/// claim says who serves the domain, the zone record which names — so a
/// client can still resolve them while this server is unreachable.
///
/// Returns when to publish again at the latest: a proof is only as good as
/// its signatures, so halfway through the remaining validity of the
/// shortest-lived one, at least an hour and at most 24 h from now.
async fn publish_all(keys: &Keys, zones: &[Zone], relays: &[String], prover: &Prover) -> Duration {
    let mut next = Duration::from_secs(24 * 3600);
    for z in zones {
        next = next.min(publish_one(keys, z, relays, prover).await);
    }
    next
}

/// One zone's claim and zone record; returns when to publish it again.
async fn publish_one(keys: &Keys, z: &Zone, relays: &[String], prover: &Prover) -> Duration {
    let Proof {
        chain,
        expires,
        retry,
    } = prover.proof(&z.record.domain).await;
    match publish_claim(
        keys.clone(),
        relays,
        &z.record.domain,
        z.port,
        chain.as_deref(),
        Duration::from_secs(10),
    )
    .await
    {
        Ok(ok) => {
            tracing::info!(domain = %z.record.domain, relays = ?ok, dnssec_proof_until = ?expires, "claim published")
        }
        Err(e) => tracing::error!(domain = %z.record.domain, error = %e, "claim not published"),
    }
    match publish_zone(
        keys.clone(),
        relays,
        &z.record.domain,
        &z.record.names,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(ok) => {
            tracing::info!(domain = %z.record.domain, names = z.record.names.len(), relays = ?ok, "zone record published")
        }
        Err(e) => {
            tracing::error!(domain = %z.record.domain, error = %e, "zone record not published")
        }
    }
    retry
}

/// A snapshot of the zones as last loaded — what the scheduler publishes.
fn snapshot(zones: &Zones) -> Vec<Zone> {
    let g = zones.zones.read().unwrap();
    g.iter()
        .map(|z| Zone {
            path: z.path.clone(),
            mtime: z.mtime,
            port: z.port,
            record: z.record.clone(),
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    // Commands that touch no key must not need one: `validate` runs from
    // fips-ui's helper, `init` before the unit ever started.
    match &cli.cmd {
        Cmd::Validate { what } => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
            let result = match what {
                Validate::Zone => parse_zone(
                    &text,
                    "stdin",
                    Npub::from_bytes([0; 32]),
                    DEFAULT_SERVER_PORT,
                )
                .map(|z| render_zone(&z)),
                Validate::Config => ServerConfig::parse(&text)
                    .and_then(|c| serde_yaml::to_string(&c).map_err(Into::into)),
            };
            return match result {
                Ok(out) => {
                    print!("{out}");
                    Ok(())
                }
                Err(e) => {
                    eprintln!("{e:#}");
                    std::process::exit(1);
                }
            };
        }
        Cmd::Init {
            zones,
            env,
            out,
            force,
        } => {
            if out.exists() && !force {
                bail!("{} exists; --force to overwrite", out.display());
            }
            let env_text = match std::fs::read_to_string(env) {
                Ok(t) => Some(t),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e).with_context(|| env.display().to_string()),
            };
            let mut cfg = ServerConfig::from_env(zones, env_text.as_deref())?;
            cfg.key = cli.key.clone();
            let text = format!(
                "# fips-pubdom-server configuration (docs/operators.md), written by `init`\n{}",
                serde_yaml::to_string(&cfg)?
            );
            std::fs::write(out, text).with_context(|| out.display().to_string())?;
            println!("wrote {}", out.display());
            if env_text.is_some() {
                println!(
                    "{}: no longer read once the unit runs `serve --config`; keep or remove it",
                    env.display()
                );
            }
            return Ok(());
        }
        _ => {}
    }
    let keys = load_keys(&cli.key)?;
    let author = author_of(&keys);

    match cli.cmd {
        Cmd::Validate { .. } | Cmd::Init { .. } => unreachable!("handled above"),
        Cmd::Txt { zone } => {
            for p in &zone {
                let z = load_zone(p, author, DEFAULT_SERVER_PORT)?;
                let rec = TxtRecord {
                    npub: author,
                    port: Some(z.port),
                };
                println!(
                    "_fips-dns.{}.  3600  IN  TXT  \"{}\"",
                    z.record.domain,
                    rec.render()
                );
            }
        }
        Cmd::Publish {
            zone,
            relay,
            dry_run,
            proof,
        } => {
            let zones: Vec<Zone> = zone
                .iter()
                .map(|p| load_zone(p, author, DEFAULT_SERVER_PORT))
                .collect::<Result<_>>()?;
            // A dry run prints what would be sent; it does not ask relays.
            let seed = if dry_run { Vec::new() } else { relay.clone() };
            let prover = Prover::new(proof, author, seed);
            if dry_run {
                for z in &zones {
                    println!(
                        "{}",
                        claim_event_json(
                            &keys,
                            &z.record.domain,
                            z.port,
                            prover.proof(&z.record.domain).await.chain.as_deref()
                        )
                        .map_err(|e| anyhow!(e))?
                    );
                    println!(
                        "{}",
                        zone_event_json(&keys, &z.record.domain, &z.record.names)
                            .map_err(|e| anyhow!(e))?
                    );
                }
            } else {
                publish_all(&keys, &zones, &relay, &prover).await;
            }
        }
        Cmd::Serve {
            config,
            zone,
            bind,
            ttl,
            publish,
            relay,
            proof,
        } => {
            // The file sets the defaults, a flag given alongside wins.
            let cfg = match &config {
                Some(p) => ServerConfig::load(p)?,
                None => ServerConfig::default(),
            };
            let ttl = ttl.unwrap_or(cfg.ttl);
            let bind_addr = bind.or(cfg.bind);
            let relays = if relay.is_empty() {
                cfg.publish.relays.clone()
            } else {
                relay
            };
            let publish = publish || (config.is_some() && !relays.is_empty());
            let proof = ProofArgs {
                no_dnssec_proof: proof.no_dnssec_proof || !cfg.publish.dnssec_proof,
                dns: if proof.dns.is_empty() {
                    cfg.publish.dns.clone()
                } else {
                    proof.dns
                },
            };
            let mut zones: Vec<Zone> = zone
                .iter()
                .map(|p| load_zone(p, author, cfg.port))
                .collect::<Result<_>>()?;
            // The process serves one port: the file's, or the one the named
            // zones agree on.
            let port = if config.is_some() {
                cfg.port
            } else {
                zones.first().map(|z| z.port).unwrap_or(DEFAULT_SERVER_PORT)
            };
            if zones.iter().any(|z| z.port != port) {
                bail!("all zones served by one process must use the same port");
            }
            let dir = config.as_ref().map(|_| cfg.zones.clone());
            if let Some(d) = &dir {
                // Named files win over the directory's copy of the same domain.
                let named: Vec<String> = zones.iter().map(|z| z.record.domain.clone()).collect();
                let store = Zones {
                    author,
                    zones: RwLock::new(Vec::new()),
                    dir: Some(d.clone()),
                    port,
                };
                store.rescan();
                zones.extend(
                    store
                        .zones
                        .into_inner()
                        .unwrap()
                        .into_iter()
                        .filter(|z| !named.contains(&z.record.domain)),
                );
                if zones.is_empty() {
                    tracing::warn!(dir = %d.display(), "no zone files yet; serving nothing until one appears");
                }
            }
            let bind = SocketAddrV6::new(
                bind_addr.unwrap_or_else(|| author.fips_address()),
                port,
                0,
                0,
            );
            for z in &zones {
                tracing::info!(domain = %z.record.domain, names = z.record.names.len(), "zone loaded");
                tracing::info!(
                    "legacy DNS record: _fips-dns.{}. TXT \"{}\"",
                    z.record.domain,
                    TxtRecord {
                        npub: author,
                        port: Some(z.port)
                    }
                    .render()
                );
            }
            let zones = Arc::new(Zones {
                author,
                zones: RwLock::new(zones),
                dir,
                port,
            });
            if zones.dir.is_some() {
                // Zones come and go with their files: follow the directory,
                // and rescan every 30 s for whatever the watcher misses (or
                // while there is none).
                let zs = zones.clone();
                tokio::spawn(async move {
                    let start = |zs: &Arc<Zones>| {
                        let d = zs.dir.clone()?;
                        let zs = zs.clone();
                        pubdom_resolve::watch::watch_dir(&d, move || zs.rescan())
                    };
                    let mut watcher = start(&zs);
                    loop {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        zs.rescan();
                        if watcher.is_none() {
                            watcher = start(&zs);
                        }
                    }
                });
            }
            if publish {
                if relays.is_empty() {
                    bail!("--publish needs at least one --relay");
                }
                let (k, zs, rl) = (keys.clone(), zones.clone(), relays.clone());
                let prover = Prover::new(proof, author, relays.clone());
                tokio::spawn(async move {
                    // Per zone: at start, whenever its file changed (the zone
                    // record must say what the server would answer), and
                    // before its DNSSEC proof runs out — every 24 h at the
                    // latest. One zone's hourly retry does not republish the
                    // others.
                    type Seen = (Vec<(String, Target)>, u16, std::time::Instant);
                    let mut seen: std::collections::HashMap<String, Seen> = Default::default();
                    loop {
                        zs.rescan();
                        zs.check_reload();
                        for z in snapshot(&zs) {
                            let d = z.record.domain.clone();
                            let due = match seen.get(&d) {
                                Some((names, port, at)) => {
                                    *names != z.record.names
                                        || *port != z.port
                                        || std::time::Instant::now() >= *at
                                }
                                None => true,
                            };
                            if due {
                                let next = publish_one(&k, &z, &rl, &prover).await;
                                tracing::debug!(domain = %d, in_secs = next.as_secs(), "next publication");
                                seen.insert(
                                    d,
                                    (
                                        z.record.names.clone(),
                                        z.port,
                                        std::time::Instant::now() + next,
                                    ),
                                );
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                });
            }
            let _ = SocketAddr::from(bind);
            serve(zones, bind, ttl).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pubdom-server-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The file's defaults, its checks, and what a flag-era install turns
    /// into.
    #[test]
    fn server_config_parses_checks_and_comes_from_the_env_file() {
        let c = ServerConfig::parse("").unwrap();
        assert_eq!(c, ServerConfig::default());
        let c = ServerConfig::parse(
            "zones: /srv/zones\nport: 5400\npublish:\n  relays: [\"wss://r.example\", \"ws://npub1x.fips:80\"]\n  dnssec_proof: false\n  dns: [9.9.9.9]\n",
        )
        .unwrap();
        assert_eq!(c.zones, PathBuf::from("/srv/zones"));
        assert_eq!(c.port, 5400);
        assert_eq!(c.publish.relays.len(), 2);
        assert!(!c.publish.dnssec_proof);
        assert!(ServerConfig::parse("nonsense: 1\n").is_err());
        assert!(ServerConfig::parse("publish:\n  relays: [\"http://x\"]\n").is_err());
        assert!(ServerConfig::parse("zones: \"\"\n").is_err());

        let env = "# the unit's file\nPUBDOM_SERVER_ARGS=\"--publish --relay wss://a.example --relay 'ws://npub1y.fips:80' --no-dnssec-proof --dns 1.1.1.1\"\n";
        let c = ServerConfig::from_env(Path::new("/etc/fips-pubdom/zones"), Some(env)).unwrap();
        assert_eq!(
            c.publish.relays,
            vec![
                "wss://a.example".to_string(),
                "ws://npub1y.fips:80".to_string()
            ]
        );
        assert!(!c.publish.dnssec_proof);
        assert_eq!(c.publish.dns, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        let c = ServerConfig::from_env(Path::new("/z"), None).unwrap();
        assert!(c.publish.relays.is_empty());
        assert!(
            ServerConfig::from_env(Path::new("/z"), Some("PUBDOM_SERVER_ARGS=--bogus\n")).is_err()
        );
        // A file with no such line: a server that never published.
        let c = ServerConfig::from_env(Path::new("/z"), Some("OTHER=1\n")).unwrap();
        assert!(c.publish.relays.is_empty());
        // The round trip the validate command prints.
        let text = serde_yaml::to_string(&c).unwrap();
        assert_eq!(ServerConfig::parse(&text).unwrap(), c);
    }

    /// What `validate zone` accepts is what the server serves, printed
    /// back normalised.
    #[test]
    fn zone_text_is_parsed_and_rendered_back() {
        let me = Npub::from_bytes([1; 32]);
        let z = parse_zone(
            "domain: Example.ORG\nnames:\n  WWW: self\n  mail: legacy\n  '*': self\n",
            "t",
            me,
            5400,
        )
        .unwrap();
        assert_eq!(z.record.domain, "example.org");
        assert_eq!(z.port, 5400);
        let out = render_zone(&z);
        assert!(
            out.starts_with("domain: example.org\nport: 5400\nnames:\n"),
            "{out}"
        );
        assert!(out.contains("\"www\": self\n") && out.contains("\"mail\": legacy\n"));
        // And back in: the rendering is a zone file.
        let again = parse_zone(&out, "t", me, 5400).unwrap();
        let sorted = |z: &Zone| {
            let mut n = z.record.names.clone();
            n.sort_by(|a, b| a.0.cmp(&b.0));
            n
        };
        assert_eq!(sorted(&again), sorted(&z));
        assert!(
            parse_zone("domain: co.uk\n", "t", me, 5355).is_err(),
            "public suffix"
        );
        assert!(
            parse_zone(
                "domain: example.org\nnames:\n  'bad label!': self\n",
                "t",
                me,
                5355
            )
            .is_err()
        );
        assert!(
            parse_zone(
                "domain: example.org\nnames:\n  git: notanpub\n",
                "t",
                me,
                5355
            )
            .is_err()
        );
    }

    /// Zones follow their files: added, removed, broken, another port, a
    /// duplicate domain.
    #[test]
    fn the_zones_directory_is_rescanned() {
        let dir = temp_dir("zones");
        let me = Npub::from_bytes([1; 32]);
        let zones = Zones {
            author: me,
            zones: RwLock::new(Vec::new()),
            dir: Some(dir.clone()),
            port: 5355,
        };
        zones.rescan();
        assert!(zones.zones.read().unwrap().is_empty());
        std::fs::write(
            dir.join("example.org.yaml"),
            "domain: example.org\nnames:\n  www: self\n",
        )
        .unwrap();
        std::fs::write(dir.join("broken.yaml"), "domain: [\n").unwrap();
        std::fs::write(dir.join("other.yaml"), "domain: example.net\nport: 5400\n").unwrap();
        // Files are taken in name order: the first file for a domain wins.
        std::fs::write(dir.join("zz-dup.yaml"), "domain: example.org\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "domain: example.com\n").unwrap();
        zones.rescan();
        let loaded: Vec<String> = zones
            .zones
            .read()
            .unwrap()
            .iter()
            .map(|z| z.record.domain.clone())
            .collect();
        assert_eq!(
            loaded,
            vec!["example.org".to_string()],
            "the good one, not the broken, the other-port, the duplicate or the .txt"
        );
        assert_eq!(zones.lookup("www.example.org"), Some(me));
        // Edited in place: picked up by the mtime check.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(
            dir.join("example.org.yaml"),
            "domain: example.org\nnames:\n  www: legacy\n",
        )
        .unwrap();
        // Windows needs the handle writable to set the time.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("example.org.yaml"))
            .unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(2))
            .unwrap();
        zones.rescan();
        assert_eq!(zones.lookup("www.example.org"), None, "legacy now");
        // Removed: gone from the store — and the file that was a duplicate
        // takes the domain over at the same scan.
        std::fs::remove_file(dir.join("example.org.yaml")).unwrap();
        zones.rescan();
        let paths: Vec<PathBuf> = zones
            .zones
            .read()
            .unwrap()
            .iter()
            .map(|z| z.path.clone())
            .collect();
        assert_eq!(paths, vec![dir.join("zz-dup.yaml")]);
        std::fs::remove_file(dir.join("zz-dup.yaml")).unwrap();
        zones.rescan();
        assert!(zones.zones.read().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_the_newest_own_claim_is_restored() {
        let me = Npub::from_bytes([1; 32]);
        let other = Npub::from_bytes([2; 32]);
        let claim = |author: Npub, created_at, chain: Option<&str>| pubdom_core::Claim {
            author,
            domain: "example.org".into(),
            port: 5355,
            created_at,
            dnssec: chain.map(str::to_owned),
        };
        let valid = |c: &pubdom_core::Claim| {
            c.dnssec.as_ref().map(|_| proof::Proven {
                records: vec![],
                signed_at: 0,
                expires: 999,
            })
        };
        // The newest own claim carries a proof: restored, even with another
        // key's newer claim beside it.
        let claims = [
            claim(me, 10, Some("old")),
            claim(me, 20, Some("new")),
            claim(other, 30, Some("theirs")),
        ];
        assert_eq!(
            own_chain(&claims, me, "example.org", valid),
            Some(("new".into(), 999))
        );
        // The newest has none (the server stopped vouching): nothing, even
        // though a relay still holds an older one.
        let claims = [claim(me, 10, Some("old")), claim(me, 20, None)];
        assert_eq!(own_chain(&claims, me, "example.org", valid), None);
        // A proof the check refuses: nothing.
        let claims = [claim(me, 20, Some("bad"))];
        assert_eq!(own_chain(&claims, me, "example.org", |_| None), None);
    }

    /// systemd expands `%` specifiers and `$` variables in `ExecStart`
    /// before any shell sees the line; 0.2.0 shipped a unit whose `%s`
    /// became `/bin/sh`. Everything meant for the shell must be doubled.
    #[test]
    fn shipped_units_escape_what_systemd_would_expand() {
        for (name, unit) in [
            (
                "fips-pubdom-server.service",
                include_str!("../../../packaging/systemd/fips-pubdom-server.service"),
            ),
            (
                "fips-pubdom.service",
                include_str!("../../../packaging/systemd/fips-pubdom.service"),
            ),
        ] {
            for line in unit.lines().filter(|l| l.starts_with("ExecStart=")) {
                let mut chars = line.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '%' || c == '$' {
                        assert_eq!(chars.next(), Some(c), "{name}: a single {c} in {line}");
                    }
                }
            }
        }
    }

    #[test]
    fn key_file_formats_and_errors() {
        let dir = std::env::temp_dir().join(format!("fips-pubdom-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let keys = Keys::generate();
        let hex_key = keys.secret_key().to_secret_hex();
        // hex text with a trailing newline, as fips writes it
        std::fs::write(dir.join("hex"), format!("{hex_key}\n")).unwrap();
        assert_eq!(
            load_keys(dir.join("hex").to_str().unwrap())
                .unwrap()
                .public_key(),
            keys.public_key()
        );
        // 32 raw bytes
        std::fs::write(dir.join("raw"), hex::decode(&hex_key).unwrap()).unwrap();
        assert_eq!(
            load_keys(dir.join("raw").to_str().unwrap())
                .unwrap()
                .public_key(),
            keys.public_key()
        );
        // the string itself
        assert_eq!(load_keys(&hex_key).unwrap().public_key(), keys.public_key());
        // garbage names the expectation, an unreadable file names the cause
        assert!(
            load_keys("not-a-key")
                .unwrap_err()
                .to_string()
                .contains("expected fips's key file")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn zone_file_loads_and_serves() {
        let dir = std::env::temp_dir().join(format!("fips-pubdom-zone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("example.org.yaml");
        let other = Npub::from_bytes([2; 32]);
        std::fs::write(&p, format!("domain: example.org\nnames:\n  www: self\n  git: {other}\n  mail: legacy\n  \"*\": self\n")).unwrap();
        let me = Npub::from_bytes([1; 32]);
        let zones = Zones {
            author: me,
            zones: RwLock::new(vec![load_zone(&p, me, 5355).unwrap()]),
            dir: None,
            port: 5355,
        };
        assert_eq!(zones.lookup("www.example.org"), Some(me));
        assert_eq!(zones.lookup("git.example.org"), Some(other));
        assert_eq!(zones.lookup("mail.example.org"), None);
        assert_eq!(zones.lookup("anything.example.org"), Some(me));
        assert_eq!(zones.lookup("example.org"), Some(me), "apex via wildcard");
        assert_eq!(zones.lookup("other.ch"), None);
        let q = synth::build_query(1, "git.example.org", synth::QTYPE_AAAA).unwrap();
        let r = reply(&zones, &q, 300).unwrap();
        assert_eq!(
            synth::parse_step3_reply(&r, 1),
            synth::Step3Outcome::Node {
                npub: other,
                ttl: 300
            }
        );
        std::fs::write(dir.join("bad.yaml"), "domain: ch\nnames: {}\n").unwrap();
        assert!(load_zone(&dir.join("bad.yaml"), me, 5355).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
