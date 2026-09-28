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
use serde::Deserialize;
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
        /// Zone file(s).
        #[arg(long, required = true)]
        zone: Vec<PathBuf>,
        /// Address to listen on; default: this node's fips address.
        #[arg(long)]
        bind: Option<Ipv6Addr>,
        /// Answer TTL in seconds.
        #[arg(long, default_value_t = 300)]
        ttl: u32,
        /// Also publish the claims at start and every 24 h.
        #[arg(long)]
        publish: bool,
        #[arg(long)]
        relay: Vec<String>,
        #[command(flatten)]
        proof: ProofArgs,
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
    /// Domains whose relays had nothing to restore, or whose record stopped
    /// naming this server: not asked again in this process.
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

    /// The chain of this server's own claim on the relays, if it is still
    /// valid for an hour and names this server — the newest record among
    /// them: after a restart during a DNS outage, what keeps the relays'
    /// copy from being replaced by a claim without a proof.
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
        let found = own_chain(&claims, self.author, domain, now, |c| {
            checker.check(c, now).ok()
        });
        if found.is_none() {
            self.no_seed.lock().unwrap().insert(domain.to_string());
        }
        found
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
            Some((chain, expires)) if expires > now + 3600 => {
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

/// The chain to restore from this server's own claims on the relays: only
/// the newest claim counts (a relay that missed the latest publication
/// must not bring back an older proof — for a key since rotated out, say),
/// and only if its proof names the server and has an hour left.
fn own_chain(
    claims: &[pubdom_core::Claim],
    author: Npub,
    domain: &str,
    now: u64,
    check: impl Fn(&pubdom_core::Claim) -> Option<proof::Proven>,
) -> Option<(String, u64)> {
    let newest = claims
        .iter()
        .filter(|c| c.author == author && c.domain == domain)
        .max_by_key(|c| c.created_at)?;
    let chain = newest.dnssec.clone()?;
    let p = check(newest)?;
    (p.expires > now + 3600).then_some((chain, p.expires))
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

fn load_zone(path: &Path, author: Npub) -> Result<Zone> {
    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let zf: ZoneFile = serde_yaml::from_str(&text).with_context(|| path.display().to_string())?;
    let domain =
        normalize(&zf.domain).ok_or_else(|| anyhow!("{}: invalid domain", path.display()))?;
    if !pubdom_core::domain::is_claimable(&domain) {
        bail!(
            "{}: {domain} is a public suffix or not registrable",
            path.display()
        );
    }
    let mut names = Vec::new();
    for (label, target) in &zf.names {
        let label = label.to_ascii_lowercase();
        if label != "@" && !pubdom_core::domain::is_valid_zone_label(&label) {
            bail!("{}: invalid label {label:?}", path.display());
        }
        let target = match target.as_str() {
            "self" => Target::Author,
            "legacy" => Target::Legacy,
            s => Target::Node(
                Npub::parse_any(s).map_err(|e| anyhow!("{}: {label}: {e}", path.display()))?,
            ),
        };
        names.push((label, target));
    }
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    Ok(Zone {
        path: path.to_path_buf(),
        mtime,
        port: zf.port.unwrap_or(DEFAULT_SERVER_PORT),
        record: ZoneRecord {
            author,
            domain,
            created_at: 0,
            names,
        },
    })
}

/// The node key: a file (fips's `fips.key`: 64 hex characters, or 32 raw
/// bytes) or an nsec/hex string. A file that exists but cannot be read is
/// reported as such — the usual cause is not being in the `fips` group —
/// rather than as an invalid key.
fn load_keys(spec: &str) -> Result<Keys> {
    let path = Path::new(spec);
    let text = if path.exists() {
        let bytes = std::fs::read(path).with_context(|| {
            format!("cannot read {spec} (is this user in the group that owns it, usually `fips`?)")
        })?;
        if bytes.len() == 32 {
            hex::encode(&bytes)
        } else {
            String::from_utf8(bytes)
                .with_context(|| format!("{spec} is neither text nor a 32-byte key"))?
        }
    } else {
        spec.to_string()
    };
    Keys::parse(text.trim()).map_err(|e| {
        anyhow!("key {spec}: {e} (expected fips's key file, an nsec, or 64 hex characters)")
    })
}

fn author_of(keys: &Keys) -> Npub {
    Npub::from_hex(&keys.public_key().to_hex()).expect("nostr pubkey is 32 bytes")
}

struct Zones {
    author: Npub,
    zones: RwLock<Vec<Zone>>,
}

impl Zones {
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
            match load_zone(&path, self.author) {
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

/// A snapshot of the zones as last loaded — what `publish_all` sends.
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
    let keys = load_keys(&cli.key)?;
    let author = author_of(&keys);

    match cli.cmd {
        Cmd::Txt { zone } => {
            for p in &zone {
                let z = load_zone(p, author)?;
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
                .map(|p| load_zone(p, author))
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
            zone,
            bind,
            ttl,
            publish,
            relay,
            proof,
        } => {
            let zones: Vec<Zone> = zone
                .iter()
                .map(|p| load_zone(p, author))
                .collect::<Result<_>>()?;
            let port = zones.first().map(|z| z.port).unwrap_or(DEFAULT_SERVER_PORT);
            if zones.iter().any(|z| z.port != port) {
                bail!("all zones served by one process must use the same port");
            }
            let bind = SocketAddrV6::new(bind.unwrap_or_else(|| author.fips_address()), port, 0, 0);
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
            });
            if publish {
                if relay.is_empty() {
                    bail!("--publish needs at least one --relay");
                }
                let (k, zs, rl) = (keys.clone(), zones.clone(), relay.clone());
                let prover = Prover::new(proof, author, relay.clone());
                tokio::spawn(async move {
                    // Per zone: at start, whenever its file changed (the zone
                    // record must say what the server would answer), and
                    // before its DNSSEC proof runs out — every 24 h at the
                    // latest. One zone's hourly retry does not republish the
                    // others.
                    type Seen = (Vec<(String, Target)>, u16, std::time::Instant);
                    let mut seen: std::collections::HashMap<String, Seen> = Default::default();
                    loop {
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

    #[test]
    fn only_the_newest_own_claim_is_restored() {
        let me = Npub::from_bytes([1; 32]);
        let claim = |author: Npub, created_at, chain: Option<&str>| pubdom_core::Claim {
            author,
            domain: "example.org".into(),
            port: 5355,
            created_at,
            dnssec: chain.map(str::to_owned),
        };
        let valid_until = |exp: u64| {
            move |c: &pubdom_core::Claim| {
                c.dnssec.as_ref().map(|_| proof::Proven {
                    records: vec![],
                    signed_at: 0,
                    expires: exp,
                })
            }
        };
        let now = 1_000_000;
        // The newest claim carries a proof: restored.
        let claims = [claim(me, 10, Some("old")), claim(me, 20, Some("new"))];
        assert_eq!(
            own_chain(&claims, me, "example.org", now, valid_until(now + 86400)),
            Some(("new".into(), now + 86400))
        );
        // The newest has none (the server stopped vouching): nothing, even
        // though a relay still holds an older one.
        let claims = [claim(me, 10, Some("old")), claim(me, 20, None)];
        assert_eq!(
            own_chain(&claims, me, "example.org", now, valid_until(now + 86400)),
            None
        );
        // Another key's claim is not ours; one with under an hour left is
        // not worth restoring.
        let other = Npub::from_bytes([2; 32]);
        let claims = [
            claim(other, 30, Some("theirs")),
            claim(me, 20, Some("mine")),
        ];
        assert_eq!(
            own_chain(&claims, me, "example.org", now, valid_until(now + 60)),
            None
        );
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
            zones: RwLock::new(vec![load_zone(&p, me).unwrap()]),
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
        assert!(load_zone(&dir.join("bad.yaml"), me).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
