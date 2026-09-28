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
use pubdom_resolve::relay::{claim_event_json, publish_claim, publish_zone, zone_event_json};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
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
    },
    /// Print the legacy DNS TXT record the operator must add (spec §4).
    Txt {
        #[arg(long, required = true)]
        zone: Vec<PathBuf>,
    },
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

fn load_keys(spec: &str) -> Result<Keys> {
    let text = match std::fs::read_to_string(spec) {
        Ok(t) => t,
        Err(_) => spec.to_string(),
    };
    Keys::parse(text.trim()).map_err(|e| anyhow!("key {spec}: {e}"))
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
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                continue;
            };
            if let Some(r) = reply(&z_udp, &buf[..n], ttl) {
                let _ = udp.send_to(&r, from).await;
            }
        }
    });
    let tcp_task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = tcp.accept().await else {
                continue;
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
async fn publish_all(keys: &Keys, zones: &[Zone], relays: &[String]) {
    for z in zones {
        match publish_claim(
            keys.clone(),
            relays,
            &z.record.domain,
            z.port,
            None,
            Duration::from_secs(10),
        )
        .await
        {
            Ok(ok) => tracing::info!(domain = %z.record.domain, relays = ?ok, "claim published"),
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
    }
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
        } => {
            let zones: Vec<Zone> = zone
                .iter()
                .map(|p| load_zone(p, author))
                .collect::<Result<_>>()?;
            if dry_run {
                for z in &zones {
                    println!(
                        "{}",
                        claim_event_json(&keys, &z.record.domain, z.port, None)
                            .map_err(|e| anyhow!(e))?
                    );
                    println!(
                        "{}",
                        zone_event_json(&keys, &z.record.domain, &z.record.names)
                            .map_err(|e| anyhow!(e))?
                    );
                }
            } else {
                publish_all(&keys, &zones, &relay).await;
            }
        }
        Cmd::Serve {
            zone,
            bind,
            ttl,
            publish,
            relay,
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
                tokio::spawn(async move {
                    // At start, every 24 h, and whenever a zone file changed:
                    // the zone record must say what the server would answer.
                    let mut last: Vec<Zone> = Vec::new();
                    let mut last_publish =
                        std::time::Instant::now() - Duration::from_secs(24 * 3600);
                    loop {
                        zs.check_reload();
                        let now = snapshot(&zs);
                        let changed = now
                            .iter()
                            .map(|z| (&z.record.domain, &z.record.names, z.port))
                            .ne(last
                                .iter()
                                .map(|z| (&z.record.domain, &z.record.names, z.port)));
                        if changed || last_publish.elapsed() >= Duration::from_secs(24 * 3600) {
                            publish_all(&k, &now, &rl).await;
                            last = now;
                            last_publish = std::time::Instant::now();
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
