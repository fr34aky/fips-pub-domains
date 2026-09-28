//! `fips-pubdom` — operator and debugging tool: run one lookup the way the
//! daemon would, show what the verifier and the relays say about a domain,
//! and inspect the pins.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use pubdom_core::Claim;
use pubdom_core::policy::{self, Input, NoProofs, ProofVerifier, ProvenRecord, TxtLookup};
use pubdom_core::{PinStore, synth};
use pubdom_resolve::relay::RelayScope;
use pubdom_resolve::{Config, FilePinStore, LookupResult, RelayClient, TxtVerifier};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "fips-pubdom", version, about)]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/fips-pubdom/config.yaml")]
    config: PathBuf,
    /// Pretend the legacy DNS is unreachable.
    #[arg(long, global = true)]
    offline: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Resolve a name through the full path and print the outcome.
    Lookup {
        name: String,
        #[arg(long, default_value = "AAAA")]
        qtype: String,
    },
    /// Show the TXT record, the claims and the decision for a domain.
    Verify { domain: String },
    /// Fetch and print the claims for a domain, as the relays return them.
    Claims { domain: String },
    /// Fetch and print the zone record the domain's pinned server published.
    Zone { domain: String },
    /// Pinned bindings.
    Pins {
        #[command(subcommand)]
        cmd: PinsCmd,
    },
}

#[derive(Subcommand)]
enum PinsCmd {
    List,
    Forget { domain: String },
}

fn qtype(s: &str) -> Result<u16> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "A" => synth::QTYPE_A,
        "AAAA" => synth::QTYPE_AAAA,
        "ANY" => synth::QTYPE_ANY,
        "CNAME" => synth::QTYPE_CNAME,
        "HTTPS" => 65,
        other => other
            .parse()
            .map_err(|_| anyhow!("unknown qtype {other}"))?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let cfg = Config::load_or_default(&cli.config).map_err(anyhow::Error::msg)?;
    let upstreams = if cli.offline {
        Vec::new()
    } else {
        cfg.current_upstreams()
    };

    match cli.cmd {
        Cmd::Lookup { name, qtype: qt } => {
            let r = cfg
                .build_resolver(upstreams)
                .await
                .map_err(anyhow::Error::msg)?;
            if cli.offline {
                r.set_online(false);
            }
            let q = synth::build_query(1, &name, qtype(&qt)?).ok_or_else(|| anyhow!("bad name"))?;
            match r.lookup(&q).await {
                LookupResult::Passthrough => println!("{name}: not over fips (legacy passthrough)"),
                LookupResult::Answer(a) => {
                    let p = simple_dns::Packet::parse(&a)?;
                    println!("{name}: over fips, rcode {:?}", p.rcode());
                    for rr in &p.answers {
                        println!("  {} {} {:?}", rr.name, rr.ttl, rr.rdata);
                    }
                }
            }
        }
        Cmd::Verify { domain } => {
            let domain =
                pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
            let pins = FilePinStore::open(&cfg.pins)?;
            let pinned = pins.get(&domain);
            match pinned.len() {
                0 => println!("pins: none"),
                _ => {
                    for (i, p) in pinned.iter().enumerate() {
                        println!(
                            "pin {}: {}:{} {:?} verified_at {}",
                            i + 1,
                            p.npub,
                            p.port,
                            p.method,
                            p.verified_at
                        );
                    }
                }
            }
            let (txt, ttl) = if upstreams.is_empty() {
                (TxtLookup::Unreachable, None)
            } else {
                let v = TxtVerifier::new(&upstreams, cfg.dnssec, Duration::from_millis(1500))
                    .map_err(anyhow::Error::msg)?;
                println!("upstreams: {:?}", v.upstreams());
                v.lookup(&domain).await
            };
            println!("txt: {txt:?} (ttl {ttl:?})");
            let scope = match txt {
                TxtLookup::Hit { .. } => RelayScope::AfterHit,
                // verify shows everything it can
                TxtLookup::Miss { .. } | TxtLookup::Disputed => RelayScope::AfterHit,
                TxtLookup::Unreachable if cli.offline => RelayScope::Offline,
                TxtLookup::Unreachable => RelayScope::MeshOnly,
            };
            let relays =
                RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, Duration::from_secs(3))
                    .await;
            let events = relays.fetch_claims(&domain, scope).await;
            println!("claim events: {}", events.len());
            let claims = policy::ingest_claims(&pins, &domain, &events, pubdom_resolve::now());
            let dnssec = pubdom_resolve::proof::DnssecProofs::default();
            let now = pubdom_resolve::now();
            // Each proof checked once, for the listing and the decision.
            let mut checked = Checked(Default::default());
            for c in &claims {
                let result = c.dnssec.as_ref().map(|_| dnssec.check(c, now));
                let proof = match &result {
                    None => "no DNSSEC proof".to_string(),
                    Some(Ok(p)) => format!(
                        "DNSSEC proof signed at {}, valid until {}",
                        p.signed_at, p.expires
                    ),
                    Some(Err(e)) => format!("DNSSEC proof {e}"),
                };
                println!(
                    "  claim by {} port {} created_at {}: {proof}",
                    c.author, c.port, c.created_at
                );
                let shown = result.and_then(Result::ok).map(Into::into);
                // `ingest_claims` keeps one claim per author.
                checked.0.insert(c.author, shown);
            }
            let proofs: &dyn ProofVerifier = if cfg.dnssec { &checked } else { &NoProofs };
            let out = policy::decide(Input {
                domain: &domain,
                pins: pinned,
                txt,
                claims: &claims,
                now,
                allow_unverified_offline: cfg.allow_unverified_offline,
                proofs,
            });
            println!("decision: {:?}", out.decision);
            println!("pin changes: {:?} (not applied by `verify`)", out.changes);
            relays.shutdown().await;
        }
        Cmd::Claims { domain } => {
            let relays =
                RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, Duration::from_secs(3))
                    .await;
            let scope = if cli.offline {
                RelayScope::Offline
            } else {
                RelayScope::AfterHit
            };
            for ev in relays.fetch_claims(&domain, scope).await {
                println!("{}", serde_json::to_string_pretty(&ev)?);
            }
            relays.shutdown().await;
        }
        Cmd::Zone { domain } => {
            let domain =
                pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
            let pins = FilePinStore::open(&cfg.pins)?;
            let pinned = pins.get(&domain);
            if pinned.is_empty() {
                println!(
                    "{domain}: not pinned; a zone record is only trusted from a pinned server"
                );
                return Ok(());
            }
            let relays =
                RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, Duration::from_secs(3))
                    .await;
            let scope = if cli.offline {
                RelayScope::Offline
            } else {
                RelayScope::AfterHit
            };
            for pin in &pinned {
                let events = relays.fetch_zone(&domain, &pin.npub, scope).await;
                match policy::ingest_zone(&pins, &domain, pin.npub, &events, pubdom_resolve::now())
                {
                    Some(z) => {
                        println!(
                            "{domain}: zone record by {} created_at {}",
                            z.author, z.created_at
                        );
                        for (label, target) in &z.names {
                            println!("  {label:<12} {target:?}");
                        }
                    }
                    None => println!("{domain}: no zone record from {}", pin.npub),
                }
            }
            relays.shutdown().await;
        }
        Cmd::Pins { cmd } => {
            let pins = FilePinStore::open(&cfg.pins)?;
            match cmd {
                PinsCmd::List => {
                    for b in pins.list() {
                        println!(
                            "{}\t{}:{}\t{:?}\tverified_at {}",
                            b.domain, b.npub, b.port, b.method, b.verified_at
                        );
                    }
                }
                PinsCmd::Forget { domain } => {
                    pins.forget(&domain);
                    println!("forgot {domain}");
                }
            }
        }
    }
    Ok(())
}

/// Proofs already checked for `verify`'s listing — at the same `now` the
/// decision uses — by author.
struct Checked(std::collections::HashMap<pubdom_core::Npub, Option<ProvenRecord>>);

impl ProofVerifier for Checked {
    fn verify(&self, claim: &Claim, _now: u64) -> Option<ProvenRecord> {
        self.0.get(&claim.author).cloned().flatten()
    }
}
