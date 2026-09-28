//! `fips-pubdom` — operator and debugging tool: run one lookup the way the
//! daemon would, show what the verifier and the relays say about a domain,
//! and inspect the pins.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use pubdom_core::policy::{self, Input, NoProofs, TxtLookup};
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
            let pin = pins.get(&domain);
            println!("pin: {pin:?}");
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
                TxtLookup::Miss { .. } => RelayScope::AfterHit, // verify shows everything it can
                TxtLookup::Unreachable if cli.offline => RelayScope::Offline,
                TxtLookup::Unreachable => RelayScope::MeshOnly,
            };
            let relays =
                RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, Duration::from_secs(3))
                    .await;
            let events = relays.fetch_claims(&domain, scope).await;
            println!("claim events: {}", events.len());
            let claims = policy::ingest_claims(&pins, &domain, &events, pubdom_resolve::now());
            for c in &claims {
                println!(
                    "  claim by {} port {} created_at {}",
                    c.author, c.port, c.created_at
                );
            }
            let out = policy::decide(Input {
                domain: &domain,
                pin,
                txt,
                claims: &claims,
                now: pubdom_resolve::now(),
                allow_unverified_offline: cfg.allow_unverified_offline,
                proofs: &NoProofs,
            });
            println!("decision: {:?}", out.decision);
            println!("pin update: {:?} (not applied by `verify`)", out.pin_update);
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
            let Some(pin) = pins.get(&domain) else {
                println!(
                    "{domain}: not pinned; a zone record is only trusted from the pinned server"
                );
                return Ok(());
            };
            let relays =
                RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, Duration::from_secs(3))
                    .await;
            let scope = if cli.offline {
                RelayScope::Offline
            } else {
                RelayScope::AfterHit
            };
            let events = relays.fetch_zone(&domain, &pin.npub, scope).await;
            match policy::ingest_zone(&pins, &domain, pin.npub, &events, pubdom_resolve::now()) {
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
