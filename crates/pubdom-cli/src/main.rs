//! `fips-pubdom` — operator and debugging tool: run one lookup the way the
//! daemon would, show what the verifier and the relays say about a domain,
//! and inspect the pins.

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use pubdom_core::policy::{
    self, Decision, Input, NoProofs, ProofVerifier, ProvenRecord, TxtLookup,
};
use pubdom_core::{Attestation, Claim, Method, Npub, PinStore, synth};
use pubdom_resolve::relay::{
    RelayScope, attestation_event_json_with, load_keys, publish_attestation_with,
};
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
    Verify {
        domain: String,
        /// Ask the public relays even when DNS says the domain does not
        /// participate (the resolver never does: a public relay would
        /// learn of a domain DNS has not vouched for).
        #[arg(long)]
        all_relays: bool,
    },
    /// Fetch and print the claims for a domain, as the relays return them.
    Claims { domain: String },
    /// Fetch and print the zone record the domain's pinned server published.
    Zone { domain: String },
    /// Be a witness: verify a domain online and publish an attestation
    /// (kind 37198) naming its servers, signed with this node's key.
    Attest {
        domain: String,
        /// The node key: fips's key file, an nsec, or 64 hex characters.
        #[arg(long, default_value = "/etc/fips/fips.key")]
        key: String,
        /// Print the signed event instead of publishing it.
        #[arg(long)]
        dry_run: bool,
        /// Refuse to publish when no previous attestation of this witness
        /// was found: an outage of the relay holding it would otherwise
        /// erase its entries for other roles (for unattended runs).
        #[arg(long)]
        require_previous: bool,
    },
    /// Fetch and print the attestations the configured witnesses published
    /// for a domain.
    Attestations { domain: String },
    /// Pinned bindings.
    Pins {
        #[command(subcommand)]
        cmd: PinsCmd,
    },
    /// Send one command to a running daemon's or server's control socket
    /// (docs/webui.md) and print the reply as JSON.
    Ctl {
        /// The socket; default: the daemon's, /run/fips-pubdom/control.sock
        /// (the server's is /run/fips-pubdom-server/control.sock).
        #[arg(long, default_value = "/run/fips-pubdom/control.sock")]
        socket: PathBuf,
        /// `status`, `pins`, `forget`, `flush`, `log`; on the server also
        /// `zones`, `txt`, `check-dns`, `publish`.
        command: String,
        /// Parameters as JSON, e.g. '{"domain":"example.org"}'.
        params: Option<String>,
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
        "SVCB" => synth::QTYPE_SVCB,
        "HTTPS" => synth::QTYPE_HTTPS,
        other => other
            .parse()
            .map_err(|_| anyhow!("unknown qtype {other}"))?,
    })
}

/// The relays as every read-only command asks them.
const RELAY_TIMEOUT: Duration = Duration::from_secs(3);

async fn relays(cfg: &Config) -> RelayClient {
    RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, RELAY_TIMEOUT).await
}

/// Which relays a read-only command asks, with no TXT answer to go by.
fn scope(offline: bool) -> RelayScope {
    if offline {
        RelayScope::Offline
    } else {
        RelayScope::AfterHit
    }
}

/// The pin file as a read-only store: what the daemon has pinned, loaded
/// once, never written back. `verify` and `zone` ingest events, which
/// records rollback state; doing that into the daemon's live file would
/// overwrite whatever it wrote since the load.
fn pins_read_only(path: &std::path::Path) -> Result<pubdom_core::MemoryPinStore> {
    let snap = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<pubdom_core::pins::PinSnapshot>(&bytes)
            .with_context(|| path.display().to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
        Err(e) => return Err(anyhow!("{}: {e}", path.display())),
    };
    Ok(pubdom_core::MemoryPinStore::from_snapshot(snap))
}

/// The witness's own newest attestation for `domain` among what the
/// relays returned: the author filter is a request to the relay, not a
/// guarantee, so another witness's event is never taken for this one's.
fn newest_own_attestation(
    events: &[pubdom_core::claim::Event],
    own: Npub,
    domain: &str,
) -> Option<Attestation> {
    events
        .iter()
        .filter_map(|e| Attestation::parse(e).ok())
        .filter(|a| a.witness == own && a.domain == domain)
        .max_by_key(|a| a.created_at)
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
    if let Cmd::Ctl {
        socket,
        command,
        params,
    } = &cli.cmd
    {
        let params = match params {
            Some(p) => serde_json::from_str(p.as_str()).map_err(|e| anyhow!("params: {e}"))?,
            None => serde_json::Value::Null,
        };
        let data = pubdom_control::query(socket, command, params).map_err(anyhow::Error::msg)?;
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }
    let cfg = Config::load_or_default(&cli.config).map_err(anyhow::Error::msg)?;
    let upstreams = if cli.offline {
        Vec::new()
    } else {
        cfg.current_upstreams()
    };

    match cli.cmd {
        Cmd::Ctl { .. } => unreachable!("handled above"),
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
                LookupResult::Unavailable { retry_in } => println!(
                    "{name}: over fips, but no server or target node reachable now (legacy passthrough for {} s)",
                    retry_in.as_secs()
                ),
                LookupResult::Answer(a) => {
                    let p = simple_dns::Packet::parse(&a)?;
                    println!("{name}: over fips, rcode {:?}", p.rcode());
                    for rr in &p.answers {
                        println!("  {} {} {:?}", rr.name, rr.ttl, rr.rdata);
                    }
                }
            }
        }
        Cmd::Verify { domain, all_relays } => {
            let domain =
                pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
            let pins = pins_read_only(&cfg.pins)?;
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
                // DNS said the domain does not participate: the resolver
                // asks no public relay about it (spec §8), nor does verify
                // unless told to.
                TxtLookup::Miss { .. } | TxtLookup::Disputed if all_relays => RelayScope::AfterHit,
                TxtLookup::Miss { .. } | TxtLookup::Disputed => RelayScope::MeshOnly,
                TxtLookup::Unreachable if cli.offline => RelayScope::Offline,
                TxtLookup::Unreachable => RelayScope::MeshOnly,
            };
            if matches!(scope, RelayScope::MeshOnly) && !cfg.public_relays.is_empty() {
                println!("relays: mesh only (--all-relays asks the public ones too)");
            }
            let relays = relays(&cfg).await;
            let events = relays.fetch_claims(&domain, scope).await;
            println!("claim events: {}", events.len());
            let claims = policy::ingest_claims(&pins, &domain, &events, pubdom_resolve::now());
            // As the resolver does: attestations matter offline only, and
            // ingesting them records rollback state, so none are fetched
            // while the record decides.
            let fetched_attestations = matches!(txt, TxtLookup::Unreachable);
            let att_events = if fetched_attestations {
                relays
                    .fetch_attestations(&domain, &cfg.witnesses, scope)
                    .await
            } else {
                Vec::new()
            };
            let attestations = policy::ingest_attestations(
                &pins,
                &domain,
                &cfg.witnesses,
                &att_events,
                pubdom_resolve::now(),
            );
            if fetched_attestations {
                println!(
                    "attestations by trusted witnesses: {} (of {} configured, k = {})",
                    attestations.len(),
                    cfg.witnesses.len(),
                    cfg.attestation_threshold
                );
            } else {
                println!(
                    "attestations: not fetched (the record decided; {} witness(es) configured, k = {})",
                    cfg.witnesses.len(),
                    cfg.attestation_threshold
                );
            }
            for a in &attestations {
                let note = if claims.iter().any(|c| c.author == a.witness) {
                    " (a server of the domain itself: does not count)"
                } else {
                    ""
                };
                println!(
                    "  {} attests {:?} {:?} verified_at {}{note}",
                    a.witness, a.servers, a.method, a.verified_at
                );
            }
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
                attestations: &attestations,
                attestation_threshold: cfg.attestation_threshold,
                now,
                allow_unverified_offline: cfg.allow_unverified_offline,
                proofs,
            });
            println!("decision: {:?}", out.decision);
            println!("pin changes: {:?} (not applied by `verify`)", out.changes);
            relays.shutdown().await;
        }
        Cmd::Claims { domain } => {
            let domain =
                pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
            let relays = relays(&cfg).await;
            for ev in relays.fetch_claims(&domain, scope(cli.offline)).await {
                println!("{}", serde_json::to_string_pretty(&ev)?);
            }
            relays.shutdown().await;
        }
        Cmd::Zone { domain } => {
            let domain =
                pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
            let pins = pins_read_only(&cfg.pins)?;
            let pinned = pins.get(&domain);
            if pinned.is_empty() {
                println!(
                    "{domain}: not pinned; a zone record is only trusted from a pinned server"
                );
                return Ok(());
            }
            let relays = relays(&cfg).await;
            for pin in &pinned {
                let events = relays
                    .fetch_zone(&domain, &pin.npub, scope(cli.offline))
                    .await;
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
        Cmd::Attest {
            domain,
            key,
            dry_run,
            require_previous,
        } => {
            let domain =
                pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
            if cli.offline {
                return Err(anyhow!(
                    "attesting needs the legacy DNS: a witness vouches for what it verified online"
                ));
            }
            let keys = load_keys(&key).map_err(anyhow::Error::msg)?;
            // No upstreams configured means the system's resolvers, as the
            // daemon's own default: a witness need not run the daemon.
            let v = TxtVerifier::new(&upstreams, cfg.dnssec, Duration::from_millis(1500))
                .map_err(|e| anyhow!("attesting needs the legacy DNS: {e}"))?;
            let (txt, _) = v.lookup(&domain).await;
            let method = match &txt {
                TxtLookup::Hit { method, .. } if *method >= Method::Dns => *method,
                TxtLookup::Hit { method, .. } => {
                    return Err(anyhow!(
                        "{domain}: verified by {method:?} only; attesting takes DNSSEC or two agreeing resolvers"
                    ));
                }
                other => return Err(anyhow!("{domain}: no verified record ({other:?})")),
            };
            let relays = relays(&cfg).await;
            let own = Npub::from_hex(&keys.public_key().to_hex()).map_err(|e| anyhow!("{e}"))?;
            // Every relay heard out: an attestation names the whole server
            // set, and a partial one would replace the witness's last. The
            // witness's own previous attestation is read at the same time,
            // from the same relays it publishes to: it has one per domain,
            // and what it said about keys in other roles (`fips-ca`, the
            // issuer of fips-pub-pki) must be carried along or is erased.
            let (events, previous) = tokio::join!(
                relays.fetch_claims(&domain, RelayScope::Full),
                relays.fetch_attestations_of(&domain, &own, RelayScope::Full)
            );
            // A witness keeps no pins of its own: the record and the claims
            // of the moment decide, as they would for a first visit.
            let pins = pubdom_core::MemoryPinStore::new();
            let now = pubdom_resolve::now();
            let claims = policy::ingest_claims(&pins, &domain, &events, now);
            let out = policy::decide(Input {
                domain: &domain,
                pins: Vec::new(),
                txt,
                claims: &claims,
                attestations: &[],
                attestation_threshold: 0,
                now,
                allow_unverified_offline: false,
                proofs: &NoProofs,
            });
            let servers: Vec<Npub> = match out.decision {
                Decision::Bound(b) => b.iter().map(|b| b.npub).collect(),
                other => {
                    relays.shutdown().await;
                    return Err(anyhow!("{domain}: nothing to attest ({other:?})"));
                }
            };
            // A witness is a third party: a key that claims the domain is
            // no witness for it, so attesting from a server would publish
            // an event no client counts.
            if claims.iter().any(|c| c.author == own) {
                relays.shutdown().await;
                return Err(anyhow!(
                    "{domain}: this key claims the domain itself; a witness must be another node"
                ));
            }
            // The other roles' entries of the previous attestation, newest
            // first and whatever its age (an old entry is re-verified, not
            // trusted). Each is carried only if its own record, verified
            // now, still names the key: the event says `verified_at` now
            // and one `method` for everything in it, so nothing goes in
            // that was not verified now, and the method is the weakest of
            // the lot.
            let mut method = method;
            let mut others: Vec<(String, Npub)> = Vec::new();
            let previous = newest_own_attestation(&previous, own, &domain);
            if previous.is_none() {
                // Nothing found is also what an outage of the relay holding
                // it looks like, and a fetch reports no such difference; a
                // new attestation then erases the other roles' entries on
                // every relay that takes it.
                if require_previous {
                    relays.shutdown().await;
                    return Err(anyhow!(
                        "{domain}: no previous attestation of this witness found on any relay (--require-previous): if there was one, its entries for other roles would be erased; check the relays"
                    ));
                }
                println!(
                    "{domain}: no previous attestation of this witness found; if there was one on a relay that did not answer, its entries for other roles are erased by this one"
                );
            }
            if let Some(prev) = previous {
                let mut roles: Vec<&String> = prev.others.iter().map(|(s, _)| s).collect();
                roles.sort();
                roles.dedup();
                for role in roles {
                    let (lookup, _) = v.lookup_service(role, &domain).await;
                    let (records, m) = match lookup {
                        TxtLookup::Hit { records, method } if method >= Method::Dns => {
                            (records, method)
                        }
                        other => {
                            println!(
                                "{domain}: the {role} record is not verified now ({other:?}); its entries are withdrawn"
                            );
                            continue;
                        }
                    };
                    for (_, key) in prev.others.iter().filter(|(s, _)| s == role) {
                        if records.iter().any(|r| r.npub == *key) {
                            others.push((role.clone(), *key));
                            method = method.min(m);
                        } else {
                            println!(
                                "{domain}: {key} is no longer in the {role} record; withdrawn"
                            );
                        }
                    }
                }
            }
            let all: Vec<String> = cfg
                .public_relays
                .iter()
                .chain(cfg.mesh_relays.iter())
                .cloned()
                .collect();
            relays.shutdown().await;
            if dry_run {
                println!(
                    "{}",
                    attestation_event_json_with(&keys, &domain, &servers, &others, method, now)
                        .map_err(anyhow::Error::msg)?
                );
                return Ok(());
            }
            let ok = publish_attestation_with(
                keys,
                &all,
                &domain,
                &servers,
                &others,
                method,
                now,
                Duration::from_secs(10),
            )
            .await
            .map_err(anyhow::Error::msg)?;
            if ok.none_accepted() {
                anyhow::bail!(
                    "no relay accepted the attestation: {}",
                    ok.rejected
                        .iter()
                        .map(|(r, why)| format!("{r}: {why}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
            }
            let kept = if others.is_empty() {
                String::new()
            } else {
                format!(
                    ", {} entry(ies) for other roles re-verified and kept",
                    others.len()
                )
            };
            println!(
                "{domain}: attested {} server(s) by {method:?}{kept}, accepted by {}",
                servers.len(),
                ok.accepted.join(", ")
            );
            for (r, why) in &ok.rejected {
                println!("  rejected by {r}: {why}");
            }
            for s in &servers {
                println!("  {s}");
            }
        }
        Cmd::Attestations { domain } => {
            let domain =
                pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
            if cfg.witnesses.is_empty() {
                println!(
                    "{domain}: no witnesses configured; attestations are fetched from witnesses only"
                );
                return Ok(());
            }
            let relays = relays(&cfg).await;
            for ev in relays
                .fetch_attestations(&domain, &cfg.witnesses, scope(cli.offline))
                .await
            {
                println!("{}", serde_json::to_string_pretty(&ev)?);
            }
            relays.shutdown().await;
        }
        Cmd::Pins { cmd } => match cmd {
            PinsCmd::List => {
                for b in pins_read_only(&cfg.pins)?.list() {
                    println!(
                        "{}\t{}:{}\t{:?}\tverified_at {}",
                        b.domain, b.npub, b.port, b.method, b.verified_at
                    );
                }
            }
            PinsCmd::Forget { domain } => {
                let domain =
                    pubdom_core::domain::normalize(&domain).ok_or_else(|| anyhow!("bad domain"))?;
                // A running daemon keeps the pins in memory and writes the
                // file itself: editing the file under it would be undone by
                // its next save. Its control socket is the way in; the file
                // is edited only when no daemon answers.
                if let Some(sock) = cfg.control.as_ref().filter(|s| s.exists()) {
                    match pubdom_control::query(
                        sock,
                        "forget",
                        serde_json::json!({ "domain": domain }),
                    ) {
                        Ok(reply) => {
                            println!("daemon: {}", serde_json::to_string(&reply)?);
                            return Ok(());
                        }
                        Err(e) => println!(
                            "daemon not answering on {} ({e}); editing the file",
                            sock.display()
                        ),
                    }
                }
                let pins = FilePinStore::open(&cfg.pins)?;
                if pins.forget(&domain) {
                    println!("forgot {domain}");
                } else {
                    println!("{domain}: was not pinned");
                }
            }
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use pubdom_core::claim::Event;

    #[test]
    fn qtypes_by_name_and_number() {
        assert_eq!(qtype("aaaa").unwrap(), synth::QTYPE_AAAA);
        assert_eq!(qtype("SVCB").unwrap(), synth::QTYPE_SVCB);
        assert_eq!(qtype("https").unwrap(), synth::QTYPE_HTTPS);
        assert_eq!(qtype("64").unwrap(), 64);
        assert!(qtype("MX?").is_err());
    }

    #[test]
    fn the_previous_attestation_is_this_witness_s_own_newest_for_the_domain() {
        let own = Npub::from_bytes([1; 32]);
        let other = Npub::from_bytes([2; 32]);
        let server = Npub::from_bytes([9; 32]);
        let ev = |witness: Npub, domain: &str, created_at: u64| Event {
            kind: pubdom_core::KIND_ATTESTATION,
            pubkey: witness.to_hex(),
            created_at,
            tags: Attestation::tags(domain, &[server], Method::Dns, created_at),
        };
        let events = vec![
            ev(own, "example.org", 100),
            ev(own, "example.org", 200),
            ev(other, "example.org", 300),
            ev(own, "example.net", 400),
        ];
        let prev = newest_own_attestation(&events, own, "example.org").unwrap();
        assert_eq!(
            prev.created_at, 200,
            "newest of this witness's for this domain"
        );
        assert!(
            newest_own_attestation(&events, Npub::from_bytes([3; 32]), "example.org").is_none()
        );
    }

    #[test]
    fn scopes_and_a_missing_pin_file() {
        assert!(matches!(scope(true), RelayScope::Offline));
        assert!(matches!(scope(false), RelayScope::AfterHit));
        let none = pins_read_only(std::path::Path::new("/nonexistent/pins.json")).unwrap();
        assert!(none.list().is_empty());
    }
}
