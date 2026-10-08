//! `fips-pubdomd` — the forwarding resolver daemon (docs/platforms.md).
//!
//! Sits in front of all DNS on the machine (full mode): every query goes
//! through `pubdom_resolve::Resolver::lookup`, and everything that is not
//! over fips is forwarded to the legacy upstreams unchanged. `setup` wires
//! the OS to send DNS here; milestone 2 implements the systemd-resolved
//! backend (a global drop-in with `DNS=[::1]:5356` and `Domains=~.`, the
//! same mechanism fips uses for `.fips`, generalised).

mod backend;
mod forward;

use anyhow::{Context, Result};
use backend::Backend;
use clap::{Parser, Subcommand};
use pubdom_resolve::{Config, LookupResult, ProdResolver};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const DEFAULT_CONFIG: &str = "/etc/fips-pubdom/config.yaml";

#[derive(Parser)]
#[command(name = "fips-pubdomd", version, about)]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve DNS (what the service unit runs).
    Run,
    /// Point the OS at the daemon and write the config (docs/daemon.md).
    Setup {
        /// Which resolver arrangement to hook into; `auto` detects it.
        #[arg(long, value_enum, default_value_t = Backend::Auto)]
        backend: Backend,
    },
    /// Undo `setup`; without --backend, the one `setup` recorded.
    Teardown {
        #[arg(long, value_enum, default_value_t = Backend::Auto)]
        backend: Backend,
    },
}

struct State {
    cfg: Config,
    resolver: ProdResolver,
    /// Re-read from `upstreams_from` when that file changes (`watch.rs`)
    /// and every 30 s as the fallback.
    upstreams: RwLock<Vec<IpAddr>>,
    /// When a query last re-read the upstreams for want of any (seconds).
    looked: std::sync::atomic::AtomicU64,
}

impl State {
    fn refresh_upstreams(&self) {
        let now = self.cfg.current_upstreams();
        let mut g = self.upstreams.write().unwrap();
        if *g != now {
            tracing::info!(upstreams = ?now, "upstreams changed");
            // The verifier must follow, or every TXT lookup keeps going to
            // the old network's resolvers and times out into "unreachable".
            if let Err(e) = self.resolver.txt().set_upstreams(&now) {
                tracing::error!(error = %e, "could not rebuild the TXT verifier; keeping the old upstreams");
                return;
            }
            *g = now;
            self.resolver.set_online(!g.is_empty());
            self.resolver.flush_caches();
        }
    }
}

async fn handle(state: &Arc<State>, query: Vec<u8>) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None; // not a DNS message; nothing to answer
    }
    // fips's own names go to its responder: in full mode we are the only
    // global server systemd-resolved knows, so `.fips` arrives here too.
    if forward::is_fips_name(&query) {
        return match forward::forward_to(&query, &[state.cfg.responder]).await {
            Some(r) => Some(r),
            None => forward::servfail(&query),
        };
    }
    // No upstream yet — the daemon came up before the network did — or
    // none any more: look again now rather than at the next poll. At boot
    // this window was thirty seconds of failed lookups.
    // At most once a second: a machine with no network asks all day.
    if state.upstreams.read().unwrap().is_empty() {
        let now = pubdom_resolve::now();
        if state.looked.swap(now, std::sync::atomic::Ordering::Relaxed) != now {
            state.refresh_upstreams();
        }
    }
    let upstreams = state.upstreams.read().unwrap().clone();
    let mut pending = Box::pin({
        let state = state.clone();
        let query = query.clone();
        async move { state.resolver.lookup(&query).await }
    });
    let mut overrun = false;
    let mut fetched = None;
    let mut legacy = None;
    // One poll before anything else: a cached decision — or a name that
    // is not a hostname, or a record type never over fips — settles here,
    // with nothing spawned and no upstream asked ahead of it. Whatever
    // the lookup itself answers at once needs no prediction from here.
    let result = match tokio::time::timeout(Duration::ZERO, &mut pending).await {
        Ok(r) => r,
        Err(_) => {
            // Almost every name is not over fips, and its answer should not
            // wait for us to find that out: fetch it alongside the decision.
            // Not for a name under a pinned domain, which is answered from
            // the pin without the upstream hearing of it.
            legacy = (!upstreams.is_empty() && !state.resolver.has_pin_for(&query)).then(|| {
                let (query, upstreams) = (query.clone(), upstreams.clone());
                tokio::spawn(async move { forward::forward(&query, &upstreams).await })
            });
            // Not awaited in place: a lookup that overruns the budget carries
            // on and caches its decision, so the next query is answered at
            // once.
            let mut lookup = tokio::spawn(pending);
            tokio::select! {
                biased;
                joined = tokio::time::timeout(state.cfg.budget(), &mut lookup) => match joined {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "lookup failed; falling back to legacy");
                        LookupResult::Passthrough
                    }
                    Err(_) => {
                        tracing::warn!("lookup exceeded the budget; falling back to legacy for now");
                        overrun = true;
                        LookupResult::Passthrough
                    }
                },
                // One upstream has no record for any domain this name could belong
                // to: the legacy answer goes out now, short-lived like an overrun's,
                // while the lookup waits for the other upstreams and caches what
                // they say. Waiting for the slowest of them cost every first
                // lookup hundreds of milliseconds.
                _ = state.resolver.denied_by_an_upstream(&query), if legacy.is_some() => {
                    // The decision may be in before the legacy answer is — at once
                    // when it was cached — and then it is the answer, and nothing
                    // needs clamping.
                    let mut l = legacy.take().expect("guarded by the branch's condition");
                    tokio::select! {
                        biased;
                        done = &mut lookup => {
                            legacy = Some(l);
                            done.unwrap_or(LookupResult::Passthrough)
                        }
                        reply = &mut l => {
                            fetched = Some(reply.ok().flatten());
                            overrun = true;
                            LookupResult::Passthrough
                        }
                    }
                }
            }
        }
    };
    match result {
        LookupResult::Answer(a) => {
            if let Some(l) = legacy {
                l.abort();
            }
            Some(a)
        }
        LookupResult::Passthrough | LookupResult::Unavailable { .. } => {
            // Bound, but no server reachable right now: the legacy answer
            // stands in until a server or node is asked again — at least
            // the overrun TTL, at most the upstream's own.
            let cap = match result {
                LookupResult::Unavailable { retry_in } => {
                    Some(pubdom_core::unavailable_ttl(retry_in))
                }
                _ if overrun => Some(pubdom_core::OVERRUN_TTL_SECS),
                _ => None,
            };
            let reply = match (fetched, legacy) {
                (Some(reply), _) => reply,
                (None, Some(l)) => l.await.ok().flatten(),
                (None, None) => forward::forward(&query, &upstreams).await,
            };
            match reply {
                // The lookup is still deciding: the stub must not keep the
                // legacy address for the upstream's TTL (a parked wildcard
                // gives a real address for 300 s) while it does.
                Some(r) => Some(match cap {
                    Some(cap) => pubdom_core::synth::clamp_ttls(&r, cap).unwrap_or(r),
                    None => r,
                }),
                None => forward::servfail(&query),
            }
        }
    }
}

async fn run(cfg: Config) -> Result<()> {
    let upstreams = cfg.current_upstreams();
    tracing::info!(?upstreams, listen = ?cfg.listen, pins = %cfg.pins.display(), "starting");
    // Only resolved routes a link's search domain past a global server;
    // glibc and dnsmasq send every name to the daemon.
    let on_resolved = cfg
        .upstreams_from
        .as_deref()
        .is_some_and(|p| p.starts_with("/run/systemd/resolve"));
    let shadowed = if on_resolved {
        cfg.link_search_domains()
    } else {
        Vec::new()
    };
    if !shadowed.is_empty() {
        tracing::warn!(
            domains = ?shadowed,
            "link search domains route past this daemon on systemd-resolved: names under them never reach it (drop the search domain from the link, e.g. nmcli con mod <con> ipv4.dns-search '')"
        );
    }
    let resolver = cfg
        .build_resolver(upstreams.clone())
        .await
        .map_err(anyhow::Error::msg)?;
    let state = Arc::new(State {
        cfg,
        resolver,
        upstreams: RwLock::new(upstreams),
        looked: Default::default(),
    });

    let mut tasks = Vec::new();
    for addr in state.cfg.listen.clone() {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("bind udp {addr}"))?;
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind tcp {addr}"))?;
        let udp = Arc::new(udp);
        let st = state.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, from) = match udp.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        pubdom_resolve::after_socket_error(&e, "receive").await;
                        continue;
                    }
                };
                let (st, udp, q) = (st.clone(), udp.clone(), buf[..n].to_vec());
                tokio::spawn(async move {
                    if let Some(r) = handle(&st, q).await {
                        let _ = udp.send_to(&r, from).await;
                    }
                });
            }
        }));
        let st = state.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (mut s, _) = match tcp.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        pubdom_resolve::after_socket_error(&e, "accept").await;
                        continue;
                    }
                };
                let st = st.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(15), async {
                        let mut hdr = [0u8; 2];
                        s.read_exact(&mut hdr).await?;
                        let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
                        s.read_exact(&mut q).await?;
                        if let Some(r) = handle(&st, q).await {
                            s.write_all(&(r.len() as u16).to_be_bytes()).await?;
                            s.write_all(&r).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    })
                    .await;
                });
            }
        }));
    }
    // The upstreams file changes when the network does: follow it, and keep
    // the poll for whatever the watcher misses — and to set the watch up
    // once the directory exists, if it did not at start.
    let st = state.clone();
    tasks.push(tokio::spawn(async move {
        let start_watch = |st: &Arc<State>| {
            st.cfg.upstreams_from.as_deref().and_then(|p| {
                let st = st.clone();
                pubdom_resolve::watch::watch(p, move || st.refresh_upstreams())
            })
        };
        let mut watcher = start_watch(&st);
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            st.refresh_upstreams();
            if watcher.is_none() {
                watcher = start_watch(&st);
            }
        }
    }));

    tokio::signal::ctrl_c().await?;
    tracing::info!("stopping");
    for t in tasks {
        t.abort();
    }
    Ok(())
}

fn setup(config_path: &Path, backend: Backend) -> Result<()> {
    let host = backend::Host::system();
    let (used, notes) = backend::setup(&host, config_path, backend)?;
    println!("backend: {used:?}");
    println!("wrote {}", config_path.display());
    for n in notes {
        println!("{n}");
    }
    let cfg = Config::load_or_default(config_path).map_err(anyhow::Error::msg)?;
    println!("upstreams now: {:?}", cfg.current_upstreams());
    println!(
        "start (or restart) the daemon: systemctl enable --now fips-pubdom; systemctl restart fips-pubdom"
    );
    Ok(())
}

fn teardown(config_path: &Path, backend: Backend) -> Result<()> {
    let host = backend::Host::system();
    let (used, notes) = backend::teardown(&host, config_path, backend)?;
    println!("backend: {used:?}");
    for n in notes {
        println!("{n}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => run(Config::load_or_default(&cli.config).map_err(anyhow::Error::msg)?).await,
        Cmd::Setup { backend } => setup(&cli.config, backend),
        Cmd::Teardown { backend } => teardown(&cli.config, backend),
    }
}
