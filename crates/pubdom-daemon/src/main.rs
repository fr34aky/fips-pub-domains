//! `fips-pubdomd` — the forwarding resolver daemon (docs/plan-platforms.md).
//!
//! Sits in front of all DNS on the machine (full mode): every query goes
//! through `pubdom_resolve::Resolver::lookup`, and everything that is not
//! over fips is forwarded to the legacy upstreams unchanged. `setup` wires
//! the OS to send DNS here; milestone 2 implements the systemd-resolved
//! backend (a global drop-in with `DNS=[::1]:5356` and `Domains=~.`, the
//! same mechanism fips uses for `.fips`, generalised).

mod forward;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use pubdom_resolve::{Config, LookupResult, ProdResolver};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const DEFAULT_CONFIG: &str = "/etc/fips-pubdom/config.yaml";
/// Sorts after fips's own drop-in (`fips-dns-setup` writes one named after
/// itself) so the list resets below win: resolved merges every drop-in
/// into ONE global server pool, and two servers with different routing
/// domains in one pool are queried interchangeably.
const RESOLVED_DROPIN: &str = "/etc/systemd/resolved.conf.d/zz-fips-pubdom.conf";
const RESOLVED_UPSTREAMS: &str = "/run/systemd/resolve/resolv.conf";

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
    /// Point the OS at the daemon and write the config.
    Setup {
        #[arg(long, value_enum, default_value_t = Backend::Resolved)]
        backend: Backend,
    },
    /// Undo `setup`.
    Teardown {
        #[arg(long, value_enum, default_value_t = Backend::Resolved)]
        backend: Backend,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Resolved,
}

struct State {
    cfg: Config,
    resolver: ProdResolver,
    /// Re-read from `upstreams_from` periodically (a network change
    /// watcher replaces the polling in a later milestone).
    upstreams: RwLock<Vec<IpAddr>>,
}

impl State {
    fn refresh_upstreams(&self) {
        let now = self.cfg.current_upstreams();
        let mut g = self.upstreams.write().unwrap();
        if *g != now {
            tracing::info!(upstreams = ?now, "upstreams changed");
            *g = now;
            self.resolver.set_online(!g.is_empty());
        }
    }
}

async fn handle(state: &State, query: Vec<u8>) -> Option<Vec<u8>> {
    // fips's own names go to its responder: in full mode we are the only
    // global server systemd-resolved knows, so `.fips` arrives here too.
    if forward::is_fips_name(&query) {
        return match forward::forward_to(&query, &[state.cfg.responder]).await {
            Some(r) => Some(r),
            None => forward::servfail(&query),
        };
    }
    let result = match tokio::time::timeout(state.cfg.budget(), state.resolver.lookup(&query)).await {
        Ok(r) => r,
        Err(_) => {
            tracing::warn!("lookup exceeded the budget; falling back to legacy");
            LookupResult::Passthrough
        }
    };
    match result {
        LookupResult::Answer(a) => Some(a),
        LookupResult::Passthrough => {
            let upstreams = state.upstreams.read().unwrap().clone();
            match forward::forward(&query, &upstreams).await {
                Some(r) => Some(r),
                None => forward::servfail(&query),
            }
        }
    }
}

async fn run(cfg: Config) -> Result<()> {
    let upstreams = cfg.current_upstreams();
    tracing::info!(?upstreams, listen = ?cfg.listen, pins = %cfg.pins.display(), "starting");
    let shadowed = cfg.link_search_domains();
    if !shadowed.is_empty() {
        tracing::warn!(
            domains = ?shadowed,
            "link search domains route past this daemon on systemd-resolved: names under them never reach it (drop the search domain from the link, e.g. nmcli con mod <con> ipv4.dns-search '')"
        );
    }
    let resolver = cfg.build_resolver(upstreams.clone()).await.map_err(anyhow::Error::msg)?;
    let state = Arc::new(State { cfg, resolver, upstreams: RwLock::new(upstreams) });

    let mut tasks = Vec::new();
    for addr in state.cfg.listen.clone() {
        let udp = UdpSocket::bind(addr).await.with_context(|| format!("bind udp {addr}"))?;
        let tcp = TcpListener::bind(addr).await.with_context(|| format!("bind tcp {addr}"))?;
        let udp = Arc::new(udp);
        let st = state.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else { continue };
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
                let Ok((mut s, _)) = tcp.accept().await else { continue };
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
    let st = state.clone();
    tasks.push(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            st.refresh_upstreams();
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
    match backend {
        Backend::Resolved => {
            if !Path::new("/run/systemd/resolve").exists() {
                bail!("systemd-resolved is not running; other backends come in a later milestone");
            }
            // Snapshot the upstreams first: once the drop-in is in place the
            // stub file points back at us, but /run/systemd/resolve/resolv.conf
            // keeps listing the real servers, which the daemon then follows.
            let mut cfg = Config::load_or_default(config_path).map_err(anyhow::Error::msg)?;
            cfg.upstreams_from = Some(PathBuf::from(RESOLVED_UPSTREAMS));
            if let Some(dir) = config_path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(config_path, serde_yaml::to_string(&cfg)?)?;
            if let Some(dir) = cfg.pins.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let listen = cfg
                .listen
                .iter()
                .map(|a| match a.ip() {
                    IpAddr::V6(v6) => format!("[{v6}]:{}", a.port()),
                    IpAddr::V4(v4) => format!("{v4}:{}", a.port()),
                })
                .collect::<Vec<_>>()
                .join(" ");
            std::fs::create_dir_all("/etc/systemd/resolved.conf.d")?;
            std::fs::write(
                RESOLVED_DROPIN,
                format!(
                    "# Managed by fips-pubdomd setup. All names go through fips-pubdom (full mode);\n\
                     # names that are not over fips are forwarded to the previous upstreams,\n\
                     # .fips names to fips's responder. The empty assignments reset the lists\n\
                     # other drop-ins (fips-dns-setup's) added to the same global pool.\n\
                     [Resolve]\nDNS=\nDNS={listen}\nDomains=\nDomains=~.\n"
                ),
            )?;
            let st = std::process::Command::new("systemctl").args(["restart", "systemd-resolved"]).status()?;
            if !st.success() {
                bail!("systemctl restart systemd-resolved failed");
            }
            println!("wrote {} and {}", config_path.display(), RESOLVED_DROPIN);
            println!("upstreams now: {:?}", cfg.current_upstreams());
            println!("start the daemon: systemctl enable --now fips-pubdom");
        }
    }
    Ok(())
}

fn teardown(backend: Backend) -> Result<()> {
    match backend {
        Backend::Resolved => {
            match std::fs::remove_file(RESOLVED_DROPIN) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let st = std::process::Command::new("systemctl").args(["restart", "systemd-resolved"]).status()?;
            if !st.success() {
                bail!("systemctl restart systemd-resolved failed");
            }
            println!("removed {RESOLVED_DROPIN}");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => run(Config::load_or_default(&cli.config).map_err(anyhow::Error::msg)?).await,
        Cmd::Setup { backend } => setup(&cli.config, backend),
        Cmd::Teardown { backend } => teardown(backend),
    }
}
