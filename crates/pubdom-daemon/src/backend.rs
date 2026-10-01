//! `fips-pubdomd setup` / `teardown`: getting the OS to send its DNS to the
//! daemon (docs/platforms.md, "full mode"), one backend per resolver
//! arrangement found on Linux. Every path is taken relative to a root and
//! every command goes through a runner, so the backends are exercised in a
//! temporary directory by the tests below; production uses `/` and the
//! real `systemctl`/`nmcli`.
//!
//! The backend `setup` chose is recorded in `/etc/fips-pubdom/backend`, so
//! `teardown` undoes the right thing without being told.

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use pubdom_resolve::Config;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Sorts after fips's own drop-in (`fips-dns-setup` writes one named after
/// itself) so the list resets below win: resolved merges every drop-in
/// into ONE global server pool, and two servers with different routing
/// domains in one pool are queried interchangeably.
const RESOLVED_DROPIN: &str = "etc/systemd/resolved.conf.d/zz-fips-pubdom.conf";
const RESOLVED_UPSTREAMS: &str = "run/systemd/resolve/resolv.conf";
const NM_DROPIN: &str = "etc/NetworkManager/conf.d/zz-fips-pubdom.conf";
const NM_UPSTREAMS: &str = "run/NetworkManager/resolv.conf";
const NM_RUNDIR: &str = "run/NetworkManager";
const DNSMASQ_DROPIN: &str = "etc/dnsmasq.d/fips-pubdom.conf";
const DNSMASQ_CONF: &str = "etc/dnsmasq.conf";
const DNSMASQ_DIR: &str = "etc/dnsmasq.d";
const RESOLV_CONF: &str = "etc/resolv.conf";
/// Where `setup` keeps what it replaced and what it snapshotted (under
/// /etc/fips-pubdom, next to the config).
const STATE_BACKEND: &str = "etc/fips-pubdom/backend";
const RESOLV_BACKUP: &str = "etc/fips-pubdom/resolv.conf.bak";
const UPSTREAMS_SNAPSHOT: &str = "etc/fips-pubdom/upstreams.conf";

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum Backend {
    /// Pick from what the machine runs: resolved, NetworkManager, dnsmasq,
    /// else a plain resolv.conf. For `teardown`: what `setup` recorded.
    Auto,
    /// systemd-resolved: a global drop-in makes the daemon the only server.
    Resolved,
    /// NetworkManager without resolved: NM stops managing resolv.conf
    /// (`dns=none`), the daemon takes port 53 and follows NM's own list of
    /// the connections' servers.
    NetworkManager,
    /// A standalone dnsmasq as the local resolver: it forwards everything
    /// to the daemon on 5356; the servers it used become the upstreams.
    Dnsmasq,
    /// Nobody manages resolv.conf: the daemon takes port 53 and the
    /// previous `nameserver` lines become its upstreams.
    ResolvConf,
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            Backend::Auto => "auto",
            Backend::Resolved => "resolved",
            Backend::NetworkManager => "networkmanager",
            Backend::Dnsmasq => "dnsmasq",
            Backend::ResolvConf => "resolv-conf",
        }
    }

    fn from_name(s: &str) -> Option<Self> {
        [
            Backend::Resolved,
            Backend::NetworkManager,
            Backend::Dnsmasq,
            Backend::ResolvConf,
        ]
        .into_iter()
        .find(|b| b.name() == s.trim())
    }
}

/// Runs a management command (`systemctl`, `nmcli`) with its arguments.
pub type Runner = Box<dyn Fn(&str, &[&str]) -> Result<()>>;

/// The machine as the backends see it: a filesystem root and a way to run
/// the resolver's management commands.
pub struct Host {
    pub root: PathBuf,
    pub run: Runner,
}

/// A symlink `link` → `target`; the daemon builds on every OS, the
/// backends run on Linux.
fn symlink(target: &str, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(not(unix))]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
}

impl Host {
    /// The real machine.
    pub fn system() -> Self {
        Host {
            root: PathBuf::from("/"),
            run: Box::new(|cmd, args| {
                let st = std::process::Command::new(cmd)
                    .args(args)
                    .status()
                    .with_context(|| format!("running {cmd}"))?;
                if st.success() {
                    Ok(())
                } else {
                    bail!("{cmd} {} failed", args.join(" "))
                }
            }),
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn exists(&self, rel: &str) -> bool {
        self.path(rel).exists()
    }

    fn write(&self, rel: &str, text: &str) -> Result<()> {
        let p = self.path(rel);
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, text).with_context(|| format!("writing {}", p.display()))
    }

    fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.path(rel)).ok()
    }

    fn remove(&self, rel: &str) -> Result<()> {
        match std::fs::remove_file(self.path(rel)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The first of `cmds` that runs successfully; the last error otherwise.
    fn run_first(&self, cmds: &[(&str, &[&str])]) -> Result<()> {
        let mut last = None;
        for (cmd, args) in cmds {
            match (self.run)(cmd, args) {
                Ok(()) => return Ok(()),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no command to run")))
    }
}

/// What the machine runs, from the files its resolver leaves behind.
pub fn detect(host: &Host) -> Result<Backend> {
    if host.exists(RESOLVED_UPSTREAMS) {
        return Ok(Backend::Resolved);
    }
    if host.exists(NM_RUNDIR) {
        return Ok(Backend::NetworkManager);
    }
    if host.exists(DNSMASQ_DIR)
        && (host.exists("run/dnsmasq/dnsmasq.pid") || host.exists("var/run/dnsmasq.pid"))
    {
        return Ok(Backend::Dnsmasq);
    }
    let rc = host.path(RESOLV_CONF);
    if rc
        .symlink_metadata()
        .map(|m| m.is_symlink())
        .unwrap_or(false)
    {
        bail!(
            "{} is a symlink to {}: another tool manages it, and no supported resolver was found running",
            rc.display(),
            std::fs::read_link(&rc)
                .map(|t| t.display().to_string())
                .unwrap_or_default()
        );
    }
    Ok(Backend::ResolvConf)
}

/// Port 53 on loopback, for the backends where the OS cannot name a port.
fn port53() -> Vec<std::net::SocketAddr> {
    vec!["[::1]:53".parse().unwrap(), "127.0.0.1:53".parse().unwrap()]
}

fn listen_spec(cfg: &Config) -> String {
    cfg.listen
        .iter()
        .map(|a| match a.ip() {
            IpAddr::V6(v6) => format!("[{v6}]:{}", a.port()),
            IpAddr::V4(v4) => format!("{v4}:{}", a.port()),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The `nameserver` entries of a resolv.conf, minus loopback (ourselves,
/// or a local forwarder about to be replaced).
fn nameservers(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for ip in text
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|s| s.split('%').next().unwrap_or(s).parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_loopback())
    {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// A resolv.conf naming `servers`, keeping `search`/`domain`/`options`
/// lines from `original`.
fn resolv_conf_text(servers: &[String], original: &str, note: &str) -> String {
    let mut s = format!("# Managed by fips-pubdomd setup ({note}).\n");
    for sv in servers {
        s.push_str(&format!("nameserver {sv}\n"));
    }
    for line in original.lines() {
        let t = line.trim_start();
        if t.starts_with("search") || t.starts_with("domain") || t.starts_with("options") {
            s.push_str(line);
            s.push('\n');
        }
    }
    s
}

/// Snapshot `source`'s servers into the daemon's own upstreams file, for
/// the backends whose resolver will be pointed at us (its file would then
/// name only ourselves).
fn snapshot_upstreams(host: &Host, source: &str) -> Result<Vec<IpAddr>> {
    let text = host
        .read(source)
        .ok_or_else(|| anyhow!("cannot read {}", host.path(source).display()))?;
    let servers = nameservers(&text);
    if servers.is_empty() {
        bail!(
            "no upstream resolver found in {}; set `upstreams` in the config and run setup again",
            host.path(source).display()
        );
    }
    let mut out =
        String::from("# Written by fips-pubdomd setup: the resolvers the machine used before.\n");
    for ip in &servers {
        out.push_str(&format!("nameserver {ip}\n"));
    }
    for line in text.lines() {
        if line.trim_start().starts_with("search") {
            out.push_str(line);
            out.push('\n');
        }
    }
    host.write(UPSTREAMS_SNAPSHOT, &out)?;
    Ok(servers)
}

/// Keep what resolv.conf was — a symlink's target, or the file — so
/// `teardown` can put it back.
fn back_up_resolv_conf(host: &Host) -> Result<()> {
    let rc = host.path(RESOLV_CONF);
    let meta = match rc.symlink_metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            host.write(
                RESOLV_BACKUP,
                "# (no resolv.conf existed)\n#fips-pubdom-absent\n",
            )?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    if meta.is_symlink() {
        let target = std::fs::read_link(&rc)?;
        host.write(
            RESOLV_BACKUP,
            &format!("#fips-pubdom-symlink {}\n", target.display()),
        )?;
        std::fs::remove_file(&rc)?;
    } else {
        host.write(RESOLV_BACKUP, &std::fs::read_to_string(&rc)?)?;
    }
    Ok(())
}

fn restore_resolv_conf(host: &Host) -> Result<()> {
    let Some(backup) = host.read(RESOLV_BACKUP) else {
        return Ok(());
    };
    let rc = host.path(RESOLV_CONF);
    let _ = std::fs::remove_file(&rc);
    if backup.contains("#fips-pubdom-absent") {
        // nothing to restore
    } else if let Some(target) = backup
        .lines()
        .find_map(|l| l.strip_prefix("#fips-pubdom-symlink "))
    {
        symlink(target.trim(), &rc)?;
    } else {
        std::fs::write(&rc, backup)?;
    }
    host.remove(RESOLV_BACKUP)
}

fn write_config(host: &Host, config_path: &Path, cfg: &Config) -> Result<()> {
    let p = if config_path.is_absolute() {
        host.root
            .join(config_path.strip_prefix("/").unwrap_or(config_path))
    } else {
        config_path.to_path_buf()
    };
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&p, serde_yaml::to_string(cfg)?)
        .with_context(|| format!("writing {}", p.display()))?;
    let pins = host
        .root
        .join(cfg.pins.strip_prefix("/").unwrap_or(&cfg.pins));
    if let Some(dir) = pins.parent() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn load_config(host: &Host, config_path: &Path) -> Result<Config> {
    let p = if config_path.is_absolute() {
        host.root
            .join(config_path.strip_prefix("/").unwrap_or(config_path))
    } else {
        config_path.to_path_buf()
    };
    Config::load_or_default(&p).map_err(anyhow::Error::msg)
}

/// Point the OS at the daemon. Returns the backend used and what to tell
/// the operator.
pub fn setup(host: &Host, config_path: &Path, backend: Backend) -> Result<(Backend, Vec<String>)> {
    let backend = match backend {
        Backend::Auto => detect(host)?,
        b => b,
    };
    let mut cfg = load_config(host, config_path)?;
    let mut notes = Vec::new();
    match backend {
        Backend::Resolved => {
            if !host.exists(RESOLVED_UPSTREAMS) {
                bail!("systemd-resolved is not running (no /run/systemd/resolve/resolv.conf)");
            }
            // Snapshot the upstreams first: once the drop-in is in place the
            // stub file points back at us, but /run/systemd/resolve/resolv.conf
            // keeps listing the real servers, which the daemon then follows.
            cfg.upstreams_from = Some(PathBuf::from("/").join(RESOLVED_UPSTREAMS));
            write_config(host, config_path, &cfg)?;
            host.write(
                RESOLVED_DROPIN,
                &format!(
                    "# Managed by fips-pubdomd setup. All names go through fips-pubdom (full mode);\n\
                     # names that are not over fips are forwarded to the previous upstreams,\n\
                     # .fips names to fips's responder. The empty assignments reset the lists\n\
                     # other drop-ins (fips-dns-setup's) added to the same global pool.\n\
                     [Resolve]\nDNS=\nDNS={}\nDomains=\nDomains=~.\n",
                    listen_spec(&cfg)
                ),
            )?;
            (host.run)("systemctl", &["restart", "systemd-resolved"])?;
            notes.push(format!("wrote {}", host.path(RESOLVED_DROPIN).display()));
        }
        Backend::NetworkManager => {
            if !host.exists(NM_RUNDIR) {
                bail!("NetworkManager is not running (no /run/NetworkManager)");
            }
            if host.exists(RESOLVED_UPSTREAMS) {
                bail!("systemd-resolved is running too; use --backend resolved");
            }
            // NM keeps writing its own list of the connections' servers to
            // /run/NetworkManager/resolv.conf whatever `dns=` says, so the
            // daemon follows DHCP changes through it. `dns=none` keeps NM
            // (and its dnsmasq plugin) off /etc/resolv.conf, which then
            // names us: resolv.conf cannot carry a port, hence 53.
            cfg.upstreams_from = Some(PathBuf::from("/").join(NM_UPSTREAMS));
            cfg.listen = port53();
            write_config(host, config_path, &cfg)?;
            host.write(
                NM_DROPIN,
                "# Managed by fips-pubdomd setup: NetworkManager leaves /etc/resolv.conf to\n\
                 # fips-pubdomd, which forwards names not over fips to the servers NM lists\n\
                 # in /run/NetworkManager/resolv.conf.\n[main]\ndns=none\n",
            )?;
            host.run_first(&[
                ("nmcli", &["general", "reload", "conf"]),
                ("systemctl", &["reload", "NetworkManager"]),
            ])?;
            let original = host.read(NM_UPSTREAMS).unwrap_or_default();
            back_up_resolv_conf(host)?;
            host.write(
                RESOLV_CONF,
                &resolv_conf_text(
                    &["::1".into(), "127.0.0.1".into()],
                    &original,
                    "NetworkManager backend; previous file in /etc/fips-pubdom/resolv.conf.bak",
                ),
            )?;
            notes.push(format!(
                "wrote {} and {}",
                host.path(NM_DROPIN).display(),
                host.path(RESOLV_CONF).display()
            ));
            notes.push("the daemon now listens on port 53 (restart it after this)".into());
        }
        Backend::Dnsmasq => {
            if !host.exists(DNSMASQ_DIR) {
                bail!("no /etc/dnsmasq.d: dnsmasq is not installed as the local resolver");
            }
            if host.exists(NM_RUNDIR) && !host.exists(NM_DROPIN) {
                bail!(
                    "NetworkManager is running: it would keep feeding dnsmasq its own servers; use --backend networkmanager"
                );
            }
            let resolv_file = host
                .read(DNSMASQ_CONF)
                .and_then(|t| {
                    t.lines().find_map(|l| {
                        l.trim()
                            .strip_prefix("resolv-file=")
                            .map(|s| s.trim().to_string())
                    })
                })
                .map(|p| p.trim_start_matches('/').to_string())
                .unwrap_or_else(|| RESOLV_CONF.to_string());
            let servers = snapshot_upstreams(host, &resolv_file)?;
            cfg.upstreams_from = Some(PathBuf::from("/").join(UPSTREAMS_SNAPSHOT));
            write_config(host, config_path, &cfg)?;
            let mut text = String::from(
                "# Managed by fips-pubdomd setup: dnsmasq forwards every name to fips-pubdomd,\n\
                 # which forwards names not over fips to the servers dnsmasq used before\n\
                 # (now in /etc/fips-pubdom/upstreams.conf). no-resolv stops dnsmasq from\n\
                 # reading resolv.conf for servers of its own; other server= lines in\n\
                 # dnsmasq's configuration would still be used and must go.\nno-resolv\n",
            );
            for a in &cfg.listen {
                let ip = match a.ip() {
                    IpAddr::V6(v6) => v6.to_string(),
                    IpAddr::V4(v4) => v4.to_string(),
                };
                text.push_str(&format!("server={ip}#{}\n", a.port()));
            }
            host.write(DNSMASQ_DROPIN, &text)?;
            (host.run)("systemctl", &["restart", "dnsmasq"])?;
            notes.push(format!(
                "wrote {} and {} (upstreams: {servers:?})",
                host.path(DNSMASQ_DROPIN).display(),
                host.path(UPSTREAMS_SNAPSHOT).display()
            ));
            notes.push(
                "the snapshot is static: run setup again if the machine's resolvers change".into(),
            );
        }
        Backend::ResolvConf => {
            if host.exists(RESOLVED_UPSTREAMS) {
                bail!("systemd-resolved is running; use --backend resolved");
            }
            if host.exists(NM_RUNDIR) && !host.exists(NM_DROPIN) {
                bail!(
                    "NetworkManager is running and would rewrite resolv.conf; use --backend networkmanager"
                );
            }
            let rc = host.path(RESOLV_CONF);
            if rc
                .symlink_metadata()
                .map(|m| m.is_symlink())
                .unwrap_or(false)
            {
                bail!(
                    "{} is a symlink to {}: another tool manages it; point it at a real file first",
                    rc.display(),
                    std::fs::read_link(&rc)
                        .map(|t| t.display().to_string())
                        .unwrap_or_default()
                );
            }
            let servers = snapshot_upstreams(host, RESOLV_CONF)?;
            cfg.upstreams_from = Some(PathBuf::from("/").join(UPSTREAMS_SNAPSHOT));
            cfg.listen = port53();
            write_config(host, config_path, &cfg)?;
            let original = host.read(RESOLV_CONF).unwrap_or_default();
            back_up_resolv_conf(host)?;
            host.write(
                RESOLV_CONF,
                &resolv_conf_text(
                    &["::1".into(), "127.0.0.1".into()],
                    &original,
                    "previous file in /etc/fips-pubdom/resolv.conf.bak",
                ),
            )?;
            notes.push(format!(
                "wrote {} (upstreams: {servers:?})",
                host.path(RESOLV_CONF).display()
            ));
            notes.push("the daemon now listens on port 53 (restart it after this)".into());
            notes.push(
                "the snapshot is static: anything that rewrites resolv.conf (dhclient hooks) undoes this".into(),
            );
        }
        Backend::Auto => unreachable!(),
    }
    host.write(STATE_BACKEND, &format!("{}\n", backend.name()))?;
    Ok((backend, notes))
}

/// Undo `setup`. With `Auto`, the backend `setup` recorded.
pub fn teardown(host: &Host, backend: Backend) -> Result<(Backend, Vec<String>)> {
    let backend = match backend {
        Backend::Auto => host
            .read(STATE_BACKEND)
            .and_then(|s| Backend::from_name(&s))
            .ok_or_else(|| {
                anyhow!(
                    "nothing recorded in {}; name the backend with --backend",
                    host.path(STATE_BACKEND).display()
                )
            })?,
        b => b,
    };
    let mut notes = Vec::new();
    match backend {
        Backend::Resolved => {
            host.remove(RESOLVED_DROPIN)?;
            (host.run)("systemctl", &["restart", "systemd-resolved"])?;
            notes.push(format!("removed {}", host.path(RESOLVED_DROPIN).display()));
        }
        Backend::NetworkManager => {
            host.remove(NM_DROPIN)?;
            restore_resolv_conf(host)?;
            host.run_first(&[
                ("nmcli", &["general", "reload", "conf,dns-rc"]),
                ("systemctl", &["reload", "NetworkManager"]),
            ])?;
            notes.push(format!(
                "removed {}, restored {}",
                host.path(NM_DROPIN).display(),
                host.path(RESOLV_CONF).display()
            ));
        }
        Backend::Dnsmasq => {
            host.remove(DNSMASQ_DROPIN)?;
            (host.run)("systemctl", &["restart", "dnsmasq"])?;
            host.remove(UPSTREAMS_SNAPSHOT)?;
            notes.push(format!("removed {}", host.path(DNSMASQ_DROPIN).display()));
        }
        Backend::ResolvConf => {
            restore_resolv_conf(host)?;
            host.remove(UPSTREAMS_SNAPSHOT)?;
            notes.push(format!("restored {}", host.path(RESOLV_CONF).display()));
        }
        Backend::Auto => unreachable!(),
    }
    host.remove(STATE_BACKEND)?;
    notes.push("the config file keeps `listen`/`upstreams_from` as setup left them; edit or delete it as you see fit".into());
    Ok((backend, notes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn host(root: &Path) -> (Host, Rc<RefCell<Vec<String>>>) {
        let ran = Rc::new(RefCell::new(Vec::new()));
        let r = ran.clone();
        let h = Host {
            root: root.to_path_buf(),
            run: Box::new(move |cmd, args| {
                r.borrow_mut().push(format!("{cmd} {}", args.join(" ")));
                Ok(())
            }),
        };
        (h, ran)
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pubdom-backend-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg_path() -> PathBuf {
        PathBuf::from("/etc/fips-pubdom/config.yaml")
    }

    #[test]
    fn detect_prefers_resolved_then_nm_then_dnsmasq_then_plain() {
        let d = tmp();
        let (h, _) = host(&d);
        h.write(RESOLV_CONF, "nameserver 9.9.9.9\n").unwrap();
        assert_eq!(detect(&h).unwrap(), Backend::ResolvConf);
        std::fs::create_dir_all(h.path(DNSMASQ_DIR)).unwrap();
        h.write("run/dnsmasq/dnsmasq.pid", "1\n").unwrap();
        assert_eq!(detect(&h).unwrap(), Backend::Dnsmasq);
        std::fs::create_dir_all(h.path(NM_RUNDIR)).unwrap();
        assert_eq!(detect(&h).unwrap(), Backend::NetworkManager);
        h.write(RESOLVED_UPSTREAMS, "nameserver 9.9.9.9\n").unwrap();
        assert_eq!(detect(&h).unwrap(), Backend::Resolved);
    }

    #[test]
    #[cfg(unix)]
    fn detect_refuses_a_symlinked_resolv_conf_nobody_known_manages() {
        let d = tmp();
        let (h, _) = host(&d);
        std::fs::create_dir_all(h.path("etc")).unwrap();
        symlink("/somewhere/else", &h.path(RESOLV_CONF)).unwrap();
        let err = detect(&h).unwrap_err().to_string();
        assert!(
            err.contains("symlink") && err.contains("/somewhere/else"),
            "{err}"
        );
    }

    #[test]
    fn resolv_conf_backend_takes_port_53_and_restores_on_teardown() {
        let d = tmp();
        let (h, ran) = host(&d);
        h.write(
            RESOLV_CONF,
            "# by hand\nnameserver 192.168.1.1\nnameserver 127.0.0.1\nsearch lan\noptions ndots:1\n",
        )
        .unwrap();
        let (b, _) = setup(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::ResolvConf);
        let rc = h.read(RESOLV_CONF).unwrap();
        assert!(rc.contains("nameserver ::1\n") && rc.contains("nameserver 127.0.0.1\n"));
        assert!(rc.contains("search lan\n") && rc.contains("options ndots:1\n"));
        assert!(
            !rc.contains("192.168.1.1"),
            "the old server moved to the snapshot"
        );
        let snap = h.read(UPSTREAMS_SNAPSHOT).unwrap();
        assert!(snap.contains("nameserver 192.168.1.1\n") && !snap.contains("127.0.0.1"));
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(cfg.listen, port53());
        assert_eq!(
            cfg.upstreams_from.as_deref(),
            Some(Path::new("/etc/fips-pubdom/upstreams.conf"))
        );
        assert_eq!(h.read(STATE_BACKEND).unwrap().trim(), "resolv-conf");
        assert!(ran.borrow().is_empty(), "nothing to restart but the daemon");

        let (b, _) = teardown(&h, Backend::Auto).unwrap();
        assert_eq!(b, Backend::ResolvConf);
        assert_eq!(
            h.read(RESOLV_CONF).unwrap(),
            "# by hand\nnameserver 192.168.1.1\nnameserver 127.0.0.1\nsearch lan\noptions ndots:1\n"
        );
        assert!(
            !h.exists(UPSTREAMS_SNAPSHOT) && !h.exists(STATE_BACKEND) && !h.exists(RESOLV_BACKUP)
        );
    }

    #[test]
    fn resolv_conf_backend_refuses_without_an_upstream_or_under_a_manager() {
        let d = tmp();
        let (h, _) = host(&d);
        h.write(RESOLV_CONF, "nameserver 127.0.0.1\n").unwrap();
        let err = setup(&h, &cfg_path(), Backend::ResolvConf)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no upstream resolver"), "{err}");
        assert!(!h.exists(STATE_BACKEND), "nothing recorded on failure");
        h.write(RESOLV_CONF, "nameserver 1.1.1.1\n").unwrap();
        std::fs::create_dir_all(h.path(NM_RUNDIR)).unwrap();
        let err = setup(&h, &cfg_path(), Backend::ResolvConf)
            .unwrap_err()
            .to_string();
        assert!(err.contains("NetworkManager"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn networkmanager_backend_hands_resolv_conf_over_and_follows_nm_list() {
        let d = tmp();
        let (h, ran) = host(&d);
        std::fs::create_dir_all(h.path(NM_RUNDIR)).unwrap();
        h.write(
            NM_UPSTREAMS,
            "# Generated by NetworkManager\nsearch home.arpa\nnameserver 192.168.1.1\n",
        )
        .unwrap();
        std::fs::create_dir_all(h.path("etc")).unwrap();
        symlink("/run/NetworkManager/resolv.conf", &h.path(RESOLV_CONF)).unwrap();
        let (b, _) = setup(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::NetworkManager);
        assert_eq!(
            h.read(NM_DROPIN).unwrap().trim_end().lines().last(),
            Some("dns=none")
        );
        assert_eq!(ran.borrow().as_slice(), ["nmcli general reload conf"]);
        let rc = h.read(RESOLV_CONF).unwrap();
        assert!(rc.contains("nameserver ::1\n") && rc.contains("search home.arpa\n"));
        assert!(!h.path(RESOLV_CONF).symlink_metadata().unwrap().is_symlink());
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(
            cfg.upstreams_from.as_deref(),
            Some(Path::new("/run/NetworkManager/resolv.conf"))
        );
        assert_eq!(cfg.listen, port53());
        assert_eq!(
            cfg.current_upstreams(),
            Vec::<IpAddr>::new(),
            "test root: the real path is not read"
        );

        teardown(&h, Backend::Auto).unwrap();
        let meta = h.path(RESOLV_CONF).symlink_metadata().unwrap();
        assert!(meta.is_symlink(), "the symlink is back");
        assert_eq!(
            std::fs::read_link(h.path(RESOLV_CONF)).unwrap(),
            Path::new("/run/NetworkManager/resolv.conf")
        );
        assert!(!h.exists(NM_DROPIN));
    }

    #[test]
    fn nmcli_falls_back_to_systemctl_reload() {
        let d = tmp();
        let ran = Rc::new(RefCell::new(Vec::new()));
        let r = ran.clone();
        let h = Host {
            root: d.clone(),
            run: Box::new(move |cmd, args| {
                r.borrow_mut().push(format!("{cmd} {}", args.join(" ")));
                if cmd == "nmcli" {
                    bail!("not installed")
                } else {
                    Ok(())
                }
            }),
        };
        std::fs::create_dir_all(h.path(NM_RUNDIR)).unwrap();
        h.write(NM_UPSTREAMS, "nameserver 10.0.0.1\n").unwrap();
        h.write(RESOLV_CONF, "nameserver 10.0.0.1\n").unwrap();
        setup(&h, &cfg_path(), Backend::NetworkManager).unwrap();
        assert_eq!(
            ran.borrow().as_slice(),
            [
                "nmcli general reload conf",
                "systemctl reload NetworkManager"
            ]
        );
    }

    #[test]
    fn dnsmasq_backend_forwards_to_the_daemon_and_snapshots_its_resolv_file() {
        let d = tmp();
        let (h, ran) = host(&d);
        std::fs::create_dir_all(h.path(DNSMASQ_DIR)).unwrap();
        h.write("run/dnsmasq/dnsmasq.pid", "1\n").unwrap();
        h.write(DNSMASQ_CONF, "# dnsmasq\nresolv-file=/etc/resolv.dnsmasq\n")
            .unwrap();
        h.write(
            "etc/resolv.dnsmasq",
            "nameserver 9.9.9.9\nnameserver 149.112.112.112\n",
        )
        .unwrap();
        h.write(RESOLV_CONF, "nameserver 127.0.0.1\n").unwrap();
        let (b, _) = setup(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::Dnsmasq);
        let drop = h.read(DNSMASQ_DROPIN).unwrap();
        assert!(
            drop.contains("no-resolv\n")
                && drop.contains("server=::1#5356\n")
                && drop.contains("server=127.0.0.1#5356\n")
        );
        let snap = h.read(UPSTREAMS_SNAPSHOT).unwrap();
        assert!(
            snap.contains("nameserver 9.9.9.9\n") && snap.contains("nameserver 149.112.112.112\n")
        );
        assert_eq!(ran.borrow().as_slice(), ["systemctl restart dnsmasq"]);
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(
            cfg.listen,
            Config::default().listen,
            "dnsmasq can name a port: 5356 stays"
        );
        assert_eq!(
            h.read(RESOLV_CONF).unwrap(),
            "nameserver 127.0.0.1\n",
            "resolv.conf untouched"
        );

        teardown(&h, Backend::Auto).unwrap();
        assert!(!h.exists(DNSMASQ_DROPIN) && !h.exists(UPSTREAMS_SNAPSHOT));
        assert_eq!(
            ran.borrow().last().map(String::as_str),
            Some("systemctl restart dnsmasq")
        );
    }

    #[test]
    fn resolved_backend_writes_the_drop_in_as_before() {
        let d = tmp();
        let (h, ran) = host(&d);
        h.write(RESOLVED_UPSTREAMS, "nameserver 192.168.1.1\n")
            .unwrap();
        let (b, _) = setup(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::Resolved);
        let drop = h.read(RESOLVED_DROPIN).unwrap();
        assert!(
            drop.contains("DNS=\nDNS=[::1]:5356 127.0.0.1:5356\nDomains=\nDomains=~.\n"),
            "{drop}"
        );
        assert_eq!(
            ran.borrow().as_slice(),
            ["systemctl restart systemd-resolved"]
        );
        teardown(&h, Backend::Auto).unwrap();
        assert!(!h.exists(RESOLVED_DROPIN));
    }

    #[test]
    fn teardown_without_a_record_needs_the_backend_named() {
        let d = tmp();
        let (h, _) = host(&d);
        let err = teardown(&h, Backend::Auto).unwrap_err().to_string();
        assert!(err.contains("--backend"), "{err}");
        teardown(&h, Backend::Resolved).unwrap();
    }
}
