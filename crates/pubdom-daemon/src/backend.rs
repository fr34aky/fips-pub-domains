//! `fips-pubdomd setup` / `teardown`: getting the OS to send its DNS to the
//! daemon (docs/platforms.md, "full mode"), one backend per resolver
//! arrangement found on Linux. Every path is taken relative to a root and
//! every command goes through a runner, so the backends are exercised in a
//! temporary directory by the tests below; production uses `/` and the
//! real `systemctl`/`nmcli`.
//!
//! The backend `setup` chose is recorded in `/etc/fips-pubdom/backend`
//! before anything else is touched, so `teardown` undoes the right thing
//! without being told — after a failed `setup` too.

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use pubdom_resolve::Config;
use pubdom_resolve::config::{nameservers, nameservers_lenient};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Sorts after fips's own drop-in (`fips-dns-setup` writes one named after
/// itself) so the list resets below win: resolved merges every drop-in
/// into ONE global server pool, and two servers with different routing
/// domains in one pool are queried interchangeably.
const RESOLVED_DROPIN: &str = "etc/systemd/resolved.conf.d/zz-fips-pubdom.conf";
const RESOLVED_UPSTREAMS: &str = "run/systemd/resolve/resolv.conf";
const NM_DROPIN: &str = "etc/NetworkManager/conf.d/zz-fips-pubdom.conf";
const NM_UPSTREAMS: &str = "run/NetworkManager/resolv.conf";
const DNSMASQ_DROPIN: &str = "etc/dnsmasq.d/fips-pubdom.conf";
const DNSMASQ_CONF: &str = "etc/dnsmasq.conf";
const DNSMASQ_DIR: &str = "etc/dnsmasq.d";
const RESOLV_CONF: &str = "etc/resolv.conf";
/// What `setup` keeps, under /etc/fips-pubdom next to the config: its
/// backend, what it replaced, what it snapshotted.
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

    /// Is the service running now? Its runtime files outlive it
    /// (`/run/systemd/resolve` survives a stopped resolved), so the files
    /// alone would hand a machine that switched resolvers to the old one.
    fn active(&self, service: &str) -> bool {
        (self.run)("systemctl", &["is-active", "--quiet", service]).is_ok()
    }

    fn is_symlink(&self, rel: &str) -> bool {
        self.path(rel)
            .symlink_metadata()
            .map(|m| m.is_symlink())
            .unwrap_or(false)
    }
}

/// What the machine runs, from its services and the files they leave.
pub fn detect(host: &Host) -> Result<Backend> {
    if host.exists(RESOLVED_UPSTREAMS) && host.active("systemd-resolved") {
        return Ok(Backend::Resolved);
    }
    if host.active("NetworkManager") {
        return Ok(Backend::NetworkManager);
    }
    if host.exists(DNSMASQ_DIR) && host.active("dnsmasq") {
        return Ok(Backend::Dnsmasq);
    }
    if host.is_symlink(RESOLV_CONF) {
        bail!(
            "{} is a symlink to {}: another tool manages it, and no supported resolver was found running",
            host.path(RESOLV_CONF).display(),
            std::fs::read_link(host.path(RESOLV_CONF))
                .map(|t| t.display().to_string())
                .unwrap_or_default()
        );
    }
    Ok(Backend::ResolvConf)
}

/// Port 53 on loopback, for the backends where the OS cannot name a port.
fn port53() -> Vec<SocketAddr> {
    vec!["[::1]:53".parse().unwrap(), "127.0.0.1:53".parse().unwrap()]
}

fn listen_spec(cfg: &Config) -> String {
    cfg.listen
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// A resolv.conf naming the daemon's `listen` addresses, keeping the
/// `search`/`domain`/`options` lines of `original`.
fn resolv_conf_text(cfg: &Config, original: &str, note: &str) -> String {
    let mut s = format!("# Managed by fips-pubdomd setup ({note}).\n");
    for a in &cfg.listen {
        s.push_str(&format!("nameserver {}\n", a.ip()));
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

/// Where the daemon's upstreams come from on a backend whose resolver
/// will be pointed at us: the config's own `upstreams` when set, else a
/// static snapshot of `source`'s servers (its file would then name only
/// ourselves). `None` means the config's list is used. `lenient` reads
/// the file as dnsmasq does (indented lines count); otherwise as glibc.
fn upstreams_or_snapshot(
    host: &Host,
    cfg: &Config,
    source: &str,
    lenient: bool,
) -> Result<Option<Vec<IpAddr>>> {
    if !cfg.upstreams.is_empty() {
        return Ok(None);
    }
    let text = host
        .read(source)
        .ok_or_else(|| anyhow!("cannot read {}", host.path(source).display()))?;
    let parsed = if lenient {
        nameservers_lenient(&text)
    } else {
        nameservers(&text)
    };
    let servers: Vec<IpAddr> = parsed.into_iter().filter(|ip| !ip.is_loopback()).collect();
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
    host.write(UPSTREAMS_SNAPSHOT, &out)?;
    Ok(Some(servers))
}

/// Keep what resolv.conf was — a symlink's target, or the file — so
/// `teardown` can put it back. Never over an existing backup: that is the
/// original, and what is there now is ours.
fn back_up_resolv_conf(host: &Host) -> Result<()> {
    if host.exists(RESOLV_BACKUP) {
        return Ok(());
    }
    let rc = host.path(RESOLV_CONF);
    let meta = match rc.symlink_metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            host.write(RESOLV_BACKUP, "#fips-pubdom-absent\n")?;
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

/// `/etc/x` under the host's root. `has_root`, not `is_absolute`: on
/// Windows, where the tests also run, a path starting with `/` has a root
/// but no drive and so is not "absolute".
fn under_root(host: &Host, path: &Path) -> PathBuf {
    if path.has_root() {
        let mut rel = PathBuf::new();
        for c in path.components() {
            if let std::path::Component::Normal(n) = c {
                rel.push(n);
            }
        }
        host.root.join(rel)
    } else {
        path.to_path_buf()
    }
}

fn write_config(host: &Host, config_path: &Path, cfg: &Config) -> Result<()> {
    let p = under_root(host, config_path);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&p, serde_yaml::to_string(cfg)?)
        .with_context(|| format!("writing {}", p.display()))?;
    if let Some(dir) = under_root(host, &cfg.pins).parent() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn load_config(host: &Host, config_path: &Path) -> Result<Config> {
    Config::load_or_default(&under_root(host, config_path)).map_err(anyhow::Error::msg)
}

fn config_backup_path(host: &Host, config_path: &Path) -> PathBuf {
    let mut p = under_root(host, config_path).into_os_string();
    p.push(".before-setup");
    PathBuf::from(p)
}

/// The config as it was before `setup` rewrote `listen`/`upstreams_from`,
/// so `teardown` is a real undo and the next `setup` starts from the
/// operator's own values rather than another backend's. Never over an
/// existing backup: that is the original.
fn back_up_config(host: &Host, config_path: &Path) -> Result<()> {
    let bak = config_backup_path(host, config_path);
    if bak.exists() {
        return Ok(());
    }
    let src = under_root(host, config_path);
    let text = match std::fs::read_to_string(&src) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "#fips-pubdom-absent\n".into(),
        Err(e) => return Err(e.into()),
    };
    if let Some(dir) = bak.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&bak, text).with_context(|| format!("writing {}", bak.display()))
}

fn restore_config(host: &Host, config_path: &Path) -> Result<bool> {
    let bak = config_backup_path(host, config_path);
    let Ok(text) = std::fs::read_to_string(&bak) else {
        return Ok(false);
    };
    let dst = under_root(host, config_path);
    if text.starts_with("#fips-pubdom-absent") {
        let _ = std::fs::remove_file(&dst);
    } else {
        std::fs::write(&dst, text)?;
    }
    std::fs::remove_file(&bak)?;
    Ok(true)
}

/// dnsmasq's `resolv-file=`, from its main file or any file in its conf
/// directory, else /etc/resolv.conf; and whether `no-resolv` is already
/// set somewhere, in which case its servers are `server=` lines we cannot
/// snapshot.
fn dnsmasq_resolv_file(host: &Host) -> (String, bool) {
    let mut texts = Vec::new();
    if let Some(t) = host.read(DNSMASQ_CONF) {
        texts.push(t);
    }
    if let Ok(dir) = std::fs::read_dir(host.path(DNSMASQ_DIR)) {
        let mut files: Vec<PathBuf> = dir
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name() != Some(std::ffi::OsStr::new("fips-pubdom.conf")))
            .collect();
        files.sort();
        for f in files {
            if let Ok(t) = std::fs::read_to_string(&f) {
                texts.push(t);
            }
        }
    }
    let mut resolv_file = RESOLV_CONF.to_string();
    let mut no_resolv = false;
    for t in &texts {
        for line in t.lines().map(str::trim) {
            if let Some(p) = line.strip_prefix("resolv-file=") {
                resolv_file = p.trim().trim_start_matches('/').to_string();
            }
            if line == "no-resolv" {
                no_resolv = true;
            }
        }
    }
    (resolv_file, no_resolv)
}

/// Point the OS at the daemon. Returns the backend used and what to tell
/// the operator.
pub fn setup(host: &Host, config_path: &Path, backend: Backend) -> Result<(Backend, Vec<String>)> {
    if let Some(prev) = host.read(STATE_BACKEND) {
        bail!(
            "already set up ({} backend, per {}); run `fips-pubdomd teardown` first",
            prev.trim(),
            host.path(STATE_BACKEND).display()
        );
    }
    let backend = match backend {
        Backend::Auto => detect(host)?,
        b => b,
    };
    let mut cfg = load_config(host, config_path)?;
    let mut notes = Vec::new();
    // Checks first, then the record, then the files and commands: a setup
    // that fails halfway is still torn down by name.
    match backend {
        Backend::Resolved => {
            if !host.exists(RESOLVED_UPSTREAMS) || !host.active("systemd-resolved") {
                bail!("systemd-resolved is not running");
            }
        }
        Backend::NetworkManager => {
            if !host.active("NetworkManager") {
                bail!("NetworkManager is not running");
            }
            if host.active("systemd-resolved") {
                bail!("systemd-resolved is running too; use --backend resolved");
            }
        }
        Backend::Dnsmasq => {
            if !host.exists(DNSMASQ_DIR) {
                bail!("no /etc/dnsmasq.d: dnsmasq is not installed as the local resolver");
            }
            if host.active("NetworkManager") {
                bail!(
                    "NetworkManager is running: it would keep feeding dnsmasq its own servers; use --backend networkmanager"
                );
            }
        }
        Backend::ResolvConf => {
            if host.active("systemd-resolved") {
                bail!("systemd-resolved is running; use --backend resolved");
            }
            if host.active("NetworkManager") {
                bail!(
                    "NetworkManager is running and would rewrite resolv.conf; use --backend networkmanager"
                );
            }
            if host.is_symlink(RESOLV_CONF) {
                bail!(
                    "{} is a symlink to {}: another tool manages it; point it at a real file first",
                    host.path(RESOLV_CONF).display(),
                    std::fs::read_link(host.path(RESOLV_CONF))
                        .map(|t| t.display().to_string())
                        .unwrap_or_default()
                );
            }
        }
        Backend::Auto => unreachable!(),
    }
    host.write(STATE_BACKEND, &format!("{}\n", backend.name()))?;
    back_up_config(host, config_path)?;
    let listen_before = cfg.listen.clone();
    match backend {
        Backend::Resolved => {
            // Once the drop-in is in place the stub file points back at us,
            // but /run/systemd/resolve/resolv.conf keeps listing the real
            // servers, which the daemon then follows.
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
                    &cfg,
                    &original,
                    "NetworkManager backend; previous file in /etc/fips-pubdom/resolv.conf.bak",
                ),
            )?;
            notes.push(format!(
                "wrote {} and {}",
                host.path(NM_DROPIN).display(),
                host.path(RESOLV_CONF).display()
            ));
        }
        Backend::Dnsmasq => {
            let (resolv_file, no_resolv) = dnsmasq_resolv_file(host);
            if no_resolv && cfg.upstreams.is_empty() {
                bail!(
                    "dnsmasq already has no-resolv: its servers are server= lines, which cannot be snapshotted; set `upstreams` in the config and run setup again"
                );
            }
            let servers = upstreams_or_snapshot(host, &cfg, &resolv_file, true)?;
            cfg.upstreams_from = servers
                .is_some()
                .then(|| PathBuf::from("/").join(UPSTREAMS_SNAPSHOT));
            write_config(host, config_path, &cfg)?;
            let mut text = String::from(
                "# Managed by fips-pubdomd setup: dnsmasq forwards every name to fips-pubdomd,\n\
                 # which forwards names not over fips to the servers dnsmasq used before\n\
                 # (now in /etc/fips-pubdom/upstreams.conf). no-resolv stops dnsmasq from\n\
                 # reading resolv.conf for servers of its own; other server= lines in\n\
                 # dnsmasq's configuration would still be used and must go.\nno-resolv\n",
            );
            for a in &cfg.listen {
                text.push_str(&format!("server={}#{}\n", a.ip(), a.port()));
            }
            host.write(DNSMASQ_DROPIN, &text)?;
            (host.run)("systemctl", &["restart", "dnsmasq"])?;
            notes.push(format!("wrote {}", host.path(DNSMASQ_DROPIN).display()));
            match servers {
                Some(s) => notes.push(format!(
                    "upstreams snapshotted from {} to {}: {s:?} (static: run setup again if they change)",
                    host.path(&resolv_file).display(),
                    host.path(UPSTREAMS_SNAPSHOT).display()
                )),
                None => notes.push(format!("upstreams: the config's own {:?}", cfg.upstreams)),
            }
        }
        Backend::ResolvConf => {
            let servers = upstreams_or_snapshot(host, &cfg, RESOLV_CONF, false)?;
            cfg.upstreams_from = servers
                .is_some()
                .then(|| PathBuf::from("/").join(UPSTREAMS_SNAPSHOT));
            cfg.listen = port53();
            write_config(host, config_path, &cfg)?;
            let original = host.read(RESOLV_CONF).unwrap_or_default();
            back_up_resolv_conf(host)?;
            host.write(
                RESOLV_CONF,
                &resolv_conf_text(
                    &cfg,
                    &original,
                    "previous file in /etc/fips-pubdom/resolv.conf.bak",
                ),
            )?;
            notes.push(format!("wrote {}", host.path(RESOLV_CONF).display()));
            match servers {
                Some(s) => notes.push(format!(
                    "upstreams snapshotted to {}: {s:?} (static: anything that rewrites resolv.conf undoes this)",
                    host.path(UPSTREAMS_SNAPSHOT).display()
                )),
                None => notes.push(format!("upstreams: the config's own {:?}", cfg.upstreams)),
            }
        }
        Backend::Auto => unreachable!(),
    }
    if cfg.listen != listen_before {
        notes.push(format!(
            "listen changed from {} to {}: restart the daemon",
            listen_before
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            listen_spec(&cfg)
        ));
    }
    Ok((backend, notes))
}

/// Undo `setup`. With `Auto`, the backend `setup` recorded — or, for an
/// installation older than the record, the resolved drop-in if present.
pub fn teardown(
    host: &Host,
    config_path: &Path,
    backend: Backend,
) -> Result<(Backend, Vec<String>)> {
    let backend = match backend {
        Backend::Auto => match host
            .read(STATE_BACKEND)
            .and_then(|s| Backend::from_name(&s))
        {
            Some(b) => b,
            None if host.exists(RESOLVED_DROPIN) => Backend::Resolved,
            None => bail!(
                "nothing recorded in {} and no resolved drop-in; name the backend with --backend",
                host.path(STATE_BACKEND).display()
            ),
        },
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
    if restore_config(host, config_path)? {
        notes.push(format!(
            "restored {} to what it was before setup (restart the daemon if it runs)",
            config_path.display()
        ));
    } else {
        notes.push(
            "no config backup (setup by an older version): the config keeps `listen`/`upstreams_from` as it left them"
                .into(),
        );
    }
    Ok((backend, notes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::rc::Rc;

    /// A host whose `systemctl is-active` answers from `active`; every
    /// other command succeeds and is recorded.
    fn host(root: &Path, active: &[&str]) -> (Host, Rc<RefCell<Vec<String>>>) {
        let ran = Rc::new(RefCell::new(Vec::new()));
        let r = ran.clone();
        let active: HashSet<String> = active.iter().map(|s| s.to_string()).collect();
        let h = Host {
            root: root.to_path_buf(),
            run: Box::new(move |cmd, args| {
                if cmd == "systemctl" && args.first() == Some(&"is-active") {
                    return if active.contains(args[2]) {
                        Ok(())
                    } else {
                        bail!("inactive")
                    };
                }
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
    fn detect_goes_by_running_services_then_the_plain_file() {
        let d = tmp();
        let (h, _) = host(&d, &[]);
        h.write(RESOLV_CONF, "nameserver 9.9.9.9\n").unwrap();
        assert_eq!(detect(&h).unwrap(), Backend::ResolvConf);
        // dnsmasq's directory alone is not a running dnsmasq.
        std::fs::create_dir_all(h.path(DNSMASQ_DIR)).unwrap();
        assert_eq!(detect(&h).unwrap(), Backend::ResolvConf);
        let (h, _) = host(&d, &["dnsmasq"]);
        assert_eq!(detect(&h).unwrap(), Backend::Dnsmasq);
        let (h, _) = host(&d, &["dnsmasq", "NetworkManager"]);
        assert_eq!(detect(&h).unwrap(), Backend::NetworkManager);
        // resolved's runtime file outlives a stopped resolved: not enough.
        h.write(RESOLVED_UPSTREAMS, "nameserver 9.9.9.9\n").unwrap();
        assert_eq!(detect(&h).unwrap(), Backend::NetworkManager);
        let (h, _) = host(&d, &["systemd-resolved", "NetworkManager"]);
        assert_eq!(detect(&h).unwrap(), Backend::Resolved);
    }

    #[test]
    #[cfg(unix)]
    fn detect_refuses_a_symlinked_resolv_conf_nobody_known_manages() {
        let d = tmp();
        let (h, _) = host(&d, &[]);
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
        let (h, ran) = host(&d, &[]);
        h.write(
            RESOLV_CONF,
            "# by hand\nnameserver 192.168.1.1\n  nameserver 10.9.9.9\nnameserver 127.0.0.1\nsearch lan\noptions ndots:1\n",
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
        assert!(
            !snap.contains("10.9.9.9"),
            "an indented line is not a server to glibc"
        );
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(cfg.listen, port53());
        assert_eq!(
            cfg.upstreams_from.as_deref(),
            Some(Path::new("/etc/fips-pubdom/upstreams.conf"))
        );
        assert_eq!(h.read(STATE_BACKEND).unwrap().trim(), "resolv-conf");
        assert!(ran.borrow().is_empty(), "nothing to restart but the daemon");

        // A second setup does not clobber the backup of the original.
        let err = setup(&h, &cfg_path(), Backend::Auto)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("already set up") && err.contains("resolv-conf"),
            "{err}"
        );
        assert!(h.read(RESOLV_BACKUP).unwrap().contains("# by hand"));

        let (b, _) = teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::ResolvConf);
        assert_eq!(
            h.read(RESOLV_CONF).unwrap(),
            "# by hand\nnameserver 192.168.1.1\n  nameserver 10.9.9.9\nnameserver 127.0.0.1\nsearch lan\noptions ndots:1\n"
        );
        assert!(
            !h.exists(UPSTREAMS_SNAPSHOT) && !h.exists(STATE_BACKEND) && !h.exists(RESOLV_BACKUP)
        );
    }

    #[test]
    fn resolv_conf_backend_refuses_without_an_upstream_or_under_a_manager() {
        let d = tmp();
        let (h, _) = host(&d, &[]);
        h.write(RESOLV_CONF, "nameserver 127.0.0.1\n").unwrap();
        let err = setup(&h, &cfg_path(), Backend::ResolvConf)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no upstream resolver"), "{err}");
        // The record is written before the files, so the failed setup can
        // be torn down; a fresh setup is then possible again.
        assert!(h.exists(STATE_BACKEND));
        teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        assert!(!h.exists(STATE_BACKEND));
        // `upstreams` in the config stands in for the snapshot.
        h.write("etc/fips-pubdom/config.yaml", "upstreams: [\"9.9.9.9\"]\n")
            .unwrap();
        let (_, notes) = setup(&h, &cfg_path(), Backend::ResolvConf).unwrap();
        assert!(
            notes.iter().any(|n| n.contains("config's own")),
            "{notes:?}"
        );
        assert!(!h.exists(UPSTREAMS_SNAPSHOT));
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(cfg.upstreams_from, None);
        assert_eq!(
            cfg.current_upstreams(),
            vec!["9.9.9.9".parse::<IpAddr>().unwrap()]
        );
        teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        let (h, _) = host(&d, &["NetworkManager"]);
        let err = setup(&h, &cfg_path(), Backend::ResolvConf)
            .unwrap_err()
            .to_string();
        assert!(err.contains("NetworkManager"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn networkmanager_backend_hands_resolv_conf_over_and_follows_nm_list() {
        let d = tmp();
        let (h, ran) = host(&d, &["NetworkManager"]);
        h.write(
            NM_UPSTREAMS,
            "# Generated by NetworkManager\nsearch home.arpa\nnameserver 192.168.1.1\n",
        )
        .unwrap();
        std::fs::create_dir_all(h.path("etc")).unwrap();
        symlink("/run/NetworkManager/resolv.conf", &h.path(RESOLV_CONF)).unwrap();
        let (b, notes) = setup(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::NetworkManager);
        assert!(
            notes
                .iter()
                .any(|n| n.contains("listen changed") && n.contains(":53")),
            "{notes:?}"
        );
        assert_eq!(
            h.read(NM_DROPIN).unwrap().trim_end().lines().last(),
            Some("dns=none")
        );
        assert_eq!(ran.borrow().as_slice(), ["nmcli general reload conf"]);
        let rc = h.read(RESOLV_CONF).unwrap();
        assert!(rc.contains("nameserver ::1\n") && rc.contains("search home.arpa\n"));
        assert!(!h.is_symlink(RESOLV_CONF));
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(
            cfg.upstreams_from.as_deref(),
            Some(Path::new("/run/NetworkManager/resolv.conf"))
        );
        assert_eq!(cfg.listen, port53());

        teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        assert!(h.is_symlink(RESOLV_CONF), "the symlink is back");
        assert_eq!(
            std::fs::read_link(h.path(RESOLV_CONF)).unwrap(),
            Path::new("/run/NetworkManager/resolv.conf")
        );
        assert!(!h.exists(NM_DROPIN));
        // No config existed before setup: teardown removes the one it wrote,
        // so a later setup under another backend starts from the defaults.
        assert!(!h.path("etc/fips-pubdom/config.yaml").exists());
        assert_eq!(
            load_config(&h, &cfg_path()).unwrap().listen,
            Config::default().listen
        );
    }

    #[test]
    fn nmcli_falls_back_to_systemctl_reload_and_a_failed_setup_is_torn_down() {
        let d = tmp();
        let ran = Rc::new(RefCell::new(Vec::new()));
        let r = ran.clone();
        let h = Host {
            root: d.clone(),
            run: Box::new(move |cmd, args| {
                if cmd == "systemctl" && args.first() == Some(&"is-active") {
                    return if args[2] == "NetworkManager" {
                        Ok(())
                    } else {
                        bail!("inactive")
                    };
                }
                r.borrow_mut().push(format!("{cmd} {}", args.join(" ")));
                if cmd == "nmcli" {
                    bail!("not installed")
                }
                if args == ["reload", "NetworkManager"] && r.borrow().len() < 3 {
                    bail!("NetworkManager is not under systemd")
                }
                Ok(())
            }),
        };
        h.write(NM_UPSTREAMS, "nameserver 10.0.0.1\n").unwrap();
        h.write(RESOLV_CONF, "nameserver 10.0.0.1\n").unwrap();
        // First attempt: both reloads fail, setup errors, but the record
        // is there and teardown cleans the drop-in up.
        assert!(setup(&h, &cfg_path(), Backend::NetworkManager).is_err());
        assert_eq!(
            ran.borrow().as_slice(),
            [
                "nmcli general reload conf",
                "systemctl reload NetworkManager"
            ]
        );
        assert!(h.exists(NM_DROPIN) && h.exists(STATE_BACKEND));
        teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        assert!(!h.exists(NM_DROPIN) && !h.exists(STATE_BACKEND));
        // Second attempt: nmcli still missing, systemctl reload works.
        setup(&h, &cfg_path(), Backend::NetworkManager).unwrap();
        assert_eq!(
            ran.borrow().last().map(String::as_str),
            Some("systemctl reload NetworkManager")
        );
    }

    #[test]
    fn dnsmasq_backend_forwards_to_the_daemon_and_snapshots_its_resolv_file() {
        let d = tmp();
        let (h, ran) = host(&d, &["dnsmasq"]);
        std::fs::create_dir_all(h.path(DNSMASQ_DIR)).unwrap();
        h.write(DNSMASQ_CONF, "# dnsmasq\n").unwrap();
        // The resolv-file directive may sit in conf.d, as on Debian.
        h.write(
            "etc/dnsmasq.d/local.conf",
            "resolv-file=/etc/resolv.dnsmasq\n",
        )
        .unwrap();
        h.write(
            "etc/resolv.dnsmasq",
            "nameserver 9.9.9.9\n  nameserver 149.112.112.112\n",
        )
        .unwrap();
        h.write(RESOLV_CONF, "nameserver 127.0.0.1\n").unwrap();
        let (b, _) = setup(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::Dnsmasq);
        let drop = h.read(DNSMASQ_DROPIN).unwrap();
        assert!(
            drop.contains("no-resolv\n")
                && drop.contains("server=::1#5356\n")
                && drop.contains("server=127.0.0.1#5356\n"),
            "{drop}"
        );
        let snap = h.read(UPSTREAMS_SNAPSHOT).unwrap();
        assert!(
            snap.contains("nameserver 9.9.9.9\n") && snap.contains("nameserver 149.112.112.112\n"),
            "dnsmasq takes an indented line, so the snapshot does too: {snap}"
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

        teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        assert!(!h.exists(DNSMASQ_DROPIN) && !h.exists(UPSTREAMS_SNAPSHOT));
        assert_eq!(
            ran.borrow().last().map(String::as_str),
            Some("systemctl restart dnsmasq")
        );

        // dnsmasq that already runs with no-resolv has nothing to snapshot.
        h.write("etc/dnsmasq.d/local.conf", "no-resolv\nserver=1.1.1.1\n")
            .unwrap();
        let err = setup(&h, &cfg_path(), Backend::Dnsmasq)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no-resolv") && err.contains("upstreams"),
            "{err}"
        );
        teardown(&h, &cfg_path(), Backend::Auto).unwrap();
    }

    #[test]
    fn resolved_backend_writes_the_drop_in_as_before() {
        let d = tmp();
        let (h, ran) = host(&d, &["systemd-resolved", "NetworkManager"]);
        h.write(RESOLVED_UPSTREAMS, "nameserver 192.168.1.1\n")
            .unwrap();
        // A custom listen address is the operator's and stays.
        h.write("etc/fips-pubdom/config.yaml", "listen: [\"[::1]:5300\"]\n")
            .unwrap();
        let (b, notes) = setup(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::Resolved);
        assert!(
            notes.iter().all(|n| !n.contains("listen changed")),
            "{notes:?}"
        );
        let drop = h.read(RESOLVED_DROPIN).unwrap();
        assert!(
            drop.contains("DNS=\nDNS=[::1]:5300\nDomains=\nDomains=~.\n"),
            "{drop}"
        );
        assert_eq!(
            ran.borrow().as_slice(),
            ["systemctl restart systemd-resolved"]
        );
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(
            cfg.listen,
            vec!["[::1]:5300".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            cfg.upstreams_from.as_deref(),
            Some(Path::new("/run/systemd/resolve/resolv.conf"))
        );
        teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        assert!(!h.exists(RESOLVED_DROPIN));
        // Teardown restored the config: the upstreams_from setup added is gone.
        let cfg = load_config(&h, &cfg_path()).unwrap();
        assert_eq!(cfg.upstreams_from, None);
        assert_eq!(
            cfg.listen,
            vec!["[::1]:5300".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn teardown_without_a_record_falls_back_to_the_resolved_drop_in() {
        let d = tmp();
        let (h, _) = host(&d, &[]);
        let err = teardown(&h, &cfg_path(), Backend::Auto)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--backend"), "{err}");
        // An installation set up by 0.2.x: the drop-in exists, no record.
        h.write(RESOLVED_DROPIN, "[Resolve]\n").unwrap();
        let (b, _) = teardown(&h, &cfg_path(), Backend::Auto).unwrap();
        assert_eq!(b, Backend::Resolved);
        assert!(!h.exists(RESOLVED_DROPIN));
    }
}
