# Platform plan: one resolver, every OS

Status: **plan**. Companion to [plan-phase1.md](plan-phase1.md); the crate
split there is what makes this possible.

The resolver runs as a **separate service/daemon** (`fips-namesd`) on every
desktop and server platform fips runs on, and is **embedded in the fips2go
app** on Android, where an app cannot run a system daemon and the VPN already
owns all DNS. Same code, same policy, same pin format; only four things are
platform-specific and they are kept in four small places.

## 1. What differs per platform — and nothing else

| Concern | Where it lives | Notes |
|---|---|---|
| (a) Reaching the local fips node | `names-resolve::MeshDns` impls + one `responder` address | Desktop: the node's TUN (`fips0`, `utun`, wintun) exists, so a plain kernel UDP/TCP socket to `fd…` works; identity registration = ask fips's responder `[::1]:5354` for `npub….fips`, same trick as the phone. Android: in-process smoltcp through `TunPacketProcessor`. |
| (b) Getting the OS to send DNS to us | `fips-namesd setup` / `teardown` subcommands (one backend per OS) | §3. Modelled on fips's `fips-dns-setup` (Linux backends tried in order, `/etc/resolver/fips` on macOS, `config.xml` on pfSense). |
| (c) Running as a service | packaging: systemd unit, rc.d script, launchd plist, Windows service, NixOS module | The daemon never forks itself; service managers supervise it. Windows needs the `windows-service` crate wrapper. |
| (d) Paths | `names-core::paths` (via the `directories` crate) | config, pins, cache, logs — §5. |

Everything else — event parsing, verification, pinning, precedence, answer
synthesis, caching, the step-3 client, the relay client, the SRV verifier —
is portable Rust with no `cfg(target_os)`. Rule: **no `cfg(target_os)` in
`names-core` or `names-resolve`**; CI enforces it with a grep.

Portable dependency choices that make this hold:

- TLS for relays: `rustls` (no OpenSSL, no system TLS on Windows/macOS).
- Legacy DNS: `hickory-resolver` reads `/etc/resolv.conf`, macOS
  SystemConfiguration and Windows adapter settings itself; configured
  upstreams override.
- DNS wire format: `simple-dns` (what fips uses).
- Async runtime: tokio, single-threaded runtime — the daemon is I/O-bound and
  tiny.

## 2. What the daemon is

`fips-namesd` is a **forwarding DNS resolver**: it listens on loopback
(default `[::1]:5356` and `127.0.0.1:5356`; port is configurable, 53 is
avoided for the same reason as 5355 on the server side), runs the resolver
from `names-resolve` for every query, and forwards anything without a binding
to the upstream resolvers it learned from the OS (or from its config).

Behaviour per query, in order: local hosts → pins/cache → (online) SRV hint →
relays → step 3 → synthesised answer; else passthrough (spec §5, §7). The
budget rules from plan-phase1 §6 apply unchanged.

It has two ways of being wired into the OS, chosen at setup time:

### Mode A — full resolver (all names)

The daemon becomes the machine's DNS server; the OS's previous resolvers
become its upstreams. Required for the "first visit, online, verify on the
fly" flow, because the daemon must *see* the name to look for a binding.
This is the Android mode (the VPN captures all DNS anyway) and optional on
desktops. Caveats: captive portals and per-network DNS changes must be
followed (the daemon re-reads upstreams on network change, §3), and the
privacy rule (spec §8: SRV before relays) matters most here.

### Mode B — bound domains only (default on desktops)

The OS keeps its resolvers; only domains the daemon **knows about** are
routed to it, using each OS's native per-domain routing (§3). The daemon
maintains that routing list itself: every pinned domain, plus domains from
a **subscription** (a list the user adds by hand — `fips-names add
example.org` — or synced from trusted nodes, like fips2go's mesh names).
Nothing else ever reaches the daemon, so it cannot leak browsing history,
cannot break unrelated resolution, and needs no upstream handling.

Discovery in mode B is explicit (add/subscribe) rather than on first visit —
the price of not sitting in front of all DNS. Both modes share the same
binary; `setup --mode full|domains`.

## 3. Per-platform integration

| Platform | Service | Route to daemon (mode B: per domain / mode A: all) | Upstreams (mode A) |
|---|---|---|---|
| **Linux, systemd-resolved** (Debian/Ubuntu, Fedora, Arch, NixOS…) | `fips-names.service` (`After=fips.service`) | mode B: `resolvectl domain <link> ~example.org` + `resolvectl dns` on a dedicated dummy link, or a `resolved.conf.d` drop-in with `Domains=~example.org`; mode A: drop-in `DNS=[::1]:5356` `Domains=~.` (what fips's setup does for `.fips`, generalised) | from `resolvectl status` / `/run/systemd/resolve/resolv.conf` |
| **Linux, dnsmasq / NetworkManager+dnsmasq** | same unit | `server=/example.org/::1#5356` per domain, in `/etc/dnsmasq.d/fips-names.conf`; mode A: `server=::1#5356` | dnsmasq's own |
| **Linux, plain `/etc/resolv.conf`** | same unit | mode B not possible (no per-domain routing) → mode A: `nameserver ::1` with the previous entries as upstreams; setup refuses if a tool rewrites the file (resolvconf, NM without dnsmasq) unless `--force` | previous `resolv.conf` |
| **OpenWrt / routers** | procd init script | dnsmasq `server=/…/` entries in `/etc/config/dhcp`, so every LAN client benefits without running anything | dnsmasq's |
| **FreeBSD / pfSense** | rc.d script (`fips-names.rc`) / `config.xml` custom options like fips does | unbound `forward-zone` per domain / DNS Resolver custom options | unbound |
| **macOS** | launchd `com.fips.names.plist` (RunAtLoad, KeepAlive) | mode B: `/etc/resolver/example.org` (`nameserver ::1`, `port 5356`) — one file per domain, exactly fips's `/etc/resolver/fips` generalised; mode A: `networksetup -setdnsservers <service> ::1` (port must be 53 → needs a launchd socket on 53 or `pf` redirect; deferred) | `scutil --dns` |
| **Windows 10/11** | Windows service (`sc create` via `install-service.ps1`, `windows-service` crate) | mode B: NRPT rules `Add-DnsClientNrptRule -Namespace .example.org -NameServers ::1` (NRPT cannot carry a port → listen on `[::1]:53`, fine as a service); mode A: `Set-DnsClientServerAddress` on the wintun adapter/all adapters | adapter settings via `Get-DnsClientServerAddress` |
| **Android** | none — embedded in fips2go's `VpnService` process | mode A: the shim's `DnsProxy` (plan-phase1 §4) | the VPN's configured upstreams |
| **iOS** | out of scope: no fips node; a future fips iOS app would embed like Android | — | — |

Mode B on macOS and Windows needs no root once the per-domain files/rules
exist, but *writing* them needs admin, so `setup` runs elevated once and the
daemon re-runs the routing step through a tiny privileged helper or at
service start (the service already runs as root/SYSTEM). Design choice:
**the daemon owns the routing list and reconciles it at start and on pin
change**; `setup` only installs the service and the mode.

Network changes: the daemon watches for them (netlink on Linux,
`SCDynamicStore` on macOS, `NotifyAddrChange` on Windows — three thin
`cfg` modules in `names-daemon`, ~50 lines each) to refresh upstreams and the
online/offline flag the resolver needs (spec §8 privacy rule: SRV first when
online).

## 4. Android: integrated, not a daemon

fips2go embeds `names-core` + `names-resolve` in the shim (plan-phase1 §4).
Nothing from `names-daemon` is used. What is shared is exactly what a phone
should share: policy, pins format, wire formats, tests. Differences:

- `MeshDns` over smoltcp (no kernel socket).
- `PinStore` in the app's private files dir; the app exposes "pinned domains"
  and "forget" in its UI instead of a CLI.
- Online flag from `network_changed` / `network_hint`.
- Mode A only.

An Android build never compiles `names-daemon`, and the shim compiles the
two library crates for `aarch64-linux-android` in fips2go's existing NDK
build — no new toolchain.

## 5. Paths

Via the `directories` crate; overridable by `--config` / env.

| | Linux / BSD | macOS | Windows | Android |
|---|---|---|---|---|
| config | `/etc/fips-names/config.yaml` (system service), `$XDG_CONFIG_HOME/fips-names/` (user) | `/Library/Application Support/fips-names/` | `%ProgramData%\fips-names\` | app config JSON |
| pins, anti-rollback, subscriptions | `/var/lib/fips-names/` | same dir | same dir | app files dir |
| cache | in memory (rebuilt from pins) | | | |
| logs | journal / syslog | unified log via stderr under launchd | Event Log via `windows-service` | logcat via tracing |

Pins are one JSON file with the same schema everywhere, so a user can copy
them between machines and a phone backup restores them.

## 6. Server side (`fips-names-server`) is portable too

It is a plain UDP/TCP DNS server on an `fd…` address plus a relay publisher;
the same service/packaging rows as the daemon apply (Linux, BSD, macOS,
Windows). It is not built for Android in phase 1 — a phone serving a public
domain is possible but not a goal.

## 7. Build and CI

- Targets built and tested in CI: `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-unknown-freebsd` (build only),
  `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`,
  `aarch64-linux-android` (library crates only).
- `names-core` and `names-resolve` tests run on all of them; the fake
  relay / fake SRV / fake step-3 server tests are loopback-only, so they run
  everywhere.
- `names-daemon` gets one smoke test per OS: start, answer a pinned name on
  loopback, passthrough an unbound one.
- Packaging mirrors fips's `packaging/` tree: `debian/`, `aur/`, `nixos/`,
  `freebsd/`, `openwrt/`, `macos/`, `windows/`, `systemd/`, `common/`
  (setup/teardown scripts). Reusing fips's script structure keeps the two
  setups from fighting over the same resolver files: both use their own
  drop-in/file names and never touch each other's.

## 8. Milestone changes

plan-phase1 milestones stay; this adds:

- M2 (server + desktop lookup) now produces `fips-namesd` on Linux in
  **mode B** with the systemd-resolved backend, rather than a CLI-only
  lookup. That is the smallest end-to-end desktop demo.
- **M5: macOS and Windows** — launchd + `/etc/resolver/<domain>`, Windows
  service + NRPT. Mode B only.
- **M6: mode A** on desktops, OpenWrt/pfSense packaging, network-change
  watchers.

## 9. Decisions to confirm

- Mode B as the desktop default (explicit add/subscribe instead of first-visit
  discovery). Mode A stays available.
- Loopback port 5356 for the daemon; Windows listens on 53 because NRPT
  cannot name a port.
- `fips-namesd` depends on fips only through two addresses (the TUN and
  the responder), never through fips's crate — so it can be packaged and
  updated independently of the fips fork.
