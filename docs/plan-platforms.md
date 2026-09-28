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
synthesis, caching, the step-3 client, the relay client, the TXT verifier —
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
(default `[::1]:5356` and `127.0.0.1:5356` where the OS can route to a
port; 53 where it cannot — macOS via a launchd socket, Windows as a
service), runs the resolver
from `names-resolve` for every query, and forwards anything without a binding
to the upstream resolvers it learned from the OS (or from its config).

Behaviour per query, in order: local hosts → pins/cache → (online) TXT hint →
relays → step 3 → synthesised answer; else passthrough (spec §5, §7). The
budget rules from plan-phase1 §6 apply unchanged.

It is in the DNS path for **all names** (the default mode, §2.1), because
discovery works by asking public DNS for the `_fips-dns.<domain>` TXT
record the first time a domain is seen — and a resolver can only ask about
domains whose queries reach it. A restricted mode (§2.2) that routes only
known domains exists for machines whose owner will not put a daemon in
front of all DNS; it gives up discovery.

### 2.1 Default mode — full path, TXT-first discovery

The daemon becomes the machine's DNS server; the OS's previous resolvers
become its upstreams. For every name it does, in order:

1. local hosts, pins, caches (spec §5.1 steps 1–2);
2. **online, domain not pinned and not in the negative cache:** ask the
   upstream for `_fips-dns.<domain> TXT` **before** anything else. This
   costs one query per new domain per 6 h (negative cache, spec §5.6) and
   reveals nothing new: the same upstream is about to resolve `<domain>`
   itself. Only the fact that this machine runs fips-names is visible to it.
3. TXT hit → fetch the claim from relays, verify the TXT names the author, pin,
   step 3, synthesise (spec §5–§7). TXT miss → passthrough, remember the
   miss.
4. **offline** (no upstream reachable): pinned domains resolve over the
   mesh; for an unpinned domain the claim is fetched from relays directly —
   the claim replaces the TXT record (spec §5.5) — over whatever relays are
   reachable, which offline means **mesh relays** (`ws://[fd…]:port` on
   fips nodes, configured or synced). Verified by pin, DNSSEC proof or
   attestation; otherwise refused unless the user opted into the visible
   "unverified" marker.

Online, relays therefore only learn about domains that already opted in
via DNS — the TXT hint is the gate. Android has always worked this way (the
VPN captures all DNS); desktops now match it.

Caveats: captive portals and per-network resolver changes must be followed
(the daemon re-reads upstreams on network change, §3), and any bug in the
daemon is a DNS outage — hence the passthrough-on-any-failure rule in spec
§7 and the per-query budget in plan-phase1 §6.

### 2.2 Restricted mode — known domains only (opt-in)

The OS keeps its resolvers; only domains the daemon **knows** are routed to
it, using each OS's native per-domain routing (§3): every pinned domain and
every domain from a **subscription** (added by hand — `fips-names add
example.org` — or synced from trusted nodes, like fips2go's mesh names). The
daemon maintains that routing list itself. Nothing else reaches it, so it
cannot break unrelated resolution — but it also cannot discover: a new
domain is only ever found by adding it. `setup --mode full|restricted`;
full is the default everywhere; restricted is unavailable on platforms
without per-domain routing (plain `resolv.conf`).

## 3. Per-platform integration

| Platform | Service | Route to daemon (full: all names / restricted: per domain) | Upstreams (full mode) |
|---|---|---|---|
| **Linux, systemd-resolved** (Debian/Ubuntu, Fedora, Arch, NixOS…) | `fips-names.service` (`After=fips.service`) | restricted: `resolvectl domain <link> ~example.org` + `resolvectl dns` on a dedicated dummy link, or a `resolved.conf.d` drop-in with `Domains=~example.org`; full: drop-in `DNS=[::1]:5356` `Domains=~.` (what fips's setup does for `.fips`, generalised) | from `resolvectl status` / `/run/systemd/resolve/resolv.conf` |
| **Linux, dnsmasq / NetworkManager+dnsmasq** | same unit | `server=/example.org/::1#5356` per domain, in `/etc/dnsmasq.d/fips-names.conf`; full: `server=::1#5356` | dnsmasq's own |
| **Linux, plain `/etc/resolv.conf`** | same unit | restricted not possible (no per-domain routing) → full: `nameserver ::1` with the previous entries as upstreams; setup refuses if a tool rewrites the file (resolvconf, NM without dnsmasq) unless `--force` | previous `resolv.conf` |
| **OpenWrt / routers** | procd init script | dnsmasq `server=/…/` entries in `/etc/config/dhcp`, so every LAN client benefits without running anything | dnsmasq's |
| **FreeBSD / pfSense** | rc.d script (`fips-names.rc`) / `config.xml` custom options like fips does | unbound `forward-zone` per domain / DNS Resolver custom options | unbound |
| **macOS** | launchd `com.fips.names.plist` (RunAtLoad, KeepAlive) | restricted: `/etc/resolver/example.org` (`nameserver ::1`, `port 5356`) — one file per domain, exactly fips's `/etc/resolver/fips` generalised; full: `networksetup -setdnsservers <service> ::1` on every network service (port must be 53 → launchd socket activation hands the daemon `[::1]:53`) | `scutil --dns` |
| **Windows 10/11** | Windows service (`sc create` via `install-service.ps1`, `windows-service` crate) | restricted: NRPT rules `Add-DnsClientNrptRule -Namespace .example.org -NameServers ::1` (NRPT cannot carry a port → listen on `[::1]:53`, fine as a service); full: `Set-DnsClientServerAddress` on the wintun adapter/all adapters | adapter settings via `Get-DnsClientServerAddress` |
| **Android** | none — embedded in fips2go's `VpnService` process | full: the shim's `DnsProxy` (plan-phase1 §4) | the VPN's configured upstreams |
| **iOS** | out of scope: no fips node; a future fips iOS app would embed like Android | — | — |

Full mode on macOS needs the daemon reachable on port 53 (`networksetup`
cannot name a port): the launchd plist hands it a socket on `[::1]:53`
(launchd socket activation, no root in the process). Windows full mode
sets the adapters' DNS to `::1`, port 53 likewise. Writing per-domain
files/rules (restricted mode) needs admin, so the service, which already
runs as root/SYSTEM, owns that list and reconciles it at start and on pin
change; `setup` only installs the service and the mode.

Known interaction (found on the first two-node test): on systemd-resolved
a link's **search domain is also a routing domain**, and the longest match
wins over the global `~.`. A LAN whose DHCP hands out `example.org` as the
search domain therefore sends every `*.example.org` query to the LAN
resolver, never to the daemon — exactly the domain the owner is most
likely to bind. The daemon warns at start (from the `search` line of
`/run/systemd/resolve/resolv.conf`); the fix is on the link
(`nmcli con mod <con> ipv4.dns-search '' ipv6.dns-search ''`, or
`UseDomains=no` in networkd, or the router). Search domains that are
*not* bound domains are unaffected and keep working as split DNS.

Network changes: the daemon watches for them (netlink on Linux,
`SCDynamicStore` on macOS, `NotifyAddrChange` on Windows — three thin
`cfg` modules in `names-daemon`, ~50 lines each) to refresh upstreams and the
online/offline flag the resolver needs (spec §8 privacy rule: TXT first when
online).

## 4. Android: integrated, not a daemon

fips2go embeds `names-core` + `names-resolve` in the shim (plan-phase1 §4).
Nothing from `names-daemon` is used. What is shared is exactly what a phone
should share: policy, pins format, wire formats, tests. Differences:

- `MeshDns` over smoltcp (no kernel socket).
- `PinStore` in the app's private files dir; the app exposes "pinned domains"
  and "forget" in its UI instead of a CLI.
- Online flag from `network_changed` / `network_hint`.
- Full mode only (the VPN captures all DNS; TXT-first discovery as on the
  desktop).

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
  relay / fake TXT / fake step-3 server tests are loopback-only, so they run
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
  **full mode** with the systemd-resolved drop-in backend (the `.fips`
  setup generalised to `~.`), plus the network-change watcher it needs for
  upstreams. That is the smallest end-to-end desktop demo, and it exercises
  TXT-first discovery.
- **M5: macOS and Windows** — launchd socket on 53 + `networksetup`,
  Windows service + adapter DNS. Full mode.
- **M6: restricted mode** (per-domain routing on all three), OpenWrt/pfSense
  packaging.

## 9. Decisions to confirm

- Full mode with TXT-first discovery is the default on every platform
  (decided 2026-09-28); restricted per-domain mode is opt-in and gives up
  discovery.
- Loopback port 5356 for the daemon on Linux/BSD; 53 on macOS (launchd
  socket) and Windows (NRPT and adapter settings cannot name a port).
- `fips-namesd` depends on fips only through two addresses (the TUN and
  the responder), never through fips's crate — so it can be packaged and
  updated independently of the fips fork.
