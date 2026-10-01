# One resolver on every platform

The resolver runs as a **separate service** on every desktop and server OS
fips runs on, and is **embedded in fips2go** on Android, where an app cannot
run a system daemon and the VPN already owns all DNS. Same code, same policy,
same pin format; only four things are platform-specific and they are kept
in four small places.

## What differs per platform — and nothing else

| concern | where it lives | notes |
|---|---|---|
| reaching the local fips node | `pubdom-resolve::MeshDns` implementations | desktop: the node's TUN exists, so a kernel socket to `fd…` works, and identity registration is a query to fips's responder; Android: smoltcp through `TunPacketProcessor` |
| getting the OS to send DNS to us | `fips-pubdomd setup` / `teardown`, one backend per OS | modelled on fips's `fips-dns-setup` |
| running as a service | `packaging/`: systemd today; rc.d, launchd, Windows service, NixOS module to come | the daemon never forks itself |
| paths | `pubdom-resolve::config` | config, pins, logs (below) |

Everything else — event parsing, verification, pinning, precedence, answer
synthesis, caching, the mesh client, the relay client, the TXT verifier — is
portable Rust. **No `cfg(target_os)` in `pubdom-core` or `pubdom-resolve`**;
CI greps for it and checks that both build for `aarch64-linux-android`.
Portable choices that make this hold: `rustls` for relays, `hickory-resolver`
for legacy DNS (reads the system's resolver configuration on every OS),
`simple-dns` for the wire format (what fips uses), a single-threaded tokio.

## Modes

**Full mode (default).** The daemon is the machine's DNS server; the
previous resolvers become its upstreams. This is required for *discovery*:
the first time a domain is seen, the daemon asks public DNS for its
`_fips-dns` TXT record, and a resolver can only ask about names whose
queries reach it. Privacy holds because the upstream that answers the TXT
query is the one about to resolve the name anyway, and relays are only
contacted after a hit. Android has always worked this way (the VPN captures
all DNS); desktops match it.

**Restricted mode (planned, opt-in).** The OS keeps its resolvers; only
domains the daemon knows — pinned, or subscribed by hand — are routed to it
through the OS's native per-domain routing. It cannot break unrelated
resolution and cannot discover anything. For machines whose owner will not
put a daemon in front of all DNS.

## Per platform

| platform | service | full mode | restricted mode | status |
|---|---|---|---|---|
| Linux, systemd-resolved | `fips-pubdom.service` | global drop-in `DNS=[::1]:5356`, `Domains=~.` (fips's `.fips` mechanism generalised); upstreams followed via `/run/systemd/resolve/resolv.conf` | `resolvectl domain … ~d` / a `Domains=~d` drop-in | **done** |
| Linux, NetworkManager (no resolved) | same unit | `dns=none` drop-in; the daemon on port 53 in `resolv.conf`; upstreams followed via `/run/NetworkManager/resolv.conf` | `/etc/resolver`-style routing does not exist; see restricted mode | **done** (full mode; verified live on Ubuntu 22.04, [testing.md](testing.md)) |
| Linux, standalone dnsmasq | same unit | `no-resolv` + `server=::1#5356`; the servers of its resolv file snapshotted as upstreams | `server=/d/::1#5356` | implemented, tested in a temporary root; not yet run live |
| Linux, plain `resolv.conf` | same unit | `nameserver ::1`, port 53, previous entries snapshotted as upstreams; refused if another tool rewrites the file | not possible | implemented, tested in a temporary root; not yet run live |
| OpenWrt / routers | procd | dnsmasq entries in `/etc/config/dhcp`: every LAN client benefits | `server=/d/` | planned |
| FreeBSD / pfSense | rc.d / `config.xml` custom options | unbound forward | `forward-zone` per domain | planned |
| macOS | launchd plist, socket on `[::1]:53` (`networksetup` cannot name a port) | `networksetup -setdnsservers` on every service | `/etc/resolver/<domain>` files | planned |
| Windows | Windows service (`windows-service` crate), port 53 | `Set-DnsClientServerAddress` on the adapters | NRPT rules | planned |
| Android | none: inside fips2go's VpnService process | the shim's `DnsProxy` | — | **done** |
| iOS | out of scope: no fips node | | | |

Network changes: the daemon follows its upstreams file as the OS rewrites
it (resolved and NetworkManager both rewrite theirs when a network comes or
goes; the directory is watched, since they rename a new file into place),
debounced, with a 30 s re-read as the fallback. The same mechanism serves
macOS and Windows once their backends name a file; `SCDynamicStore` /
`NotifyAddrChange` watchers are only needed where none exists.

Known interaction on systemd-resolved: a link's **search domain is also a
routing domain**, and the longest match beats the global `~.`. A LAN whose
DHCP hands out `example.org` as the search domain therefore sends every
`*.example.org` query to the LAN resolver, never to the daemon — exactly the
domain its owner is most likely to bind. The daemon warns at start; the fix
is on the link ([daemon.md](daemon.md), Troubleshooting). Search domains
that are not bound domains keep working as split DNS.

## Paths

| | Linux / BSD | macOS | Windows | Android |
|---|---|---|---|---|
| config | `/etc/fips-pubdom/config.yaml` | `/Library/Application Support/fips-pubdom/` | `%ProgramData%\fips-pubdom\` | app config JSON |
| pins | `/var/lib/fips-pubdom/pins.json` | same dir | same dir | `files/names-pins.json` |
| logs | journal | unified log via stderr | Event Log | logcat via tracing |

Pins are one JSON file with the same schema everywhere.

## Ports

- Domain server: **5355** on the node's fips address (53 needs privileges;
  the port travels in the claim and the TXT record anyway).
- Daemon: **5356** on loopback where the OS can route to a port; 53 on
  macOS and Windows, which cannot.

## Build matrix

CI tests on Linux, macOS and Windows, and checks the library crates for
`aarch64-linux-android`. Packaging mirrors fips's `packaging/` layout so the
two never touch each other's resolver files.
