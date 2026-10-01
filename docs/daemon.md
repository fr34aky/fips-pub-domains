# The desktop resolver: fips-pubdomd

`fips-pubdomd` is a forwarding DNS resolver that sits in front of all DNS
on a machine running fips. Names bound to fips nodes resolve over the mesh;
everything else is forwarded to the resolvers the machine had before,
unchanged. On Android the same logic lives inside fips2go
([android.md](android.md)).

## What `setup` does (Linux)

Building and installing — binaries, unit, `sudo fips-pubdomd setup`,
enabling the service — is one procedure, kept in one place:
[install.md](install.md). This section explains the OS integration that
`setup` performs. It detects which resolver arrangement the machine runs
(`--backend auto`, the default: by the services that are active, not
by files they may have left behind) and records its choice in
`/etc/fips-pubdom/backend` before touching anything, so `sudo
fips-pubdomd teardown` undoes the right thing without being told — after
a `setup` that failed halfway too; `--backend` names one explicitly. A
second `setup` is refused until `teardown` has run, so the backups of the
original `resolv.conf` and config are never overwritten by our own. An installation
set up before the record existed is torn down by its resolved drop-in.
On the backends that snapshot upstreams, an `upstreams` list in the
config is used instead of a snapshot.

**systemd-resolved** (`resolved`; Ubuntu, Fedora, Arch, Debian with
resolved). `setup` writes `/etc/systemd/resolved.conf.d/zz-fips-pubdom.conf`:

```
[Resolve]
DNS=
DNS=[::1]:5356 127.0.0.1:5356
Domains=
Domains=~.
```

and restarts resolved. The empty assignments matter: resolved merges every
global drop-in into **one** server pool and queries its members
interchangeably, so fips's own `.fips` drop-in and this one would otherwise
share a pool and each see the other's names. The daemon therefore becomes
the only global server and forwards `.fips` names to fips's responder
itself. The upstreams are followed through
`/run/systemd/resolve/resolv.conf`, which keeps listing the real servers.

**NetworkManager without resolved** (`networkmanager`; Debian and others
with NM's `dns=default` or `dns=dnsmasq`). NM cannot be told to use one
server exclusively — with its dnsmasq plugin it keeps feeding dnsmasq the
connections' servers over D-Bus — so `setup` takes DNS away from it: a
drop-in `/etc/NetworkManager/conf.d/zz-fips-pubdom.conf` with `dns=none`
(reloaded with `nmcli general reload conf`), after which NM leaves
`/etc/resolv.conf` alone but still writes its list of the connections'
servers to `/run/NetworkManager/resolv.conf`, which the daemon follows —
DHCP changes included. `setup` then writes `/etc/resolv.conf` naming the
daemon (the previous file or symlink is kept in
`/etc/fips-pubdom/resolv.conf.bak`) and sets `listen` to port 53, since
resolv.conf cannot carry a port. Restart the daemon after `setup`.

**Standalone dnsmasq** (`dnsmasq`; a server whose local resolver is dnsmasq
reading `resolv-file`). `setup` snapshots the servers of dnsmasq's resolv
file (`resolv-file=` from `dnsmasq.conf` or `dnsmasq.d/`, else
`/etc/resolv.conf`) into `/etc/fips-pubdom/upstreams.conf`, writes
`/etc/dnsmasq.d/fips-pubdom.conf` with `no-resolv` and `server=::1#5356` /
`server=127.0.0.1#5356`, and restarts dnsmasq. The daemon keeps port 5356.
The snapshot is static: run `teardown` and `setup` again if the machine's
resolvers change, and remove other `server=` lines from dnsmasq's
configuration, which it would otherwise keep using. A dnsmasq that
already runs with `no-resolv` has its servers in `server=` lines, which
cannot be snapshotted: give the daemon `upstreams` in the config.

**Plain resolv.conf** (`resolv-conf`; nothing manages the file). `setup`
snapshots its `nameserver` lines into `/etc/fips-pubdom/upstreams.conf`,
keeps the file in `/etc/fips-pubdom/resolv.conf.bak`, writes one naming
`::1` and `127.0.0.1` (the `search`/`options` lines kept), and sets
`listen` to port 53. Refused when resolved or NetworkManager is running,
or when the file is a symlink into something else's directory: whatever
rewrites the file would undo this. Restart the daemon after `setup`.

`setup` keeps the config as it found it (`config.yaml.before-setup`
next to it) before rewriting `listen` and `upstreams_from`, and says so
when the listen addresses changed: restart the daemon then. `teardown`
removes what `setup` wrote, restores the backed-up resolv.conf and the
config, and restarts or reloads the resolver it touched — so the next
`setup`, under whatever backend, starts from your own values.

Other backends (launchd, Windows, OpenWrt, pfSense) are on the
[roadmap](roadmap.md); the daemon itself is portable
([platforms.md](platforms.md)).

## Configuration

`/etc/fips-pubdom/config.yaml`, all keys optional:

```yaml
listen: ["[::1]:5356", "127.0.0.1:5356"]
upstreams: []                                    # explicit legacy resolvers; empty → follow upstreams_from
upstreams_from: /run/systemd/resolve/resolv.conf # written by setup; re-read every 30 s, minus ourselves
dnssec: true                                     # validate TXT answers and accept DNSSEC proofs in claims (unsigned zones still work, as method dns)
public_relays: ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net", "wss://relay.nostr.band"]
mesh_relays: ["ws://npub1….fips:80"]             # relays on fips nodes, by .fips name (see below)
responder: "[::1]:5354"                          # fips's .fips responder
mesh_bind: null                                  # bind mesh queries to this node's fips address
pins: /var/lib/fips-pubdom/pins.json
allow_unverified_offline: false                  # resolve unverifiable claims offline, with a WARN per use
witnesses: []                                    # npubs whose attestations count offline (spec §3.2); nobody else's are fetched
attestation_threshold: 2                         # k: witnesses that must attest a server; 0 = off
budget_ms: 4500                                  # whole lookup; on expiry the legacy answer is used
```

Not in the file (built-in, see the resolver's `ResolverConfig`): a server
that does not answer step 3 is skipped for 5 minutes, tripling per
consecutive failure up to 3 hours, then tried again.

```yaml
```

**Witnesses** are nodes you trust to have verified a domain online — your
own other nodes, or a friend's — that publish attestations with
`fips-pubdom attest` ([operators.md](operators.md), "Witnesses"). Offline,
for a domain with no pin and no DNSSEC proof in its claim, a server attested
by `attestation_threshold` of them is used and pinned as `attested`; the
next online lookup re-verifies it properly. Attestations are read from
the `mesh_relays` only, so the witness list never reaches a public relay.
With `witnesses` empty nothing changes.

**Mesh relays** are Nostr relays that run on fips nodes and are reachable
without the Internet. Configure them by their `.fips` hostname, never as an
`[fd…]` literal: nostr-sdk cannot dial bracketed IPv6, and resolving the
name through fips is what registers the relay's identity with the local
node. Online they are asked alongside the public relays; offline they are
the only discovery there is.

## Verifying it works

```sh
resolvectl query www.example.org      # → fdd9:… -- link: lo, with the CNAME npub….fips
resolvectl query peer.fips      # .fips still resolves
resolvectl query github.com          # legacy, untouched
fips-pubdom pins list                 # one line per pinned server, primary first
journalctl -u fips-pubdom | grep pinned
```

`fips-pubdom zone <domain>` prints the zone record the pinned server
published. `fips-pubdom verify <domain>` prints every input to the decision — pin, TXT
result and method, claims — and the decision itself, without applying it.
`fips-pubdom --offline lookup <name>` runs a lookup as if no upstream
existed.

## Behaviour in one table

| situation | what the application gets |
|---|---|
| domain has no `_fips-dns` TXT | the legacy answer (miss cached 6 h) |
| TXT present, claim verified | `CNAME npub….fips` + `fd…` AAAA; pinned |
| TXT present, claim missing or by another key | the legacy answer; the pin, if any, stays |
| TXT removed | the legacy answer; the pin is forgotten |
| name bound but not in the zone, or `legacy` | the legacy answer |
| the primary server does not answer | the next pinned server (the TXT record names several); the failed one is retried after its backoff |
| no server answers | a published zone record, if any: names pointing at nodes that answer an echo resolve over the mesh, the rest get the legacy answer |
| target node unreachable through the local fips node | the legacy answer |
| offline, domain pinned | the mesh answer, no DNS, no relays |
| offline, unpinned, claim on a mesh relay | refused (legacy fails too) — unless `allow_unverified_offline` |
| any error or the budget exceeded | the legacy answer |

## Troubleshooting

**`resolvectl query` shows the public address, `-- link: <lan interface>`.**
The link carries a **search domain** that matches the name — a LAN whose
DHCP hands out `example.org` as the search domain is the common case. On
systemd-resolved a search domain is also a routing domain, and the longest
match beats the global `~.`, so those names never reach the daemon. The
daemon warns about this at start (`link search domains route past this
daemon …`). Fix it on the link:
`nmcli con mod "<connection>" ipv4.dns-search "" ipv6.dns-search ""`
(networkd: `UseDomains=no`), or stop the router from pushing it.
`sudo resolvectl domain <iface> ''` works until the next DHCP renewal.

**Cold lookups take ~2 s.** That is the full chain — TXT, relay, step 3 —
and it happens once per domain per hour; pinned names answer in
milliseconds. If every lookup is slow, a configured relay is unreachable:
check `journalctl -u fips-pubdom` for `Connection failed`.

**`.fips` names stopped resolving after setup.** The daemon forwards them to
`responder`; make sure fips's responder is at `[::1]:5354` (fips's default)
or set `responder:` accordingly.

**Testing offline without pulling the cable.** Block legacy DNS but not the
loopback stub: `iptables -I OUTPUT ! -o lo -p udp --dport 53 -j DROP` (and
`ip6tables`), `resolvectl flush-caches`, then query. Remove the rules with
the same lines and `-D`.
