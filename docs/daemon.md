# The desktop resolver: fips-pubdomd

`fips-pubdomd` is a forwarding DNS resolver that sits in front of all DNS
on a machine running fips. Names bound to fips nodes resolve over the mesh;
everything else is forwarded to the resolvers the machine had before,
unchanged. On Android the same logic lives inside fips2go
([android.md](android.md)).

## What `setup` does (Linux, systemd-resolved)

Building and installing — binaries, unit, `sudo fips-pubdomd setup`,
enabling the service — is one procedure, kept in one place:
[install.md](install.md). This section explains the OS integration that
`setup` performs.

`setup` snapshots the machine's current upstream resolvers, writes
`/etc/systemd/resolved.conf.d/zz-fips-pubdom.conf`:

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
itself. `sudo fips-pubdomd teardown` removes the drop-in and restarts
resolved; nothing else is left behind.

Other backends (dnsmasq, plain `resolv.conf`, launchd, Windows) are on the
[roadmap](roadmap.md); the daemon itself is portable
([platforms.md](platforms.md)).

## Configuration

`/etc/fips-pubdom/config.yaml`, all keys optional:

```yaml
listen: ["[::1]:5356", "127.0.0.1:5356"]
upstreams: []                                    # explicit legacy resolvers; empty → follow upstreams_from
upstreams_from: /run/systemd/resolve/resolv.conf # written by setup; re-read every 30 s, minus ourselves
dnssec: true                                     # validate TXT answers (unsigned zones still work, as method dns)
public_relays: ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net", "wss://relay.nostr.band"]
mesh_relays: ["ws://npub1….fips:80"]             # relays on fips nodes, by .fips name (see below)
responder: "[::1]:5354"                          # fips's .fips responder
mesh_bind: null                                  # bind mesh queries to this node's fips address
pins: /var/lib/fips-pubdom/pins.json
allow_unverified_offline: false                  # resolve unverifiable claims offline, with a WARN per use
budget_ms: 4500                                  # whole lookup; on expiry the legacy answer is used
```

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
fips-pubdom pins list                 # example.org  npub…:5355  Dnssec  verified_at …
journalctl -u fips-pubdom | grep pinned
```

`fips-pubdom verify <domain>` prints every input to the decision — pin, TXT
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
