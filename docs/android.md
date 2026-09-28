# Android: the fips2go integration

On a phone the resolver cannot be a daemon, and the VPN already owns all
DNS of the captured apps. So [fips2go](https://github.com/fr34aky/fips2go)
embeds the two library crates — `pubdom-core` and `pubdom-resolve`, pinned
git dependencies like fips itself — in its shim and supplies the parts only
the phone can: the mesh transport and the responder registration.

## Where it lives

| fips2go file | role |
|---|---|
| `shim/src/names.rs` | builds the resolver over the engine's `MeshLink`, runs it from the DNS proxy's blocking per-query thread on a one-worker tokio runtime, implements `MeshDns` |
| `shim/src/meshtcp.rs` | relays on the mesh: a loopback listener per relay, admitting only the resolver (random path token), each connection carried over the in-process smoltcp TCP stack to the relay's fips address |
| `shim/src/meshudp.rs` | one UDP request/response over the mesh from the node's own address through a smoltcp socket — the UDP twin of `meshhttp.rs`; and the ICMPv6 echo that confirms a target node is reachable. `Divert` claims UDP flows and echo replies (by identifier) for it |
| `shim/src/dns.rs` | the proxy asks the resolver for every non-`.fips` name before the upstreams; `None` means "not over fips" and the query goes upstream unchanged |
| `shim/src/config.rs` | knobs `names_pins_path` (set = on), `names_mesh_relays`, `names_allow_unverified_offline` |
| `ConfigStore.kt` / `SettingsFragment.kt` | Settings → *Public domain names over fips* (`public_names`, default on) decides whether the pin path is sent; *Mesh relays for public names* below it lists relays on fips nodes, validated (bech32 checksum) and sent as `names_mesh_relays` while the switch is on |

The pin file is `names-pins.json` in the app's private files directory,
same schema as the desktop daemon's, so a backup restores it.

## Why the mesh transport is special

The app's own UID sits outside its tunnel whenever mesh apps are selected
(and must stay out — see fips2go's CLAUDE.md), and a VPN network refuses
`bindSocket` from a UID it does not cover. So no kernel socket in the app
can reach `fd00::/8`. The Mesh names sync solved this for HTTP with a
userspace TCP stack whose packets go through the node's
`TunPacketProcessor` like an app's; step 3 reuses that design with a UDP
socket, and the reply comes back through `Divert` before the inbound
firewall and the TUN.

## Limits today

- **No TCP fallback for step 3.** A step 3 answer is a single CNAME and is
  never truncated; the TCP path would ride on `meshhttp`'s stack and is not
  wired yet.
- **Mesh relays go through a loopback proxy.** nostr-sdk opens kernel
  websockets, which the app's UID cannot point at an `fd…` address, so each
  relay in Settings → "Mesh relays for public names"
  (`ws://<npub>.fips[:port][/path]`, port 80 if none; the scheme may be
  left out) gets a listener on loopback, reachable only with a random path
  token, and every connection is carried over the in-process TCP stack
  (`meshtcp.rs`). With one configured, an offline phone discovers domains
  through it, and verifies a domain it never saw — provided the claim
  carries a valid DNSSEC proof (a 0.2.0 server, a signed zone) and the
  phone has a mesh path to the relay. Otherwise such a domain is refused
  offline, as before.
- **No explicit online flag.** An unreachable upstream simply takes the
  offline path; `network_hint` flushes the resolver's caches so the next
  lookup re-decides.
- The whole lookup runs on a 3.5 s budget so the legacy fallback still fits
  inside bionic's 5 s resolver timeout. A lookup that overruns it (offline:
  TXT timeout, then a mesh relay) finishes in the background and caches,
  so the application's retry resolves.

## Verifying on a device

Install a current fips2go build, connect, then in a captured browser open a
name of a bound domain (`www.example.org`). Diagnostics shows `public name
answered over fips`; the log at info level also shows `binding verified
and pinned`. Offline with a pin: block the phone's Internet (keep a mesh
link) and repeat — the pinned name still resolves. Offline without one:
configure a mesh relay, empty `files/names-pins.json` (debug build, `adb
shell run-as org.fips.android`), block the Internet and open the name — the
first lookup may fall back once, the retry resolves from the claim's
proof ([testing.md](testing.md), level 5b).
