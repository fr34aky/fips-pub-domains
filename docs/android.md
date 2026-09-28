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
| `shim/src/meshudp.rs` | one UDP request/response over the mesh from the node's own address through a smoltcp socket — the UDP twin of `meshhttp.rs`; `Divert` claims UDP flows for it |
| `shim/src/dns.rs` | the proxy asks the resolver for every non-`.fips` name before the upstreams; `None` means "not over fips" and the query goes upstream unchanged |
| `shim/src/config.rs` | knobs `names_pins_path` (set = on), `names_mesh_relays`, `names_allow_unverified_offline` |
| `ConfigStore.kt` / `SettingsFragment.kt` | Settings → *Public domain names over fips* (`public_names`, default on) decides whether the pin path is sent |

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
- **No mesh relays.** nostr-sdk opens kernel websockets, which the app's UID
  cannot point at an `fd…` address, so offline discovery through a relay on
  the mesh is not available on the phone. **Offline on Android means pinned
  domains only** — verified once online, they keep working.
- **No explicit online flag.** An unreachable upstream simply takes the
  offline path; `network_hint` flushes the resolver's caches so the next
  lookup re-decides.
- The whole lookup runs on a 3.5 s budget so the legacy fallback still fits
  inside bionic's 5 s resolver timeout.

## Verifying on a device

Build and install fips2go from the `names` branch, connect, then in a
captured browser open `http://www.example.org:8321/` (fips-ui on the demo
node). Diagnostics shows `public name answered over fips` for the lookup;
`fips2go`'s log at info level also shows `binding verified and pinned`. For
the offline case, switch to the FIPS Hotspot or airplane mode with a mesh
link and repeat: the pinned name still resolves.

fips2go's CI cannot build the `names` branch until it can fetch this
repository (private): a token in the workflow, or the repository made
public.
