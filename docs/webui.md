# The domain server's web UI — design

Status: design, 2026-10-08. Nothing of it is built. The decisions below
are proposals until the maintainer has answered the open questions at
the end; the phases are ordered so that each ships on its own.

## What it is for

Today an operator configures `fips-pubdom-server` with a YAML zone file
written by hand, flags in `/etc/fips-pubdom/server.env`, and the
`txt` subcommand to learn which DNS record to add. Whether it all works
— the record resolving, the claim on the relays, the DNSSEC proof still
valid, the zone record current — is spread over `dig`, the journal and
`fips-pubdom verify` on another node. The web UI puts the configuration
and the state of each domain on one page, in a browser, on the node
that serves it: add a domain, name what is on the mesh, see the record
to set, see that the world can verify it.

It is the server's UI, not the resolver's: it configures what this node
*serves*. It does not replace fips-ui, which manages the fips node
itself; it sits beside it, reached the same way.

## Where it runs

Inside `fips-pubdom-server`, as part of `serve`: one process, one unit,
no helper. The server already holds everything the UI shows — the
zones, the key, the publisher's schedule, the proofs — and already
re-reads zone files it did not write. A separate process would need an
IPC surface for all of that, and a privileged helper to write files
the server reads; fips-ui needs one because the fips daemon is not its
code. Here both halves are ours.

The server grows a configuration file, which the UI edits and the
server reloads:

```yaml
# /etc/fips-pubdom/server.yaml
key: /etc/fips/fips.key
zones: /etc/fips-pubdom/zones          # every *.yaml in it, followed as it changes
port: 5355                              # the default for zones that name none
ttl: 300
publish:
  relays: ["wss://relay.example", "ws://npub1….fips:80"]
  dnssec_proof: true
  dns: []                               # resolvers for the proof; empty: system, 9.9.9.9, 1.1.1.1
ui:
  listen: ["[::1]:5357", "127.0.0.1:5357", "[<this node's fips address>]:5357"]
  admins: ["npub1…"]                    # over the mesh; loopback is admin without being listed
  viewers: []
```

`serve --config /etc/fips-pubdom/server.yaml` replaces `--zone` ×N and
`PUBDOM_SERVER_ARGS`; the flags keep working for scripts, and
`fips-pubdom-server init` writes a `server.yaml` from the existing
`zones/` and `server.env` so an upgrade is one command. The zones
directory is watched (the daemon's `watch.rs` moved into
`pubdom-resolve` or copied — the notify dependency is the same), so a
zone the UI adds is served without a restart; today a new file needs
one.

The unit keeps `DynamicUser=yes`. Files the UI writes must survive the
next start under a different UID, which `ReadWritePaths` would not
give; `ConfigurationDirectory=fips-pubdom` does (systemd chowns the
directory to the unit's user at every start, as the daemon's unit
already relies on for `/var/lib/fips-pubdom`).

## Who may open it

The same rule as fips-ui, because it is the same network: **a connection
from loopback is an admin; a connection over the mesh is whoever its
source address says**, with no password. fips rebuilds the IPv6 header on
the receiving side, so the source address of a connection arriving
through `fips0` is the `fd…` address derived from the sender's key and
cannot be spoofed by another node. The server computes the address of
every npub in `admins` and `viewers` (`Npub::fips_address`) and grants
that role; any other mesh address gets 403 and a log line. Nobody else
can reach the socket: the UI binds loopback and the node's fips address
only, never a LAN interface — a LAN binding would need TLS and real
authentication, and the operator has `ssh -L` for the one-off case.

Writes additionally require the `X-Requested-With: fips-pubdom` header
and an `Origin` that matches one of the UI's own addresses, which keeps
a page in another tab from posting on the operator's behalf; the `Host`
header must be one of the listen addresses or `<npub>.fips`, as fips-ui
checks it. The key is never shown or sent; the UI shows the npub and the
address.

## What it shows and does

One page per domain, and a few around it. Everything below the fold of
a page is read from the server's own state; nothing polls the relays or
DNS on every page load — the server keeps what it learned at its last
publish and refreshes on a schedule or on request.

**Overview.** This node: npub, fips address, port, whether `serve` is
listening (UDP and TCP), relays and whether each accepted the last
publish. The domains, one card each: zone loaded or broken (with the
error), TXT record state, claim published when and where, DNSSEC proof
valid until, zone record current or stale. A broken state is red with
the reason, as `fips-pubdom verify` would print it.

**Domain.** The zone as a table — label, target (*this node* / another
node's npub or a name fips-ui knows for it / *legacy*), the wildcard
row — editable in place, with the same validation the server applies on
load (hostname labels, no npub-shaped label, the wildcard warning from
operators.md shown next to the row). *Save* writes the YAML atomically
(temp file, rename) with a comment that the UI wrote it; the server
picks it up through the watcher like any other edit and republishes.
Below: **the DNS record to add**, verbatim, with a copy button, and
**Check DNS**, which runs the resolver's own TXT verification
(`TxtVerifier` from `pubdom-resolve`, two resolvers, DNSSEC) and reports
*verified (dnssec)*, *verified (two resolvers)*, *record names another
key*, *no record* — the four things an operator wants to know after
editing their hoster's panel. **Publish now** sends the claim and the
zone record ahead of schedule and shows each relay's answer.

**Publishing.** The relay list (add, remove; validated as the daemon
validates `mesh_relays`), the DNSSEC proof switch and resolvers, the
schedule (next publish, why: proof halfway through validity, 24 h, zone
changed), and the last outcome per relay. Secrets: none here; the key
path is shown, not the key.

**Attestations.** Read-only: what the witnesses a client would trust
have said about this domain — fetched from the configured mesh relays
on request, so an operator can see that a friend's node vouched for
them. Being a witness oneself (`fips-pubdom attest`) stays a client-side
action on another node and is out of scope.

**Log.** The server's last few hundred log lines, from a ring buffer
the tracing subscriber feeds; filter by level. No journal access
needed, so it works the same under every service manager.

Not in the UI: the firewall drop-in (one `cp`, documented), the unit,
the key.

## How it is built

- **Rust, in the server crate**, behind a `ui` cargo feature on by
  default: `axum` on the server's existing tokio runtime, routes under
  `/api/…` returning JSON, static files embedded at build time. One
  more dependency family (`axum`, `tower-http` for static files and
  compression); `rust-embed` or `include_str!` for the assets.
- **The page is one HTML file and one script, no framework, no build
  step, no CDN** — fips-ui's rule ("no external fonts or CDNs") and the
  phone's: the UI must work on a node with no Internet, which is the
  point of the whole project. Vanilla DOM, `fetch`, and an `EventSource`
  on `/api/events` for live state (the same server-sent-events shape
  fips-ui uses, so a reader of one is at home in the other). Dark and
  light, following the browser.
- **The API is the UI's only door**, and the CLI could use it later:
  `GET /api/status`, `GET/PUT /api/zones/<domain>`, `POST
  /api/zones/<domain>/check-dns`, `POST /api/publish`, `GET/PUT
  /api/publishing`, `GET /api/attestations/<domain>`, `GET /api/log`,
  `GET /api/events`. Every PUT is whole-document, validated with the
  same code the server loads with; a rejected document returns the
  error and changes nothing on disk.
- **Validation lives in `pubdom-core`** where it belongs: the zone file
  parser the server uses is what the API calls, so the UI cannot write
  a file the server will not load. The TXT check is `pubdom-resolve`'s
  verifier; the publish is the server's own publisher.
- **State the UI reads is state the server already keeps**, held in a
  `watch` channel the serve loop updates (zone loaded/broken, last
  publish per relay, proof expiry, next schedule). The UI never reaches
  into the serve loop; it reads a snapshot and asks for actions through
  channels. That is also what makes the ring-buffer log and SSE cheap.

## Phases

1. **`server.yaml`, the zones directory watched, `init`** — no UI yet;
   the unit switches to `serve --config`, `install.md` and
   `operators.md` follow, the flags stay. Shippable on its own: a new
   zone no longer needs a restart.
2. **The read-only UI**: Overview, Domain (view), Publishing (view),
   Log; loopback only. Everything an operator checks today with `dig`
   and the journal, on one page.
3. **Editing**: zone table, Save, Check DNS, Publish now, relay list.
4. **Over the mesh**: `admins`/`viewers`, the fips-address listener,
   Host and Origin checks, a line in fips-ui's docs on how to find it.
5. **Attestations** page.

Each phase is one PR with its review; live tests on the serving node
go into [testing.md](testing.md) as a new level.

## Open questions for the maintainer

- **Port.** 5357 is proposed (5355 the server, 5356 the daemon, 8321 is
  fips-ui). Any other?
- **Mesh access from the start or later?** Phase 4 is where the
  address-as-identity rule and the header checks come in; until then
  loopback only, reached over `ssh -L` from elsewhere.
- **Should the UI also edit the daemon's `config.yaml`** on a node that
  runs both (witnesses, mesh relays, `plain_probe`)? Proposed: no — the
  daemon is the client side and fips-ui's territory is the node; a
  second page for it is easy to add later if wanted.
- **Names for npubs**: show fips-ui's hosts-file names next to npubs in
  the zone table (read `/etc/fips/hosts` if present)? Proposed: yes,
  read-only, since operators think in `home.fips`, not in npubs.
- **The `init` migration**: write `server.yaml` from `server.env` and
  the zones directory once, keep `server.env` working forever, or drop
  it after one release? Proposed: keep both working; `init` is a
  convenience, not a requirement.
