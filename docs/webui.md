# Public domains in fips-ui — design

Status: design, 2026-10-08, revised the same day after the maintainer's
proposal. Nothing of it is built. The decisions are proposals until the
open questions at the end are answered; the phases are ordered so that
each ships on its own.

## What it is for

Today an operator configures `fips-pubdom-server` with a YAML zone file
written by hand, flags in `/etc/fips-pubdom/server.env`, and the `txt`
subcommand to learn which DNS record to add; a resolver node has
`config.yaml`, a pin file and `fips-pubdom verify`. Whether it all works
— the record resolving, the claim on the relays, the DNSSEC proof still
valid, a domain pinned — is spread over `dig`, the journal and the CLI.
The goal: configuration and state of both halves on one page, in a
browser, including from another node.

## Where it lives: a section of fips-ui, not a UI of its own

[fips-ui](https://github.com/fr34aky/fips-ui) already is the browser
for a fips node: it has the privileged helper that edits root-owned
files and restarts units, access over the mesh with admin and viewer
roles granted per npub, hosts-file names next to every npub, SSE for
live state, dark and light. A second web server on the same node would
repeat all of that for one feature. So:

- **fips-ui gets a "Public domains" section** that appears when it
  finds a domain server or a resolver on the node — the server's or
  the daemon's control socket, or `/etc/fips-pubdom/` — and is absent
  otherwise. Its pages are fips-ui's; the work on them happens in that
  repository.
- **fips-pub-domains provides what the pages need and nothing else**:
  a control socket per binary with the state only the process has, a
  configuration file layout the helper can edit, and validation
  commands the helper runs before writing. This repository stays
  independent of fips-ui, as of fips2go: fips-ui is a consumer.
- **Remote management comes for free**: whoever has the admin role on
  the fips-ui node over the mesh ([fips-ui's mesh
  access](https://github.com/fr34aky/fips-ui/blob/main/docs/mesh-access.md))
  manages its public domains too; a viewer sees the state and nothing
  more. No new listener, no new port, no new authentication.

This is the same division as between fips and fips-ui: the daemon
exposes a control socket, fips-ui reads it and edits the daemon's files
through its helper.

### Rejected: a web UI inside `fips-pubdom-server`

The first draft put an axum server with its own page into
`fips-pubdom-server` (loopback and the node's fips address, admins by
npub). It would have duplicated fips-ui's mesh access, header checks,
hosts names and theming, needed its own port and its own way for the
server to write the files it reads under `DynamicUser`, and given the
resolver nothing. Dropped the same day for the design above.

## What fips-pub-domains provides

### 1. Configuration the helper can edit

The server moves from flags to a file, the daemon already has one:

```yaml
# /etc/fips-pubdom/server.yaml
key: /etc/fips/fips.key
zones: /etc/fips-pubdom/zones          # every *.yaml in it, followed as it changes
port: 5355
ttl: 300
publish:
  relays: ["wss://relay.example", "ws://npub1….fips:80"]
  dnssec_proof: true
  dns: []                               # resolvers for the proof; empty: system, 9.9.9.9, 1.1.1.1
```

`serve --config /etc/fips-pubdom/server.yaml` replaces `--zone` ×N and
`PUBDOM_SERVER_ARGS`; the flags keep working, and `fips-pubdom-server
init` writes a `server.yaml` from an existing `zones/` and `server.env`.
The zones directory is watched (the daemon's `watch.rs` shared through
`pubdom-resolve`), so a zone the UI adds is served without a restart.
`server.yaml` itself is re-read on change for the publishing section;
`key`, `port` and `ttl` take a restart, which the helper does.

The daemon's `/etc/fips-pubdom/config.yaml` is what it is today
(`witnesses`, `attestation_threshold`, `mesh_relays`, `plain_probe`, …);
it is re-read on change for everything that does not need a listener
rebound.

### 2. Validation the helper runs before writing

The helper passes new content on stdin, so the check must be a command:

- `fips-pubdom-server validate zone < file` — the server's own zone
  parser; prints the normalised zone or the error, exit 1 on error.
- `fips-pubdom-server validate config < server.yaml`, `fips-pubdomd
  validate config < config.yaml` — the same.

Validation is in `pubdom-core` (zone) and the two binaries' config
types, so nothing the helper writes is a file the process will not
load.

### 3. A control socket per binary

Unix sockets, fips's own protocol — one request per connection, the
request one JSON line `{"command": "…", "params": {…}}` of at most
4096 bytes, the reply one line `{"status": "ok", "data": …}` or
`{"status": "error", "message": "…"}` — so fips-ui's `control.ts` and
`fipsctl`'s client code apply unchanged. The daemon's is
`/run/fips-pubdom/control.sock`, the server's
`/run/fips-pubdom-server/control.sock` (one `RuntimeDirectory` each:
systemd removes a unit's runtime directory when it stops, so two units
cannot share one); both are mode 0660 and handed to group `fips`
(fips-ui's user is in it for fips's socket already; the server's unit
is in it as a supplementary group, which is enough to chgrp). By hand,
`control:` in either configuration file points anywhere (a socket path
is at most 107 bytes), or `null` for none. Read commands for the
viewer, write commands for the admin — the roles are fips-ui's; the
sockets trust whoever can open them, as fips's does.

Server (`fips-pubdom-server`):

| command | reply |
|---|---|
| `status` | version, npub, fips address, bind, port, zones directory, whether publishing, relays each with when it last accepted and its last error |
| `zones` | per domain: file, port, names, the TXT record line, claim and zone record published at, DNSSEC proof valid until, next publish at, last error; plus the files skipped |
| `txt {domain}` | the TXT record line, as the `txt` subcommand prints it |
| `check-dns {domain}` | the resolver's own TXT verification with the proof's resolvers (`publish.dns`, else the system's and two public validating ones): `verified (Dnssec)` / `verified (Dns)` / `names another key` / `names this server with another port` / `no record` / `resolvers disagree` / `unreachable`, plus the record text to add |
| `publish {domain?}` | publish now, one domain or all; the outcome lands in `status` and `zones` |
| `log {n?}` | the last n lines (default 200) from the process's ring buffer of 500 |

`attestations` waits for phase 5.

Daemon (`fips-pubdomd`):

| command | reply |
|---|---|
| `status` | version, online, upstreams and where they come from, listen addresses, the backend `setup` recorded, pin file, dnssec, plain_probe, witnesses, threshold, relays configured |
| `pins` | the pin file as `fips-pubdom pins list` shows it |
| `forget {domain}` | drop the domain's pins and flush the caches (admin) |
| `flush` | flush caches (admin) |
| `log {n?}` | ring buffer |

`verify` as a socket command waits for the pages that need it (phase
3): the CLI's verify is inline there and becomes a library report
first.

`fips-pubdom ctl [--socket PATH] COMMAND [PARAMS-JSON]` sends one
command and prints the reply — the test tool, and a script's way in.

## What fips-ui shows

Under **Public domains**, present only when something is found:

- **Server** (when the server's socket or `server.yaml` exists). This
  node: npub, address, port, listening. Relays with their last outcome,
  **Publish now**. One card per domain: zone loaded or broken, TXT
  state with **Check DNS**, the record to add with a copy button, claim
  and zone record published at, proof valid until. **Edit** opens the
  zone as a table — label, target (*this node* / an npub, shown with its
  hosts-file name / *legacy*), the wildcard row with operators.md's
  warning — and **Save** goes stdin → `validate zone` → atomic write by
  the helper, after which the server picks the file up and republishes.
  **Add domain** is the same with an empty table. **Publishing**: the
  relay list (validated as `mesh_relays` is), proof switch, resolvers;
  saved to `server.yaml` the same way, with a restart where needed.
  **Attestations**: read-only, on request.
- **Resolver** (when the daemon's socket or `config.yaml` exists).
  Status, the pins table (**Forget** per domain), **Verify** a domain
  with the full input list, the configuration (`witnesses` with hosts
  names, threshold, `mesh_relays`, `dnssec`, `plain_probe`,
  `allow_unverified_offline`) edited through the helper, **Flush
  caches**.
- **Log** tabs on both, from the ring buffers.

Viewers see all of it; admins get the buttons. Over the mesh, that is
fips-ui's existing access list.

## Phases

1. Done (fips-pub-domains #24): **`server.yaml`, the zones directory
   watched, `init`, the `validate` commands** — the unit uses `serve
   --config` when the file exists, the flags stay. A new zone no longer
   needs a restart. One difference from the draft: `server.yaml` is read
   at start, a change to it takes a restart (the helper restarts the
   unit after writing it anyway).
2. Done (fips-pub-domains #25): **the two control sockets**, the
   `pubdom-control` crate (protocol, log ring, client), `fips-pubdom
   ctl`; `RuntimeDirectory` in the units; testing.md level 3f drives
   both. `verify` and `attestations` as socket commands are left for
   the phases that need them.
3. **fips-ui: detection and the read-only pages** (Server, Resolver,
   Log), with mesh viewers.
4. **fips-ui: editing** through the helper (new verbs `pubdom-zone-apply
   <domain>`, `pubdom-zone-delete`, `pubdom-config-apply <server|
   daemon>`, `service` extended to the two units), **Publish now**,
   **Check DNS**, **Forget**, **Flush**.
5. **Attestations** on the Server page.

Phases 1 and 2 are PRs here, each with its review; 3 to 5 are PRs in
fips-ui, where that repository's rules apply. Phases 1 and 2 are useful
without 3: the sockets serve the CLI too.

## Open questions for the maintainer

- Settled: the socket protocol is fips's own line-JSON shape, read
  from `fipsctl` and fips-ui's `control.ts`.
- **Who runs `init`**: the install guide (once, by hand) or the unit at
  start when `server.yaml` is missing and `zones/` is not? Proposed:
  the guide; the unit falls back to the old flags while there is no
  `server.yaml`, so nothing breaks on upgrade.
- **The daemon's configuration on the Resolver page from the start, or
  pins and verify only first?** Proposed: pins and verify in phase 3,
  the configuration editor in phase 4 with the rest of the editing.
- **Names for npubs** in the zone table from `/etc/fips/hosts`:
  fips-ui does this everywhere already, so it is a given there;
  nothing for this repository to decide.
