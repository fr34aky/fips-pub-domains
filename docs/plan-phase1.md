# Phase 1 plan: MVP of domain binding over fips

Status: **plan**, nothing implemented. Spec: [domain-binding.md](domain-binding.md)
§9 phase 1 — claim + SRV verification + pinning + step 3 over UDP with
CNAME, unverified refused, phone integration in the fips2go shim.

## 1. What the MVP must demonstrate

On a phone running fips2go, with the fips2go Wi-Fi off and only the mesh
reachable, a browser opens `http://www.example.org/` and lands on the fips
node `npub1234` — provided the phone verified the binding once while it had
Internet (pinning). With Internet, the first visit verifies and pins the
binding on the fly. A domain with no claim behaves exactly as today.

Everything else in the spec (attestations, zone records, DNSSEC proofs,
desktop resolver) is later phases; the MVP must not make them harder.

## 2. Constraints found in the sibling codebases

These decide where code can and cannot go. Verified 2026-09-28.

| Fact | Where | Consequence |
|---|---|---|
| fips's DNS responder binds `[::1]:5354`, answers only `.fips`, and **drops queries that arrive on the mesh interface** (`is_mesh_interface_query`, to stop hosts-file enumeration). | `~/fips/src/upper/dns.rs`, `src/upper/config.rs` | Step 3 needs its **own** listener on the node's fips address. It is a separate program/task, not a mode of fips's responder, and its mesh exposure is the point, so it must not inherit the mesh filter. |
| The fips2go shim cannot open a kernel socket to an `fd…` address (its UID is outside the tunnel). `meshhttp.rs` runs an in-process **smoltcp** stack whose packets go through the node's `TunPacketProcessor`; replies come back via `Divert`. Only TCP sockets are set up today. | `~/fips2go/shim/src/meshhttp.rs` (`MeshLink`) | Step 3 from the phone = a **UDP** flavour of `MeshLink` (smoltcp `udp` socket, `proto-ipv6` + `socket-udp` features). TCP fallback reuses the existing TCP path. |
| The shim's DNS proxy is synchronous per query: `DnsProxy::serve` runs on a short-lived thread, `.fips` names go to the responder, everything else to upstreams with a read timeout. | `~/fips2go/shim/src/dns.rs` | The binding lookup is a blocking call with a budget (§6) inserted before the upstream forward. No async runtime plumbing inside the proxy. |
| Registering an identity so the node can route to `fd…` = asking the in-process responder for `<npub>.fips` (`MeshLink::responder`). | `meshhttp.rs`, `dns.rs` `npub_query` | After a `CNAME npub….fips.` answer the shim re-asks the responder for that name, exactly like a hosts-file name today. No new node API. |
| fips's Nostr runtime has no generic "fetch events by filter" entry point; its `fetch_events_from` calls are internal to advert/signal handling. Relay lists live in node config (`advert_relays`, `dm_relays`, defaults `relay.damus.io` etc.). fips2go passes `nostr_relays` in its config JSON. | `~/fips/src/nostr/runtime.rs`, `src/config/node.rs`, `~/fips2go/shim/src/engine.rs` | The resolver has its **own** small relay client (nostr-sdk, already a transitive dependency), fed the same relay list as the node. Sharing fips's pool is a later optimisation behind a hook, not an MVP dependency. |
| The Nostr key is the node identity key. | `runtime.rs` builds `nostr::Keys` from the node keypair | The server-side claim publisher signs with the node's key file; no second identity. |

## 3. Components

All Rust, one workspace in this repo. Split so that the parts with I/O are
thin and swappable (phone vs. desktop), and the policy is testable without
network.

```
fips-names/
  crates/
    names-core/       policy, no I/O          — events, verification, pins, precedence, DNS synthesis
    names-resolve/    client I/O adapters     — relay fetch, legacy SRV lookup, step-3 query (via trait)
    names-server/     step-3 authoritative server + claim publisher (binary `fips-names-server`)
    names-cli/        `fips-names` tool: claim publish, verify, pin inspect (binary)
```

### 3.1 `names-core` (no I/O)

- `Claim`: parse/validate kind 37197 events (author, `d` lowercase, port,
  size and tag limits, public-suffix check with a bundled PSL snapshot).
- `Binding { domain, npub, port, verified_at, method }` and the `PinStore`
  trait (get/put/list, plus the "highest `created_at` seen" anti-rollback
  table). One file-backed implementation (JSON, atomic rename) — good enough
  for the phone's app-private dir and `~/.config/fips-names/` on desktop.
- `Policy`: given (local hosts hit?, pins, claims, SRV result) → `Decision`:
  `Local(npub) | Bound(binding) | Refuse(reason) | Passthrough`. This is §5.1
  minus the attestation/DNSSEC steps, which are stubs that always fail in
  phase 1 so the enum and precedence are already right.
- `domain_of(name)`: right-to-left walk with PSL (§5.2).
- `synth`: build the application-facing answer from a step-3 reply:
  `CNAME npub.fips` + AAAA `fd…`; A → NODATA; drop public AAAA; 30 s TTL (§7).
  Uses `simple-dns` (what fips uses) so the shim does not add a second DNS
  library.
- `cache`: TTL table for the five items in §5.5.

### 3.2 `names-resolve` (client I/O)

- `RelayClient`: fetch `{"kinds":[37197],"#d":[domain]}` from a relay list,
  2 s timeout (fips's own figure), returns raw events → `names-core`.
- `SrvVerifier`: `_fips-dns._udp.<domain> SRV` via `hickory-resolver` against
  the system's or a configured upstream set; phase 1 = unsigned DNS, at least
  **two** resolvers agreeing when more than one is configured (§4). DNSSEC
  validation is behind a feature flag, off, so the API already carries
  `method`.
- `MeshDns` trait: `fn query(&self, to: SocketAddrV6, msg: &[u8], budget) ->
  Result<Vec<u8>>` (UDP first, TCP on TC). Two impls:
  - `KernelUdp` for desktop and tests (plain `UdpSocket`).
  - the phone impl lives in fips2go (`MeshLink` UDP), *not* here — the trait
    is the seam.
- `Resolver::lookup(name, qtype) -> Outcome` orchestrating: local → pins →
  (online? SRV first, then relays only on a hint or when offline — the §8
  privacy rule) → verify → pin → step 3 → synthesise.

### 3.3 `names-server` (server side, new in this plan)

The spec assumed "the domain's fips DNS server" without saying what runs it.
It is this binary, run on the node that serves the domain:

- Listens for DNS on **the node's own fips address** (from
  `npub → fd…`), UDP and TCP, default port **5355** — 53 needs root or
  `CAP_NET_BIND_SERVICE`, and the port travels in the claim and the SRV
  anyway. `port` is a claim tag precisely so the default can change.
- Zone: a small file `example.org.zone`-like YAML:
  ```yaml
  domain: example.org
  names:
    www: npub1234…
    git: npub5678…
    "*": self
  ```
  Answers `CNAME <npub>.fips.` for known names, NXDOMAIN otherwise, `self`
  → the server's own npub. Hot-reloaded on mtime like fips's hosts file.
- `fips-names-server publish` signs and publishes the kind 37197 claim for
  each configured domain with the node key (`--key-file`, same format as
  fips), to the configured relays, and re-publishes on start and every 24 h
  (addressable events are replaced, so this is idempotent).
- Prints the SRV record the operator must add to legacy DNS:
  `_fips-dns._udp.example.org. 3600 IN SRV 0 0 5355 npub1xyz….fips.`

The zone record event (kind 37199, phase 2) will be produced from the same
YAML, so the format is chosen with that in mind.

### 3.4 `names-cli`

Operator and debugging tool: `claim show <domain>`, `verify <domain>`
(runs SRV verification and prints the decision), `pins list|forget`,
`lookup <name>` (full resolver path against a kernel UDP mesh socket — the
desktop path in miniature, and the thing integration tests drive).

## 4. Phone integration (fips2go)

In `shim/src/dns.rs`, the non-`.fips` branch of `serve` becomes:

```
if let Some(answer) = names.lookup(qname, qtype, budget) { return answer }
forward to upstreams as today
```

where `names` is a `names_resolve::Resolver` held by the engine, with:

- `PinStore` file in the app's private directory (path passed in the config
  JSON like the hosts path).
- `MeshDns` implemented over `MeshLink` with a smoltcp UDP socket (new
  `meshudp.rs` next to `meshhttp.rs`; the divert/flow-key logic is shared).
- Relay list = the engine's `nostr_relays`.
- `budget`: the whole lookup, including a relay round trip and step 3, must
  finish inside the proxy's existing per-query timeout minus a margin; on
  budget exhaustion the proxy falls through to the upstream — a public domain
  must never become unreachable because of us (§7).
- Online/offline: the engine already knows whether the public network is
  up (`network_changed`/`network_hint`); the resolver takes it as a flag.

Outside the shim: a setting "Public domains over fips: on/off" and a log line
per decision (`bound`, `refused: unverified claim`, `passthrough`). No UI
beyond that in phase 1.

## 5. Legacy DNS side for the demo domain

For `example.org`: add the SRV above at the registrar. No DNSSEC required for
phase 1 (multi-resolver check instead); enabling DNSSEC on the zone is the
phase 3 enabler and costs nothing now.

## 6. Timeouts and budgets

| Step | Budget | Note |
|---|---|---|
| Local hosts + pins + cache | ~0 | in-memory |
| Legacy SRV (online only) | 1.5 s | parallel over the resolver set |
| Relay fetch | 2 s | fips's figure; only on SRV hint / offline |
| Step 3 UDP | 1 s, one retry | mesh RTT is typically < 300 ms |
| Step 3 TCP fallback | 3 s | only on TC |
| Whole lookup, cold, online | ≤ 4.5 s | must stay under the proxy timeout; upstream fallback afterwards |
| Whole lookup, pinned, mesh | ≤ 1.2 s | the common case |

## 7. Tests

- `names-core`: table tests for precedence (§5.1), conflict rules (§5.3),
  pin-change rules (§5.4), PSL edge cases, anti-rollback, answer synthesis
  (A → NODATA, AAAA suppression, TTL cap).
- `names-resolve`: fake relay (loopback websocket, as fips2go's engine test
  does), fake SRV upstream (`hickory` in-process authority), fake step-3
  server on loopback → end-to-end `lookup("www.example.org")` produces
  `CNAME npub1234.fips.` + synthesized AAAA, and `lookup("example.org")`
  is `Passthrough` with the negative cache set.
- `names-server`: zone parse/reload, UDP and TCP answers, TC on oversize.
- fips2go: one proxy test with a fake `MeshDns` and a pre-pinned binding —
  no relay, no network — asserting the wrapped IPv6/UDP reply carries the
  synthesized AAAA and that the responder was asked for `npub1234.fips`.

## 8. Milestones

1. **Workspace + `names-core`** with tests. No network. (Policy is the part
   most likely to be wrong; get it reviewed first.)
2. **`names-server`** + `names-cli lookup` on a desktop mesh node: two Linux
   nodes, claim on a test relay, SRV in `example.org`, `lookup www.example.org`
   over the mesh.
3. **fips2go**: `MeshLink` UDP, resolver in the proxy, pin store, setting.
   Demo of §1.
4. Write-up of what changed versus the spec; open the kind-number
   registration.

## 9. Decisions on spec §10 (proposed)

- **Kind numbers:** keep 37197–37199 during phase 1; register in the NIP
  process once the wire format has survived milestone 3.
- **Desktop resolver:** standalone (`names-cli lookup` grows into a
  `fips-namesd` forwarding resolver in phase 4). Not inside fips — keeps
  this repo independent of the fips fork and avoids the mesh-filter tangle.
- **Default witnesses (phase 2):** the user's synced trusted nodes, opt-in.
- **Relays:** the node's own relay list; no dedicated set.

## 10. Risks

- smoltcp UDP through `MeshLink` is the least-known piece; do it early in
  milestone 3 and fall back to TCP-only step 3 on the phone if UDP costs more
  than a week.
- Two independent upstream resolvers are not always available on a phone
  (one DHCP-provided resolver is common). Phase 1 then verifies with one
  and records `method: dns-single`; the pin-upgrade rule (§5.4) means a
  later two-resolver or DNSSEC verification strengthens it.
- Browser DoH bypass (§7) makes the demo silently fail in Chrome with
  "secure DNS" on; the demo notes say to use the system resolver.
