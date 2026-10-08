# Architecture

How the code is cut, what flows where, and why. The protocol itself is in
[spec.md](spec.md); this is about the implementation.

## Crates

```
crates/
  pubdom-core/      policy, no I/O
  pubdom-resolve/   client I/O adapters + the resolver
  pubdom-server/    fips-pubdom-server  (the domain's mesh DNS server, claim publisher)
  pubdom-daemon/    fips-pubdomd        (desktop forwarding resolver)
  pubdom-cli/       fips-pubdom         (operator tool)
```

The split follows one rule: **everything that can be wrong about the
design is testable without a network.** `pubdom-core` is where the
decisions live; the other crates move bytes.

### pubdom-core

| module | what |
|---|---|
| `identity` | `Npub`: x-only key ↔ bech32 ↔ hex; the `fd…` address (`fd` + SHA-256(key)[0..15], the same arithmetic as fips's `FipsAddress`, without linking fips); the `<npub>.fips` name |
| `domain` | hostname syntax, Public Suffix List (`psl`), the candidate walk `www.a.example.org → [example.org, a.example.org, www.a.example.org]`, zone label rules |
| `txt` | the `v=fips1 npub=… port=…` verifier record |
| `claim` | kind 37197 claims and kind 37199 zone records from a transport-neutral `Event`, with the size limits |
| `pins` | `Binding`, `Method` (ordered by strength), the `PinStore` trait, the anti-rollback table, the JSON snapshot every platform shares |
| `policy` | `decide()`: spec §5.1 precedence, §5.3 conflicts, §5.4 pin changes, §5.5 offline, §5.1 step 4 attestations by *k* trusted witnesses; `ingest_claims()` / `ingest_attestations()`: future-dated and rolled-back events, untrusted witnesses |
| `synth` | DNS wire format via `simple-dns` (what fips uses): the application query, the step 3 exchange, the server's reply, the synthesized answer |
| `cache` | TTL tables for spec §5.6 |

`policy::decide` takes what the resolver gathered — pin, TXT lookup result,
claims — and returns a `Decision` plus a `PinUpdate`. Every negative outcome
is `NotOverFips(reason)`; the reason is logged, never shown to the
application (spec §7: a name is never made unreachable by this code).

### pubdom-resolve

| module | what |
|---|---|
| `txt` | `TxtVerifier`: one hickory resolver **per upstream**, asked in parallel, so agreement can be counted: DNSSEC-validated (`Proof::Secure`) → `Dnssec`; two agreeing → `Dns`; one → `DnsSingle`; all failed → `Unreachable` (the offline path). When they disagree and anything validated, only validated answers count (a validated denial included), otherwise records outrank denials; the majority wins, a tie is `Disputed` (pins resolve, nothing else; re-asked after 60 s); bogus answers count as failed |
| `relay` | `RelayClient`: nostr-sdk with two relay sets, public and mesh; online both are asked at once (after a TXT hit), offline the mesh set first; `publish_claim` for the server |
| `mesh` | the `MeshDns` trait — step 3 over UDP, TCP on truncation, identity registration through fips's responder — and `KernelMeshDns` for hosts with a TUN |
| `pins` | `FilePinStore`: the JSON pin file, written atomically |
| `proof` | DNSSEC proofs in claims: `build_chain` (the server collects the TXT RRset and the DNSKEY/DS chain to the root with the DO bit), `verify_chain` (RFC 4035 validation offline against hickory's built-in root anchors), `DnssecProofs`, the resolver's `ProofVerifier` |
| `config` | the YAML config shared by daemon and CLI; `build_resolver()` |
| `resolver` | `Resolver::lookup(query) → Answer | Passthrough | Unavailable { retry_in }` |

The resolver is generic over the TXT and claim sources (`TxtSource`,
`ClaimSource`) so its tests inject tables instead of networks, and takes the
mesh transport as `Arc<dyn MeshDns>` so the phone can plug in a userspace
stack. The trait is **blocking** on purpose: the phone's only way onto the
mesh is a smoltcp stack driven from the calling thread; the daemon calls it
through `spawn_blocking`.

### The lookup, end to end

```
lookup(query)
  parse question ─ not a hostname / public suffix / unknown TLD ─► Passthrough
  candidates, decided concurrently, the longest bound one wins
    (offline: pinned candidate first, no relay round trip)
  ┌ decision(domain)   [cached per domain, TTL per outcome]
  │   pin ← pin store
  │   online:  unpinned (unless `plain_probe: false` with `dnssec`):
  │              plain probe ← every upstream in parallel;
  │              "no record" from all that answer → Miss, nothing validated
  │            TXT (validated) ← every upstream in parallel
  │            Hit  → claims ← public + mesh relays   (the privacy gate: relays only after a hit)
  │            Miss → no claims; the pin, if any, is forgotten
  │   offline: pinned → no relays; else claims ← mesh relays, then public
  │   policy::decide → Bound / Unverified(opt-in) / NotOverFips
  │   apply PinUpdate
  └
  step3(name, binding)  [cached per name]
      register binding.npub with fips's responder
      UDP query to [fd…]:port over the mesh, one retry; TCP on TC
      CNAME <npub>.fips  → register that npub; if it is not the server just
                           answered, an ICMPv6 echo must come back within
                           1.5 s (spec §7) — fips drops traffic for unknown
                           nodes silently, so nothing else distinguishes them
      NXDOMAIN           → NotOverFips → Passthrough (settled; the zone record saying so too)
      no server answers, no zone record, or the target answers no echo
                         → Unavailable { retry_in }: the host gives the legacy
                           answer with TTLs capped at retry_in (≥ 5 s)
  answer: CNAME + AAAA fd… for AAAA/ANY; CNAME only for A; NODATA for HTTPS/SVCB
```

Budgets (plan values, enforced by per-step timeouts and a whole-lookup
budget in the daemon and the phone): TXT 1.5 s (500 ms on a phone without
a validated Internet network, plus 200 ms of slack either way), relays 2 s, step 3 1 s +
retry, TCP 3 s; a cold online lookup stays under 4.5 s, a pinned mesh
lookup around 1 s, a cached one milliseconds. The relay fetch asks every
relay on its own subscription and, after a TXT hit, returns 750 ms after
the first one that delivered a claim, so one quiet relay no longer costs
the whole 2 s; offline, where the claims alone decide and a conflict is
only visible with every relay heard, it still waits for all of them. A
lookup that overruns the whole-lookup budget (3.5 s on the phone, the
daemon's `budget`) finishes in the background and caches its decision; the
legacy answer forwarded meanwhile has its TTLs capped at
`OVERRUN_TTL_SECS` (5 s), so the stub resolver asks again about when the
decision is in, instead of keeping the upstream's address for its TTL.

An ordinary name — no pin, no record — costs one plain TXT query per
candidate domain and upstream, all at once, and the daemon does not hold
its answer back for the slowest of them: the lookup is polled once (a
cached decision, a name that is no hostname or a record type never over
fips settle there, with nothing else started), then the legacy answer is
fetched alongside it (not for a name under a pinned domain, which the
upstream need not hear of), and `Resolver::denied_by_an_upstream`
releases it once one upstream has denied the record for every candidate.
If the decision is not in by then the answer goes out with the overrun
TTL; the lookup carries on and caches what all upstreams said.

### pubdom-server

`serve --config /etc/fips-pubdom/server.yaml` (`ServerConfig`) or the
older flags; with the file, the zones directory is followed
(`pubdom_resolve::watch::watch_dir`, plus a 30 s rescan) so zones come
and go with their files — `Zones::rescan` loads new files, drops gone
ones, skips a broken or duplicate one with a log line, and the per-query
mtime check reloads edits as before. `validate zone|config` reads stdin
and runs the same parsers the server loads with, for tooling that writes
those files; `init` writes a `server.yaml` from a flag-era install. The
watcher lives in `pubdom-resolve` behind the `watch` feature, which the
daemon and the server enable and the phone does not.

A UDP+TCP DNS server bound to the node's own fips address (default port
5355; 53 needs privileges and the port travels in the claim anyway),
answering from YAML zone files that are re-read on mtime like fips's hosts
file. It is deliberately **not** fips's `.fips` responder: that binds
loopback, knows only `.fips`, and drops queries arriving on the mesh
interface to protect the hosts file from enumeration — mesh exposure is the
point here, so the fips firewall needs the drop-in in `packaging/common/`.
The same binary signs and publishes the claim with the node's key file
(`/etc/fips/fips.key`, hex — `nostr::Keys::parse` accepts it) and can
re-publish every 24 h while serving.

### pubdom-daemon

A forwarding resolver on loopback (`[::1]:5356`, `127.0.0.1:5356`) in front
of **all** names: everything goes through `Resolver::lookup`; `Passthrough`
is forwarded byte for byte to the upstreams (UDP, TCP on truncation),
`Unavailable` the same with the reply's TTLs capped at its `retry_in`;
`.fips` goes to fips's responder, because in full mode the daemon is the
only server the OS knows. `setup` writes the OS integration
([daemon.md](daemon.md)); the upstreams are followed through
`/run/systemd/resolve/resolv.conf`, which keeps listing the real servers
after the stub points at us — watched for changes, polled every 30 s as
the fallback, and re-read on the spot by a query that finds no upstreams
(the daemon routinely starts before the network has any).

`backend.rs` is `setup`/`teardown`: detection of the resolver arrangement
(resolved, NetworkManager, standalone dnsmasq, plain `resolv.conf`), one
backend each, every path relative to a root and every command through a
runner so the tests run them in a temporary directory; the chosen backend
is recorded in `/etc/fips-pubdom/backend` for `teardown`
([daemon.md](daemon.md)).

## Decisions worth knowing

- **The npub travels in the answer, not just an address.** A fips node can
  only route to an `fd…` address whose identity it knows; resolving
  `<npub>.fips` through fips's responder is what registers it. Hence step 3
  answers `CNAME <npub>.fips.` and the client re-asks the responder.
- **Suppress the public addresses.** RFC 6724 (bionic, glibc, Chromium)
  ranks `fd00::/8` below IPv4 and global IPv6; returning both would almost
  never use the mesh. A bound name gets the CNAME + `fd…` AAAA, NODATA for
  A, NODATA for HTTPS/SVCB (their hints could steer to the legacy path).
  Every other type (MX, TXT, SRV, …) stays legacy DNS.
- **UDP first.** fips authenticates the source address, so the spoofing
  problem that motivates TCP on the Internet does not exist; UDP saves a
  round trip. TCP remains for truncation (RFC 7766).
- **TXT, not SRV.** SRV targets are hostnames that DNS hosters validate;
  `npub….fips.` is rejected by common control panels. TXT under an
  underscore label is what ACME DNS-01 and DKIM use for the same reason.
- **Mesh relays by `.fips` hostname.** nostr-sdk cannot dial a bracketed
  IPv6 literal, and resolving the name is what registers the relay's
  identity with the node anyway.
- **Refusal applies to the binding, never the name.** Unverified, mismatched
  or absent bindings, NXDOMAIN from the server, unreachable nodes, timeouts —
  all become the legacy answer. Only offline, with no upstream to forward
  to, does the application see the failure any offline machine sees.
