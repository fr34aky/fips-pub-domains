# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

A design (no code yet) for resolving public domain names such as
`www.example.org` to [fips](https://github.com/jmcorgan/fips) mesh nodes, with
or without Internet access. The spec is `docs/domain-binding.md` — read it
first; this file records how it came about and the decisions behind it.

It is deliberately **independent** of fips2go (`~/fips2go`, the Android
client), fips-ui (`~/fips-ui`) and fips itself (`~/fips`, fork
`fr34aky/fips` branch `android-hooks`), so any fips client can use it. Do not
move it into one of those repos.

## Working rules

- Private repo `fr34aky/fips-names`. Commit and push only as
  `fr34aky <162515565+fr34aky@users.noreply.github.com>`.
- **No Claude attribution anywhere**: no `Co-Authored-By: Claude`, no
  `Claude-Session:` trailer, no claude.ai links, no "Generated with Claude
  Code" in commits or PR bodies.
- Commit messages explain *why*, as in the sibling fips2go repo.

## How the design evolved (2026-09-27/28)

1. Started from fips2go's mesh names (a flat `name npub` hosts file, synced
   from fips-ui nodes since fips2go 0.8.0). fips only allows single-label
   `.fips` names (`validate_hostname` in fips `src/upper/hosts.rs`; the
   resolver takes everything before `.fips` as one label).
2. Subdomains: proposed *delegation under a trusted anchor* (`www.home.fips`:
   `home` trusted locally or an npub label; `home` publishes a signed Nostr
   record for names under itself). Trusted (local) always beats learned; no
   squatting possible because a publisher can only define names under itself.
3. `.com`/other TLDs via legacy DNS binding (`_fips` TXT, DNSSEC, pinning) —
   the user **rejected making legacy DNS a dependency**: only decentralized
   infrastructure (Nostr, fips) for operation.
4. Alternative separators (`www,home,shop`) — rejected: dots are only
   presentation in DNS; routing happens by suffix (`.fips` / reserved `.alt`,
   RFC 9476), and non-LDH characters break apps.
5. The user's flow, adopted as the spec: (1) Nostr claim for the domain →
   server npub, (2) legacy DNS SRV only as an *optional* verifier (later TXT, see spec §4), (3) ask
   that server over the mesh for individual names. Refinements agreed:
   - HTTPS is not required (fips is end-to-end encrypted and authenticates
     the npub) — so binding verification is what security rests on; HSTS and
     secure-context caveats remain.
   - Step 3 over **UDP**, TCP only on truncation.
   - Browsers are never changed; the **machine's resolver** is (fips2go shim
     on the phone, a forwarding resolver on desktops). Bound names: synthesize
     the `fd…` AAAA and suppress A/public AAAA (RFC 6724 ranks `fd00::/8`
     last). DoH-in-browser is a known hole.
   - Unverified claims are **refused**, not silently used; offline trust comes
     from pinning, attestations by trusted witnesses, or DNSSEC proofs carried
     in the Nostr event.
   - Privacy: don't query relays for every visited domain.

## Facts from the fips codebase the design relies on

- fips's Nostr key is the node identity key (`src/nostr/runtime.rs` builds
  `nostr::Keys` from the node keypair) — events authored by `npubX` are
  authentic for mesh node `npubX`.
- Kinds in use by fips: `37195` overlay advert (`d=fips-overlay-v1`), `21059`
  signal (`src/nostr/types.rs`) — neither registered. This spec uses
  37197–37199; checked free on 2026-09-28 in the NIPs README and
  `nostr-protocol/registry-of-kinds`. No NIP covers domain → pubkey
  bindings; `docs/nip-draft.md` is ours.
- fips fetches per-author addressable events with
  `Filter::new().author(pk).kind(..).identifier(..)` and a 2 s timeout.
- A node can only route to an `fd…` address whose npub it knows; resolving
  `npub….fips` through fips's DNS responder registers the identity. Hence
  step 3 answers with `CNAME npub….fips.`
- fips's mesh effective IPv6 MTU is ~1200 bytes.
- In fips2go the integration point is the non-`.fips` branch of
  `DnsProxy::serve` in `shim/src/dns.rs` (forwards to upstreams today).
- fips's own DNS responder (`src/upper/dns.rs`) binds `[::1]:5354`, answers
  only `.fips`, and drops queries arriving on the mesh interface — so the
  step 3 server is a separate program (spec §6.1), default port 5355.
- The fips2go shim cannot open kernel sockets to `fd…` addresses; mesh
  traffic goes through its in-process smoltcp stack (`shim/src/meshhttp.rs`,
  TCP only today). Step 3 on the phone needs a UDP flavour of that.
- fips's Nostr runtime has no generic "fetch events by filter" API; the
  resolver brings its own relay client (nostr-sdk) using the node's relay
  list.

## Next steps

Phase 1 is planned in `docs/plan-phase1.md` (2026-09-28): a Rust workspace
in this repo — `names-core` (policy, no I/O), `names-resolve` (relay/TXT/mesh
adapters behind a `MeshDns` trait), `names-server` (step 3 server + claim
publisher), `names-daemon` (`fips-namesd`), `names-cli`. Milestones:
core+tests → server + Linux daemon over the mesh → fips2go integration →
kind registration → macOS/Windows → full-resolver mode and routers.
Nothing is coded yet.

Platform rule (`docs/plan-platforms.md`): the resolver is a **separate
daemon** on every desktop/server OS and **embedded in fips2go** on Android;
no `cfg(target_os)` in `names-core`/`names-resolve`. Default on every
platform: the resolver is in the path for **all names** and discovers
domains by asking public DNS for the `_fips-dns` TXT first (user decision
2026-09-28); relays are only asked after a TXT hit. With no upstream
reachable, the claim is fetched from relays directly (mesh relays on fips
nodes first) — the claim replaces the TXT record (spec §5.5). Opt-in
restricted mode routes only known domains via per-domain OS routing and
gives up discovery.
