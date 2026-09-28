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

## State (2026-09-28)

Milestones 1–3 of `docs/plan-phase1.md` are coded, not yet demoed end to
end across two nodes:

- Workspace: `names-core` (35 tests), `names-resolve` (14), `names-server`,
  `names-daemon` (`fips-namesd`, Linux/systemd-resolved full mode),
  `names-cli`. `cargo test --workspace` is green. Clippy is not usable on
  this host (no rustup default toolchain).
- Verified live: the `_fips-dns.example.org` TXT record validates under
  DNSSEC through hickory; the server signs a claim with this host's node
  key (`/etc/fips/fips.key`, group `fips`); a single-node offline lookup
  with a pinned binding runs step 3 over the node's fips address and
  synthesizes the AAAA.
- fips2go: branch `names` in `~/fips2go` (commit on top of 0.8.0) adds
  `shim/src/names.rs` + `meshudp.rs`, the proxy hook, three shim knobs and
  the Settings switch; host suite 38 green. The fips-names crates are git
  deps pinned by rev — the repo is private, so fips2go's CI cannot fetch
  them until it has a token or the repo is public. Nothing built for
  Android or run on a device yet (no rustup/Android target on this host).
- Level 1+2 of the test ladder passed 2026-09-28: a real peer (`home`,
  Ubuntu) queried the server over the mesh (UDP, TCP, wildcard,
  `legacy` carve-out with hot reload); the claim is published on the
  user's **mesh-only strfry relay** (`ws://npub1c8n8….fips:80`, see memory);
  from this node `verify` → `Bound(Dnssec)`, `lookup` pins and answers,
  offline `lookup` answers from the pin, offline-unpinned is refused unless
  `allow_unverified_offline` (then answered with the WARN marker), and
  `mail.example.org` / `www.github.com` pass through. Nothing on public
  relays; no kind registration; no NIP submission (user instruction).
- Known gap: mesh relays are desktop-only — on the phone nostr-sdk needs a
  kernel socket to an `fd…` address, which the app's UID cannot open, so
  Android offline = pinned domains only until a websocket-over-smoltcp
  path exists.

## Next steps

1. Two-node demo (plan-phase1 §8 M2): publish the claim for `example.org`
   from this node (`fips-names-server serve --publish`), run `fips-namesd`
   on a second Linux node, `fips-names verify` / `lookup www.example.org`.
2. Phone: build the shim for arm64 on a machine with the Android toolchain,
   verify the Settings switch and a lookup on a device, open the PR from
   branch `names`.
3. Phase 2: DNSSEC proofs in claims; zone records; TCP fallback on the
   phone; network-change watchers; macOS/Windows daemon.
