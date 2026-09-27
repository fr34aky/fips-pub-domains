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
   server npub, (2) legacy DNS SRV only as an *optional* verifier, (3) ask
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
  signal (`src/nostr/types.rs`). This spec uses 37197–37199 as placeholders.
- fips fetches per-author addressable events with
  `Filter::new().author(pk).kind(..).identifier(..)` and a 2 s timeout.
- A node can only route to an `fd…` address whose npub it knows; resolving
  `npub….fips` through fips's DNS responder registers the identity. Hence
  step 3 answers with `CNAME npub….fips.`
- fips's mesh effective IPv6 MTU is ~1200 bytes.
- In fips2go the integration point is the non-`.fips` branch of
  `DnsProxy::serve` in `shim/src/dns.rs` (forwards to upstreams today).

## Next steps (not started)

Phase 1 MVP per spec §9: claim + SRV verification + pinning + step 3 over UDP
with CNAME, unverified refused, phone integration in the fips2go shim. Open
questions are listed in spec §10 (kind numbers, where the desktop resolver
lives, default witnesses, relay selection).
