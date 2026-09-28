# Roadmap

## Done — phase 1

- Claims (kind 37197), the `_fips-dns` TXT verifier with DNSSEC, pinning,
  the mesh lookup with `CNAME <npub>.fips`, unverified bindings refused
  (opt-in marker offline).
- `fips-pubdom-server`, `fips-pubdomd` (Linux, systemd-resolved),
  `fips-pubdom`; mesh relays for offline discovery on desktops.
- fips2go: resolver in the VPN's DNS proxy, UDP over smoltcp, Settings
  switch (PR open; device-verified: pinned, first-visit discovery, offline).
- Live tests through level 5 ([testing.md](testing.md)).
- Zone records (kind 37199): published by the server with the claim, used
  by the resolver when the server does not answer.

## Next

1. **fips2go PR review and merge** (#55). Every path is device-verified;
   what the phone lacks is discovery through relays inside the mesh (item
   6).
2. **Registration and the NIP** — submitted 2026-09-28:
   [registry-of-kinds #16](https://github.com/nostr-protocol/registry-of-kinds/pull/16)
   and [nips #2487](https://github.com/nostr-protocol/nips/pull/2487)
   (NIP-DB). Until merged, the kind numbers are provisional; if others are
   assigned, `pubdom-core::KIND_*` and the docs follow.
3. **DNSSEC proofs in claims** (spec §3.1 `dnssec` tag, §5.5): the RFC 9102
   chain for the TXT RRset, verified locally against the root trust anchor
   — the only trustless verification of a domain never seen online. Moved
   ahead of attestations because the mesh-only case depends on it. Design
   points settled in advance: the chain is only valid for its RRSIGs'
   lifetime (typically 2–4 weeks) and goes stale at every key rollover, so
   the server must re-publish the claim with a fresh chain well inside that
   window (the 24 h re-publish loop is the place); verifiers must refuse
   expired signatures, which means a node off the relays longer than one
   signature lifetime can no longer verify a *new* domain offline (pinned
   ones keep working); and the root trust anchor rollover (KSK-2024) needs
   current software — RFC 5011 automatic updates are not implemented, and
   `dnssec: false` is the emergency switch back to multi-resolver DNS.
4. **Attestations** (kind 37198) and the trust setting *k*; default
   witnesses = the user's synced trusted nodes, opt-in.
5. **Daemon backends**: dnsmasq / NetworkManager, plain `resolv.conf`,
   then macOS (launchd + `networksetup`) and Windows (service + adapter
   DNS); restricted per-domain mode on all three; OpenWrt and pfSense
   packaging. Network-change watchers instead of the 30 s poll.
6. **Phone gaps**: TCP fallback for step 3 over the smoltcp stack; a way to
   reach mesh relays from the app (a websocket client over smoltcp, or a
   local proxy in the shim) so offline discovery works there too; an
   explicit online flag from the VpnService.

## Known gaps and interactions

- Browsers with their own encrypted DNS (Firefox TRR, Chrome "secure DNS
  with a provider") bypass the system resolver. Answering the canary
  `use-application-dns.net` with NXDOMAIN disables Firefox's automatic DoH;
  enterprise policies can still override. Not implemented yet.
- The reachability check is an ICMPv6 echo (1.5 s budget) because fips
  drops traffic for unknown nodes silently. fips's own `probe` control
  command gives a definitive verdict (`bloom_miss` in ~60 ms) and would be
  the better source on the desktop, but it is a mutating command on the
  control socket and not reachable from fips2go's shim; worth wiring in
  where available.
- Once an `fd…` address has been handed to an application, DNS is out of
  the path: a later connection failure is only re-decided at the next
  lookup (30 s TTL).
- On systemd-resolved, a link search domain equal to a bound domain shadows
  the daemon ([daemon.md](daemon.md), Troubleshooting).
- Mesh relays are desktop-only; on Android offline means pinned domains.
- When DNS fails while the node believes it is online (every upstream
  timing out, or answers failing DNSSEC validation — a router stripping
  DNSSEC records does that for every signed zone), an unpinned domain is
  looked up on the mesh relays and the decision is cached for an hour.
  A shorter retry would recover sooner from a hiccup but ask the relays
  more often; the balance is open.
- Online verification is unaffected by DNSSEC key rollovers done properly
  (every lookup validates the live chain; the pin stores no key). A broken
  rollover makes validation *bogus*, which counts as an unreachable
  upstream — pins keep working, nothing is downgraded to unsigned `dns`,
  nothing is unpinned.
- Two independent upstream resolvers are not always available (one
  DHCP-provided resolver is common on phones); the verification is then
  `dns-single`, and a later two-resolver or DNSSEC verification upgrades the
  pin.
- Clippy has not been run on the reference machine (no rustup toolchain);
  CI should add it.

## Open questions

- Should the daemon in full mode also answer the Firefox DoH canary, or is
  that the user's call per browser?
- Relay selection for claims: the node's own relay list is used today. A
  curated set of "claim relays" might be worth publishing once there are
  more than a handful of domains.
- Whether a domain's server should be *required* to run a mesh relay
  carrying its own claim, making every bound domain discoverable offline by
  anyone who knows the server.
