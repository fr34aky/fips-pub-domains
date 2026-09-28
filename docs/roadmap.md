# Roadmap

## Done — phase 1

- Claims (kind 37197), the `_fips-dns` TXT verifier with DNSSEC, pinning,
  the mesh lookup with `CNAME <npub>.fips`, unverified bindings refused
  (opt-in marker offline).
- `fips-pubdom-server`, `fips-pubdomd` (Linux, systemd-resolved),
  `fips-pubdom`; mesh relays for offline discovery.
- fips2go: resolver in the VPN's DNS proxy, UDP over smoltcp, Settings
  switch (#55; pins bumped in #56–#58); mesh relays reached through a
  loopback proxy over the in-process TCP stack, configured in Settings
  (#59). Device-verified:
  pinned, first-visit discovery, offline, and — offline with no pins — a
  domain verified from its claim's DNSSEC proof via a relay on the mesh.
- Live tests through level 5 ([testing.md](testing.md)).
- Zone records (kind 37199): published by the server with the claim, used
  by the resolver when the server does not answer.
- Redundant servers: every server the TXT record names is pinned; failover
  with a growing backoff.
- DNSSEC proofs in claims: the server attaches the signed TXT record and
  its chain to the root, re-published before the signatures expire; an
  offline client with no pin verifies a domain from the proof alone
  (verified live, [testing.md](testing.md) level 4d). Signature lifetime,
  unsigned zones and the built-in root anchors are the limits (spec §5.5).

## Next

1. **Registration and the NIP** — submitted 2026-09-28:
   [registry-of-kinds #16](https://github.com/nostr-protocol/registry-of-kinds/pull/16)
   and [nips #2487](https://github.com/nostr-protocol/nips/pull/2487)
   (NIP-DB). Until merged, the kind numbers are provisional; if others are
   assigned, `pubdom-core::KIND_*` and the docs follow.
2. **Attestations** (kind 37198) and the trust setting *k*; default
   witnesses = the user's synced trusted nodes, opt-in.
3. **Daemon backends**: dnsmasq / NetworkManager, plain `resolv.conf`,
   then macOS (launchd + `networksetup`) and Windows (service + adapter
   DNS); restricted per-domain mode on all three; OpenWrt and pfSense
   packaging. Network-change watchers instead of the 30 s poll.
4. **Phone gaps**: TCP fallback for step 3 over the smoltcp stack; an
   explicit online flag from the VpnService (would skip the TXT wait
   offline, so a first lookup through a mesh relay fits the 3.5 s budget
   instead of resolving only on the retry); a `dnssec` switch in the app;
   upstream ports kept for the TXT verifier.

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
- When DNS fails while the node believes it is online (every upstream
  timing out, or answers failing DNSSEC validation — a router stripping
  DNSSEC records does that for every zone under a signed TLD, unsigned
  domains included, since the proof of an insecure delegation is stripped
  too), an unpinned domain is
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
