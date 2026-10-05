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
- Linux `setup` backends beyond systemd-resolved: NetworkManager
  (`dns=none`, the daemon on port 53, NM's server list followed; verified
  live on Ubuntu 22.04, [testing.md](testing.md) level 6), standalone
  dnsmasq (`no-resolv` + `server=`) and plain `resolv.conf` (tests in a
  temporary root only so far); detected, recorded for `teardown`, which
  restores resolv.conf and the config.
- Zone records (kind 37199): published by the server with the claim, used
  by the resolver when the server does not answer.
- Redundant servers: every server the TXT record names is pinned; failover
  with a growing backoff.
- DNSSEC proofs in claims: the server attaches the signed TXT record and
  its chain to the root, re-published before the signatures expire; an
  offline client with no pin verifies a domain from the proof alone
  (verified live, [testing.md](testing.md) level 4d). Signature lifetime,
  unsigned zones and the built-in root anchors are the limits (spec §5.5).

- Attestations (kind 37198) and the trust setting *k*: witnesses listed
  in the config, `fips-pubdom attest` to be one; used offline for a domain
  with no pin and no proof, pinned as `attested`. On the phone: the
  witness list and *k* in fips2go's Settings (#62), the DNSSEC switch
  and "Forget verified domains" (#65). Verified live on the desktop
  ([testing.md](testing.md) level 4e) and on the phone (level 5c): a
  witness's attestation on the mesh relay, an offline client with no pin
  and no usable proof binding the server as `attested`.

## Next

1. **Registration and the NIP** — submitted 2026-09-28:
   [registry-of-kinds #16](https://github.com/nostr-protocol/registry-of-kinds/pull/16)
   and [nips #2487](https://github.com/nostr-protocol/nips/pull/2487)
   (NIP-DB). Until merged, the kind numbers are provisional; if others are
   assigned, `pubdom-core::KIND_*` and the docs follow.
2. Done: **default witnesses on the phone** from the Mesh names (the
   sync upstream and the hosts-file entries), opt-in (fips2go #66) — which
   is what made the policy exclude a domain's own servers as witnesses
   (#17).
3. **Daemon backends**: macOS (launchd + `networksetup`) and Windows
   (service + adapter DNS); restricted per-domain mode; OpenWrt and
   pfSense packaging. Implemented and unit-tested; seen live only on a
   scratch instance ([testing.md](testing.md) level 3d), not under
   resolved or NetworkManager themselves: the upstreams file is followed
   as they rewrite it, the 30 s poll kept as the fallback (the snapshot
   backends are static by nature). Done on Linux: NetworkManager, standalone dnsmasq and plain
   `resolv.conf` beside systemd-resolved, with detection and a recorded
   teardown.
4. **Phone gaps**: TCP fallback for step 3 over the smoltcp stack;
   upstream ports kept for the TXT verifier. Done: the `dnssec` switch
   (fips2go #65); the Internet flag from the VpnService (fips2go #67,
   `MaybeTxt::set_timeout`): without a validated network the TXT wait is
   500 ms, so a first offline lookup fits the budget — verified on the
   phone ([testing.md](testing.md) level 5c).

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
- The daemon forwards to the first upstream and tries the next only on
  a 2 s timeout, as a stub resolver would; a first upstream that is slow
  rather than dead is what a first lookup now costs. Asking the second
  after a short delay would help, but changes which server's answer wins
  on a split-horizon network; open.
- A first visit no longer survives a forged "no record" by way of the
  mesh relays (spec §5.1) unless `plain_probe: false` restores the
  validated denial at its old cost ([daemon.md](daemon.md)). The phone
  has no switch for it; there the probe is already off whenever the
  Internet is not validated.
- The phone has the plain probe (fips2go #70, pinned at 0.2.4), used
  only while Android reports a validated Internet: without one, a router
  with no uplink answering "no record" would end the lookup before the
  mesh-only path. Fetching the legacy answer alongside the decision and
  releasing it on the first denial is merged there (fips2go #72), not
  yet in a release or checked on the phone.
- Clippy is not available on the reference machine (no rustup toolchain);
  CI runs it with `-D warnings`.

## Open questions

- Should the daemon in full mode also answer the Firefox DoH canary, or is
  that the user's call per browser?
- Relay selection for claims: the node's own relay list is used today. A
  curated set of "claim relays" might be worth publishing once there are
  more than a handful of domains.
- Whether a domain's server should be *required* to run a mesh relay
  carrying its own claim, making every bound domain discoverable offline by
  anyone who knows the server.
