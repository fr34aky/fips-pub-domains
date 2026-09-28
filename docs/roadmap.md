# Roadmap

## Done — phase 1

- Claims (kind 37197), the `_fips-dns` TXT verifier with DNSSEC, pinning,
  the mesh lookup with `CNAME <npub>.fips`, unverified bindings refused
  (opt-in marker offline).
- `fips-pubdom-server`, `fips-pubdomd` (Linux, systemd-resolved),
  `fips-pubdom`; mesh relays for offline discovery on desktops.
- fips2go: resolver in the VPN's DNS proxy, UDP over smoltcp, Settings
  switch (branch `names`, not yet device-verified).
- Live tests through level 4 ([testing.md](testing.md)).

## Next

1. **Phone on a device** (test level 5); fips2go PR once its CI can fetch
   this repository.
2. **Registration and the NIP.** Kinds 37197–37199 into
   `nostr-protocol/registry-of-kinds`, then [nip.md](nip.md) to
   `nostr-protocol/nips` with the two implementations as reference. Not
   started, by decision.
3. **DNSSEC proofs in claims** (spec §3.1 `dnssec` tag, §5.5): the RFC 9102
   chain for the TXT RRset, verified locally against the root trust anchor
   — the only trustless verification of a domain never seen online. Moved
   ahead of attestations because the mesh-only case depends on it.
4. **Zone records** (kind 37199) so a client can resolve while the domain's
   server is unreachable.
5. **Attestations** (kind 37198) and the trust setting *k*; default
   witnesses = the user's synced trusted nodes, opt-in.
6. **Daemon backends**: dnsmasq / NetworkManager, plain `resolv.conf`,
   then macOS (launchd + `networksetup`) and Windows (service + adapter
   DNS); restricted per-domain mode on all three; OpenWrt and pfSense
   packaging. Network-change watchers instead of the 30 s poll.
7. **Phone gaps**: TCP fallback for step 3 over the smoltcp stack; a way to
   reach mesh relays from the app (a websocket client over smoltcp, or a
   local proxy in the shim) so offline discovery works there too; an
   explicit online flag from the VpnService.

## Known gaps and interactions

- Browsers with their own encrypted DNS (Firefox TRR, Chrome "secure DNS
  with a provider") bypass the system resolver. Answering the canary
  `use-application-dns.net` with NXDOMAIN disables Firefox's automatic DoH;
  enterprise policies can still override. Not implemented yet.
- Once an `fd…` address has been handed to an application, DNS is out of
  the path: a later connection failure is only re-decided at the next
  lookup (30 s TTL).
- On systemd-resolved, a link search domain equal to a bound domain shadows
  the daemon ([daemon.md](daemon.md), Troubleshooting).
- Mesh relays are desktop-only; on Android offline means pinned domains.
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
