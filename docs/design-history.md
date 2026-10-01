# Design history

How the design got here, including what was rejected. Kept because several
decisions look arbitrary without the road not taken.

## Starting point

fips2go's mesh names: a flat `name npub` hosts file, synced from fips-ui
nodes since fips2go 0.8.0. fips itself only allows single-label `.fips`
names (`validate_hostname` in fips `src/upper/hosts.rs`; the resolver takes
everything before `.fips` as one label). Wanted: real domains,
`www.example.org`, resolving to mesh nodes, from unchanged browsers, with and
without the Internet.

## Ideas considered

1. **Subdomains under a trusted anchor** (`www.home.fips`: `home` trusted
   locally or an npub label; `home` publishes a signed record for names
   under itself). Trusted always beats learned; no squatting because a
   publisher can only define names under itself. Kept as the model for
   delegation, but it does not give public domains.
2. **`.com` and other TLDs via legacy DNS binding** (`_fips` TXT, DNSSEC,
   pinning) — rejected as *the* mechanism: legacy DNS must not be a
   dependency for operation, only decentralized infrastructure (Nostr,
   fips) may be. It survived as the optional verifier.
3. **Alternative separators** (`www,home,shop`) — rejected: dots are only
   presentation in DNS, routing happens by suffix (`.fips`, or the reserved
   `.alt` of RFC 9476), and non-LDH characters break applications.
4. **The adopted flow:** (1) a Nostr claim for the domain → the server's
   npub, (2) legacy DNS only as an optional verifier, (3) ask that server
   over the mesh for individual names.

## Refinements, in the order they were settled

- **HTTPS is not required.** fips is end-to-end encrypted and authenticates
  the far npub, so the security of a lookup is exactly the security of the
  name → npub binding; that makes the verification precedence more
  important, not less. HSTS and secure-context APIs still demand `https://`.
- **Step 3 over UDP, TCP only on truncation.** fips authenticates the source
  address; UDP saves a mesh round trip.
- **Browsers are never changed; the machine's resolver is.** Synthesize the
  `fd…` AAAA and suppress the public addresses, because RFC 6724 ranks
  `fd00::/8` last. Browser-side DoH is a known hole.
- **Unverified claims are refused, not silently used.** Offline trust comes
  from pins, attestations, or DNSSEC proofs carried in the claim.
- **Privacy:** never ask relays for every visited domain. The TXT hint is
  the gate.
- **Platform independence:** a daemon on every desktop OS, embedded in
  fips2go on Android; no target-specific code in the libraries.
- **Full mode with TXT-first discovery is the default** on every platform.
  Per-domain routing was the desktop default for one afternoon, until it
  became clear that a resolver can only discover domains whose queries reach
  it; it survives as the opt-in restricted mode.
- **Offline: the claim is the TXT record.** With no upstream reachable, the
  claim is fetched from relays directly — mesh relays on fips nodes first.
  This is why DNSSEC proofs in claims moved ahead of attestations.
- **"Not over fips" is never a failure for the application.** A bound domain
  whose zone lacks a name, a refused binding, an unreachable node — all fall
  through to the legacy answer. The zone format gained `legacy` to carve a
  name out of a wildcard.
- **TXT instead of SRV**, after the SRV target `npub….fips.` was rejected by
  the domain hoster's control panel.
- **The domain server is its own program**, after reading fips's responder:
  it binds loopback, knows only `.fips`, and drops mesh-side queries by
  design.
- **Mesh relays by `.fips` hostname**, after nostr-sdk refused an `[fd…]`
  literal; **both relay sets online**, after a claim that lived only on the
  mesh relay could not verify while the Internet was up.
- **The daemon owns the resolved pool and forwards `.fips` itself**, after
  the first two-node run showed that resolved merges global drop-ins.
- **A legacy answer given on a budget overrun is short-lived (5 s)**, after
  the phone showed a parked wildcard's address for `relay.example.org`
  "always": one cold lookup had overrun the 3.5 s budget, Android's
  resolver kept the legacy address for the record's 300 s, and the
  finished lookup's cached decision was never asked for. Returning
  SERVFAIL instead was rejected: a name of a bound domain may be `legacy`
  in the zone, and a lookup that is merely slow must not make it fail.
  The overrun itself came from the relay fetch waiting for every relay to
  send EOSE or time out — a half-dead public relay cost 2 s of the 3.5 s
  on every cold lookup — so each relay now has its own subscription and
  the others get 750 ms once one has delivered a claim. Only after a TXT
  hit: the record names the server, so a claim a slow relay would have
  added costs at most that relay's say until the next TXT TTL. Offline the
  claims alone decide, a conflict is only visible with every relay heard,
  and the fetch still waits for all of them.

- **Attestations come from an explicit witness list, not from the
  network.** The resolver asks relays for kind 37198 by the configured
  authors only, so an untrusted key's attestation is never fetched; *k*
  counts distinct witnesses, default 2, 0 switches the feature off. They
  are consulted offline only, after pins and proofs and before the
  unverified opt-in: online the record decides, and a pin is never
  revised by hearsay. One attestation names every server of the domain
  (`p` tags), since a witness that verified a domain with redundant
  servers has verified the set; it vouches only for keys with a claim of
  their own, the claim being what carries the port. `attest` refuses a
  single-resolver verification: a witness should not be weaker than what
  it replaces. A verification older than 30 days does not count, after
  review: nothing else bounded a decommissioned witness's last word. The
  attestation filter carries the user's witness list, so it goes to mesh
  relays only — a public relay learning whom a user trusts is a leak §8's
  gate never covered. "Default witnesses = the user's synced trusted
  nodes" is the phone's job, where that list exists.

- **NetworkManager is bypassed, not configured.** Its dnsmasq plugin
  takes the connections' servers over D-Bus and cannot be told to use one
  server only, so `setup` sets `dns=none` and owns `resolv.conf`; NM still
  writes `/run/NetworkManager/resolv.conf`, which keeps the upstreams
  following DHCP. Plain `resolv.conf` and standalone dnsmasq get a static
  snapshot of their servers instead — nothing else on such a machine
  tracks them. Where the OS cannot name a port the daemon takes 53;
  `setup` records its backend so `teardown` needs no flag.

## Facts from the fips codebase the design rests on

- fips's Nostr key is the node identity key (`src/nostr/runtime.rs` builds
  `nostr::Keys` from the node keypair): events authored by `npubX` are
  authentic for mesh node `npubX`.
- A fips node can only route to an `fd…` address whose npub it knows;
  resolving `npub….fips` through fips's DNS responder registers the
  identity. Hence `CNAME npub….fips.`
- The mesh address is `fd` + SHA-256(x-only key)[0..15]
  (`src/identity/{node_addr,address}.rs`).
- Kinds fips uses: 37195 overlay advert, 21059 signal; neither registered.
- fips's Nostr runtime exposes no generic "fetch events by filter"; the
  resolver has its own relay client.
- fips's mesh effective IPv6 MTU is ~1200 bytes.
- In fips2go, the app's own UID is outside its tunnel; mesh traffic from the
  app goes through an in-process smoltcp stack (`meshhttp.rs`).
