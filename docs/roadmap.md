# Roadmap

What is done, what is next, what is known to be imperfect, and what is
undecided. The source of truth for the state of the project: when
something is finished or verified it is moved here and in
[testing.md](testing.md), not noted elsewhere. Dates are absolute.

## Done

Phase 1, through fips-pub-domains 0.2.4 (2026-10-04) and fips2go 0.9.3
(2026-10-05):

- **Protocol**: claims (kind 37197), attestations (37198), zone records
  (37199); the `_fips-dns` TXT verifier with DNSSEC; pinning; the mesh
  lookup answered `CNAME <npub>.fips`; unverified bindings refused
  (opt-in marker offline). DNSSEC proofs in claims let an offline client
  with no pin verify a domain from the claim alone; attestations by a
  configured witness list (threshold *k*) cover domains with no proof. A
  claimant is no witness for its own domain.
- **Desktop**: `fips-pubdom-server` (one process per port, every zone
  file, publishes claim, proof and zone record), `fips-pubdomd` with
  `setup`/`teardown` for systemd-resolved, NetworkManager, standalone
  dnsmasq and plain `resolv.conf`; `fips-pubdom` (`lookup`, `verify`,
  `claims`, `pins`, `attest`, `attestations`). Redundant servers with
  failover and backoff; zone records used when no server answers; the
  upstreams file followed as the OS rewrites it; a plain probe before the
  validated TXT lookup for unpinned domains, the legacy answer fetched
  alongside and released on the first upstream's denial
  (`plain_probe: false` restores the validated denial).
- **Phone (fips2go)**: the resolver inside the VPN's DNS proxy; UDP over
  smoltcp for step 3; mesh relays through a loopback proxy over the
  in-process TCP stack; Settings for the feature, mesh relays, witnesses,
  *k*, DNSSEC, "Forget verified domains", "Trust my Mesh names as
  witnesses"; the Internet-validated flag shortens the TXT wait and
  gates the plain probe; the legacy answer fetched alongside and
  released early as on the desktop.
- **Verified live** ([testing.md](testing.md)): levels 1–6 — server from
  a peer, claim on a relay, daemon on a second and third node, a name
  pointing at no node, a server down, redundant servers, offline from
  the DNSSEC proof, attestations (desktop and phone), the phone online,
  offline by witness and offline for a domain never seen, the
  NetworkManager backend, first lookups and the boot window.

## Next

Grouped by component. Each item says what, why, and where it stands.

### Protocol and registration

- **Kind registration and the NIP** — submitted 2026-09-28:
  [registry-of-kinds #16](https://github.com/nostr-protocol/registry-of-kinds/pull/16)
  and [nips #2487](https://github.com/nostr-protocol/nips/pull/2487)
  (NIP-DB). Until merged the kind numbers are provisional; if others are
  assigned, `pubdom-core::KIND_*` and the docs follow. #2487 does not yet
  carry the rule from #17 that a claimant is no witness for its domain
  (spec §3.2); adding it is the maintainer's call, the PR being outside
  this repository.

### Desktop resolver

- Done (0.2.6; on the phone in fips2go 0.9.5, 2026-10-07): **the
  validated lookup releases the legacy answer on its first denial** too
  (`TxtSource::lookup_with`), so `plain_probe: false` costs the
  validated decision, not the wait for the slowest upstream. A
  `TxtSource` wrapper must forward `lookup_with` and `probe`, or it
  silently loses both (fips2go's `PhoneTxt` forwards both since #79).
- **Hedged forwarding.** The daemon forwards to the first upstream and
  tries the next only after a 2 s timeout, as a stub resolver would. A
  first upstream that is slow rather than dead — the reference machine's
  router takes up to 400 ms on uncached names and drops some queries
  under bursts — is now what a first lookup costs
  ([testing.md](testing.md) level 3d). Asking the second after a short
  delay would help, but changes which server's answer wins on a
  split-horizon network. Undecided.
- **A shorter retry when DNS fails while believed online.** Every
  upstream timing out, or answers failing validation (a router stripping
  DNSSEC does that for every zone under a signed TLD, unsigned domains
  included), sends an unpinned domain to the mesh relays and caches the
  decision for an hour. A shorter TTL recovers sooner from a hiccup but
  asks the relays more often. Undecided.
- **fips's `probe` command for reachability.** The echo through the
  mesh (1.5 s budget) exists because fips drops traffic for unknown
  nodes silently; `probe` on the control socket answers definitively
  (`bloom_miss` in ~60 ms) and would be better where it is available —
  the desktop, not the phone's shim. It is a mutating command.
- Done: `pubdom_core::unavailable_ttl` is the one definition of the cap
  on an unavailable name's legacy answer; the phone takes it with its
  next pin.
- **One wake-up per denial.** `Resolver::denied_by_an_upstream` uses one
  `Notify` for all domains, so each first denial wakes every waiting
  query, which rescans its candidates. Fine at a desktop's query rate; a
  per-domain signal if it ever shows in a profile.
- **Firefox DoH canary.** Browsers with their own encrypted DNS (Firefox
  TRR, Chrome "secure DNS with a provider") bypass the system resolver.
  Answering `use-application-dns.net` with NXDOMAIN disables Firefox's
  automatic DoH; enterprise policies still override. Whether the daemon
  should do that in full mode, or leave it to the user per browser, is
  an open question below.

### Domain server

- **Public domains in fips-ui** — wanted by the maintainer (2026-10-06,
  shaped 2026-10-08): the server and the resolver configured and
  watched from fips-ui, which shows a "Public domains" section when it
  finds either on the node, and manages them from another node through
  its mesh access. Designed in [webui.md](webui.md): this repository
  provides `server.yaml`, a watched zones directory, `validate`
  commands and a control socket per binary; fips-ui provides the
  pages. Phases 1–2 here, 3–5 in fips-ui. Phase 1 (the configuration
  file, the watched zones directory, `init`, `validate`) is done (#24,
  unreleased); the control sockets are next.

### Phone (fips2go)

- **First lookup right after connecting.** The mesh session to the
  domain's server is not up yet when the first step 3 query goes out, so
  it times out and the zone record answers instead (seen 2026-10-05 in
  the log; the late reply then arrives as an "unsolicited mesh packet").
  Without a zone record covering the name that lookup ended in the
  legacy address for the record's TTL, with the server backed off for 5
  minutes. Done on both sides (`LookupResult::Unavailable { retry_in }`,
  the legacy answer's TTL capped at the next retry, first backoff 20 s —
  released in 0.2.5; fips2go #74 forwards such a name as `Capped`, #76
  pins the tag, shipped in fips2go 0.9.4 on 2026-10-06). Checked on the phone 2026-10-06 with a fresh connect and
  a bound name right away and 35 s later: both answered over fips, so
  the unreachable-server path itself was not exercised and stays
  verified by tests only.
- Done, by reading the code rather than changing it: the shim's debug
  lines *are* available on a release build — Settings → Advanced → Log
  level `debug` sets the whole tracing filter (`init_logging`), the
  public-names lines included. The early release and first-lookup
  behaviour can be observed on a device that way; 0.9.3's speed-up has
  still only been measured on the desktop.
- **A second copy of the release-and-race logic** (the daemon has it as
  one `select!`, the proxy as blocking threads); a shared helper in
  `pubdom-resolve` would need an async DNS proxy on the phone. The
  daemon starts the legacy fetch only after one poll of the lookup
  found it pending (#23, 0.2.6); the phone follows the same rule — the
  lookup tells the proxy when to start the thread (fips2go #79, in
  0.9.5).
- **TCP fallback for step 3** over the smoltcp stack. Low value: a step 3
  answer is one CNAME and never truncates.
- **Upstream ports** kept for the TXT verifier (the shim hands the
  library addresses only).
- Process: GitHub's AI code scanning fails on every fips2go pull request
  with a quota error since 2026-10-05; it is not a required check and
  says nothing about the change.

### Platforms and packaging

- **macOS** (launchd + `networksetup` or `/etc/resolver/`) and
  **Windows** (service + NRPT) `setup` backends; the binaries build there
  and ship in the release archives, the wiring is by hand
  ([platforms.md](platforms.md)).
- **Restricted per-domain mode**, OpenWrt and pfSense packaging.
- **Not yet run live**: the standalone dnsmasq and plain `resolv.conf`
  backends (tests in a temporary root only), and the upstreams watcher
  under systemd-resolved or NetworkManager themselves (seen on a scratch
  instance only, [testing.md](testing.md) level 3d).

## Behaviour worth knowing

By design, not on the list to change:

- A first visit to a bound domain does not survive a forged plain "no
  record" by way of the mesh relays (spec §5.1) unless `plain_probe:
  false` restores the validated denial at its cost
  ([daemon.md](daemon.md)). On the phone the probe is already off
  whenever the Internet is not validated, and there is no switch.
- Once an `fd…` address has been handed to an application, DNS is out of
  the path: a later connection failure is only re-decided at the next
  lookup (30 s TTL).
- On systemd-resolved, a link search domain equal to a bound domain
  shadows the daemon ([daemon.md](daemon.md), Troubleshooting).
- Online verification is unaffected by DNSSEC key rollovers done properly
  (every lookup validates the live chain; the pin stores no key). A
  broken rollover makes validation *bogus*, which counts as an
  unreachable upstream — pins keep working, nothing is downgraded to
  unsigned `dns`, nothing is unpinned.
- Two independent upstream resolvers are not always available (one
  DHCP-provided resolver is common on phones); the verification is then
  `dns-single`, and a later two-resolver or DNSSEC verification upgrades
  the pin.

## Open questions

- Should the daemon in full mode answer the Firefox DoH canary, or is
  that the user's call per browser?
- Relay selection for claims: the node's own relay list is used today. A
  curated set of "claim relays" might be worth publishing once there are
  more than a handful of domains.
- Whether a domain's server should be *required* to run a mesh relay
  carrying its own claim, making every bound domain discoverable offline
  by anyone who knows the server.
