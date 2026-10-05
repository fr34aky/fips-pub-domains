# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `plain_probe: false` (daemon config, `ResolverConfig::plain_probe`)
  turns the plain probe of 0.2.4 off: every `_fips-dns` lookup is
  validated again, so a forged "no record" for a signed domain sends a
  first visit to the mesh relays instead of the legacy answer — at the
  cost of a validated denial per first lookup of an ordinary name.
  Default `true`, unchanged behaviour.

## [0.2.4] - 2026-10-04

### Changed

- The first lookup of an ordinary name no longer waits for a DNSSEC
  proof that it has no `_fips-dns` record. A domain with no pin is asked
  plainly first, every candidate domain and every upstream at once; the
  validated lookup runs only where a record exists. The daemon fetches
  the legacy answer alongside and hands it out — short-lived, 5 s — as
  soon as one upstream has denied the record for every domain the name
  could belong to; the decision waits for the others and is cached.
  Measured on the reference machine: 0.5–1 s per first lookup before;
  after, a median of 171 ms where the first upstream alone takes 54 ms —
  what is left is mostly that upstream answering the forwarded query.
  An answer released early is asked for again by the stub after its 5 s.
  Pinned domains are still validated every time: forgetting a pin takes
  a denial as strong as the pin. The price: on a first visit, a forged
  plain "no record" now ends the lookup with the legacy answer, where a
  forged denial of a signed domain used to fail validation and send the
  resolver to the mesh relays, which could still bind the domain from
  the claim's DNSSEC proof or from attestations. `TxtSource::probe` and `Resolver::denied_by_an_upstream` are the
  library side; a `TxtSource` without a probe behaves as before.

- `MaybeTxt::set_timeout`: a host that knows the Internet is gone can
  shorten the TXT lookup's wait (the phone does, from Android's network
  validation) so a first offline lookup fails into the mesh path within
  its budget — rather than skip the lookup, which would also skip it on a
  network that works but was never validated.

- On the resolved and NetworkManager backends the daemon follows its
  upstreams file as the resolver rewrites it, so a network change is
  picked up within a second instead of at the next 30 s poll (kept as
  the fallback, which also sets the watch up late if the directory did
  not exist at start). The directory is watched, since both resolvers
  rename a new file into place.

### Fixed

- A daemon that started before the network had upstreams answered
  SERVFAIL until the next 30 s poll — at boot, half a minute of "site not
  available". A query that finds no upstreams now re-reads the upstreams
  file first.

- A key that claims a domain is no witness for it: its attestations no
  longer count toward *k*, for itself or for a sibling server. With
  witnesses drawn from the nodes a client knows (the phone's Mesh names),
  the servers themselves are routinely on the list, and a claim vouched
  for by its author — or two claimants vouching for each other — would
  have been its own proof. `fips-pubdom attest` refuses to run from a
  key that claims the domain, and `verify` marks such attestations.
- The daemon's upstreams and `setup`'s snapshot read `resolv.conf` as
  glibc does: a `nameserver` line must start the line and be followed by a
  space or tab, and the address ends at `;` or `#`. An indented line, which
  the system resolver ignores, no longer becomes an upstream. The dnsmasq
  backend reads dnsmasq's resolv file as dnsmasq does, indented lines
  included.

## [0.2.3] - 2026-10-01

### Added

- `fips-pubdomd setup` on Linux beyond systemd-resolved: NetworkManager
  without resolved (`dns=none` drop-in, the daemon on port 53 in
  `resolv.conf`, NM's own server list followed for the upstreams), a
  standalone dnsmasq (`no-resolv` and `server=` to the daemon, the servers
  of its resolv file snapshotted), and a plain `resolv.conf` (the daemon on
  port 53, the previous `nameserver` lines snapshotted; refused when
  something else manages the file). `--backend auto` (the default) detects
  the arrangement, `setup` records it, and `teardown` undoes the recorded
  one without being told, restoring resolv.conf and the config to what
  they were. The NetworkManager backend is verified live.

- Attestations (kind 37198, spec §3.2, phase 3): a client lists the
  witnesses it trusts (`witnesses`, `attestation_threshold` in the config)
  and, offline, resolves a domain it has no pin and no proof for once *k*
  of them attest a server; the binding is pinned as `attested`, the
  weakest method, and replaced by the next online verification. Only the
  configured witnesses' events are fetched, from mesh relays only, and a
  verification older than 30 days does not count. `fips-pubdom attest <domain>
  --key …` makes a node a witness: it verifies the record online (DNSSEC
  or two agreeing resolvers) and publishes one attestation naming the
  domain's servers; `fips-pubdom attestations <domain>` shows what the
  witnesses published, and `verify` lists them with the decision.

## [0.2.2] - 2026-10-01

### Fixed

- A lookup that overran its budget left the application on the legacy
  address for the upstream record's whole TTL: on the phone, a parked
  wildcard's 300 s made `relay.example.org` look as if it never resolved
  over fips. The legacy answer forwarded during an overrun now carries TTLs
  of at most 5 s (`OVERRUN_TTL_SECS`, `synth::clamp_ttls`), and the daemon
  lets the overrunning lookup finish in the background, as the phone
  already did, so the stub's next query is answered from its decision.
- Cold lookups paid the full 2 s relay timeout whenever one relay in the
  pool stayed quiet, because the fetch waited for every relay's EOSE. Each
  relay is now asked on its own subscription; after a TXT hit, once one
  has delivered a claim the others get 750 ms, then the fetch returns.
  Offline every relay is still heard, so a conflict between claims stays
  visible.

### Added

- docs/operators.md: how to remove a server from a domain — in which order,
  and why its claim must be published once more without a DNSSEC proof
  (hosters that re-sign a changed record with the same signature date
  otherwise leave offline clients with two proofs they cannot order).

## [0.2.1] - 2026-09-28

### Fixed

- The `fips-pubdom-server` systemd unit never started: systemd expands
  `%s` in `ExecStart` to the service user's shell and `$z` itself, so the
  server was told to load a zone file named `/bin/sh`. The command no
  longer needs a specifier and escapes the shell's variables; zone paths
  may contain spaces, relay URLs are not glob-expanded, and with no zone
  file the unit stops once instead of restarting forever. **Existing
  installs must copy the unit again** (`sudo install -m644
  packaging/systemd/fips-pubdom-server.service /etc/systemd/system/ &&
  sudo systemctl daemon-reload`); the upgrade steps in docs/install.md
  now include this.

### Changed

- The server unit runs as an unprivileged dynamic user in group `fips`
  instead of root.

## [0.2.0] - 2026-09-28

### Fixed

- A pinned server that the TXT record no longer names is now unpinned even
  when the claim of the server it names instead did not reach us (with a
  record as strong as the pin, as before). It used to stay pinned and
  answer the next offline lookup.
- The failover backoff now actually grows (5 min, 15, 45, … up to 3 h); a
  server that stayed down was retried every 5 minutes.
- A name answered by its domain server itself no longer needs an ICMPv6
  echo for the record types that follow from the cache; where echo is
  blocked, A went to the public address while AAAA went to the mesh. The
  answer counts as proof for two minutes; after that the server is asked
  again instead of pinged, and only if that fails is the node pinged.
- Only address types (A, AAAA, ANY, CNAME) of a bound name go over fips,
  and HTTPS/SVCB get NODATA; MX, TXT, SRV and every other type stay legacy
  DNS. Under a wildcard zone they were answered empty, which broke mail
  and SPF lookups from machines running the daemon.
- Upstream resolvers that disagree on the `_fips-dns` record: once any
  answer validated, only validated answers count (a validated denial
  included), so a forged or stale unsigned answer cannot outvote a signed
  zone; a tie is no longer broken by list order but treated as disputed —
  pins keep resolving, an unpinned domain stays legacy and is asked again a
  minute later.
- DNSSEC status was judged from single records: a TXT denial counted as
  validated whenever its SOA did, and a record whenever any TXT record did.
  For an unsigned domain, one bad upstream could then fake a validated
  answer — replaying the TLD's signed SOA or opt-out NSEC3, or putting an
  unvalidated CNAME in front of a signed name — and bind an attacker's key
  at DNSSEC strength or unpin every server. Answers are now judged as a
  whole, and a validated denial must be for the name asked and proven by a
  validated NSEC/NSEC3 without opt-out.
- A denial from a signed zone using more NSEC3 iterations than the
  validator accepts (insecure by RFC 9276) counted as a failed upstream,
  sending the domain down the offline path; it is an unvalidated denial.
  Every form of answer that fails DNSSEC validation counts like no answer,
  and is logged as such.
- Re-verifying an unchanged binding no longer rewrites the pin file and
  logs "binding verified and pinned" each time.
- The reachability echo could panic on a scheduling delay; the daemon's
  and server's socket loops spun at full CPU on a persistent error.
- `fips-pubdom-server` said "Invalid secret key" when the key file merely
  could not be read (a `fips.key` with mode 600 and a user outside the
  `fips` group); it now says so, and also accepts a 32-byte raw key file.

### Changed

- `ProofVerifier::verify` takes the time to check signatures at.

### Removed

- `ResolverConfig.upstreams` (never read), and with it the argument of
  `Config::resolver_config`. fips2go sets the field and drops that line at
  its next pin bump.

### Added

- **DNSSEC proofs in claims** (spec §3.1, §5.5): for a DNSSEC-signed
  domain, `fips-pubdom-server` attaches the signed `_fips-dns` TXT record
  and its DNSKEY/DS chain to the root to the claim, checks it as a client
  would, and re-publishes before the signatures expire (halfway through the
  remaining validity, every 24 h at the latest). A client with no pin and
  no DNS — only a relay on the mesh — verifies the domain from the proof
  alone against the built-in root keys, and pins it as `dnssec`; the newest
  proven record decides which claims are servers. If collecting the chain
  fails, the server keeps the last one while it is valid (after a restart,
  from its own claim on the relays) and retries hourly; once the record no
  longer names the server's key, the claim goes out without a proof. `--dns` picks the resolvers the chain is
  collected from, `--no-dnssec-proof` turns it off, `dnssec: false` on the
  client ignores proofs. `fips-pubdom verify` shows each claim's proof.

- **Redundant servers** (spec §5.3): every key the TXT record names and
  that claims the domain is pinned as a server; step 3 asks them in pin
  order, fails over when one does not answer, and retries a failed server
  after a backoff (5 min, tripling per failure, at most 3 h). Zone records
  from any pinned server are accepted. `fips-pubdom verify` and `pins list`
  show the whole set. The pin file's format is unchanged — it was already a
  list; a file from before simply has one server per domain.

- **Zone records** (kind 37199, spec §3.3): the domain server publishes the
  names it serves next to its claim — at start, every 24 h, and whenever a
  zone file changes — and a client whose step 3 gets no answer from the
  server resolves the name from that record instead, so names pointing at
  other nodes keep working while the domain's server is down. Every target
  reached this way has to answer an echo, the server's own node included.
  `fips-pubdom zone <domain>` shows the record; `publish --dry-run` prints
  both events.

## [0.1.0] - 2026-09-28

### Added

- **The protocol** ([docs/spec.md](docs/spec.md)): a signed Nostr claim
  (kind 37197, placeholder) binds a domain to the fips node that serves it;
  a `_fips-dns.<domain>` TXT record verifies the binding, DNSSEC when the
  zone is signed; names under the domain are asked of that node over the
  mesh as ordinary DNS and answered `CNAME <npub>.fips.`; the application
  gets the node's `fd…` address with the public addresses suppressed.
  Verified bindings are pinned and keep resolving offline. Unverified
  claims are refused. Relays are asked about a domain only after its TXT
  record vouched for it, or offline — then relays on the mesh first.
- `pubdom-core`: the policy with no I/O — identities and mesh addresses,
  Public Suffix List rules, the TXT record, claims and zone records with
  size limits, pins with an anti-rollback table, the verification
  precedence and the offline path, DNS synthesis.
- `pubdom-resolve`: the TXT verifier (one hickory resolver per upstream,
  agreement counted; DNSSEC validation), the relay client with public and
  mesh relay sets, the mesh transport trait with a kernel implementation
  (UDP, TCP on truncation, ICMPv6 echo as the reachability check), the JSON
  pin file, and the resolver with per-domain and per-name single-flight.
- `fips-pubdom-server`: the domain's mesh DNS server on the node's fips
  address (default port 5355) from a hot-reloaded zone file with `self`,
  `legacy` and wildcard entries; publishes the claim and prints the TXT
  record to add.
- `fips-pubdomd`: the desktop resolver in front of all DNS, `setup` /
  `teardown` for systemd-resolved (a drop-in that resets the global pool;
  `.fips` forwarded to fips's responder), upstreams followed through
  `/run/systemd/resolve/resolv.conf`, a warning when a link search domain
  would shadow bound names.
- `fips-pubdom`: `lookup`, `verify` (every input to a decision), `claims`,
  `pins`.
- Android: the same library crates inside fips2go's VPN DNS proxy, with
  the mesh query and the echo over a smoltcp stack (fips2go PR #55).
- Packaging: systemd units, the fips firewall drop-in.
- Documentation: spec, NIP draft, architecture, install, operator and
  daemon guides, Android, platforms, the live test ladder with its
  results, roadmap, design history.

[Unreleased]: https://github.com/fr34aky/fips-pub-domains/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/fr34aky/fips-pub-domains/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/fr34aky/fips-pub-domains/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/fr34aky/fips-pub-domains/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/fr34aky/fips-pub-domains/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/fr34aky/fips-pub-domains/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fr34aky/fips-pub-domains/releases/tag/v0.1.0
