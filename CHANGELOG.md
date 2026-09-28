# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/fr34aky/fips-pub-domains/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/fr34aky/fips-pub-domains/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fr34aky/fips-pub-domains/releases/tag/v0.1.0
