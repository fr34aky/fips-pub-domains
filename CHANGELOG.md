# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/fr34aky/fips-pub-domains/commits/main
