# fips-pub-domains

**Public domain names for [fips](https://github.com/jmcorgan/fips) mesh nodes — with or without the Internet.**

A website's owner points `www.example.ch` at a fips node. Anyone running fips
then reaches it *over the mesh*, by that ordinary name, from an unchanged
browser — while the Internet is up, and after it goes away.

```
 you: http://www.example.org/
                │
                ▼
 your resolver ──► _fips-dns.example.org TXT?  (legacy DNS, DNSSEC)   "v=fips1 npub=npub1uyut… port=5355"
                ──► claim for example.org?     (Nostr relays)          signed by npub1uyut… — verified against the TXT
                ──► www.example.org?           (DNS over the mesh, to npub1uyut…:5355)
                ◄── CNAME npub1uyut….fips.
                │
                ▼
 browser gets  AAAA fdd9:…:8f4d   — the node's mesh address; the connection goes over fips
```

Once a binding has been verified it is **pinned**: the name keeps resolving
with no legacy DNS at all. A domain that has no binding behaves exactly as
before. A binding that cannot be verified is never used.

## Why

fips gives every node a stable address derived from its Nostr key, but the
only names it knows are single-label `*.fips` names from a hosts file. Real
sites have real domains, and the people who run them already control DNS and
already have a Nostr key. This project connects those two facts:

- **Nostr is the discovery channel.** A signed, addressable event ("I,
  `npub…`, serve `example.org` on port 5355") replaces the DNS record when
  DNS is unreachable.
- **Legacy DNS is only a verifier**, never a dependency: a TXT record proves
  the domain's owner agreed, DNSSEC makes that proof cryptographic, and a
  verified binding survives offline.
- **The mesh carries the lookups.** Individual names under the domain are
  asked of the domain's own server over fips, end-to-end encrypted and
  authenticated by the node's key.
- **Browsers are never changed.** The machine's resolver is.

Not a goal: replacing ICANN, or a global registry of names. Names bind to
keys only through verification or explicit trust; everything else is refused.

## Status

Phase 1 is implemented and tested across two nodes and a mesh-only relay
([docs/testing.md](docs/testing.md)): claims, TXT verification (DNSSEC when
the zone is signed), pinning, the mesh lookup, the desktop daemon on Linux
with systemd-resolved, and the Android integration in
[fips2go](https://github.com/fr34aky/fips2go). The event kinds are not yet
registered and the [NIP](docs/nip.md) is a draft. See
[docs/roadmap.md](docs/roadmap.md) for what comes next.

## Components

| binary / crate | runs on | does |
|---|---|---|
| `fips-pubdom-server` (`pubdom-server`) | the node that serves a domain | answers the mesh lookups from a zone file; publishes the claim |
| `fips-pubdomd` (`pubdom-daemon`) | desktops and servers | forwarding resolver in front of all DNS; `setup` wires the OS |
| `fips-pubdom` (`pubdom-cli`) | anywhere | `lookup`, `verify`, `claims`, `pins` |
| `pubdom-core` | everywhere | the policy: parsing, verification precedence, pinning, DNS synthesis — no I/O |
| `pubdom-resolve` | everywhere | relay client, TXT verifier, mesh transport trait, pin file, the resolver |
| fips2go `shim/src/names.rs` | Android | the same two library crates inside the VPN's DNS proxy |

## Quick start

Install first — [docs/install.md](docs/install.md) has one
self-contained section per role (the domain server, the desktop
resolver, the CLI): release archives or `cargo build --release`, where
each binary and unit goes, upgrading and uninstalling. A machine usually
needs one role.

### Serve a domain

On the fips node that should answer for `example.org`
([docs/operators.md](docs/operators.md)):

```yaml
# /etc/fips-pubdom/zones/example.org.yaml
domain: example.org
names:
  www: self          # this node
  git: npub1…        # another node
  mail: legacy       # stays on the public Internet
  # no wildcard: every other name stays wherever it is today
```

```sh
sudo cp packaging/common/fips-pubdom.nft /etc/fips/fips.d/ && sudo systemctl try-reload-or-restart fips-firewall
fips-pubdom-server --key /etc/fips/fips.key txt --zone example.org.yaml      # → the TXT record to add at your DNS hoster
fips-pubdom-server --key /etc/fips/fips.key serve --zone example.org.yaml --publish --relay wss://…
```

### Resolve on a desktop

```sh
sudo fips-pubdomd setup                        # systemd-resolved: all DNS through the daemon
sudo systemctl enable --now fips-pubdom
fips-pubdom verify example.org                  # TXT → claim → decision
curl http://www.example.org/                    # over the mesh, by name
```

[docs/daemon.md](docs/daemon.md) has the configuration reference and the
one systemd-resolved interaction you will want to know about.

### Resolve on Android

Built into fips2go: Settings → *Public domain names over fips* (on by
default); relays on fips nodes go in *Mesh relays for public names*, for
offline discovery. [docs/android.md](docs/android.md).

## Documentation

| | |
|---|---|
| [docs/install.md](docs/install.md) | installing, upgrading and uninstalling, one section per role: domain server, desktop resolver, CLI |
| [docs/spec.md](docs/spec.md) | the protocol: events, records, verification precedence, wire format, OS integration, security |
| [docs/nip.md](docs/nip.md) | the Nostr NIP draft (kinds 37197–37199, placeholders) |
| [docs/architecture.md](docs/architecture.md) | crates, data flow, the decisions behind them |
| [docs/operators.md](docs/operators.md) | serving a domain: zone file, TXT record, firewall, claims, relays |
| [docs/daemon.md](docs/daemon.md) | the desktop resolver: install, config, troubleshooting |
| [docs/android.md](docs/android.md) | the fips2go integration and its limits |
| [docs/platforms.md](docs/platforms.md) | one resolver on every OS: what is platform-specific and where |
| [docs/webui.md](docs/webui.md) | the domain server's web UI: design, phases, open questions (not built yet) |
| [docs/testing.md](docs/testing.md) | the test ladder, with commands and expected output |
| [docs/roadmap.md](docs/roadmap.md) | done, next (per component), behaviour by design, open questions |
| [docs/design-history.md](docs/design-history.md) | how the design got here and what was rejected |

## Building

```sh
cargo build --release          # Rust stable; no system libraries — see docs/install.md
cargo test --workspace         # 50 tests, no network needed
```

The library crates carry no platform-specific code (CI checks) and build for
`aarch64-linux-android`; the binaries target Linux first, then macOS and
Windows ([docs/platforms.md](docs/platforms.md)).

## Contributing and releases

[CONTRIBUTING.md](CONTRIBUTING.md) has the workflow, [PR-REVIEW.md](PR-REVIEW.md)
the checklist every PR is read against, [CHANGELOG.md](CHANGELOG.md) what
changed between releases. Releases are annotated `vX.Y.Z` tags on `main`;
the release workflow builds the binaries for Linux, macOS and Windows.

## License

MIT — see [LICENSE](LICENSE).
