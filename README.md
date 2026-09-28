# fips-names

Resolving public domain names (e.g. `www.example.org`) to [fips](https://github.com/jmcorgan/fips)
mesh nodes — with or without Internet access — using Nostr for discovery, the
mesh for lookups, and legacy DNS only as an optional verifier.

Independent of any one fips client: meant to be usable from fips2go (Android),
desktop nodes, and a standalone resolver.

Spec: [docs/domain-binding.md](docs/domain-binding.md). Plans:
[phase 1](docs/plan-phase1.md), [platforms](docs/plan-platforms.md),
[NIP draft](docs/nip-draft.md).

## Crates

| crate | what | binary |
|---|---|---|
| `names-core` | policy, no I/O: identities, domain rules, TXT/claim parsing, pins, precedence, DNS synthesis | — |
| `names-resolve` | I/O adapters: relay client, TXT verifier (hickory, DNSSEC), mesh transport trait, pin file, the resolver | — |
| `names-server` | the domain's fips DNS server (step 3) and claim publisher | `fips-names-server` |
| `names-daemon` | forwarding resolver for desktops (systemd-resolved backend so far) | `fips-namesd` |
| `names-cli` | operator tool: `lookup`, `verify`, `claims`, `pins` | `fips-names` |

The Android side lives in fips2go (`shim/src/names.rs`, `meshudp.rs`) and
uses the two library crates.

```
cargo test --workspace
fips-names-server --key /etc/fips/fips.key txt --zone example.org.yaml   # the TXT record to publish
fips-names-server --key /etc/fips/fips.key serve --zone example.org.yaml --publish --relay wss://…
sudo fips-namesd setup && sudo systemctl enable --now fips-names
fips-names verify example.org
```
