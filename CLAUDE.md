# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

`fips-pub-domains`: public domain names (`www.example.org`) resolving to
[fips](https://github.com/jmcorgan/fips) mesh nodes, with or without the
Internet. Read [README.md](README.md) first, then [docs/spec.md](docs/spec.md)
(the protocol) and [docs/architecture.md](docs/architecture.md) (the code).
[docs/design-history.md](docs/design-history.md) records the decisions and
what was rejected; do not re-litigate them without new information.

The repository is deliberately **independent** of fips2go (`~/fips2go`, the
Android client), fips-ui (`~/fips-ui`) and fips itself (`~/fips`, fork
`fr34aky/fips` branch `android-hooks`): the library crates are consumed by
fips2go as pinned git dependencies. Do not move code into those repos except
the Android-specific parts that already live there (`shim/src/names.rs`,
`meshudp.rs`, `meshtcp.rs`).

## Working rules

- Public repo `fr34aky/fips-pub-domains`. Commit and push only as
  `fr34aky <162515565+fr34aky@users.noreply.github.com>`.
- **No Claude attribution anywhere**: no `Co-Authored-By: Claude`, no
  `Claude-Session:` trailer, no claude.ai links, no "Generated with Claude
  Code" in commits or PR bodies.
- Commit messages explain *why*, as in the sibling fips2go repo.
  [CONTRIBUTING.md](CONTRIBUTING.md) and [PR-REVIEW.md](PR-REVIEW.md) are
  the rules for PRs and reviews; every user-visible change gets a line
  under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- Releases: bump `version` in `[workspace.package]`, annotated tag
  `vX.Y.Z` on `main`; `.github/workflows/release.yml` does the rest.
  Never tag without the user asking.
- Nothing gets published outside this repository without the user saying
  so. Done on the user's word: the demo domain's claim on public relays,
  registry-of-kinds #16, nips #2487 (NIP-DB), the v0.1.0, v0.2.0 and
  v0.2.1 tags (2026-09-28), v0.2.2 and v0.2.3 (2026-10-01), v0.2.4
  (2026-10-04). Tagging a release still needs the user's explicit word each time.
- No `cfg(target_os)` in `pubdom-core` or `pubdom-resolve` (CI enforces).
- `cargo test --workspace` must stay green; the policy tables in
  `pubdom-core` are the place to add a case before changing behaviour.
- **Every PR gets one code review before it merges** (`/code-review high`
  on the branch). Real bugs it finds are fixed on the branch; everything
  else — polish, docs, deliberate trade-offs, pre-existing issues — is
  listed in the PR body as deferred or declined. Then merge when the checks
  are green. No review-fix-review loop: a high-effort review never comes
  back empty, and repeated rounds started reversing each other. User rule,
  2026-09-28 (revised the same day after 12 rounds on one PR).

## Layout

```
crates/pubdom-{core,resolve,server,daemon,cli}   see docs/architecture.md
docs/           install, spec, nip, architecture, operators, daemon, android, platforms, testing, roadmap, design-history
packaging/      systemd units, the fips firewall drop-in
```

Binaries: `fips-pubdom-server`, `fips-pubdomd`, `fips-pubdom`. Config
`/etc/fips-pubdom/`, pins `/var/lib/fips-pubdom/pins.json`, daemon on
loopback 5356, server on the node's fips address 5355.

## Environment notes

- The demo domain, the serving node, the client node and the mesh relay
  used for the live tests are private; they are recorded in Claude's memory
  for this project, not in the repository. Documents use `example.org` and
  placeholder npubs/addresses for them.
- `cargo clippy` is unavailable on the reference machine (no rustup default
  toolchain).
- fips2go host tests: `cd ~/fips2go/shim && FIPS_LIBCLANG_PATH=/usr/lib
  CARGO_NET_GIT_FETCH_WITH_CLI=true source ../android-env.sh && cargo test`.
  No Android target on the reference machine; the `.so` is built elsewhere.

## State and next steps

[docs/roadmap.md](docs/roadmap.md) is the source of truth; keep it and
[docs/testing.md](docs/testing.md) current when something is done or
verified, rather than adding status notes elsewhere.
