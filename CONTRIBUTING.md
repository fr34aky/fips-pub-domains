# Contributing to fips-pub-domains

<!-- markdownlint-disable MD013 -->

fips-pub-domains resolves public domain names (`www.example.org`) to
[fips](https://github.com/jmcorgan/fips) mesh nodes, with or without the
Internet. The protocol is small and the code is cut so that the part that
can be wrong is testable without a network:

- **`pubdom-core`** — the policy, no I/O: identities, domain rules, the
  TXT record, claims, pins, the verification precedence, DNS synthesis.
  Every rule in [docs/spec.md](docs/spec.md) has a table test here.
- **`pubdom-resolve`** — the I/O adapters (relays, legacy DNS, the mesh
  transport trait, the pin file) and the resolver that ties them to the
  policy. Generic over its sources so tests inject tables.
- **`pubdom-server`, `pubdom-daemon`, `pubdom-cli`** — the domain server,
  the desktop resolver daemon, the operator tool.
- **fips2go** (a separate repository) embeds the two library crates on
  Android and supplies the phone's mesh transport.

Two invariants shape every change, and reviewers check them first
([docs/spec.md](docs/spec.md) §5.1, §7):

1. **A name is never made unreachable.** Everything short of a verified
   binding, a positive answer from the domain's server and a reachable
   node is the legacy answer, never an error of ours.
2. **A claim alone never resolves.** Unverified bindings are refused (or
   used only with the explicit, logged opt-in offline).

Most behaviour is visible only against a live mesh, and there is no mock
fips. [docs/testing.md](docs/testing.md) is the ladder of live checks,
with the commands and the output they produced; run the levels your
change touches before opening a PR.

## Quick start

```bash
git clone https://github.com/fr34aky/fips-pub-domains.git
cd fips-pub-domains
cargo test --workspace      # no network needed
cargo build --release
```

Requirements: Rust 1.88 or newer (rustup; see
[docs/install.md](docs/install.md) for distribution packages), and a
running fips node for anything beyond the unit tests — the daemon asks its
`.fips` responder, the server binds its address.

## Branches

There is one long-lived branch, `main`. Open PRs against it. Tags mark
releases (see [Releasing](#releasing)) and [CHANGELOG.md](CHANGELOG.md)
records what changed between them.

## Reporting bugs

Search [open issues](https://github.com/fr34aky/fips-pub-domains/issues)
before filing a new one. Please include:

- **Version** (`fips-pubdomd --version`, or `git rev-parse --short HEAD`)
  and which component: daemon, server, CLI, or the fips2go integration.
- **OS / distro** and how DNS is wired (`resolvectl status | head` on
  systemd-resolved hosts), **fips version** (`fipsctl --version`).
- **What you expected** and **what happened** — for resolution bugs, the
  `resolvectl query <name>` (or `dig @::1 -p 5356`) output *and*
  `fips-pubdom verify <domain>`, which prints every input to the decision.
- **The daemon's log** (`journalctl -u fips-pubdom`) around the time; on
  the phone, fips2go's Diagnostics log. Redact your domain and npubs if
  you prefer — the shapes matter more than the values.

One issue per bug.

## Submitting pull requests

### Scope discipline

Every PR makes one logical change. The reviewer should be able to read the
whole diff and trace every line back to the PR's stated purpose.

- No drive-by reformatting of unrelated files.
- No unrelated refactors folded into a bug fix or a feature PR.
- No "while I was in there" cleanups outside the change's natural
  footprint. Send them separately; they land faster on their own.

### Required before opening any PR

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same on Linux, macOS and Windows, checks that the two library
crates build for `aarch64-linux-android`, and greps them for
`cfg(target_os)` — the libraries carry no platform-specific code
([docs/platforms.md](docs/platforms.md)). Then exercise the change
against a live node as [docs/testing.md](docs/testing.md) describes for
the level it touches.

### Self-review against the project review checklist

The 13-criteria checklist used on every incoming PR is published at
[PR-REVIEW.md](PR-REVIEW.md). Run your own change through it before
opening, or hand the document to your coding agent with "review my
branch against this checklist". It is the first thing that happens to
any submission, so doing it yourself saves a round trip.

### Additional requirements for changes to the protocol

Anything that changes what goes on the wire or how a binding is judged
must:

- update [docs/spec.md](docs/spec.md) in the same PR, and
  [docs/nip.md](docs/nip.md) if an event's shape changes;
- add the case to the policy tables in `pubdom-core` *before* the
  behaviour changes;
- say in the PR body what a client running the old version does when it
  meets the new event or record.

### Additional requirements for feature PRs

- **Documentation updated alongside the code**: the operator or daemon
  guide for user-visible changes, [docs/install.md](docs/install.md) for
  anything touching installation, the config reference in
  [docs/daemon.md](docs/daemon.md) for new keys.
- **A CHANGELOG entry** under `[Unreleased]`.
- **A note for fips2go** when `pubdom-core` or `pubdom-resolve` change
  their public surface: fips2go pins these crates by commit and its
  `names.rs` must follow.

### Merge mechanics

PRs are squash-merged. One logical change per PR becomes one commit on
`main`; the commit message is rewritten at merge time to say *why*, in the
style of the existing history, so in-PR history does not need to be
pretty.

## Releasing

Not every merged change is a release. Changes collect under `[Unreleased]`
in [CHANGELOG.md](CHANGELOG.md) until the maintainer decides to release
them. A release is a version bump and a tag:

```bash
git switch main && git pull
# set version = "0.2.0" in [workspace.package] in Cargo.toml, commit it
git tag -a v0.2.0 -m "fips-pub-domains 0.2.0"
git push origin main v0.2.0
```

Versions follow [Semantic Versioning](https://semver.org/): patch for
fixes, minor for features, major for breaking changes to the wire format,
the pin file, the config file or the library crates' public API. All
crates share the workspace version; the binaries report it with
`--version`.

Pushing the tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml):

1. Checks the tag: annotated, `vX.Y.Z` or `vX.Y.Z-pre` (for example
   `v0.2.0-rc.1`), on a commit of `main`, equal to the workspace version
   in `Cargo.toml`, and not released yet.
2. Runs the [CI checks](.github/workflows/ci.yml) on the tagged commit.
   If they fail, nothing is published; delete the tag
   (`git push --delete origin v0.2.0 && git tag -d v0.2.0`), fix, tag again.
3. Builds the three binaries for Linux (x86_64, aarch64), macOS (Apple
   silicon, Intel) and Windows (x86_64), packs each with the `packaging/`
   files, and publishes the GitHub release with the `[Unreleased]`
   section as its notes and a `SHA256SUMS` file. A pre-release suffix
   makes a pre-release.
4. Moves the `[Unreleased]` entries under `## [X.Y.Z] - date` on `main`
   (a commit by `github-actions[bot]`; skipped with a warning if
   `[Unreleased]` changed after the tag).

fips2go picks up a release by bumping its pins to the tagged commit.

## AI coding assistant policy

Use of AI coding assistants in preparing a contribution is welcome. What
is required is that the contributor does a thorough manual review and
editorial pass over the output before submission:

- Verify the code does what it claims, not just that it builds — for this
  project, that means against a live mesh where the change is reachable.
- Verify the documentation matches the behaviour.
- Spot-check the diff: no unrelated files, no fabricated APIs, no
  references to symbols that do not exist, no version bumps you did not
  intend.
- Do not include coding-assistant attribution trailers in commit messages
  or PR descriptions.
- Be ready to discuss the design choices in the PR as if you wrote every
  line, because for the purposes of accountability you did.

Submissions that show signs of being unreviewed agent output will be
closed without human review.

## Where the conversation happens

- **GitHub issues** — bugs, feature requests, design discussion.
- **GitHub PRs** — discussion specific to a change in flight.

For anything about the fips protocol or daemon itself, go upstream to
[jmcorgan/fips](https://github.com/jmcorgan/fips); for the Android
integration, to [fr34aky/fips2go](https://github.com/fr34aky/fips2go).
Questions about the Nostr events belong here until the NIP is submitted
([docs/nip.md](docs/nip.md)).

## Further reading

- [PR-REVIEW.md](PR-REVIEW.md) — the review checklist.
- [docs/spec.md](docs/spec.md) — the protocol; [docs/architecture.md](docs/architecture.md) — the code.
- [docs/design-history.md](docs/design-history.md) — what was rejected and why, so it stays rejected.
- [docs/testing.md](docs/testing.md) — the live test ladder.
