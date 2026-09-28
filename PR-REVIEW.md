# PR Review Checklist

<!-- markdownlint-disable MD013 -->

This is the 13-criteria checklist run against every incoming PR. The
first pass on any submission is exactly this list, so executing it
yourself before opening, or after pushing a fresh revision, saves a
review round trip.

The document is also written so you can hand it to a coding agent with
"review my branch against this checklist" and get a structured pass.

This project puts a resolver in front of all of a machine's DNS and hands
applications mesh addresses for public names. A wrong decision here
either makes a website unreachable for everyone running fips, or points a
name at a node that merely claimed it. The criteria are weighted
accordingly.

## Step 1 — Should this even be reviewed?

Skip the review (and say so) if the PR is:

- closed, merged, or marked draft
- automated (bot author, dependency bumps) and trivially OK — except a
  bump of `hickory-*`, `nostr-sdk`, `simple-dns` or `psl`, which change
  what is validated, signed, parsed or considered a public suffix
- so small and obviously correct (typo fix, single-line doc tweak) that a
  thirteen-point pass is overkill; a one-paragraph informal review is
  better in that case

## Step 2 — Gather context

Read these *before* analyzing the diff:

1. PR metadata.

   ```bash
   gh pr view <num> --json title,body,author,headRefName,baseRefName,headRefOid,baseRefOid,mergeable,statusCheckRollup,commits
   ```

2. The diff.

   ```bash
   gh pr diff <num>
   ```

3. Base-branch freshness: how far `main` has moved since the PR forked.
4. Project guidance: [CONTRIBUTING.md](CONTRIBUTING.md); the spec
   sections the diff touches in [docs/spec.md](docs/spec.md); and
   [docs/design-history.md](docs/design-history.md) — several rejected
   ideas come back looking like improvements.
5. The invariants the code exists to keep (spec §5.1, §7, §8): a name is
   never made unreachable; a claim alone never resolves; relays are asked
   only after the TXT record vouched for the domain (or offline, and then
   the mesh relays first); a pinned binding changes only through a
   verification at least as strong as the one it rests on.
6. Related work: skim open issues and PRs for overlap, and fips2go's
   `names` integration if `pubdom-core` or `pubdom-resolve` change their
   public surface.
7. For "this looks wrong" observations: `git blame` the lines first. The
   history explains *why*; several rules exist because a live test broke
   without them ([docs/testing.md](docs/testing.md) says which).

## Step 3 — The 13 criteria

### Group A — PR hygiene

1. **PR body and issue cross-reference.** Does the body describe the
   change accurately and match what the diff does? Should it carry
   `Closes #N`? Does it say how the change was exercised against a live
   node, and at which level of the test ladder?
2. **Commit hygiene and base freshness.** Clean commits or a single
   commit, no "WIP" / "fix typo" noise, based on a recent `main`.
3. **Commit message quality.** Subject plus a body that says *why* —
   this history is unusually good at that and a PR that degrades it is a
   real cost. Free of extraneous footers, in particular coding-assistant
   attribution trailers.

### Group B — Diff content

4. **Does it do what it says it does.** Walk each claimed behaviour from
   the PR body against the diff, and each changed decision against the
   spec section it implements.
5. **Coherent whole.** All of the diff serves the stated goal; no
   drive-by formatting, no unrelated touch-ups, no scope creep.
6. **Fits the codebase as a natural extension.** Policy in
   `pubdom-core`, I/O in `pubdom-resolve`, nothing platform-specific in
   either; new sources behind the existing traits (`TxtSource`,
   `ClaimSource`, `MeshDns`, `PinStore`) rather than beside them; DNS
   wire format through `synth`, never hand-rolled bytes; caches through
   `TtlCache` with a TTL from spec §5.6.

### Group C — Cross-cutting concerns

7. **New dependency surface.** A new crate needs a stated reason and must
   build for `aarch64-linux-android` if it enters a library crate;
   anything with C code (`ring`, `openssl`) needs the CI cross-check to
   still pass. System tools shelled out to (`systemctl`, `resolvectl`,
   `nft`) count, and so do new relays or DNS servers used by default.
8. **Verification.** Unit tests for every policy change (the tables in
   `pubdom-core` are the contract); and was it run against a live mesh?
   The PR says which ladder level and what came back. A change to
   `meshudp.rs`-facing behaviour needs the phone.
9. **Documentation impact.** `docs/spec.md` for protocol changes (and
   `docs/nip.md` for event shapes), the operator/daemon/install guides
   for user-visible ones, `docs/roadmap.md` when a gap opens or closes, a
   CHANGELOG entry under `[Unreleased]`.
10. **Security and the invariants.** Can this ever return a mesh address
    for a binding that was not verified, pinned, or explicitly opted in?
    Can it return an error to the application where the legacy answer was
    available? Does anything reach a public relay about a domain DNS has
    not vouched for? Can an unauthenticated DNS answer unpin or downgrade
    a pin? Does the server accept anything from the mesh it did not
    intend to (the zone file is the only input)? Untrusted input — DNS
    replies, relay events, zone files — parsed with the size limits.
11. **Rust practices.** No `unwrap` on data from the network; timeouts on
    every I/O with a budget the caller can reason about; blocking work
    off the async runtime (`spawn_blocking`); no `cfg(target_os)` in the
    libraries; errors logged with the fields a support request needs
    (domain, npub, reason).
12. **Overlap with existing work.** Open issues and PRs that this
    duplicates, partially addresses, or unblocks; roadmap items it
    completes.
13. **Other concerns.** Behaviour on hosts unlike the author's: no
    systemd-resolved, a LAN search domain equal to a bound domain, one
    upstream resolver, no DNSSEC, a mesh-only node with no upstream at
    all, a phone. Effect on the pin file's compatibility (it is shared
    across platforms and survives upgrades). Fragility notes for future
    maintainers.

## Step 4 — Compose the review

The report is **not** a Q&A walk through the 13 criteria. Write it as
prose that reads start to finish, ordered by what matters most for this
PR. All 13 criteria are addressed somewhere in the body; do not reference
criterion numbers.

A typical shape: an opening paragraph on what the PR does and the
headline observations; a body covering diff analysis, design fit,
cross-cutting concerns and surprises; a closing with a disposition:
*land*, *land-with-followups* (list them), *request-changes* (name the
blockers), or *hold*.

## Step 5 — Filter aggressively

Do not flag:

- pre-existing issues on lines the PR did not modify
- anything `cargo fmt`, `clippy` or the build would catch
- pedantic style nitpicks a senior engineer would not call out
- likely intentional changes related to the broader goal
- stylistic preferences not anchored in CONTRIBUTING.md or the
  surrounding code

For every issue you do surface, include a concrete fix suggestion so the
author can act without a round trip.

## Step 6 — Citation discipline

Reference code by full-SHA permalink so the link survives history
rewrites:

```text
https://github.com/fr34aky/fips-pub-domains/blob/<full-40-char-sha>/<path>#L<start>-L<end>
```

## Notes

- Distinguish "blocker" from "worth asking about" from "fragility note".
  The closing disposition makes the action explicit.
- On re-review after new commits, lead with the delta from the prior
  review.
- The checklist exists to surface problems, not to assign blame.
