# Fork integration

`upstream` is bramble-sh/bramble. `origin` is vbargl/bramble.

Each `fix/*` or `feat/*` branch is one change, a single commit on top of
upstream, and stays independent for an upstream PR. `main` is one merge commit
above upstream: its parents are the upstream tip and the head of every branch
recorded in [.fork/stack.json](.fork/stack.json). Everything that reconciles
those branches (overlaps between them and upstream, the lockfile and Nix hash,
this file, `stack.json`) lives inside that merge commit; none of it belongs to an
individual PR.

## Branching rules

1. **One branch, one commit.** Every new feature, like every fix, gets its own
   branch (`fix/*` for fixes, `feat/*` for features), based on `main@upstream`, so it
   stays independent and can become an upstream PR. The branch holds exactly one
   commit: the tests, the implementation and any docs the change needs, together.
   Change it by amending (`jj squash`, `jj describe`), never by adding a follow-up
   commit. It contains no fork-only files (`FORK.md`, `.fork/`), so the commit can go
   upstream as it is. The branch is kept until the change is implemented upstream.
   Once a `fix/*` branch is on origin jj treats it as immutable, so settle the commit
   before its first push. Needing to rewrite a pushed branch is a decision to put to
   the user, not something to work around.
2. **`main` is one merge commit.** Above upstream, `main` has exactly one commit, a
   merge whose parents are the upstream tip and every branch in `sourceHeads`. Work
   is never committed on `main` and `main` never grows a second commit. Anything the
   merge itself needs (conflict resolution, a lockfile refresh, a docs edit, a
   `stack.json` update) is made inside it: `jj new main`, edit, then `jj squash`.
3. **Adding and removing a branch** changes the merge's parents and `sourceHeads`
   together. The branch itself is never touched.

   ```sh
   jj rebase -r main -o 'parents(main) | feat/new'   # add
   jj rebase -r main -o 'parents(main) ~ feat/old'   # remove, e.g. upstream shipped it
   ```

   Leaving a branch out of the merge is how a change is kept outside `main` without
   losing it.

**Current state.** `main` is the single merge commit described above. Two things
predate the one-commit rule and are merged as they are: each `fix/audit-*` branch has
two commits (the reproduction test, then the fix), and so do `fix/native-refusal-test`
and a few others. They are already immutable on origin, so they are not squashed.

- `fix/audit-f2-roster-admission` is **not merged** (`excluded` in `stack.json`).
  Strict admission refuses any device whose roster entry has no admission authority,
  which breaks pairing with every extension, phone or desktop build from before it.
  It becomes a parent of the merge again, with the migration in
  `docs/p2p-sync-revocation-hardening.md`, once every device is updated. F3 keeps its
  own copy of the password-change handling it shares with F2.
- `feat/vault-sealed-pairing-key` is stacked on the commit of
  `feat/vault-sealed-device-keys` (`4a938c85`), so merging it brings both; the device
  keys branch has no entry of its own. Its old head on origin (`a4ea6fbd`) was built on
  the previous linear stack, F2 included, and is no longer used.

## Version control

This repository is managed with [jj](https://jj-vcs.github.io/jj/), colocated with
Git (`jj git init --colocate`), so Git tooling, CI and the remotes see ordinary
branches. Branches are jj bookmarks; use jj, not raw Git, to commit, rebase and
push. A new isolated checkout is a `jj workspace add`.

`main` is rewritten by every refresh, so the repository config (`.jj/repo/`,
not versioned) differs from the global one. Recreate it after a fresh clone:

```sh
jj git init --colocate
jj config set --repo 'revset-aliases."trunk()"' 'main@upstream'
# Only upstream, tags and the PR branches are protected. main@origin stays rewritable.
jj config set --repo 'revset-aliases."immutable_heads()"' \
  'trunk() | tags() | remote_bookmarks(glob:"fix/*", remote="origin")'
jj config set --repo 'remotes.origin.auto-track-bookmarks' '"main | glob:feat/*"'
jj bookmark track main 'glob:feat/*' --remote origin   # never track main@upstream
```

`fix/*` branches on origin are immutable, which enforces "never rewrite PR
branches". `feat/*` branches are not protected by jj, so keep them unrewritten once
pushed by convention. (The current `feat/*` branches are built on top of `main`'s
old stack and would pin it; new ones are based on `main@upstream`.)

The operation log replaces ad-hoc backups: `jj op log` lists every refresh and
`jj op restore <id>` or `jj undo` reverses one.

The three fixes developed in this thread are:

- `fix/desktop-page-reporting`: announce the current page after connecting to desktop and on window focus.
- `fix/linux-quick-access-backdrop`: opaque Linux Quick Access background.
- `fix/sync-startup-retry`: release failed startup reservations and retry synchronization.

The seven `fix/audit-*` branches other than F2 are included too. Their original branches and
authorship remain unchanged. Newer upstream dependencies take precedence over
older audit versions; the Capacitor security upgrade is retained. The initial
combined branch reconciles the lockfile and its Nix dependency hash.

`archive/combined-fixes-before-split` preserves the original local combined work.
Previously prepared test binaries refer to that original history, not to this
expanded integration. No installed application is updated by repository upkeep.

## Daily refresh

A T3 scheduled task in the existing conversation owns daily repository upkeep.
It runs with an explicit automation task scope, not inferred coop preferences.

1. `jj git fetch --all-remotes`. Require an empty working-copy change, no
   conflicted commits, and local `main` matching `main@origin` (`jj bookmark list
   main` shows no `behind`/`ahead`); otherwise preserve work and report. Note the
   current operation id (`jj op log -n 1`) as the restore point.
2. Check every branch in `sourceHeads` still is what it was: one commit on top of
   its base, and the fetched head (`fix/x@origin`) equal to the recorded one. Stop
   and report on a rewritten or multi-commit branch rather than guessing. Branches
   are never rebased by the refresh, so they need no conflict handling of their own.
   A branch that upstream already contains is dropped from the merge (rule 3).
3. Move the merge onto the new upstream with all of its branches:
   `jj rebase -r main -o main@upstream -o <branch head> ...`, one `-o` per branch
   in `sourceHeads`. jj carries earlier conflict resolutions along, so overlaps
   already resolved in the merge are not reconstructed.
4. Conflicts are recorded in the merge commit rather than stopping the rebase: list
   them with `jj log -r 'conflicts()'`. Resolve only when both intended behaviors
   can be retained and verified. Do not weaken tests or security checks to make an
   integration pass. On an uncertain conflict, `jj op restore` the noted operation.
5. Run affected checks. Refresh the lockfile/Nix dependency hash when needed, inside
   the merge commit. Update source-head metadata only after the corresponding
   changes are included.
6. Publish only main: `jj git push --bookmark main`. jj leases against the
   fetched remote position and refuses if origin moved, and signs unsigned commits
   on push. Fetch again and verify `main@origin` equals `main`. Restore the last
   working main with `jj op restore` when validation fails. Never rewrite PR
   branches, and never push with `--deleted`.

The first refresh is a no-op if upstream and the source branches have not moved.
Keep validation evidence separate from live runtime acceptance. The native upload
test `stream::tests::streams_an_upload_body_with_its_declared_length` failed with
both original and earlier patched sources in the Nix sandbox; report that known
limitation explicitly, and do not silently excuse new failures. Real macOS native
security scenarios, Android/iOS acceptance and mixed-client rollout remain
separate checks. The strict admission changes (F2, currently not merged) require the migration described in
`docs/p2p-sync-revocation-hardening.md`.

## Integration validation limitation

The initial combined native build compiled successfully. With the previously
documented upload test excluded, 218 tests passed, the MinIO test was ignored,
and `native_webrtc::tests::the_engine_opens_a_channel_in_this_apps_build`
timed out with `no channel opened` in the Nix sandbox. The WebRTC test/module and
desktop Cargo.lock match upstream exactly. This is an unresolved test limitation,
not a passing native suite or proof of a specific environmental cause. Do not
silently ignore it or claim live WebRTC acceptance. The full extension suite,
core/desktop/mobile JS suites, workspace type checks, website CSP build check,
mailbox routing checks and fixed-output Nix dependency build passed.

## Native refusal test race

`fix/native-refusal-test` keeps both early-refusal tests enabled and sends only
the link hello before asserting refusal. Sending a handshake frame after the
hello races the server closing an already-refused connection and caused
BrokenPipe in nixfiles CI. This changes test drivers only, not admission logic.
