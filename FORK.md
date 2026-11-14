# Fork integration

`upstream` is bramble-sh/bramble. `origin` is vbargl/bramble.

Each `fix/*` branch contains one issue and stays independent for an upstream PR.
`main` contains current upstream commits first, followed by the fixes from all
branches recorded in [.fork/stack.json](.fork/stack.json). The final integration
commits reconcile overlaps between those fixes and upstream; they do not belong
to any individual issue PR.

The three fixes developed in this thread are:

- `fix/desktop-page-reporting`: announce the current page after connecting to desktop and on window focus.
- `fix/linux-quick-access-backdrop`: opaque Linux Quick Access background.
- `fix/sync-startup-retry`: release failed startup reservations and retry synchronization.

The eight `fix/audit-*` branches are included too. Their original branches and
authorship remain unchanged. Newer upstream dependencies take precedence over
older audit versions; the Capacitor security upgrade is retained. The initial
combined branch reconciles the lockfile and its Nix dependency hash.

`archive/combined-fixes-before-split` preserves the original local combined work.
Previously prepared test binaries refer to that original history, not to this
expanded integration. No installed application is updated by repository upkeep.

## Daily refresh

A T3 scheduled task in the existing conversation owns daily repository upkeep.
It runs with an explicit automation task scope, not inferred coop preferences.

1. Fetch both remotes. Require a clean working tree, no Git operation in progress,
   and local `main` matching `origin/main`; otherwise preserve work and report.
2. Back up the old main ref. Start a temporary integration branch from it and
   rebase it on `upstream/main`. This keeps upstream commits first without
   repeatedly reconstructing already-resolved integration commits.
3. Preserve every issue branch. Compare its fetched head with `sourceHeads`.
   Append new commits from a source branch only when that head advanced normally;
   stop for a rewritten branch rather than guessing which changes to replace.
   Include new `origin/fix/*` branches after checking their base and scope.
4. Let rebase drop equivalent changes already upstream. Resolve conflicts only
   when both intended behaviors can be retained and verified. Do not weaken tests
   or security checks to make an integration pass. Abort on uncertain conflicts.
5. Run affected checks. Refresh the lockfile/Nix dependency hash when needed.
   Update source-head metadata only after the corresponding changes are included.
6. Publish only main with an explicit force-with-lease against the fetched old
   remote SHA, verify the remote SHA, then fast-forward/repoint local main to it.
   Preserve the last working main when validation fails. Never rewrite PR branches.

The first refresh is a no-op if upstream and the source branches have not moved.
Keep validation evidence separate from live runtime acceptance. The native upload
test `stream::tests::streams_an_upload_body_with_its_declared_length` failed with
both original and earlier patched sources in the Nix sandbox; report that known
limitation explicitly, and do not silently excuse new failures. Real macOS native
security scenarios, Android/iOS acceptance and mixed-client rollout remain
separate checks. The strict admission changes require the migration described in
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
