# Jump-host validation — 2026-10-28

The bot runs on `87.106.63.105` as the `hami` user service
`phorvex-benchmark-bot`. Its release is independent of the dashboard's `current`
symlink. No workload, cluster configuration or AWS infrastructure was changed.

## Executed checks

- Telegram `getMe`: token identifies `@phorvexbot`; no webhook is configured.
  At the time of inspection, no owner message had arrived and the env allowlist
  still contained the placeholder `0`. One-time private owner pairing is supported.
- The Telegram command menu was configured successfully for `/bench`, `/param`,
  `/status`, `/runs`, `/check`, `/cancel` and `/help`.
- Dashboard login through Caddy's CA succeeds. The dashboard API has remained
  running since 2026-10-12; installation of the bot does not restart it.
- The dashboard's model gateway is `https://codex.algoty.com/v1`, using
  `gpt-6.1-sol` and Responses. Authenticated model listing and real generation
  both succeed with the application User-Agent. The original bot configuration
  incorrectly sent this gateway's key to the public OpenAI endpoint.
- Go unit tests on the previously cached source
  `b11de0aa084a754851cd54c4ec0ddc3638058dd6`: 396 pass events, 2 skips, no failures
  in `./internal/decision` and `./cmd/brain-replay`, uncached with Go 1.26.1.
  This is historical source, not the current cluster revision.
- 65 offline bot tests passed. They cover candidate decision changes, failure before replay,
  credential-free test subprocesses, Responses, revision filtering, parameter
  time windows, private expiring owner pairing, and metric-delta restrictions.
  All 22 Math Lab tests passed, covering the shared replay/analysis/export
  contracts and expired-blob sync behavior.

Host validation artifacts are private under
`~/phorvex-benchmark/bot-validation-20261028/`. The separate historical smoke
uses an isolated data directory, actual archived snapshots and the archived
binary from source `3051797426ce51265bf2757561bffded3bb69268`. Its candidate
adds a comment only; it is a pipeline check and makes no improvement claim.
The first job, `smoke-state/jobs/a16f1ca06712/`, stopped correctly at baseline
tests: 395 pass events, 2 skips, one `TestExactRuntimeMatrix` failure because a
subprocess exceeded its 500 ms budget while other compilation was active.
No benchmark was accepted from that run. A separate retry,
`smoke-state/jobs/cf3d20439055/`, completed the pipeline: both arms passed
396 test events with 2 skips each, baseline fidelity was `EXACT`, and 15 of
16 selected ticks were control-eligible (one was `UNREPLAYABLE`). The result
was `PARTIAL` and the comment-only candidate changed zero decisions. Corrected
exports are in `experiment-verified/`, `report-verified.html` and
`metrics-verified.csv`; arm levels and paired differences are kept distinct,
and the evidence ZIP retains the final result state.
It does not overwrite the dashboard's current binary identity or its corpus.
Owner pairing was subsequently verified on the host. On 2026-10-28 at
17:29 UTC, Telegram accepted a message explaining the prior parameter
validation and its HTML/CSV attachments (message ids 16 and 17). This was
delivery of the recorded result, not a new experiment. The private receipt
is `~/phorvex-benchmark/bot-validation-20261028/telegram-delivery.json`.
This verifies API acceptance, not whether the owner opened the files.

A real parameter experiment on the **current** `0058a3edd2eb` binary also
completed through the dashboard: `/param P-FEA-006 1.2 ticks=16 nosync`, bot
validation job `e42ad15d2ad0`, state `COMPLETE`, comparison `MATCHED_REPLAY`,
16/16 matched ticks per arm and zero changed decisions. Files are retained in
`param-state/jobs/e42ad15d2ad0/`. This is a transport/replay check, not evidence
that changing this parameter improves defense.

## Current source blocker and resolved capture failure

A real dashboard sync resolved the currently deployed binary to source
`0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`, from image
`phorvex:kv-drain-reset-0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`.

None of the existing host clones contains that source commit. A dedicated
bot clone was created at `~/phorvex-benchmark/operator`, borrowing existing
objects read-only. Fetching from GitHub failed because no authentication was
available. Supply read-only access to the correct source repository or a
clone containing that exact commit, then fetch it into the bot repository.
After owner pairing, a second search covering all six host repositories and
linked worktrees still found no such commit; no standard Git credential
helper, GitHub CLI credentials or SSH identity was configured for `hami`.

Sync job `11a22d48-abdd-42bf-9a6d-e1a22c5f3a05` failed with
`HTTPFailure: Console HTTP 404` while downloading a batch. Follow-up reads
established that the index works and three `0058a3edd2eb` blobs return
HTTP 200 with matching content hashes. The deployed console image is
`phorvex-console:actuator-integration-66f9fb1415e8f804b0701871b357c25400955ebe`.
The sync worker now records a missing blob as an explicit rejected tick and
continues downloading valid blobs, newest first; authentication/server
errors still fail. The dashboard worker patch is deployed as the composite
release `20261028-snapshot-sync-27a56761`, retaining every other file from
`20261012-livehub`; the API process was not restarted. A bounded real sync
then downloaded **64/64** verified current-revision snapshots with zero
rejected blobs and refreshed inspection. More snapshots remain available;
the bounded sync is not an exhaustive production backfill.

`/check` reports missing source; matching current ticks are now present.
`/bench` refuses a missing source commit or absent matching ticks before
asking the model or building a candidate. An archived replay
or healthy bot transport is not evidence of current production improvement.
Live defense and SLO outcomes additionally require the separately unfinished
live lab; replay describes decisions on recorded states.
