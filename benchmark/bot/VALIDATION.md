# Jump-host validation — 2026-10-28

The bot runs on `87.106.63.105` as the `hami` user service
`phorvex-benchmark-bot`. Its release is independent of the dashboard's `current`
symlink. No workload, cluster configuration or AWS infrastructure was changed.

## Declarative study deployment — 2026-10-31

The user explicitly requested deployment after the local implementation. Source
`bb22a9bdda4e3c9b7a13cd0d1c358ea8c052b4fc` is now active as
`~/phorvex-benchmark/releases/bot-dynamic-bb22a9bd`. Activation occurred at
06:57:42 UTC; post-deployment verification completed at 06:58:41 UTC.

All 17 existing bot Python files matched the reviewed base before staging. The
release preserves the previous release's worker/registry dependencies and guide
assets, and overlays the 18 committed changed/new files; all 18 hashes matched
after deployment. The initial staging test found a missing deployment-unit test
fixture; including the previous release's `benchmark/deploy` directory resolved
it, and all **111 bot tests passed on the server**. Preflight passed for Telegram,
authorization, private state, dashboard, current replay/source, disk, Go and model
access. No completion-generating model call was made.

Both reference-study examples completed on the host: Cost with 2 arms × 3 seeds,
History with 4 arms × 3 seeds. These are explicitly **synthetic**, not observed
production coverage or SLO outcomes. The normalized recorded History dataset is
not yet installed; a recorded study correctly requires that evidence.

There were no queued/running jobs before the switch. Only the bot unit's working
directory changed. The running process uses the new release and had no restarts
or startup errors at verification. Telegram read-back confirmed `/study` and the
full 13-command menu for default, English and Persian locales; polling started.
Verification sent no Telegram chat messages. API, web and proxy process identities
and uptime, dashboard `current`, owner, membership and update offset were preserved.

Private evidence and the original service unit are retained under
`~/phorvex-benchmark/bot-validation-20261031/dynamic-bb22a9bd/`:
`baseline.json`, `preflight.log`, `host-bot-tests.log`, both study outputs,
`activation.json`, `verification.json`, and `previous-bot.service`.
The previous release `bot-ebc3dbce` remains available. Rollback consists of restoring
the saved service unit, running `systemctl --user daemon-reload`, and restarting
`phorvex-benchmark-bot.service`; it does not require changing persisted bot state.

## Playbook refresh — 2026-10-28

Documentation commit `1f04c275` synchronizes the Persian and English playbooks
with document uploads, validate-only captions, optional sections, batch summaries
and activity cards. Both HTML editions have 11 sections. The Persian PDF has
18 pages and the English PDF has 19. All embedded file examples matched the
bundled templates and parsed with the actual request parser. Both editions
passed browser layout and interaction checks at 320–1440 px.

The four guide assets were updated in the active `bot-ebc3dbce` directory using
staged atomic file replacements, with previous files retained privately. No bot
code or unit was changed: PID and start time were unchanged, as were dashboard
identity, API uptime and the paired owner.

An operator-invoked `/guide` handler sent the refreshed English HTML and PDF;
Telegram accepted them as messages 148 and 149. Both attachments were downloaded
again through Telegram, and their SHA256 digests matched the committed assets.
This was a delivery check, not an incoming user command. All four services were
active. Private installation and delivery evidence is under
`~/phorvex-benchmark/bot-validation-20261028/guide-refresh-1f04c275/`.

## Document batches and activity cards — 2026-10-28

Bot release `bot-ebc3dbce` adds Markdown/TXT/DOCX uploads, `/upload`,
`/validate` captions and `/templates`. All **93 offline bot tests** passed,
including mixed bench/param execution, optional sections, registry domains,
malformed documents, ZIP/XML bounds, authorization, cancellation, partial
runtime failures, and editable heartbeat cards. The combined code/parameter
test uses the existing fake-Go/model/dashboard fixtures; it establishes routing
and evidence behavior, not a new live candidate's quality.

The updated English guide passed browser checks at 320–1440 px. Its **18-page
PDF** includes the upload examples, validation modes and activity explanation.
Five completed examples are shipped, including a real `.docx` document.

Host verification used the same document handler with actual Telegram file IDs
and `getFile` downloads. It was **operator-invoked, not an incoming user update**:
all five template documents were accepted by Telegram; the Word document parsed
both sections in validate-only mode without queuing; a mislabeled binary file
was rejected without a queued experiment.

The uploaded parameter-only TXT became batch `fd6c55c5b647`, child job
`9093f5e2030e`. It completed through the real dashboard with `MATCHED_REPLAY`
and **16 control-matched ticks**. The per-experiment report and batch JSON/CSV
were delivered. Four activity cards received **22 successful edits**, including
terminal states; no Telegram API errors were recorded. There were 11 accepted
attachments across template, sample and report delivery.

Private evidence is retained in
`~/phorvex-benchmark/bot-validation-20261028/file-batches/delivery.json`.
All four services remained active; the dashboard pointer, API uptime and paired
owner matched the pre-install baseline, and membership records remained valid.

## English interface and guide delivery — 2026-10-28

Bot release `bot-ed00c1f6` serves `/guide` and includes the English HTML
playbook and its 15-page PDF. All 76 offline bot tests passed, including
authorized member downloads, stranger refusal, missing-file handling, upload
failure/retry and duplicate requests without blocking other commands. Browser
checks passed at widths 320, 390, 768, 1024 and 1440, including the command
builder, copy fallback and print output. PDF text extraction verified English
content, `/guide` and the expanded FAQ.

Telegram read-back confirmed the English name, descriptions and nine-command
menu for default, English and Persian locales. Startup reapplies these settings.
The running service handled a **real incoming `/guide`** at 19:41:48 UTC:
Telegram accepted its HTML and PDF attachments as messages 90 and 91.
The uploaded release contains the 70,434-byte HTML and 215,920-byte PDF.
Telegram reports the HTML as `application/octet-stream` and the PDF as
`application/pdf`; the download filenames retain their correct extensions.

Private verification evidence is in
`~/phorvex-benchmark/bot-validation-20261028/english-guide/delivery.json`.
The dashboard release pointer and API uptime matched the pre-install baseline,
and all four benchmark services were active. The paired owner's file was
unchanged. One new member joined through a valid invitation during verification;
that membership was preserved and its invitation event was verified.

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
- 66 offline bot tests passed. They cover candidate decision changes, failure before replay,
  credential-free test subprocesses, Responses, revision filtering, parameter
  time windows, private expiring owner pairing, and metric-delta restrictions.
  All 24 Math Lab tests passed, covering the shared replay/analysis/export
  contracts, expired-blob sync behavior and bounded header-only indexing.

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

## Source access restored and resolved capture failure

After the owner supplied GitHub access, source
`0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec` was fetched successfully from
`PhorvexSecurity/operator` into `~/phorvex-benchmark/operator` and pinned under
`refs/benchmark/deployed/<full-sha>`. Authentication used a temporary private
askpass file; the token was removed and never written to Git configuration.
Earlier failed source-access checks below describe the pre-fetch state.

The verified deployed binary reports **Go 1.26.10**, while the host SDK is
1.26.4 and the original helper default was 1.26.1. The bot now reads the
compiler release from deployed build metadata and selects it for both test
arms and both builds. The exact 1.26.10 toolchain was fetched successfully.
Offline tests also exercise a deployed compiler newer than the installed SDK.

## Current-source verification

The first current-source job, `0fa8ea377742`, stopped at baseline tests:
397 pass events, 2 skips and one `TestExactRuntimeMatrix` failure when its
subprocess exceeded the unchanged 500 ms budget during cold compilation and
concurrent sync. The failed job, raw log and Telegram receipt are retained;
Telegram accepted that failure log as message 24.

On this 1.8 GiB host, test packages now run serially; no tests were excluded
and no deadlines were relaxed. Snapshot indexing reads the declared header
only, rather than reading payload bytes from every corpus file. The worker
change is deployed in composite release `20261028-header-reader-54417066`;
the Telegram service runs bot release `bot-54417066`.

Retry `0deacfd4c571` ran uncached tests on source `0058a3edd2eb` and its
comment-only candidate `396a3f2b7b69ec1815d71d2323b36ecacdbcf538`, both using
Go 1.26.10. **Each arm passed 398 test events with 2 skips and zero failures**
in the decision/replay packages. The full result and delivery receipt are
retained in `~/phorvex-benchmark/bot/jobs/0deacfd4c571/`.

The current-source pipeline completed at **2026-10-28 18:22:59 UTC**:

- Result `COMPLETE`, comparison `OBSERVATIONAL`, toolchain fidelity `EXACT`.
- All **64/64** frozen ticks were control-eligible and matched in all three
  arms, with no exclusions.
- The locally rebuilt baseline is **byte-identical** to the deployed binary
  (same sha256), in addition to reproducing its decisions.
- The comment-only candidate changed **0/64** decisions. This is an expected
  pipeline positive control and makes no optimization or defense claim.
- Telegram accepted the HTML report, CSV, candidate diff and tests JSON as
  messages **59, 60, 61 and 62**. The API receipts are retained in the job's
  `delivery.json`; they establish delivery acceptance, not whether files were opened.
- The evidence ZIP contains final state `COMPLETE`, consistent with `result.json`.

The source-access blocker is resolved and `/bench` is enabled. This verification
was initiated by the operator on the server using the same bot pipeline and
the authorized owner's real Telegram transport; it was not an incoming user
command. The normal Telegram command queue remains served by the running bot.

Dashboard sync `3b521a06-d84c-4ea3-bbf4-a9a24db9fc13` completed successfully:
5000 indexed entries were processed, 4907 verified snapshots downloaded and
93 missing blobs explicitly rejected. Together with the earlier bounded sync,
the host holds 4971 finalized snapshots from the current source. The full
corpus holds 14916 snapshots; older revisions are excluded before sampling.
More entries remain available, so this is a bounded batch, not an exhaustive
backfill.

A real dashboard sync resolved the currently deployed binary to source
`0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`, from image
`phorvex:kv-drain-reset-0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`.

Initially none of the existing host clones contained that source commit. A dedicated
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

`/check` can now resolve the source; matching current ticks are also present.
`/bench` refuses a missing source commit or absent matching ticks before
asking the model or building a candidate. An archived replay
or healthy bot transport is not evidence of current production improvement.
Live defense and SLO outcomes additionally require the separately unfinished
live lab; replay describes decisions on recorded states.
# Declarative studies — local validation, 2026-10-31

Implemented on `feat/benchmark-dynamic`, based on bot source
`42f387829150ee4e6722ced81ffc1e9d9e5df71f`. This record is local development
evidence, not a new live-deployment claim.

* Python bot suite: **111 tests passed**, including 18 new study tests.
* Python worker suite: **54 tests passed**.
* `git diff --check`: passed.
* Executable Cost example: COMPLETE, explicitly synthetic, 2 arms × 3 seeds.
* Executable History example: COMPLETE, explicitly synthetic, 4 arms × 3 seeds.
* Telegram upload/validation/queue/report delivery exercised using the real study
  implementation and a fake Telegram transport; no LLM, dashboard, Go or cluster
  calls are required for inline studies. Recorded-trace import/load/freeze is tested
  with local fixtures, not an actual deployment ledger.
* Checks cover cold/calibrated/censored duration bounds, failure bounds, quarantine
  holds, epsilon/tie correctness, stable seeds, arm isolation, acknowledged starts,
  identity replacement, rolling expiry, fact novelty, missing-history fallback,
  missing budgets, mandatory/NOOP behavior, cancellation and output escaping.
* A diverged local baseline now marks a code-replay experiment INVALID. Declined
  code requests send sanitized context/attempt diagnostics to the requesting chat.

Commands used from the implementation worktree:

```sh
python -m unittest discover -s benchmark/bot -p 'test_*.py'
python -m unittest discover -s benchmark/worker -p 'test_*.py'
```

Python 3.11 and the existing pinned `openpyxl==3.1.5` requirement were used in an
isolated venv. TMPDIR was on `/workspace` because this environment mounts `/tmp`
with `noexec` and existing pipeline tests execute temporary fixture binaries.
The workflow doctor was unavailable because PyYAML is absent; no workflow state or
product code was changed. The new reference runner itself uses only the standard
library. No live model call, deployment or defense/SLO outcome experiment was run.

Current limitations and the normalized recorded-evidence contract are documented
in [STUDIES.md](STUDIES.md); successful synthetic execution does not resolve them.
