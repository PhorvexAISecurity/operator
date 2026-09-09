# End-to-End

A pipeline that drives Phorvex from its **first** stage to its **last** and proves, with
evidence, that every stage in between did what it claims — plus a dashboard that shows
every value the engine produced and why it decided what it decided.

It runs against the **live** system. Nothing here is simulated: the decision records come
from the operator's own audit stream, and the actuator's claims are checked against the
cluster and against the attacked workload's own logs, never against Phorvex's report of
itself.

---

## Why it exists

`audit.Record` already carries a complete trace of one decision — the physics residual,
the context signals, the kill-chain assessment, the brain's cost terms, the feasibility
verdict, and what the actuator touched. What was missing was something that (a) captures
those records around a real attack, (b) asserts the contracts each stage is supposed to
hold, and (c) shows the whole thing in one place a person can read.

That is this project.

## The six stages

| # | Stage | What it does | What can go wrong |
|---|-------|--------------|-------------------|
| 0 | پیش‌پرواز | console + operator health, target pods, live policy budget | testing a dead system and calling it green |
| 1 | ضبط پایه | capture the decision stream before anything is fired | a stale audit file read as live behaviour |
| 2 | شلیک | fire a real attack through the console's armed path | — (skipped in `observe`) |
| 3 | ضبط پس از حمله | capture only the records the attack produced | attributing pre-existing decisions to the attack |
| 4 | راستی‌آزمایی | verify each actuated claim against the cluster | trusting "success" from the thing under test |
| 5 | چک‌ها | run the assertion catalogue over every record | — |
| 6 | گزارش | write `run-*.json` and a self-contained dashboard | — |

## What it drives

The **in-cluster** stack — the one ArgoCD deploys:

| | |
|---|---|
| console | `https://console.phorvex.ai`, a container inside the operator's pod |
| audit | `/audit/live.jsonl` on a PVC the operator writes and the console streams |
| kill-switch gauge | the operator's `:8080/metrics`, read through the API server's pod proxy |
| ground truth | `kubectl` over SSH to the jump host — deliberately independent of all of the above |

The console has to sit in the operator's pod because it streams `/api/live` from a **file**
and the operator writes that file. Two Deployments cannot share a ReadWriteOnce volume, and
an RWX filesystem would mean provisioning EFS for one append-only file.

Earlier this suite drove a console on the jump host instead. That console was a systemd
service running a binary built from a loose copy of the source — never built by CI, never
deployed by ArgoCD — so the contracts were being asserted against code that could not be
traced to a commit. The jump host is now only the SSH route to `kubectl`.

## Running it

```bash
export PHORVEX_SSH_PASSWORD='…'          # or write it to ~/.phorvex-e2e/secret (chmod 600)

python3 pipeline/e2e.py --list-targets
python3 pipeline/e2e.py --mode observe                    # read-only, no target
python3 pipeline/e2e.py --mode observe --target nats      # read-only, target-aware checks
python3 pipeline/e2e.py --mode attack  --target voicebot  # fires a REAL attack, then clears it
```

`observe` is the default and touches nothing. `attack` posts to the console's armed attack
endpoint, waits for the operator to react, then posts the clear — it changes a live
cluster, so it always requires an explicit `--target` and always prints what it is about
to do.

Output lands in `runs/`: `run-<ts>.json` (everything) and `run-<ts>.html` +
`latest.html` (the dashboard). Exit code is `1` only when a `critical` or `major` check
fails.

### Controller health

`controller_deployments` is the nonempty list of expected Deployment names in
`operator_namespace`. The shipped names match the Phorvex stack and prefixed
Phoenix manager; configure the list when using another release name or topology.
Discovery requires read access to Deployments, ReplicaSets and Pods and follows
their `controller: true` owner UIDs. It does not infer controllers from Pod names,
labels, or merely sharing the namespace. Unrelated helpers and Jobs are ignored.

Both the preflight board and P05 use the same verdict: every expected Deployment
must have owned Pods, and observed controller Pods must be Running, Ready and
within the configured restart limit (including secondary and init containers).
Missing deployments/pods and unreadable or malformed inventories stay explicitly
non-green. This is a snapshot health check, not a Deployment rollout-completion
or desired-replica-count guarantee.

### Targets

| target | namespace | kind | what it exercises |
|--------|-----------|------|-------------------|
| `voicebot` | `voice` | Deployment | the stateless path — Phorvex should **rotate** |
| `nats` | `nats` | StatefulSet | the stateful path — rotate is vetoed, so it should **quarantine** |
| `vllm-kvcache` | `vllm` | vLLM | the AI path — `kv-reset`, confirmed from vLLM's own log |
| `vllm-poison` | `vllm` | vLLM | the AI path — `adapter-rotate`, confirmed from vLLM's own log |

A target has to be armed in **two** places: `targets` here, and `armedWorkloads` in
`phorvex/internal/console/workload_attack.go`. The console refuses an unarmed namespace, so
adding one to this file alone yields a 400 rather than an attack.

### Telegram

`--telegram` posts a live board to a channel and edits it as each of the seven stages
finishes, then rewrites the footer with the verdict, the failing check ids and a link to
the published report.

```bash
export TELEGRAM_BOT_TOKEN='…'
export TELEGRAM_CHAT_ID='-1001234567890'
python3 pipeline/e2e.py --mode attack --target voicebot --telegram \
  --run-label 'local · hami' \
  --report-url 'https://ci-report.phorvex.ai/manual/run-{stamp}.html'
```

Without both variables the notifier is inert, so nothing here is required for a local run.
A Telegram failure is logged and never fails the run — the thing under test is Phorvex, not
the messenger.

## In CI

`.github/workflows/ci.yml` runs the live suite on non-draft pull requests targeting
main and after a release has successfully rolled out. Draft PRs do not fire attacks.
The separate `e2e-contract.yml` workflow runs isolated harness/config/chart regressions
on **all PR bases**, including stacked and draft PRs, without cluster credentials.
Its success is not a live E2E pass or complete operator/backend validation.

| | pull request | after merge to main |
|---|---|---|
| job | `e2e` | `e2e-main` |
| runs against | the **deployed** build | the build the merge just produced |
| report | `ci-report.phorvex.ai/pr-<n>/` | `ci-report.phorvex.ai/main/` |
| result shows up in | a PR comment, updated in place | the job summary |

Both post to Telegram, and both take the `phorvex-e2e-live` concurrency group: the suite
fires real attacks into one shared audit stream, so two runs at once would interleave their
attacks in the same capture window and make attribution unreliable.

### The baseline

`baseline.json` lists checks that are known to fail right now, each with a reason and the
condition that clears it. CI passes `--baseline baseline.json`, which changes **only the
exit code**: a baselined failure is still a failure in the report, in the dashboard and in
the pull-request comment.

The distinction it draws is between *already broken* and *broken by this change*. A gate
that demands an all-green board cannot be adopted onto a system that has a known defect —
the first pull request is blocked by something it did not cause, and the usual response is
to disable the gate entirely. This keeps the gate on and narrows what it asserts to the one
thing a pull request can actually be held responsible for.

Two rules keep it from rotting into a list of muted checks:

- **Every entry needs a `clears_when`.** An entry without an exit condition is a disabled
  check wearing a disguise.
- **A baselined check that starts passing is reported as an error.** The run prints it, the
  PR comment calls it out, and `staleBaseline` records it in the run JSON — because a
  baseline that outlives its cause is a permanent blind spot, and the failure mode is
  silent.

Removing the last entry is the goal, not the exception.

**What a PR run does and does not prove.** There is one live cluster and no ephemeral
environment, so a pull-request run exercises the build that is *currently deployed*, not the
build the PR would produce. It proves the contracts still hold, and it exercises any change
the PR makes to the suite itself. The gate on the PR's own code is `e2e-main`, which runs
after the new image is actually serving.

Reports are published by `publish-report.sh`, which routes runner → jump host → `kubectl cp`
into the `ci-reports` nginx pod, because GitHub's runners cannot reach the EKS API directly.
`summary.py` turns `run-<stamp>.json` into the PR comment.

### Keeping old PRs and the harness current

A rerun uses the workflow and test code of the original revision. It does not
automatically pick up fixes subsequently merged into main. Update the PR branch
with current main (preserving its changes), or explicitly backport the reviewed
harness fix, then validate the new revision. For stacked PRs, update the parent
first and resolve/review each child; do not replace their source with main.

The September 8 failures had distinct causes:

- Older A05 runs used the console-created signal and post-fire capture. Main's
  merged #126 supplies a dedicated authenticated detector and connects capture
  before injection. Do not relax production detector trust to make old tests pass.
- #140's chart-sync failure found a leftover `leader-election-rbac.yaml` in the
  runner's shared `/tmp/vendored`. Main's #126 already uses a fresh temporary
  extraction directory, with positive and negative regression tests.
- Run `34249621578` received the dedicated signal, but F01 rejected the legitimate
  `proactive-cadence` veto from deployed 0.4.97. The E2E law map now includes it.
  A regression replays that exact reason, and a source-inventory test requires
  every production feasibility law to have a reviewed E2E reason prefix.

Do not add these failures to the baseline or disable the checks. New feasibility
laws must update `known_laws` and `law_reason_prefixes` together with the code.
Release rollout failures are separate: if `deploy` fails, `e2e-main` is skipped,
and no post-deployment E2E success may be claimed.

## The check catalogue

39 checks across the six stages. Each one records what a pass *proves*, not only that it
passed. Severity is about consequence:

- **critical** — a contract violation; the system did something it says it never does
- **major** — a value or explanation the dashboard would show that is wrong or impossible
- **minor** — a smell worth reporting that does not by itself invalidate a run

The load-bearing ones:

| id | Checks | Why it matters |
|----|--------|----------------|
| `PH01` `PH02` | residual in `[0,1]`; **no non-finite number in any field** | the NaN class that silently collapsed selection to noop |
| `C06` | `nextStage` is a legal successor of `stage` | catches a broken kill-chain classifier, including the lateral jump |
| `C08` | `margin < 0 ⟺ hazard > 0.5` | both come from the same Weibull, so at `exposure = median` the hazard is exactly `0.5` — an exact identity, not a tuned threshold |
| `B01` | `net == risk − λ·cost` | the identity the whole decision rests on |
| `B05` | selected ⟹ feasible | the brain must never pick a move safety vetoed |
| `B07` `B08` | tick budget respected; one action per asset per tick | the greedy loop's two hard constraints |
| `F02` | no infeasible action was actuated | fail-closed actually holds at the emit boundary |
| `F03` | no rotate on a stateful pod — **verified with kubectl**, not the record | `stateful-integrity` in reality, not in claim |
| `A01` `A04` | actuated ⟹ selected ∧ feasible ∧ ¬dryRun | the authorisation chain |
| `A03` | the cluster confirms the change | pod UID, AMTD ownership, or the workload's own log |
| `P05` | expected controllers are present, Running and Ready, within restart limits | follows configured Deployment ownership; namespace helpers cannot satisfy or fail controller health |
| `A06` | absence of actuation matches the writer's real state | "selected but never actuated" has two very different causes — a deliberate kill switch, or a broken actuator. Read from the operator's own `phorvex_kill_switch_engaged` gauge rather than inferred from an absence |
| `A07` | the dashboard's source identifies itself | a kill-switched mirror whose records don't say so is indistinguishable from a broken actuator |

A check that cannot be evaluated returns **skip** with the reason. It never returns pass
for something it did not look at — a green board built on unrun checks is worse than a
red one.

## Ground truth

`groundtruth.py` reads no Phorvex field at all:

| action | how it is confirmed |
|--------|---------------------|
| `rotate` | the pod's UID changed, or the name is gone |
| `quarantine` | `ownerReferences[0].kind == AdaptiveMovingTargetDefense` |
| `kv-reset` | vLLM logged `reset_prefix_cache` itself |
| `adapter-rotate` | vLLM logged the adapter unload/load itself |
| anything else | reported **unverifiable** — deliberately not confirmed |

## The dashboard

`runs/latest.html` — self-contained, no build step, opens from a double-click, light and
dark. Four parts:

1. **Verdict band** — the roll-up, the four counters, and the run's own metadata
   (versions, transport, policy budget, record counts).
2. **Signal path** — the six stages as one strip, each coloured by its *worst* check. This
   answers "which stage broke" before you read anything.
3. **Checks ledger** — grouped by stage, filterable, each expanding to what a pass proves
   and the raw evidence rows.
4. **Decision traces** — every decision, expanded into its six stages, with each field next
   to **its value, its legal range, the function that produced it, and why it matters**.
   Every acted or selected decision is rendered in full; the repetitive no-action tail is
   sampled one-per-pod and the omitted count is printed.

Absence is drawn differently from zero throughout — a missing field is an em dash, because
`residual = 0` and "no telemetry" are not the same claim.

## Layout

```
config.json               targets, endpoints, thresholds, and the law→reason map
pipeline/
  e2e.py                  orchestrator + CLI
  transport.py            local | ssh; console API and kubectl access
  trace.py                record → six-stage trace, with per-field provenance
  checks.py               the assertion catalogue
  groundtruth.py          independent verification of actuator claims
  report.py               the dashboard renderer
  notify.py               the Telegram progress board
summary.py                run-<ts>.json → the Markdown that lands on the pull request
publish-report.sh         runner → jump host → ci-report.phorvex.ai
runs/                     run-<ts>.json, run-<ts>.html, latest.html
```

Adding a field to the dashboard means adding one line to `FIELDS` in `trace.py`. Adding a
check means one decorated function in `checks.py`.

## Known limits

- The SSE endpoint replays the audit file, so a capture window includes recent history,
  not only new records. The pipeline de-duplicates and separates pre/post by key, but a
  very long window will pull in older ticks.
- `A03` can only confirm four action types. Everything else is reported `unverifiable`
  rather than assumed good.
- `A07` stays red until the operator is **rebuilt and deployed**. The `killSwitch` stamp
  exists in `model.Decision` / `audit.Record` / `runner.processTenant` in this repo, but the
  running binary predates it, so a kill-switched mirror is still indistinguishable in the
  audit from a broken actuator. The first `e2e-main` run after a merge that rebuilds the
  operator is the one that turns it green — until then every PR run reports this single
  known failure.
- `--mode attack` covers one target per run. Firing several in one pass would let their
  reactions overlap in the same audit window and make attribution unreliable.
