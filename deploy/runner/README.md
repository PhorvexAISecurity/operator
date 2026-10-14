# Phorvex shared-host runner capacity

This payload is for server 165066825 / ubuntu-8gb-fsn1-4 / 91.99.2.226 only.
No credentials or runner registrations are copied. Runner 130 stays primary;
runner 133 remains disabled until the capacity gate and authentication checks pass.
The empty action-runner-2 directory is unclassified and is never a deletion root.

## Installation and admission

First run the focused tests from the repository root:

```
PYTHONPATH=deploy/runner python3 -m unittest discover -s deploy/runner/tests -v
python3 .github/runner/test_workflow_policy.py RunnerSpeedPolicy
```

The legacy workflow-policy suite's old hardening baseline has independent failures
on current main. Record main/candidate side by side rather than expanding this diff.
The fresh-main comparison must pass. Re-pin RUNNER_SPEED_BASELINE after rebasing.

Use the existing ten-ADMIN-repository local gate.py orchestration and audited live
maintenance controller to drain at an idle boundary. A busy/API/unknown result means
defer; do not cancel jobs. Upload these reviewed payloads to a task-owned staging
folder and run install.py as root with a unique /var/backups/phvx-runner-speed-* path.
It requires the existing offline fence, absent runner processes/descendants and
runner 133 disabled. Preserve the existing primary lease directory in place.
The capacity oneshot sets R1/300%/weight100/P2 on four cores. Docker/containerd are
never restarted to apply CPU properties. After installation, recover-fence starts
only the configured listener(s). Ensure the hourly hygiene timer remains enabled.
The root guard uses ExecStartPre=+ so it can own the global admission lock. No job
receives root access through this unit setting.

Both profiles are an exact root-owned allowlist in /etc/phvx-runner-hygiene.json.
Both timer passes share one cleanup lock and the original 80-second total budget.
Either Worker, unknown runner process, unknown descendants, unmatched active logs,
nonterminal attempt or wrong-profile lease prevents deletion. Legacy schema-1 ID130
leases retain their original identities and state. The failed inactive R2 has no
admitted job and is verified absent instead of treating its OOM log as idle evidence.
Completion hooks return success; their destructive flags remain false.

## Final host and persistent admission hold

The final host is CPX42: 8 vCPU / approximately 15 GiB physical RAM. No further
rescale is required. The 2026-10-14 18:20 update replaces the old 24 GiB threshold.

Setting `hold <nonce>` still requires a fresh complete idle gate after drain.
The root-owned persistent task/nonce hold blocks starts across reboot. Explicit
`release <nonce>` accepts queued work with fresh complete ADMIN evidence, verifies
this task's nonce, and removes only that hold. Follow immediately with start-only
`recover-fence`; neither operation stops or cancels work. Wrong nonces remain refused.
Draining/stopping services and setting a hold retain the strict idle gate.

## Accept runner 133 on CPX42

Measure the CI slice over real console and operator builds while Mehrdad's slice
is running. Retain job/run IDs, successful conclusions, physical RAM, boot ID,
CI memory.peak and memory.events. If CI peak exceeds 11 GiB or an OOM occurs,
keep runner 133 disabled. An idle memory sample does not prove build capacity.

A root-owned measurement receipt supplies `physical_bytes`, `ci_peak_bytes`,
`mehrdad_running`, `oom_kill_delta`, `boot_id`, and `build_jobs` containing name,
job_id, run_id and conclusion for both builds. At a fresh idle drain, run
`phvx-runner-capacity --accept-second --measurement /root/task-measurement.json`.
It requires a receipt from this boot, at least 8 cores / 14 GiB physical RAM,
30 GiB free disk, and full memory PSI avg10 below 1%. R2 sets the aggregate
phvxci.slice MemoryHigh=9G, MemoryMax=11G and MemorySwapMax=0, verified in cgroup v2.
Listeners, rootful Docker/containerd and nested build containers must all be in
that slice. A ceiling-triggered OOM is confined to CI cgroups; Mehrdad's slice
and system service memory policies are unchanged. Eight-core R2 uses CPU700%,
weight300 and Go P3 per build.

Release this task's hold and use start-only recovery. Verify authentication and
actual jobs on IDs130/133, overlapping builds, separate work/Docker/state roots,
cleanup-hook success and memory.events. Enable the existing runner-133 service
for boot after these checks; no re-registration or credential copy is needed.
If no idle boundary arrives, defer service changes and report the queue.

## Rollback

CPU pressure/OOM: use rollback.py --cpu-only with the captured CPU baseline even
while a job runs. It restores quota/weight and exact task runtime/persistent files;
no process signals/restarts. Configuration/helper regression: drain both listeners
with a fresh global gate, leave runner 133 disabled, restore listeners=1, and restore
the captured helper/configuration backup with rollback.py. Keep newer leases and
evidence; restoring legacy helpers is permitted only after R2 is fully absent.
Recover primary through start-only admission. Never recreate the old orphan state.
Source regression: reviewed revert of this PR only, preserving newer work and
release/hardening policies; let live jobs finish, never retag/manual-push images.
Cache eviction cannot be rolled back. Do not prune shared caches, ptest volumes,
workspaces, rootless objects or any Mehrdad files/services/slice.

## Performance verification

Builds remain in self-hosted ci.yml with existing ECR OIDC, push/tag/cache settings,
per-job Buildx cleanup, release pins, runs-on and protected concurrency unchanged.
Only operator/console capacity steps and BUILD_JOBS arguments were added. There
is no BuildKit max-parallelism cap; Go builder stages explicitly consume BUILD_JOBS.
Cache mounts reuse compilation within a builder; GHA does not preserve mount contents
between disposable jobs. Do not describe an unchanged full layer hit as build speed.
Controlled old/new image equivalence and cold/warm/source-change timing require an
isolated idle window on the resized host, pinned input digests and task-owned exact
builders. PR builds do not prove deploying-main timing or the out-of-scope rollout wait.
