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

## Rescale and persistent admission hold

Recommended: same server/fsn1, x86 CX53, 16 vCPU / 32 GB, CPU/RAM only. Keep the current
~160 GB disk. CX53 was publicly unavailable on 2026-10-14; check this server's selector.
If absent, wait for Milad's explicit priced fallback choice. No automatic CPX62 upgrade.
The whole-host outage interrupts Mehrdad as well; the owner must schedule it.
Drain is preparation (historical heavy jobs 15–18m); actual shutdown/provider action
are unbounded references, boot previously 62.468s. CI readiness adds separate checks
and a ten-minute R2 idle sample. Do not promise a fixed total downtime.

After the fresh drain, pass fresh gate evidence to the generalized controller's
`hold <nonce>` action. It creates a root-owned persistent task/nonce hold. Record the
nonce in the task evidence. Every start/abort watchdog respects this hold, including
across reboot when the /run fence disappears. Never set it merely to wait for a date.
If the rescale is cancelled/deferred, `release <nonce>` removes only this task's hold;
use start-only recover-fence immediately. An unknown hold must not be removed.

Mostafa gracefully shuts down, waits for Hetzner Off, chooses Rescale -> CX53 ->
CPU and RAM only (disk disabled), waits for action completion, and powers on.
Do not Rebuild/Reset or force power-off. Record listener-stopped, Off, power-on and
CI-admitted times separately. Rescales use current tariffs; account SKU/price and
backup/recovery access must be confirmed beforehand.

Keep the hold during post-boot checks: same IP/disk/mounts, CPU/RAM, boot journal,
rootless workload presence/health, effective slice properties and daemon containment.
R1 adapts to the new core count. Do not restart Mehrdad's services to repair readiness.
Release the hold and reset primary failure only after these checks, then recover
through the controller's start-only path. Primary recovery precedes R2 acceptance.

## Accept runner 133 after rescale

At another ten-repo idle boundary, drain the primary, set this task's persistent
hold, and run `phvx-runner-capacity --accept-second` as root. It samples for at least
600 seconds: N >=8, physical MemTotal >=24 GiB, MemAvailable >=12 GiB, available
root disk >=40 GiB, full memory PSI avg10 <1%, no new memory events. Any runner
process refuses acceptance. Receipt and root-owned listener count become R2 only
on success. With 16 cores R2 gets CPUQuota1500%, weight700, Go P7.
On failure remain R1; do not lower thresholds to admit a 24 GB advertised plan.

Release only this task's hold, then use start-only recovery. Start runner 133 after
primary readiness; verify its authentication/listener and first actual job ID133,
then enable its existing service for boot. A stale registration blocks admission;
no new registration token, credential copying or scope expansion is permitted.
Run systemctl reset-failed only for a diagnosed guarded-start failure.
Verify two jobs overlap on IDs130/133, separate work/Docker roots, nested build
children in phvxci.slice, cleanup-hook success and combined build disk growth.
Disk below30 GiB, OOM, pressure or output/release differences require R1 rollback
at the next safe drain; only verified completed builders may be reclaimed.

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
Before any downgrade disable R2 and restore R1, then repeat the whole-host drain
and power-off procedure. Original CPX32, if selectable, is current €35.49/month;
CX43 €15.99/month is a disk-compatible R1 candidate, subject to Milad's choice.
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
