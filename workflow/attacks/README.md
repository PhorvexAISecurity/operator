# Reusable attack tests

One catalogue, two consumers: scoped fix L3 and campaign rounds. Results and
findings stay in those existing records; this directory is not another backlog.

## Agent entry

- “Verify fix X on dev”: select relevant cases into that fix's attack plan.
- “Test Phorvex on dev”: create a campaign, start with `dev-smoke`, then propose
  the applicable actuator/brain/defense cases. The request need not say “campaign.”
- Read `workflow.py attacks show <id>` and its one procedure, not the reference
  corpus. A catalogue name or realism score is not a verified capability.

Commands use `python3 workflow/tools/workflow.py attacks …`:

```text
list --suite brain-regression
show A1
preflight --context <explicit-context> --namespace <tenant> --output <evidence/preflight.yaml>
plan --fix <fix-id> --case A1 --preflight <file> --by <live-verifier>
plan --campaign <campaign-id> --round round-1 --suite dev-smoke --preflight <file> --by <lead>
record --plan <owner/attack-plan.yaml> --case A1 --observation <file> --by <executor>
report --plan <owner/attack-plan.yaml>
```

Preflight is executable and read-only. Run it where `kubectl` can reach the
cluster (including the existing SSH jump host); never export credentials into
catalogue or evidence files. A context is mandatory. It records what it can
observe; unprobed capabilities remain unknown.

Most cases are **guided**: the assigned agent follows the bounded procedure
using the approved environment and tools. They are not automatically runnable
shell scripts. Historical-only cases require a reviewed, concrete run procedure
in the plan before execution. The old scripts are not blindly invoked: they
patch shared policies, assume old topology, and sometimes force-replace objects.

## Plan and result contract

Attach one `attack-plan.yaml` to a fix or campaign round. It pins catalogue,
procedure hashes, deployment, scope, permission, capabilities, and selected cases.
Use `--permission attack --approval-ref <existing-authorization>` only when that
scope is authorized. Reuse the same explicit approval across its covered cases.
Mutating tests also require `--criteria-file <owner-relative YAML>`; use
`criteria.example.yaml` to pin target, duration, request ceiling, thresholds, abort
and cleanup before execution. Limits apply per case; the owning campaign’s
overall duration/cost ceilings still apply. Historical cases additionally require
`--procedure-file CASE=<owner-relative runbook>`. Missing capabilities block a case; they do not silently remove it from coverage.
Capability additions to preflight use `{available: true, evidence: <local-file>}`.
An observed source SHA needs `--source-sha` and `--pin-evidence`, not a guess from
the image tag. Plans may be made while blocked, to make the missing work visible.

Copy `observation.example.yaml` into the owner's evidence directory and fill it
from the run. Record PASS/FAIL/BLOCKED/NOT_APPLICABLE/NOT_RUN separately from
`defense_outcome`. Every executed case retains hashes of raw evidence, current
pins, executor, approval scope, controls, individual stage results, service
impact and cleanup. PASS of a boundary probe can document an unmitigated attack;
it must never be counted as successful defense.

`record` saves results under the owner's `evidence/attacks/` and adds them to the
existing evidence manifest. `report` writes a coverage report there. Missing,
failed or blocked cases cannot produce a passing fix L3. Campaigns may close
with a reviewed negative verdict, but not unfinished tests or unresolved cleanup.
New findings go through `new-intake`, linked from the observation.

Use `plan --replace` for a new attempt/build: the old plan and its evidence stay
retained. It invalidates earlier aggregate L3 evidence; re-sign current results.
Original August reports are read-only historical references. They do not certify
today's deployment, current CVE applicability, or complete security mitigation.
