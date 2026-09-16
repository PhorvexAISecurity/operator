# Phorvex agent operations framework

**Default fix request:** “Start issue X” → an independently reviewed **PR link**.
Agents handle routine design decisions, tests, peer review and branch/PR publishing
under [standing authorization](operations/AUTONOMY.md). Merge and shared-cluster
changes require separate scope. All quality gates and later live-verification
obligations remain; opening a PR is not closing the issue.

New fixes use a lead and a worker. The lead investigates and writes the fix plan;
the worker implements it. The lead reviews each revision until accepted, delivers
the PR, and verifies the fix live after merge and deployment. See [the fix runbook](operations/FIX.md).

Code and `workflow/fixes/<id>` belong to the same issue branch. Only the runtime
bus is shared between worktrees. Continue verification on that branch after its
code PR merges; see [worktree lifecycle](operations/WORKTREES.md).

One discoverable, versioned home for:

- routing and governing agent requests;
- bug, risk, incident and enhancement intake;
- the generated product anatomy;
- the master issue register;
- fresh system assessments and evidence-backed recommendations;
- the two-agent fix loop;
- per-fix records and reproducible evidence;
- release synchronization;
- optional full-system live campaigns.

The production code remains outside this directory. This initial migration is
additive: the existing local `build/test-harness/`, `fixes/`, and `campaign/`
trees are neither moved nor removed.

## Start here

| Reader | First file |
|---|---|
| Agent receiving any request | `AGENTS.md`, then `OPERATIONS.md` |
| Agent starting/resuming a fix | `operations/FIX.md`, then the stage named by `brief` |
| Agent reporting or verifying a bug | `operations/INTAKE.md` |
| Agent reconciling colleague/main changes | `operations/SYNC.md` |
| Engineer learning the process | `WORKFLOW.md` |
| Engineer choosing work | `issues/MASTER_ISSUES.md` |
| Engineer locating code/operations | `anatomy/ANATOMY.md` |
| Release coordinator | `operations/SYNC.md` and `releases/CURRENT.yaml` |
| Outstanding live verification and missing fixtures | [Live-verification backlog](assessments/LIVE-VERIFICATION-BACKLOG.md) |
| Full-system investigator / master-register regeneration | `operations/ASSESSMENT.md` |
| Campaign owner | `operations/CAMPAIGN.md` |

Run the consistency check from the code-repository root:

```bash
python3 workflow/tools/workflow.py doctor
```

Show the bounded context for one issue or fix:

```bash
python3 workflow/tools/workflow.py brief M-160
python3 workflow/tools/workflow.py brief T1-M160 --agent k3
```

## Source-of-truth map

| Fact | Authority |
|---|---|
| Request routing and common gates | `OPERATIONS.md`, `operations/POLICY.yaml` |
| Fix process and gates | `WORKFLOW.md` |
| Agent startup | `AGENTS.md` |
| Pre-issue claim and dedup state | `intake/*/STATUS.yaml` |
| Issue body, state, tier and dependencies | `issues/entries/*.md` front matter |
| Consolidated issue view | generated `issues/MASTER_ISSUES.md` |
| Anatomy facts | `anatomy/pipeline/*.{tsv,json}` at `anatomy/PIN.yaml` |
| Readable anatomy | generated `anatomy/ANATOMY.md` |
| Current deployed release | `releases/CURRENT.yaml` |
| Main/release reconciliation | `releases/<sync-id>/STATUS.yaml` |
| Per-fix current state | `fixes/*/STATUS.yaml` |
| Campaign state | `campaigns/*/STATUS.yaml` |
| Evidence provenance | each record's `evidence/manifest.yaml` |
| Notifications | `coordination/`; never authoritative |

Generated files are reviewed but not hand-edited.

## Directory guide

- `operations/`: request-specific runbooks and machine-readable policy.
- `assessments/`: four-axis research, coverage, independent review and recommendations.
- `intake/`: non-canonical reported findings and their verification/dedup state.
- `issues/`: one source entry per issue plus the generated master view.
- `anatomy/`: version-pinned source inventories, generators and rendered map.
- `fixes/`: active and closed cycle records with a common schema.
- `verification/`: L0–L4 definitions, shared baselines and permanent suites.
- `releases/`: deployed-build truth and one synchronization record per release.
- `attacks/`: reusable guided tests and read-only preflight; evidence stays in fixes/campaigns.
- `campaigns/`: requested broad testing, including “test the dev cluster.”
- `coordination/`: capability registry and notification bus.
- `archive/`: legacy documents and migration provenance; not startup context.
- `artifacts/`: large retained evidence, normally excluded from Git.

## Two live workflows, deliberately separate

**Fix-level L3** is narrow and closes one fix. It is required for a live
finding, deployment/RBAC/actuation changes, and open-world or timing behavior.

**Full-system campaign** is broad, long-running and optional. It begins only
when the human owner requests it, possibly after several fixes. It can reopen
issues but does not replace each fix's required L3.

## Migration provenance

The first version is assembled from the existing local artifacts under:

- `build/test-harness/PHORVEX_*.md`;
- `build/test-harness/campaign/anatomy-v2/`;
- `build/test-harness/campaign/`;
- `fixes/`.

Those originals remain local and untouched. `archive/MIGRATION.md` records
what was copied, omitted, normalized, or generated.
