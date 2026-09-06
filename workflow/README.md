# Phorvex workflow

One discoverable, versioned home for:

- the generated product anatomy;
- the master issue register;
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
| Agent starting/resuming a fix | `AGENTS.md` |
| Engineer learning the process | `WORKFLOW.md` |
| Engineer choosing work | `issues/MASTER_ISSUES.md` |
| Engineer locating code/operations | `anatomy/ANATOMY.md` |
| Release coordinator | `releases/CURRENT.yaml` and `WORKFLOW.md` |
| Campaign owner | `campaigns/README.md` |

Run the consistency check from the code-repository root:

```bash
python3 workflow/tools/workflow.py doctor
```

Show the bounded context for one issue or fix:

```bash
python3 workflow/tools/workflow.py brief M-160
python3 workflow/tools/workflow.py brief T1-M160
```

## Source-of-truth map

| Fact | Authority |
|---|---|
| Process and gates | `WORKFLOW.md` |
| Agent startup | `AGENTS.md` |
| Issue body, state, tier and dependencies | `issues/entries/*.md` front matter |
| Consolidated issue view | generated `issues/MASTER_ISSUES.md` |
| Anatomy facts | `anatomy/pipeline/*.{tsv,json}` at `anatomy/PIN.yaml` |
| Readable anatomy | generated `anatomy/ANATOMY.md` |
| Current deployed release | `releases/CURRENT.yaml` |
| Per-fix current state | `fixes/*/STATUS.yaml` |
| Evidence provenance | `fixes/*/evidence/manifest.yaml` |
| Notifications | `coordination/`; never authoritative |

Generated files are reviewed but not hand-edited.

## Directory guide

- `issues/`: one source entry per issue plus the generated master view.
- `anatomy/`: version-pinned source inventories, generators and rendered map.
- `fixes/`: active and closed cycle records with a common schema.
- `verification/`: L0–L4 definitions, shared baselines and permanent suites.
- `releases/`: deployed-build truth and one synchronization record per release.
- `campaigns/`: explicit-request-only full-system campaigns.
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
