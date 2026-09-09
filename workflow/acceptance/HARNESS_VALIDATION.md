# Harness validation — 2026-09-07

Scope: offline harness implementation and migrated anatomy reproducibility.
Source: `docs/workflow`, commit `59be161468307c01d7cd10ce97543f817e2ef96d` plus the working-tree files hashed below.

- `bash workflow/tools/check.sh`: **PASS**, 40 tests; index/render checks pass;
  doctor reports zero errors. Raw output: [harness-check.txt](evidence/harness-check.txt).
- `python3 workflow/tools/workflow.py anatomy-refresh --source-ref fb52e6c976df --check`:
  **PASS**, 11 audits, 65/65 mutations caught, no generated drift.
  Raw output: [anatomy-check.txt](evidence/anatomy-check.txt).
- `git diff --check`: **PASS**.

The synthetic lifecycle covers new-fix → configuration → independent seal →
agreement → implementation → offline verification → P3 → PR_READY; a separate
integration test exercises main/deployment/final-verdict reconciliation.
Adversarial tests reject missing evidence, self-review, stale revisions,
concurrent overwrite, changed artifacts/plans, wrong source pins, and forced
forward transitions. Startup instructions plus one fix stage are bounded at
1,250 words, excluding task-specific issue/source evidence.

Remaining warnings are historical: ten missing legacy verifiers, a newer main
ref, 126 unreviewed keyword joins, and an anatomy pin older than the observed
release. These are not silently waived or represented as current verification.

This does not establish live release acceptance or an independent model's
behavior. The first real reconciliation remains in [HELD_INTEGRATION.md](HELD_INTEGRATION.md).
No product fixes, cluster changes, PR creation or merge are part of this run.

## Reviewed working-tree files

| File | SHA-256 |
|---|---|
| `AGENTS.md` | `ca7025c1978475aea1a2a0095258fa210ddee975c00e67d0adb3e910d94073b9` |
| `OPERATIONS.md` | `5ff96369f63c43d1e42f47f60636befde1b6bd66772bf1bc8205bfd1d60b68a0` |
| `WORKFLOW.md` | `02a6925d330395e5697a8fea268a1bd51932533f501369d73dd12384e62632ab` |
| `tools/workflow.py` | `709a62978b95b22200c1985a359bad2c9e376ecbf1ea21e1f2340d934263ea50` |
| `tools/gates.py` | `b305f5a448d81af2701ccb9e74f9e9c2c169ef56efba3446953bcc9dc2631ed8` |
| `tools/tests/test_contracts.py` | `15fb41a659a9096ac829e33e62cfcc9aba628ce954bbe753f4c944f92df68b02` |
| `tools/tests/test_operations.py` | `234b3a6c5f3feb43347a4fccf805dd7a0bff1a2972b5e5fb1d3905aba2c79442` |
| `tools/tests/test_workflow.py` | `ccdcefd0ad4f6ddce2eb152d5ea8fdcd24994b155b9c3e99e98f4b06c95b4d01` |
