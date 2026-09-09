# Attack workflow integration — 2026-09-07

One reusable catalogue feeds fix L3 and existing campaign rounds. Imported 60
canonical historical cases (preserving G2/G3 redirects and prior realism scores)
and added seven explicit engineering probes. Agents load selected procedures;
the historical corpus is optional reference, not startup context.

Plans bind assigned execution roles, deployment pins, prerequisite evidence,
namespace/workload scope, per-case limits, success/abort/cleanup criteria and
procedure hashes. Results preserve raw evidence and separate test disposition
from defense outcome. Replacing a plan preserves history and invalidates prior
aggregate verification. Fix/campaign transitions consume the recorded results.

Validation:

- Full harness check: **52 tests passed**, index/render checks passed, doctor
  zero errors. [Raw output](evidence/attack-integration-check.txt).
- After the final target-scope validation and its extra regression test:
  **13 attack tests passed**. [Raw output](evidence/attack-integration-targeted.txt).
- CLI discovery and suite selection exercised; changed-file whitespace check passed.

Tests cover blocked prerequisites, deployment mismatch, role assignment, natural
versus synthetic detection, independent outcome stages, run limits, namespace
scope, retained evidence tampering, immutable attempts, rollback, cleanup,
negative campaign results, transition gates and stale aggregate attestations.
Read-only preflight/health use mocked Kubernetes responses in tests.

Two existing fix records (T1-M020/T1-M023) needed folded YAML scalars around
PR-reference text; their state and next-action wording were preserved.
Doctor's 13 warnings remain: ten legacy verifier gaps, newer main, unreviewed
historical anatomy joins, and a stale anatomy/release pin.

No live attack, deployment or campaign was executed. Mutating tests remain
agent-guided procedures; this integration does not establish current actuator,
brain or full-system defense coverage. Historical reports/scores are not current
verification. Product findings continue through the existing intake process.

## Implementation fingerprints

| File | SHA-256 |
|---|---|
| `attacks/catalogue.yaml` | `9e28c5487ad56ff09036639b37f1ba8f74ef92ecf26e32341dd754ce02ee1376` |
| `attacks/README.md` | `de85c23dcdf54b572c1667a1e3c0ba27d6ebc8263f9df0ef297659159962ab90` |
| `tools/attacks.py` | `b725e54aa6f68cf530abae805c3a81d2236d247bcb079e076bb0632b21df0ec4` |
| `tools/gates.py` | `916a57088280f744767e812db2b064a0deb68c9c975efc3770405fdb8dde3170` |
| `tools/workflow.py` | `891f09773b28073ffb7b2712288e596a58aa85afd54523bb8fc5aafcf3a11891` |
| `tools/tests/test_attacks.py` | `29b48310ec9df21377bb2b817f91af17db77a15ece83b25780d5751daedfa8ce` |
