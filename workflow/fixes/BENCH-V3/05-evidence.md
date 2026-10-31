# BENCH-V3 implementation evidence

## Source and scope

- Baseline: `bb92355cf7b6c4a696f44caf52bd5fa1268e7303`.
- Proposed source: `00eac153f3f27929907f91d4231362051664364c`, branch `fix/benchmark-v3-capture`.
- Final compiler: exact Go 1.26.3 with GOTOOLCHAIN=local, matching current CI's
  build/test-harness/go.mod authority. Python 3.11.17/3.12.15, Helm 3.16.4,
  and genuine GNU tar 1.35 are provisioned locally.
- Recorded/deployed corpus remains `0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`.
  This worker made no production query or operator rollout.

Adds UID-bound controller replica-spec observations, immutable bounded replica
history export, a default-off manager capture option, actual brain/sensor
transport coverage and optional snapshot inspection. Existing DesiredReplicas,
admission, selection, policy defaults and actuators remain unchanged.

The integrated proposal preserves upstream --version, StatefulRotation behavior
and GVK-aware cache identity. Evidence reads the owner cache only after the two
existing observers; it cannot issue additional API Get/List calls. Existing
StatefulSet reads can supply spec observations. Unobserved direct Deployment
owners and Phoenix without a reader remain unknown. Counting-reader and GVK
regressions exercise the actual producer chain.

Shared model DTOs carry all 26 replica-history fields through explicit value
conversion. No shared/brain package imports the dispatcher ledger. Clone owns
mutable slices. The real ledger-to-DTO JSON comparison prevents silently losing
attribution, censoring, bounds or separately observed availability evidence.

## Current source verification

`evidence/final-source/committed-boundary-and-map.txt` passes on committed 0435:
architecture service-boundary checks, the complete slo suite (including immutable
replacement, bounds/missing ledger and all-field DTO export), and the complete
cover-map suite. The exact generator output is `covermap-generate.txt`; its diff
only changes model source hashes/counts/file inventory, with no cover behavior
or fixture result changes.

`evidence/final-source/adapter-tests.txt` has 11 passing adapter regressions,
including current and legacy CI authority, seven exact Go unit commands, strict
Go/Helm/environment pins, unsupported-recipe refusal, historical receipt version
compatibility, rejection of legacy receipts for new submissions, and correct
proposal-base reporting after a docs-only branch tip.

`evidence/final-source/precompile-tests.txt` is build preparation only (-run ^$),
not execution of test cases. Current 00eac153 L0/L1/L2 all completed with exit 0
at 20:32:08 UTC: full eight-package boundary/producer suites, focused real-producer
invariants and manager/remote-wire/legacy snapshot integration. Raw logs and
owned-run status are under final-source/. Independent lead current-head
producer, architecture, cover-map and both console controls also passed.
The single coherent final preflight completed PASS at 21:05:46 UTC (2001.952s),
18/18 selected checks, exact source 00eac153. Receipt SHA256:
34df9b73d52feb8c7cd687ce84ca1e5033efeba2f63389cfdbaf8212819505d1.
Workflow: 296 tests PASS. Tooling: 441 tests complete successfully with one existing
skip and nine expected failures. All seven exact Go module unit commands,
pinned-base affected-services report and changed-module build/vet PASS.
The complete console package passes in 277.744s. Receipt, raw logs and supervisor
exit/status are retained under evidence/preflight/ and final-source/. Formal P3 remains the independent lead's
separate decision after the completed handoff.

## Incident and positive control

`evidence/integration-bb92355c/baseline-red.txt` executes the real ingest
counterexample on an isolated untouched bb92355c archive. The positive control
verifies one observed pod, actual Deployment spec.replicas 4, valid UID-bound
lineage, and legacy desired count 1. The intended new observation assertion then
fails. Exit 1 is expected incident reproduction, not a build/fixture error.
Its exact script is `evidence/integration-bb92355c/reproduce-baseline.sh`.
Independent lead proofs are indexed separately; old 193 proofs are preserved
under `evidence/pre-dto-193923cc/`.

## Preflight authority and retained failures

Recipe 2 follows current workflow/charts CI, including committed-staging
reconstruction, and every current go-unit module command. It resolves Go from
CI's highest-version file, pins local mode and the non-cluster environment,
and preserves extra changed-module build/vet checks. The informational affected
services report writes to its local log and uses the pinned proposal base in
place of GitHub's merge-parent HEAD^1. Historical recipe 1 retains its old
module-minimum behavior for historical verification only; it cannot satisfy a
current submission. Source/recipe hashes and complete raw-output checks remain
mandatory. Unsupported recipes fail rather than losing checks.

The coherent preflight at 193923cc finished FAIL and is retained intact at
`evidence/pre-dto-193923cc/preflight-failed/receipt.json`. It exposed GNU tar 1.34
header encoding drift, the shared DTO dependency defect, generated cover-map
source drift, two console polling assertions, and the obsolete Go 1.26.1
selection. `evidence/final-source/corrections.md` records each finding. The tar
failure reproduced on unchanged baseline; the official tar 1.35 binary makes all
eight unchanged archives compare byte-for-byte. Source/binary hashes and logs
are in `evidence/integration-bb92355c/chart-tool-fidelity.md`.

The exact idle current-head control and untouched baseline both failed the 1-second
poison assertion. A separate logging-only baseline overlay retained the failure
and proved the existing watcher finished at 1.370 seconds with done/LANDED/completed
and no observation, cleanup or persistence error. Both tests already waited for
that watcher during cleanup, so the 1/2-second polling loops never bounded their
total duration. The lead signed the precise synchronization repair at revision 15:
00eac153 replaces only those loops with the existing watcher Wait before snapshot,
retaining cleanup fallback, every behavior assertion and the 15-minute CI deadline.
See final-source/console-diagnosis.md and the complete raw failed controls. The independent reviewer also reproduced the original failure and observed
correct terminal completion at 1.449 seconds. Current acceptance and the complete
coherent preflight are PASS, with original failed controls retained separately.

Earlier base 1c23931/source 773f782b remains in the backup branch and evidence.
Two pre-rebase preflight runs were interrupted on lead instruction before source
changed, exited 130 and cleaned up their process groups; no receipt was invented.
Their raw logs remain under `evidence/pre-bb92355c/`. A reserved-manifest packaging
error was corrected from existing signed hashes/producers/timestamps; malformed
notes and doctor recovery remain retained. Earlier unchanged M174 timing tests
failed under cold builds and passed complete warm reruns; both results remain.

## Data prerequisites and activation

`evidence/producer-findings.md` records the irreducible source limitations.
EndpointSlice point observations and Pod.ReadyAt are not durable move-attributed
endpoint-loss intervals. Exported history remains replica-readiness, with
history_complete=false, endpoint loss unavailable and admission ledger
not-authoritative. Accepted endpoint availability targets, authoritative endpoint
budget history and a faithful pre-selection candidate export remain prerequisites.
No historical completeness or complete V3 dataset readiness is claimed.

Capture stays off until --math-lab-capture-cost-evidence is enabled on the manager,
alongside the existing brain capture allowlist/storage. Compatible manager,
brain and sensor source is needed for the additive flow; exact bounds/flags and
components are documented in `docs/math-lab/SNAPSHOT_AND_REPLAY.md`.
Remote go-envtest (local API binaries), other remote CI jobs, images, shared
cluster/live checks, soak, merge and operator deployment are not executed or
signed by this local preflight.
