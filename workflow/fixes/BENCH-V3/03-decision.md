# BENCH-V3 lead plan

Signed by bench-v3-lead, 2026-10-31. Source main: 1c23931621d47218ded424b58e4db127344fb33b; recorded incident: 0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec.

Implement additive read-only replay input capture. Preserve current DesiredReplicas and all selection behavior. Capture true controlling workload spec.replicas, UID, resource version and observation time through real Kubernetes reads. Validate controller lineage, prefer the top workload controller (Deployment over incidental ReplicaSet), retain pod controller identity separately, and preserve unknown on stale/missing/ambiguous owners. Never substitute ready or observed pod counts.

Add an optional versioned endpoint-cost evidence envelope to snapshot inputs. Include explicit measurement status, source provenance, observation time, policy/workload identity, available duration/outcome history and completeness-start metadata. Export immutable ledger copies under its lock. Preserve observation IDs and open/settled/censored state. Add pod/workload UID to real ledger producers where known; never guess policy attribution.

The current ledger measures replica-readiness impact, not necessarily endpoint-seconds. Capture it truthfully but do not allow it to activate endpoint-cost pricing. Inspect real EndpointSlice and move-acknowledgement producers and wire qualified capture where move identity, endpoint membership and observed intervals are established. History gaps, restarts and unmeasured/unsupported actions must remain explicit. A schema/import interface alone is not a live telemetry producer. Report an irreducible producer gap to the lead immediately instead of fabricating completeness.

Old snapshot v1 files must continue decoding with the new optional envelope absent. Add evidence and precise readiness reasons to inspection output. Keep the legacy engine result unchanged. No production cost formula, policy default, admission rule or actuator changes.

Test real ingest, ledger and recorder producers with realistic Kubernetes objects. Required cases: desired=4 with one observed pod, missing/stale owner UID, known authoritative observation, censored retention, immutable exports, open-to-settled replacement, and old snapshot absence. Show that replica-only observations cannot qualify as measured endpoint loss. Preserve the independently executed baseline counterexample before review. Use meaningful tests, not mocked final readiness flags.

Verification: L0 targeted Go suites; L1 producer and immutability invariants; L2 serialization and unchanged legacy replay. No shared-cluster or soak is required for proposed-code delivery; none is claimed. Stop on contradictions and request a plan amendment from the lead. No weaker guarantees or fabricated evidence. Preserve all source pins and test logs.

Rollback is reverting the additive proposed source. This record grants no product deployment. Existing user approval for benchmark-bot deployment does not authorize activating V3 in the operator. Delivery is an independently reviewed source proposal plus explicit remaining collection requirements.

Amendment signed by bench-v3-lead, 2026-10-31: the source preflight adapter
currently assumes .github/workflows/ci.yml, which main removed in favor of
pr-validation.yml. Repair this necessary delivery dependency narrowly. Resolve
and attest the actual current CI authority while retaining legacy ci.yml receipt
compatibility. Add a discriminating regression and preserve the observed failure.
Do not weaken recipe checking, skip checks, or change workflow permissions.
The worker implements this amendment; the lead reviews it independently with
all product changes. Source validation evidence remains mandatory.

Integration amendment signed by bench-v3-lead, 2026-10-31: origin/main advanced
to bb92355cf7b6c4a696f44caf52bd5fa1268e7303 during verification. Rebase the source
proposal onto that exact main revision before delivery. Preserve all upstream
stateful-rotation behavior and its GVK-aware owner-cache identity. The replay-only
reader must use the complete new cache key without issuing API reads. Update the
counting control to include the actual upstream observation chain; do not remove
upstream observers to satisfy the test. Reproduce the same missing-spec incident
at the new base, retain all old evidence as superseded, and rerun affected source
and exact preflight checks before review. This is conflict resolution under the
existing repair/PR scope, not permission to merge or deploy the operator.

CI fidelity amendment signed by bench-v3-lead, 2026-10-31: the complete run on
193923cc found that current pr-validation.yml uses build/test-harness/go.mod
(Go 1.26.3), GOTOOLCHAIN=local, and seven separate module unit-test commands.
The legacy module-minimum adapter's Go 1.26.1 cannot traverse the current service
import graph and does not represent this CI authority. Extend the narrow adapter
repair to resolve and attest the actual current Go job, tool version file, strict
non-cluster environment, Helm setup and all gating commands. Retain historical
receipt behavior at its pinned authority. Unsupported recipes must fail explicitly;
any local handling of the informational GitHub summary output must be bounded and
recorded. No CI test, architecture boundary, generated-document gate or timeout may
be weakened to obtain a pass. Provision the genuine matching Go toolchain and run
a new coherent preflight after the shared DTO boundary correction and exact
generated producer-document refresh. Preserve the complete failed run and its
concrete architecture, documentation, toolchain and timing findings. Timing cases
require warm independent controls before attributing failure to compilation load.
This repairs the delivery dependency under the existing authorized source proposal;
it grants no merge, product deployment or live actuation.

Test synchronization amendment signed by bench-v3-lead, 2026-10-31: the exact
idle Go1.26.3 control also fails on unchanged main bb92355c. The poison case
samples a running record after its one-second poll, while logging-only baseline
instrumentation shows the existing watcher completes at1.370 seconds with
done/LANDED/completed and no observation, cleanup or persistence errors. The
two-second lost-ack control completes correctly at1.522 seconds. Preserve both
baseline failures and the diagnostic overlay; neither is a passing test.
Repair only these two test polling loops by waiting for the existing
s.attackWatchers completion before reading terminal records. Their registered
t.Cleanup already waits for that same watcher regardless of the poll result,
so the poll does not bound total test execution. Retain the cleanup fallback,
all outcome/identity/load/unload assertions, and the exact existing fifteen-minute
Go command timeout. Do not change production behavior, add sleeps, increase a
timeout, skip a test or suppress a failure. This is a narrowly evidenced fixture
synchronization repair necessary for reliable delivery under existing source
repair authority. Commit the test delta, rerun its controls and the complete
coherent final acceptance/preflight at the new source, and obtain independent
review before PR delivery. No product deployment scope is added.
