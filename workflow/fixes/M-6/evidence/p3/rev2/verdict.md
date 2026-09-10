# M6 independent implementation review — FAIL (round 2)

Reviewer: codex-m006. Head `d68a9edb361c81a31afd1e670416b2a6eadce77a`;
base `5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9`.
Prior review retained at `rev1/verdict.md`. Original decision and 02A unchanged.

## Confirmed progress

The seven prior enforcement-drift tests, namespace-label-removal test and unchanged
manifest control now PASS. The reviewer adapted the overlay only for the new
FinalCheck namespace argument and ninth validation. Author tests for codeexec,
runner, capability and actuator pass independently; Helm binary was explicitly set,
so CEL evaluation and enabled/disabled rendering ran rather than skipped.

## Blocking findings

1. **P1 — real API defaults reject a legitimate installation.**
   `verifier.go:401-421` compares absent selectors in trusted YAML against empty
   selectors populated by Kubernetes. Server-side dry-run of the exact committed
   manifest succeeded on the authorized dev API; the returned policy has
   matchConstraints.namespaceSelector={} and objectSelector={}, and its binding
   has matchResources.objectSelector={}. Passing these actual returned objects
   through the production reader/verifier rejects both as content mismatches.
   This prevents the valid installed policy from enabling code-exec. Compare
   canonical defaults on BOTH sides; retain any nonempty selectors in comparison.
   Evidence: `rev2/api-defaulted-objects.json`, original JSON stream
   `rev2/api-dry-run.json`, `TestReviewerAllowsActualAPIDefaultedContract`.

2. **P1 — normalization erases a security-relevant scope change.**
   `verifier.go:408` clears EVERY rule scope, including explicit `Cluster`, not
   only the equivalent missing/default `*`. A cluster-only rule cannot cover
   namespaced pods. The verifier accepts this mutation of the manifest fixture;
   server dry-run also confirms Kubernetes accepts the Cluster-scope policy.
   Explicitly reject incompatible scopes or compare them without erasing values.
   The current live-default rejection in finding 1 masks this permissive comparison
   on ordinary server-returned objects; do not fix that rejection while retaining
   this omission. `TestReviewerRejectsClusterOnlyScope` fails; raw API validation
   response is `rev2/api-cluster-scope-dry-run.json`.

3. **P1 — final scope read can outlive verification validity.**
   `verifier.go:317-334` checks readiness BEFORE namespace I/O, then returns true
   without rechecking epoch/expiry/deadline. A deterministic namespace-read reactor
   calls Invalidate (representing a concurrent poll observing policy removal),
   then returns legitimate labels: FinalCheck=true while Status=false. This is an
   invalidation observed DURING the check, not the accepted post-check race.
   Also, a namespace read returning DeadlineExceeded refuses that call but leaves
   global validity true and epoch unchanged, contrary to the agreed partial-read
   failure invalidation rule. Preserve a verification token across final I/O,
   check its epoch/TTL/deadline before success, and invalidate on read failure.
   Do not silently use an unrelated verification after discarding an error.
   Tests: TestReviewerInvalidationDuringFinalScopeReadStopsSubmit and
   TestReviewerNamespaceReadFailureInvalidates.

## Reproduction and limits

```sh
cd /home/mehrdad/operator-m006/phorvex
/usr/local/go/bin/go test -overlay=/home/mehrdad/operator-workflow/workflow/fixes/M-6/evidence/p3/rev2/overlay.json ./internal/codeexec -run TestReviewer -count=1 -v
```

Exit 1, with the intended failures above; `rev2/adversarial.log` and retained test
source. Production files remain unchanged. Fake transport is used for production
reader/verifier tests. Actual server dry-runs establish object validation/defaulting
only, NOT activated admission enforcement or the full incident proof.

API probes used `kubectl create --dry-run=server -f - -o json`; no objects installed,
no injection/grant/enablement. Follow-up GET found neither named object. Raw
responses and provenance are retained in rev2. Kubernetes default behavior is also
visible in the upstream SetDefaults_MatchResources implementation:
https://github.com/kubernetes/kubernetes/blob/v1.33.0/pkg/apis/admissionregistration/v1/defaults.go
Actual dev API responses, rather than that older source version, ground finding 1.

Independent author-suite rerun (exit 0), `rev2/author-tests.log`:
```sh
HELM_BIN=/tmp/claude-1001/-home-mehrdad-ai-analyzer/14f967ed-09c1-4f28-bc23-ef0751092eb4/scratchpad/linux-amd64/helm /usr/local/go/bin/go test ./internal/codeexec ./internal/runner ./internal/capability ./internal/actuator -count=1
```

## Remaining evidence

The implementation attestation now correctly binds 04-diff.patch. Original-incident
baseline execution remains missing: red-demo-content.log is modified-head mutation
control, not a run at the baseline SHA attached to the red attestation. Keep that
distinction truthful; do not sign baseline RED from it. CEL/Helm execution is now
present. Full real-subresource incident evidence remains UNAVAILABLE, no waiver.

Next: Claude repairs these bounded cases, adds permanent regressions including
server-defaulted positive controls, repins/re-signs owned evidence, and requests
renewed independent review. No PR approval or shared deployment follows this FAIL.
