# M6 independent incident proof — PASS

Reviewer: codex-m006. Original baseline `79c0370dd460a1d6400bc62346638655f64ae709`;
reviewed implementation base `5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9`;
head `9eb14271625620aef6b6184386764e29f0d71ea3`.

## Real producer and API

The SAME independent test source is overlaid into internal/actuator at the original
baseline and head. It invokes production dispatch -> registered debugger/custom-inject
handler -> real Get + pods/ephemeralcontainers UPDATE. A capturing client records
payloads but forwards calls to a real API. NewDryRunClient adds dryRun=All to every
subresource write; it does not mock admission or replace the decision outcome.

Two isolated envtest Kubernetes **v1.36.2** servers run on loopback with real RBAC
and admission. The request identity is exactly
system:serviceaccount:phorvex-system:phorvex-phorvex-manager, authenticated via test
admin impersonation and granted only fixture-local get-pods/update-ephemeralcontainers.
Fixture policy/binding installation occurs only on these disposable local servers.
No dev deployment, grant, policy installation, or persisted injection took place.

## Baseline RED / head GREEN

| Case | Baseline | Head |
|---|---|---|
| Real handlers before admission installed | API accepts mutable busybox tag, no securityContext; security assertion FAILS for both actions | API accepts pinned hardened profile; same assertions PASS |
| Real handlers under head's actual VAP | Both old incompatible profiles denied with VAP attribution | Both unchanged real head producers allowed |
| Approved manager + compliant request | Allowed | Allowed |
| Each of 9 VAP rule families | Attributable denials under head policy | Attributable denials under head policy |
| Human identity, managed namespace | Denied by identity rule | Denied by identity rule |
| Human debug, unlabelled namespace | Allowed (legitimate control) | Allowed (legitimate control) |
| Persisted ephemeralContainers after requests | Empty | Empty |

Baseline exits **1 only at OriginalProducerProfile's two intended security assertions**;
ProtectedRealProducers and AdmissionControls pass. Head exits **0**, all cases pass.
A compliant cross-source control is explicitly constructed from the captured debugger
request and corrected to the approved profile; it is not presented as baseline output.
Real-producer cases use the captured emitted profile unchanged.

Negative controls cover image, name, core securityContext (root UID and privileged),
capabilities, seccomp, securityContext extra fields, command/args (debugger and custom),
stdin and identity. Expected denial messages name the VAP/binding and specific code-exec
rule. The privileged case sets allowPrivilegeEscalation=true too so ordinary Kubernetes
validation permits the request to reach VAP; a root-UID case independently exercises
that same rule with one changed field. The first attempt accidentally used a combination
rejected by native API validation; its failing logs/source are retained as *.attempt1,
not claimed as VAP evidence. Corrected runs use identical fixtures at baseline/head.

## Commands / retained artifacts

From each corresponding phorvex module root:
```sh
/usr/local/go/bin/go test -mod=mod -modfile=/tmp/phorvex-m6-head.mod -overlay=/home/mehrdad/operator-workflow/workflow/fixes/M-6/evidence/incident-local/head-overlay.json ./internal/actuator -run TestReviewerRealAPIIncident -count=1 -v
/usr/local/go/bin/go test -mod=mod -modfile=/tmp/phorvex-m6-baseline.mod -overlay=/home/mehrdad/operator-workflow/workflow/fixes/M-6/evidence/incident-local/baseline-overlay.json ./internal/actuator -run TestReviewerRealAPIIncident -count=1 -v
```

Artifacts in incident-local/: incident_test.go, head.log, baseline.log, policy.yaml,
per-source overlay maps, separate test dependency mod/sum files, binary-source.json
(SHA512 verified before extracting Kubernetes binaries), and sha256.json.
Product go.mod/go.sum and source trees were not modified. Test dependency manifests
are separate because envtest adds test-only dependencies; they retain each source's
module requirements and point its Phoenix replace to that source's worktree.

## Limits / remaining live verification

This PASS establishes the original admission/profile defect and corrected producer/API
behavior, with legitimate and adversarial controls. It is not a deployed brain campaign,
container-execution proof, full operator integration test, or shared-dev L3/L4 signature.
Envtest has no nodes/controllers and disables ServiceAccount admission; actual RBAC and
VAP run. The exact manager username is impersonated, not authenticated using a dev token.
Deployment provenance, permission migration, controller-runtime polling/TTL latency,
queued decisions and soak remain required in separately authorized L3/L4 verification.
Prior reader/verifier and runner regressions separately cover M99, admission absence,
namespace drift, invalidation, API defaults and fail-closed dispatch.
