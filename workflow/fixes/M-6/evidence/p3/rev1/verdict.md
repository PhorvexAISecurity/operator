# M6 independent implementation review — FAIL (round 1)

Reviewer: codex-m006. Reviewed head `8da845ab8f38b06cab120cfe30239b3722c03c25`,
implementation base `5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9`.
The signed decision and original blind derivation remain unchanged.

## Blocking findings

1. **P1: enforcement content and effective scope are not verified.**
   `internal/codeexec/reader_k8s.go:GetPolicy/GetBinding` discard validations,
   variables, matchConditions, API groups/versions, exclusions, object selectors,
   and namespace matchExpressions. The verifier consequently accepts a policy
   whose only validation is `true`, a newContainers variable of `[]`, or a binding
   that does not cover the target. The unchanged `m6-1` annotation is not a content
   hash or evidence of enforcement. Seven isolated mutations of the committed
   manifest return Verify=nil and Available=true through the production reader.
   Verify the complete actual enforcement contract, including ways selection can
   narrow/skip it. Reject unexpected deviations or establish their semantics.
   Compare actual normalized content against a trusted expected contract, not
   merely a self-reported annotation. Handle API defaults deliberately.

2. **P1: final dispatch scope uses stale namespace labels.**
   `runner/manager.go:1295` passes tick-snapshot labels to FinalCheck. The latter
   refreshes admission objects but never the namespace. Removing the managed
   label after snapshot collection therefore leaves final authorization true,
   although the binding no longer covers that namespace. Independent reproduction:
   initial legitimate control passes; mutate namespace in transport fixture;
   assert actual labels removed; FinalCheck still returns true with zero namespace
   GETs. Carry target identity into the final check and read current scope uncached
   within the aggregate deadline. This stale input precedes the check and differs
   from the acknowledged last-check-to-submit race.

3. **P1: the exact securityContext allow-set is incomplete in CEL.**
   Both policy manifests check selected fields but do not reject extra fields
   such as `appArmorProfile: {type: Unconfined}`, `seLinuxOptions`, `windowsOptions`,
   or `procMount`. The approved contract says securityContext equals the selected
   allow-set. Add explicit handling and isolated semantic tests for extra fields,
   preserving Kubernetes defaulting. This finding is source inspection; attached
   tests do not evaluate CEL or claim real API admission for these fields.

## Independent reproduction

`rev1/reviewer_adversarial_test.go` is overlaid into internal/codeexec; product
files are untouched. `rev1/overlay.json` records the exact mapping.

```sh
cd /home/mehrdad/operator-m006/phorvex
/usr/local/go/bin/go test -overlay=/home/mehrdad/operator-workflow/workflow/fixes/M-6/evidence/p3/rev1/overlay.json ./internal/codeexec -run TestReviewer -count=1 -v
```

Exit 1; `rev1/adversarial.log`: seven drift cases and stale-scope case fail at the
intended safety assertions; unchanged production manifest positive control passes.
The tests use a fake Kubernetes transport with SSAR allowed and the unchanged
production K8sReader/Verifier against full typed manifest objects. They prove
reader/verifier behavior, NOT RBAC, API validation, CEL admission, deployment,
or the full baseline-to-head incident acceptance gate.

## Evidence corrections required

- Signed implementation attests `05-evidence.md`; doctor requires `04-diff.patch`.
  Implementer must correct its own attestation.
- Baseline source excerpts and modified-head mutation controls are not an executed
  baseline RED. Produce the baseline/head behavioral comparison and positive control.
- L0–L2 acceptance includes CEL semantic cases and chart rendering. String searches
  over unrendered templates provide neither. Exercise actual expressions (allow and
  isolated deny cases, oldObject boundary and extra fields) and render enabled and
  disabled chart configurations. Keep actual API/L3 coverage explicitly pending.
- `incident.md` was an unfilled template at handoff. Independent real-subresource
  incident evidence remains unavailable; no PASS or waiver is claimed.
- Reconcile safe teardown/disable ordering and visible degraded reporting with
  the signed contract; template comments alone do not establish rollout safety.

Next owner: Claude (implementer). Repair in the existing branch, add permanent
regressions through production readers, repin head, regenerate patch/evidence,
and re-sign owned checks. Then request renewed independent review. No PR approval,
deployment, permission grant or live mutation follows this failed review.
