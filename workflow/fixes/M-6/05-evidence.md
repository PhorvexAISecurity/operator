# M-6 · 05 Evidence — implementation + L0–L2 (criterion → artifact)

**Coordinator delivery update:** incident and P3 now PASS at the pinned head; original baseline execution is retained in `evidence/incident-local/baseline.log`. Product PR #143 is open. The implementer narrative below records its own scope; current independent results are in `evidence/incident.md`, `evidence/p3/verdict.md`, and STATUS.yaml. Shared-dev L3/L4 remain required and pending.

**Author:** claude (implementer). **Round 3** — addresses P3 rev2 (`evidence/p3/verdict.md`).
**Base:** `5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9` (reviewed; `base_review` signed).
**Head:** `9eb14271625620aef6b6184386764e29f0d71ea3` on `parallel/contract-m006-code-exec-admission`
(descends from base). **Diff:** `04-diff.patch` (`git diff --binary <base> <head>`, no unrelated edits).
**Toolchain:** go1.26.1; cel-go v0.23.2 (direct test dep, for semantic CEL evaluation); helm v3.16.2.
**Scope:** implementation + L0–L2 only. **L3 (real API-server admission + per-rule attribution on the
real subresource), the incident-evidence gate, and L4 timing remain the skeptic's / live steps.**
No deploy / execution grant / action enablement / persisted injection is authorized.

Raw logs under `evidence/l0-l2/`. Reproduction: `evidence/l0-l2/commands.txt`.

## P3 rev2 findings → resolution (round 3)
1. **Real API defaults rejected a legitimate install.** FIXED: spec comparison now FILLS the
   server defaults (matchPolicy=Equivalent, empty namespace/object selectors, rule scope "*") on
   BOTH sides, so the actual server-returned object (`evidence/p3/rev2/api-defaulted-objects.json`)
   canonicalizes equal to the trusted contract (`TestServerDefaultedContractAccepted`,
   reviewer `TestReviewerAllowsActualAPIDefaultedContract`).
2. **Scope erased.** FIXED: filling only replaces UNSET defaults; an explicit incompatible value is
   preserved, so a `Cluster`-scoped rule (cannot cover namespaced pods) is rejected
   (`TestClusterScopeRejected`, reviewer `TestReviewerRejectsClusterOnlyScope`). Same for a
   narrowing selector.
3. **Final scope-read race.** FIXED: `FinalCheck` captures a verification token before the live
   namespace read and re-checks epoch/TTL/deadline at completion — an invalidation observed DURING
   the read voids the submit, and a partial/timed-out read invalidates global state
   (`TestFinalCheckInvalidationDuringScopeReadStopsSubmit`, `TestFinalCheckNamespaceReadFailureInvalidates`;
   reviewer `TestReviewerInvalidationDuringFinalScopeReadStopsSubmit`, `TestReviewerNamespaceReadFailureInvalidates`).
- **Independent proof:** the skeptic's own rev2 adversarial overlay run against this head PASSES all
  cases — `evidence/l0-l2/reviewer-rev2-overlay-green.log`.
- **RED truthfulness:** `evidence/l0-l2/red-attestation.md` states plainly that the red-demo-* logs are
  HEAD non-vacuity controls and red-baseline-source.md is baseline SOURCE — NOT a baseline behavioral
  run. Original-incident baseline behavioral execution is the skeptic's incident gate (UNAVAILABLE).

## P3 rev1 findings → resolution
1. **Enforcement content not verified (annotation only).** FIXED: the verifier now reads the FULL
   typed VAP + Binding and compares the COMPLETE normalized spec (validations, variables,
   matchConstraints, matchConditions, binding validationActions/matchResources/namespaceSelector
   matchLabels+matchExpressions/objectSelector/excludeResourceRules) field-for-field to an embedded
   trusted contract (`internal/codeexec/expected_vap.yaml`), tolerating only two named, justified
   API defaults (matchPolicy, rule scope). Nothing security-relevant is projected away — the whole
   spec participates. The seven reviewer bypasses + more are rejected (`TestEnforcementContentDriftRejected`).
2. **FinalCheck used stale tick namespace labels.** FIXED: `FinalCheck(ctx, namespace)` now carries the
   target identity and reads the namespace scope LIVE (uncached) within the aggregate deadline; a
   managed label removed since the tick is caught (`TestFinalCheckRejectsNamespaceLabelRemovedSinceSnapshot`
   asserts rejection AND a fresh namespace GET). The gate-time `Available(nsLabels)` remains the cheap
   best-effort tick path; the pre-submit is authoritative.
3. **securityContext allow-set incomplete.** FIXED: a 9th VAP validation forbids
   `appArmorProfile`/`seLinuxOptions`/`windowsOptions`/`procMount` (config + chart); CEL-evaluated
   (`TestCELDeniesEachViolationIsolated/apparmor-extra`, `/procmount-extra`).
- **Evidence corrections:** `implementation` now attests `04-diff.patch`. CEL semantics and chart
  rendering are executed at L0–L2 (below), not string checks. `incident` remains UNAVAILABLE (skeptic's
  real-subresource proof) — not waived.

## RED → GREEN
- **RED (executed, this head), `red-demo-content.log`:** the full-spec compare disabled ⇒ the 14
  enforcement-drift cases are accepted (unsafe) ⇒ the drift test FAILS. Restored. Proves the content
  comparison is load-bearing (the annotation alone is not).
- **RED (executed, round 1), `red-demo-gate.log` / `red-demo-handler.log`:** gate leg disabled ⇒
  exclusion test fails; handler image reverted to `busybox:1.36` ⇒ paired-profile tests fail.
- **RED (skeptic, prior head 8da845a), `evidence/p3/rev1/adversarial.log`:** the seven enforcement-drift
  + stale-scope bypasses executed through the production reader. Those cases are now rejected at head.
- **RED (baseline), `red-baseline-source.md`:** literal `5a0fd3f` source (the original pre-M6 insecure
  state: handler `busybox:1.36`+no securityContext, no gate leg, no verifier). Original-incident behavioral
  proof through the real producers is the skeptic's L3/incident gate.
- **GREEN, `green-head.log`:** every code-exec / CEL / Helm / gate / handler / M99 test PASSES;
  full-module `go test ./internal/... ./cmd/...` exits 0.

## Acceptance criteria (03-decision §4) → artifact
| Criterion | Artifact (test) | Result |
|---|---|---|
| **CEL semantics** — compliant debugger/custom ALLOWED; each isolated violation DENIED by its rule; oldObject boundary | `codeexec` `TestCELAllowsCompliantRequests`, `TestCELDeniesEachViolationIsolated`, `TestCELNewContainersIgnoresPreexisting` (real cel-go over the shipped expressions) | PASS |
| **C1** debugger empty command+args (CEL deny of debugger-with-command; emit side) | `TestCELDeniesEachViolationIsolated/debugger-with-command`; `actuator` `TestDebuggerEmitsOptionAEmptyCommand` | PASS |
| Full enforcement-content verified vs trusted contract (validations/variables/matchConstraints/matchConditions/binding selectors/exclusions) | `codeexec` `TestEnforcementContentDriftRejected` (14 isolated + positive control) | PASS |
| Boot fail-closed; SSAR deny/error; absent objects | `TestUnavailableBeforeFirstVerify`, `TestAbsentAndSSARFailures` | PASS |
| **C3** out-of-scope ⇒ unavailable | `TestVerifyThenAvailableInScopeOnly` | PASS |
| **C2** epoch interleaving (stale in-flight discarded; timeout→recover) | `TestInvalidationMidVerifyDiscardsInFlightSuccess`, `TestInvalidateThenFreshVerifyRecovers` | PASS |
| TTL independent expiry | `TestTTLExpiry` | PASS |
| Pre-submit reads LIVE namespace scope (stale-label bypass closed); direct + queued | `codeexec` `TestFinalCheckRejectsNamespaceLabelRemovedSinceSnapshot`, `TestFinalCheckNamespaceAbsentFailsClosed`; runner `TestCodeExecPreSubmitGateFailsClosed` | PASS |
| Capability-gate exclusion attributed to `codeexec-admission-unverified`; non-code-exec unaffected | capability `TestEligible_CodeExec*`, `TestEligible_NonCodeExecUnaffectedByAdmissionLeg` | PASS |
| **M99** qualified-outcome/SLO path cannot bypass the gate | runner `TestM99CannotBypassCodeExecAdmissionGate`, `TestM99NoRBACPathPreserved` | PASS |
| **Chart render (actual Helm)** — enabled ⇒ VAP+Binding+read-grant == trusted contract; disabled ⇒ none; no execution grant bound | `codeexec` `TestHelmRenderEnabledProducesEnforcementAndReadGrant`, `TestHelmRenderDisabledProducesNothing`; raw `helm-render-enabled.yaml` / `helm-render-disabled.yaml` | PASS |
| Trusted contract == config manifest == rendered chart | `TestConfigManifestEqualsTrustedContract` + the render test's spec compare | PASS |
| Off by default; minimal resourceName-scoped get read grant; no list/watch/write | `TestCodeExecAdmissionDefaultsOff`, `TestRuntimeReadGrantIsResourceNameScopedGetOnly`, `TestChartBindsNoEphemeralContainersWrite` | PASS |
| Handler paired VAP profile (digest/securityContext/Option A/split) | `actuator` `TestDebuggerEmitsOptionAEmptyCommand`, `TestCustomInjectEmitsSplitCommandArgs` | PASS |

## Explicitly deferred to the skeptic / live (not signed here)
- **L3** real API-server server-side dry-run against the actual `pods/ephemeralcontainers` subresource,
  each denial attributed to its VAP rule vs RBAC/PSA, both action forms. (CEL is evaluated here with
  cel-go over the shipped expressions; it is not the API server admission chain.)
- **Incident-evidence gate** — independent reproduction of the original admission gap through the real
  producers. Remains **UNAVAILABLE**, not waived.
- **L4** §2 timing targets under bounded conditions.
- Effective-permission migration (revoke `phorvex-actuation` grants) is a deploy/rollout step.

## Dependency note
`go.mod`/`go.sum`: `github.com/google/cel-go v0.23.2` promoted from indirect to direct (test-only import)
for the semantic CEL evaluation; it was already in the module graph via k8s. No new module enters the
production build (the import is under `_test.go`).
