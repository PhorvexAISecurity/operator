# M-6 RESUME — implementation pickup (post-compaction)

**UPDATE 2026-09-08 (rev53): ✅ OFFLINE VERIFICATION COMPLETE — incident=PASS + p3=PASS + all implementer checks signed. Head `9eb14271625620aef6b6184386764e29f0d71ea3`.**
- Codex signed **incident=PASS + p3=PASS** at 9eb1427 (real envtest k8s v1.36.2, RBAC+VAP, real handlers baseline 79c0370 vs head:
  baseline accepts mutable/unhardened producer = the defect; head hardened profile admitted; all 9 VAP rule families attributable).
- `red` re-signed against the EXECUTED baseline (`evidence/incident-local/baseline.log`), rev53. All checks PASS.
- **Codex (coordinator) now drives OFFLINE_VERIFIED → PR_READY → opens BOTH PRs** (product `parallel/contract-m006-code-exec-admission`
  + `docs/workflow`). I do NOT open PRs / amend source/head. L3 shared-deploy + L4 remain pending (not waived). No merge/deploy.

**UPDATE 2026-09-08 (rev50, ROUND 3): P3 rev2 FAIL addressed. Head `9eb14271625620aef6b6184386764e29f0d71ea3`. Awaiting renewed P3.**
- rev2 P1s fixed: (1) spec compare FILLS API defaults both sides (server-returned object accepted; incompatible
  values preserved+rejected); (2) `Cluster` scope / narrowing selector rejected (not erased); (3) FinalCheck carries a
  verification token across the live namespace read + re-checks epoch/TTL/deadline (invalidation-during-read voids;
  partial read invalidates). Codex's OWN rev2 overlay PASSES at head (`evidence/l0-l2/reviewer-rev2-overlay-green.log`).
- RED attestation made truthful (`evidence/l0-l2/red-attestation.md`): head controls vs baseline source; baseline
  behavioral = incident gate (Codex, UNAVAILABLE). Re-signed impl/red/l0/l1/l2/positive_control rev50. Handoff #51.

**UPDATE 2026-09-08 (rev40, ROUND 2): P3 rev1 FAIL addressed — three P1 fixed + CEL/Helm executed; awaiting renewed P3.**
- P3 rev1 (Codex) FAILED head 8da845a with 3 correct P1s. Fixed at new head **`d68a9edb361c81a31afd1e670416b2a6eadce77a`**:
  (1) verifier compares the FULL normalized enforcement spec vs an embedded trusted contract
  (`internal/codeexec/expected_vap.yaml`), not the annotation; (2) `FinalCheck(ctx, namespace)` reads
  LIVE namespace scope uncached (stale-label bypass closed); (3) VAP forbids securityContext extras
  (appArmor/SELinux/Windows/procMount). CEL now REAL cel-go semantic eval; chart render is ACTUAL helm
  v3.16.2 (binary in scratchpad; permanent test uses `$HELM_BIN`/PATH else skips-with-reason).
- Re-pinned head + re-signed implementation(04-diff.patch)/red/l0/l1/l2/positive_control (rev40). incident stays UNAVAILABLE (Codex).
- Handoff bus #49. cel-go promoted indirect→direct (test-only). Codex's rev1 overlay needs its FinalCheck
  call updated to the new (ctx, namespace) signature — that signature change IS the P1-2 fix.
- **(round-1 note below is superseded by the above.)**

**UPDATE 2026-09-08 (rev30): L0–L2 IMPLEMENTATION COMPLETE + GREEN + signed. Now awaiting Codex incident/P3/L3.**
- Head pinned: `8da845ab8f38b06cab120cfe30239b3722c03c25` (base `5a0fd3f`, branch `parallel/contract-m006-code-exec-admission`).
- Built: `internal/codeexec` verifier; capability gate code-exec leg (`codeexec-admission-unverified`, C3);
  runner pre-submit `FinalCheck` + extracted `codeExecAwareEligibility` (M99-safe); handler paired VAP
  profile (pinned digest / hardened securityContext / Option A / split custom-inject); `config/admission`
  VAP + chart template + resourceName-scoped read grant (off by default, no exec grant bound).
- Signed checks: implementation, red, l0, l1, l2, positive_control = PASS. Full module `go test` exit 0.
- Evidence: `04-diff.patch`, `05-evidence.md`, `evidence/l0-l2/{green-head.log,red-demo-*.log,red-baseline-source.md,commands.txt}`.
- Handoff sent to Codex (bus #45) requesting incident / P3 / L3 (real-subresource dry-run). I do NOT sign those.
- **Push-cred note:** operator-m006 remote is HTTPS `PhorvexSecurity/operator.git`, `gh` not installed —
  the eventual M-6 PR push needs a token or `gh`. Workflow PR (docs/workflow) to be opened once M6 PR is ready.
- **Next:** Codex reviews diff + reproduces incident + signs incident/p3 → DIFF_REVIEW_PASSED → PR_READY →
  open PR under recorded scope (no new human gate). Nothing deployed/enabled.

---
**(original note) As of 2026-09-08. Ticket state: `AGREED` (rev20). Phase: IMPLEMENTATION. Owner now: claude (me).**

## Re-orient in 4 commands (from /home/mehrdad/operator-workflow)
1. `python3 workflow/tools/workflow.py brief M-6 --agent claude`
2. read `workflow/fixes/M-6/STATUS.yaml` (owns state) + this file + `03-decision.md` (the FROZEN contract, SHA 9d566b9f…)
3. `python3 workflow/coordination/bus.py list --agent claude` (read/handle/ack any new messages)
4. **Re-arm the monitor** (it does not survive compaction): Monitor tool, persistent, command
   `cd /home/mehrdad/operator-workflow && python3 -u workflow/coordination/bus.py monitor --agent claude --interval 10 2>&1`
   (old task id was `bdf4iffwm` — likely dead; re-arm fresh).

## Product worktree + base
- Worktree `/home/mehrdad/operator-m006`, branch `parallel/contract-m006-code-exec-admission`.
- **Base = `5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9`** (reviewed integration base, M99 present). Codex
  recorded `implementation.base_sha`. **Stay on 5a0fd3f;** origin/main has advanced to `11778ae` but that
  needs a delta review sent to Codex before adopting.

## Done
- Rebased onto 5a0fd3f (M99 `47cc544` present; M6 substrate intact).
- **VAP written:** `phorvex/config/admission/codeexec-ephemeral-vap.yaml` — the frozen contract as CEL,
  each rule a separate validation (attributable, P4), Deny binding, namespace-label scope, validates only
  newly-added containers (has()-guarded). NOT YET compiled/tested.

## Remaining L0–L2 build (ordered)
1. **Go capability verifier** (biggest): GET-by-**resourceName** + SSAR of the VAP+binding; single
   **aggregate deadline D=2s**; **TTL=30s** independent expiry; **atomically-published `invalidationEpoch`**
   (timeout/partial-failure increments it; a stale-`startEpoch` in-flight success cannot clear it; fresh
   verify after timeout recovers unchanged valid objects); **final pre-submit check** (unexpired + matching
   epoch + target-in-verified-scope) for BOTH direct handler dispatch AND queued work.
2. **Fail-closed wiring** via the existing capability-witness gate → reason `codeexec-admission-unverified`;
   **boot check** in `cmd/main.go` (init unavailable until first success); **out-of-scope target ⇒ unavailable** (C3).
3. **Paired handler change** (`internal/actuator/handlers_k8s.go`): pin image
   `busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f`; add the hardened
   `securityContext` (privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true,
   runAsUser/runAsGroup:65534, capabilities.drop:[ALL], readOnlyRootFilesystem:true,
   seccompProfile:RuntimeDefault); **Option A**: debugger command+args EMPTY; custom-inject command
   `["sh","-c"]` args `["echo phorvex-custom-action; sleep 1"]`.
4. **RBAC read grant** (`config/rbac` + chart): installer-owned, **resourceName-scoped `get`** on the two
   named objects (VAP + binding `phorvex-codeexec-ephemeral`) + namespace `get`. READ-ONLY, no injection,
   **no list/watch**. + **chart templates** for the VAP+binding+scope-label + read grant. Keep Role B / exec
   grant UNBOUND (off by default).
5. **M99 regression:** prove M99's qualified-outcome/SLO path can NOT bypass the M6 admission-unavailability
   gate. Keep native system-namespace `codeExecGuard` + unrelated defenses byte-parity.
6. **Tests + immutable RED/GREEN evidence** (L0–L2, positive controls): CEL (each allow + isolated
   violation; absent-oldObject first-injection; C1 empty debugger command/args required); boot/runtime per
   failure-mode incl. C3; **epoch interleaving** (bump-mid-verify ⇒ in-flight can't clear; timeout→recover);
   capability-gate exclusion + queued-not-dispatched; chart render (Deny/Fail/scope/no-role-bound + read
   grant minimal). Criterion mapping to the 03-decision acceptance list.

## After the build
- Send **commit head + binary diff vs base 5a0fd3f + immutable RED/GREEN evidence + criterion mapping** to
  Codex via the bus. Codex records source pins (configure is coordinator-owned) BEFORE my check signatures,
  then does the **incident-evidence gate + L3 (real-subresource dry-run) + live verify** — I (implementer)
  CANNOT sign those.
- **NOT authorized:** deploy, the ephemeralcontainers/`phorvex-actuation` grant, action enablement,
  persisted injection. Those stay separate human gates.

## Two-branch push plan (boss request)
- Product CODE → `parallel/contract-m006-code-exec-admission` (operator-m006) → the M-6 PR.
- Workflow RECORDS/evidence/bus → `docs/workflow` (operator-workflow) — currently uncommitted. **When
  PR-ready, commit + push `docs/workflow` too.** Keep agent names OUT of the commit MESSAGE (standing rule);
  bus files legitimately contain agent IDs (that's data, fine).

## Standing constraints
- No agent names / Co-Authored-By / "Generated with" in commit messages or PR text (grep -i before commit).
- Canonical `bus.py` only (not the legacy campaign bus); K3 not in this cycle; don't edit `bus.py` (Codex owns transport).
- Roles: claude=proposer/implementer; codex-m006=skeptic/verifier/coordinator; Mostafa=security_decision_owner (approvals recorded via Mehrdad, `evidence/decision/human-decision-2026-09-08.md`).
