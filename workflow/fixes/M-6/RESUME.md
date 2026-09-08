# M-6 RESUME — implementation pickup (post-compaction)

**As of 2026-09-08. Ticket state: `AGREED` (rev20). Phase: IMPLEMENTATION. Owner now: claude (me).**

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
