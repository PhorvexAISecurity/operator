# NEXT-SESSION — start here to resume Phorvex cold

## 1. CURRENT STATE
All **in-session-buildable code is COMPLETE through P-REALCODE (§9.23)**. **PROVEN-REAL** (run on kind /
measured / adversarially tested): the deterministic K8s engine, the optimizer (greedy **exactly optimal**;
recon-per-$ **ratio > 1.0** fleet-dependent — not a fixed "1.62×"), the RL red-team + 2 real vulns fixed, and
multi-tenant **decision isolation exact-zero** + the safe write-path (OIDC / allowlist+gate-check / two-key /
per-namespace-SA / DoS quotas). **CODE-COMPLETE-PENDING-VALIDATION** (real code behind mockable interfaces,
CI-tested with mocks, labeled `[PENDING-*]`): the 9 AI/GPU actuators, the production CRD applier, the MIG
node-exec transport, the OIDC config loader, the vLLM routes. **One-liner:** *the deterministic K8s brain is
real, tested, and isolation-proven today; the AI/GPU + cluster-write paths are built and sound but
design-complete-pending hardware/cluster/IdP validation.*
**Commit status:** in the **working tree, NOT yet committed** — HEAD = `803dfe6 P-DASHBOARD COMPLETE`. Commit
when the user authorizes.

## 2. WHAT TO DO NEXT (real-world steps — NOT more building)
- **(a)** Dev team runs **`REAL-ENV-VALIDATION.md`** on a real cluster / GPU+DCGM / IdP / deployed vLLM
  (validates the actuators, applier, MIG transport, OIDC, vLLM routes — each has a command + acceptance test).
- **(b)** Run the **EKS benchmark** via **`BENCHMARK-RUNBOOK.md`** (report the measured per-fleet ratio).
- **(c)** **Provisional patent BEFORE any public disclosure** — the **demo / investor deck count as disclosure**;
  the **greedy-exact-optimality** result is a strong novel claim. File first.
- **(d)** **SSPL §13 license review with a software-IP attorney before GA.**

## 3. ENVIRONMENT
Windows + **PowerShell** (use `$null`, `$env:VAR`; Bash tool also available) · kind cluster **`kind-amtd-test`
(NO GPU)** · **Go 1.26.3** · tools in **`C:\kube`** · **rebuild `bin/harness.exe` after any harness change** ·
**weekly-usage-limit-aware** (don't burn budget on rebuilds you don't need).

## 4. KEY POINTERS
- **`PROJECT-LOG.md`** — §9 (full stage history + the CURRENT STATE summary) · §10 (roadmap + §10.0 status).
- **`phorvex/REAL-ENV-VALIDATION.md`** — the dev-team handoff checklist (every `[PENDING-*]` item).
- **`phorvex/P5-FINAL-REPORT.md`** — the fundable package (the honest investor/diligence narrative).
- **`journal.txt`** — the transcript catalog (what happened when).

## 5. STANDING RULES (one line)
Design-fork stages: **deep multi-agent search + STOP for approval** before building · **both products**
first-class · **no hardcoded where scannable** · **persona panel + premortem + steelman** · **prove by
running / verify by clicking** · **honesty, no overclaim, label the unproven** · **brain untouched — gates stay
green** (recon-per-$ ratio>1.0 / P3 / lead-demo / O1 golden).

## 6. IN-SESSION TASKS STILL AVAILABLE
- The **investor deck** (assemble from `P5-FINAL-REPORT.md`).
- Anything new the user wants (a feature, a deeper search, a refactor) — open it under the per-stage contract.
