# P-VCLUSTER — multi-tenancy decision (search + plan; STOP for approval; NOTHING built)

**Contract.** This opens the P-VCLUSTER stage per the per-stage discipline: a deep search + decision, then STOP.
**No code is built this pass.** Every obligation below is currently RED (fail-closed) — "pass-1" means *scheduled
first*, not *done*. Produced by a 12-agent search over the real single-tenant baseline; the four load-bearing
leak claims were **independently re-verified against the code** by the main loop (citations inline).

**Verification caveat (original run).** The search's first adversarial peer-verification did not complete (the
subagents tripped a cyber-safeguard and emitted `undefined`). It was **RE-RUN** with correct defensive
isolation-review framing — see the next section.

---

## PASS 2 — BUILT + VERIFIED (the deferred write-path scope; console/auth only, brain & Pass-1 gates untouched)

A FRESH premortem (this pass, write-path-focused; pen-tester/MLSecOps/cloud/security leading) drove the design:
*malicious policy-delta → degrade the brain* (allowlist + bounds + server-side gate-check); *gate bypass /
TOCTOU* (atomic re-check on the same candidate); *forge identity past OIDC* (RS256-only, JWKS-by-kid,
exp/nbf/iss/aud, claims-verified tenant); *two-key bypass* (distinct verified approver); *limiter exhaustion*
(per-tenant token bucket + bounded map). **Steelman:** free-form YAML (arbitrary write) and allowlist-only
(within-bounds degradation) lose; allowlist + server-gate + two-key + per-namespace-SA wins — each layer closes
a distinct class, none trusted alone. **Built as 9 separate console files (no monolith); brain decision logic
untouched (git scope: console-only + `server.go` wiring); Pass-1 gates + O1–O10 + 1.62×/P3/lead-demo all green.**

| Component / obligation | Result | Proof (test) |
|---|---|---|
| **OIDC verified identity** (closes O6's forged-`?tenant=`) | **GREEN** | `oidc.go` (RS256 on the stdlib, no new dep); `TestOIDC_*` (6): valid verifies + **tenant/lens from the verified claim**; forged-signature, `alg=none`, expired, wrong-aud, wrong-iss, unknown-kid, missing-tenant ALL rejected (fail-closed) |
| **Safe apply-fix write-path** | **GREEN** | `applyfix.go` + `applyfix_gate.go`: **allowlist + bounds** (no EnabledActions ⇒ no RCE action; no free-form YAML), **server-side gate-check** (`PolicySafetyGate`: shadow engine, 1.62×/P3/no-harm), **two-key distinct approver**, **per-namespace-SA applier**, **audited** |
| ↳ malicious/gate-breaking delta REJECTED | **GREEN** | `TestPolicySafetyGate_RejectsStarve…` (real gate rejects a starve policy), `TestApplyFix_AllowlistRejectsMalicious` (MaxMoves=0 bounded), `TestApplyFix_GateRejectionBlocksApply` (gate-failing delta never reaches the applier) |
| ↳ two-key + audit | **GREEN** | `TestApplyFix_TwoKeyDistinctApproverAndAudit` — same-principal approve REFUSED; distinct approver applies; submit+applied audited |
| ↳ live HTTP flow ("verify by clicking") | **GREEN** | `TestApplyFixEndpoints_LiveTwoKeyFlow` — through the real router: submit→200 pending, malicious→422, same-user approve→422 two-key, distinct approve→200 applied |
| **Per-tenant DoS quota (R5)** | **GREEN** | `quota.go` (token bucket + concurrency cap + bounded map); `TestQuota_*` (4): a noisy tenant's flood is capped to its OWN burst, the quiet tenant unaffected; refill; per-tenant concurrency; limiter map bounded (anti-memory-DoS) |

**Requirement-coverage map (Pass 2):**
- **OIDC identity → MET** (`oidc.go`, `vcluster_endpoints.go verifiedIdentity` — authoritative when configured; demo-trust dev fallback otherwise). Live IdP/JWKS config + the React login is deployment wiring.
- **O6 forged-`?tenant=` → CLOSED at identity level** (tenant from the verified claim; a request param is ignored under OIDC).
- **apply-fix write-path → MET** (allowlist + gate + two-key + per-namespace-SA + audit; the `Applier` hook is record-only by default, the production namespaced-CRD-patch is injected at deploy).
- **Per-tenant DoS quotas (R5) → MET** (`quota.go`, wired on the write-path).
- **R9 availability blast-radius → STILL the hard-isolation escalation condition** (single-process; only vcluster/per-tenant process closes it) — documented, not closed.
- **R1 GPU/MIG side-channel → AUDIT-ONLY** (uncloseable in software).

**"Verify by clicking" (your part).** The backend is built + the live HTTP flow is test-proven. To click it
end-to-end: run the console, point `EnableVCluster` at your OIDC IdP (issuer/audience/JWKS), and the dashboard
apply-fix button drives `POST /api/apply-fix/submit` then a *distinct* approver drives `/approve`. For a local
dev click-through without an IdP, the demo-trust fallback accepts `?user=&tenant=` so you can exercise the
two-key flow in the browser. (The React apply-fix/approve UI wiring + the live IdP are the remaining
integration; the safety substance — identity, allowlist, gate, two-key, quota — is built and proven by running.)

---

## PASS 1 — BUILT + VERIFIED (per-obligation RED→GREEN). Brain change is ONLY the per-tenant bucketing.

The verification re-run (§0) gaps were incorporated. Pass 1 is built and proven by running. **The single-tenant
default is byte-identical (O1 golden), and the gates survive (1.62×/P3/lead-demo green).** Change is confined to
4 files + tests: `internal/decision/coverage.go` (per-tenant cost buckets), `internal/killchain/conjugate.go`
(gated fleet prior), `internal/actuator/native.go` (O7 assertion), `internal/audit/log.go` (O10 router). The
optimizer/cost/feasibility DECISION LOGIC is untouched.

| Obligation | Was | Now | Proof (test) |
|---|---|---|---|
| **O1** single-tenant byte-identity | RED | **GREEN** | `TestO1SingleTenantByteIdentical` — 5184-byte golden captured pre-refactor, reproduced bit-for-bit post-refactor (default-to-old-scalar: first bucket reuses the singleton) |
| **O2** λ non-influence (exact-zero) | RED | **GREEN** | `TestO2_LambdaNonInfluenceExactZero` — tenant A's decoy flood (the RL λ-pump/dispersion-steer attack) co-resident with B → B's full decision stream byte-identical to A-idle |
| **O3** fleet-prior non-leak | RED (leak by construction) | **GREEN** | `TestHierarchicalColdTenant` — cross-feed OFF by default ⇒ a cold tenant inherits NOTHING from another's evidence (exact equality); opt-in path still works. G3 rescale write is gated. |
| **O4** RLS/Conformal non-influence | RED (latent) | **GREEN** | `TestO4_RLSConformalNonInfluenceExactZero` — A's `ObserveRotation` fired 50× on the co-resident engine → B's cost-based decisions byte-identical (per-tenant buckets BEFORE `ObserveRotation` is ever wired) |
| **O5** owner IP-wall on the real SSE stream | RED (untested path) | **GREEN** | `TestO5_OwnerSSEStreamBytesRedacted` — drives `live()` end-to-end, asserts the REAL wire bytes carry none of the redacted IP tokens (and the test "bites" — a raw Record would trip it) |
| **O6** cross-tenant read denial | partial | **GREEN (data-level) / OIDC deferred** | `TestO6_OwnerStreamCrossTenantReadDenied` — another tenant's records never reach acme's stream. (Binding `?tenant=` to a VERIFIED identity is Pass-2 OIDC — residual R3.) |
| **O7** cross-tenant actuation denial | RED (single-layer) | **GREEN** | `TestO7_CrossTenantActuationDenied` — a `Request{Tenant:A, Namespace:B-ns}` is fail-fast REJECTED at the Phorvex boundary, before dispatch (above the K8s-RBAC backstop) |
| **O8** co-residency count bound | (claimed) | **GREEN** | `TestO8_CoResidencyCountOnlyIdentityFree` — same co-tenant COUNT, different identities ⇒ identical CoResidency; bounded [1,2] |
| **O9** fleet-relative physics disclosure | MISSING | **GREEN (bound+disclose)** | `TestO9_…BoundedDisclosure` — image/model-rarity identity-free + bounded [1,2]; the magnitude shift (2.0→1.5 when a tenant deploys your rare image) is a MEASURED, disclosed, coarse membership-inference residual (R2-class, not closeable — physics is fleet-relative) |
| **O10** per-tenant audit isolation | MISSING | **GREEN** | `TestO10_PerTenantAuditIsolation` — a noisy tenant's 10k-record flood routes to its OWN sink; the quiet tenant's history is intact, zero mixing. Default single-sink unchanged. |

**R9 — crash/OOM availability blast-radius (DOCUMENTED escalation condition; NOT closed in Pass 1).** The
operator is a single-process sequential tick loop (`runner/manager.go`), so a panic/OOM in one tenant's `Decide`
halts all tenants' protection. Per-tenant *state* buckets (Pass 1) do **not** fix availability-coupling — only
**hard isolation** (a separate supervised operator process / vcluster per tenant) does. This is the explicit
**escalation condition to hard isolation**: adopt it when availability becomes part of the tenant contract
(mutually-distrusting tenants where one tenant crashing another's protection is unacceptable). Until then the
operator is single-leader anyway, so Pass 1 does not regress today's blast-radius — an honest deferral.

**DEFERRED (design-noted, not built):** OIDC verified identity (closes O6's forged-`?tenant=`, R3), the safe
apply-fix write-path (R4), per-tenant DoS quotas (R5). **R1 GPU/MIG side-channel stays AUDIT-ONLY** —
uncloseable in software (only physical separation), honestly disclosed.

---

## 0. VERIFICATION RE-RUN RESULTS (R8 resolved) — NEW gaps found; (incorporated into Pass 1 above)

The premortem/steelman verification was re-run (3 independent reviewers, defensive framing, grounded in the real
code). It **completed** and **confirmed the core diagnosis** (shared-λ + fleet-prior leaks are real; per-tenant
buckets drive them to *exact zero*; per-tenant memory + namespace-scoped actuation already isolated; the
default-to-old-scalar precedent preserves single-tenant byte-identity; **soft isolation is defensible for
Pass 1**). **But it surfaced gaps the design missed — so per the approval condition, build is PAUSED for review.**

**NEW obligations the design must add before building:**
- **O9 — generalized fleet-relative physics disclosure bound (HIGH; the biggest miss).** O8 bounded only the
  co-residency *count*; the same global `platform.Derive` (`platform.go:80`, run per-tenant `manager.go:276`)
  also leaks **image-rarity** (`platform.go:133,148`), **model-rarity** (`:139`), and **scheduler-slack**
  (`:151`) into each tenant's observable `Decision`/per-$/Prometheus — cross-tenant **membership-inference**
  channels (a tenant learns another deployed the same rare image/model; model-rarity+co-residency even flips A's
  pod's kill-chain **Stage/PHold/StageUrgency** via `hazard.go:215,219`). O9 must bound ALL fleet-derived
  multipliers (coarse-bucketed, identity-free), tested adversarially (tenant B deploys/scales → assert A's
  `Decision[]`/Stage reveal no co-tenant identity, only the disclosed bucket).
- **O10 — shared multi-tenant audit-sink integrity/retention (MEDIUM).** One `jsonOut`/`RotatingWriter`
  (`audit/log.go:90,145`, `manager.go:378`) mixes all tenants' records; **rotation drops segments fleet-wide**
  (a noisy tenant evicts another's audit history). O6 covers read-denial only. O10 = per-tenant partition/retention,
  or an explicit accepted-design statement + rotation-fairness test. Also: make explicit that operator/investor
  lens is an **intended** fleet-wide scope (not a missing filter).

**NEW residual (the design under-stated it):**
- **R9 — crash/OOM availability blast-radius (the soft-model limit).** The single-process sequential tick loop
  (`manager.go:217-219`) means a panic/OOM in one tenant's `Decide` stops **all** tenants. Per-tenant buckets do
  **not** fix this — it is the one threat **hard isolation (separate supervised process per tenant) uniquely
  closes**. **Escalation condition:** move to hard isolation when availability becomes part of the tenant
  contract (mutually-distrusting tenants where crash-containment is contractual). Until then soft does not
  regress today's single-leader blast-radius — an honest deferral, disclosed.

**Test-validity sharpenings (the obligation TESTS, not the design, were too weak):**
- **O2/O4 (G2/G4):** as written they can **pass trivially** (a fresh engine is already byte-identical). They MUST
  run against the **co-resident, post-refactor bucketed engine** — A and B in one process — comparing B's full
  λ / cost-prediction trajectory element-by-element to an A-idle control. ("Unwired ⇒ can't leak" is BOUNDED,
  not PROVABLE; per-tenant bucketing must precede wiring `ObserveRotation` — hard CI dependency.)
- **O3 (G3):** the global `gAlpha/gBeta` **rescale** is a shared *write* (`conjugate.go:102-106`) — it must be
  gated/removed, not merely left dormant.
- **O5 (G5):** assert on `live.go`'s actual SSE bytes (`live.go:40-61`), not a second `ToOwnerEvent` call.
- **O7 (G6):** confirmed **no** Phorvex-layer tenant↔namespace assertion exists today (`handler.go`/`actuator.go`
  ignore `req.Tenant`) — single-layer (K8s RBAC) until the explicit fail-fast check is added.

**Per-obligation verdicts (re-run):** O1 PROVABLE (mechanism sound, test feasible); O2/O4 PROVABLE-after-refactor
(test must be co-resident); O3 GAP-today→PROVABLE-with-default-OFF (gate the rescale write); O5 BOUNDED (SSE
coverage gap); O6 GAP correctly deferred to OIDC; O7 BOUNDED (needs the assertion); O8 identity-free PROVABLE /
count BOUNDED-disclosed; **O9/O10 MISSING — must add.**

**Required action before building (per the approval condition):** update the plan to add **O9, O10, R9** and the
test-validity requirements, then proceed to Pass 1. **STOPPED for review — no build code written.**

---

**Original verification caveat (now resolved by §0).** The premortem residuals R1–R8 below stand; §0 adds
O9/O10/R9 and sharpens the obligation tests.

---

## 1. The chosen tenancy model (split by product — proven vs the single-tenant baseline)

The baseline that ships today is **one shared `CoverageEngine` whose calibration state is reused across
per-tenant `Decide` calls** — verified: `CoverageEngine.Cost.Dual` is a single DualSolver (`coverage.go:117`
reads λ, `:332` steps it), and `ConjugateMemory.Observe` feeds a **global** `gAlpha/gBeta` fleet prior
(`conjugate.go:92,95`) that a cold tenant inherits. These are **active cross-tenant channels**, not tuning
choices. The model is split by product:

| Layer | Decision | Why (vs baseline) |
|---|---|---|
| **Decision brain** (the dangerous one) | **Per-tenant state buckets, zero fleet cross-feed** — `e.Cost` → `map[tenant]*P1Cost` (one DualSolver λ, one RLS θ/P, one Conformal window per tenant); `ConjugateMemory` fleet hyperprior `gAlpha/gBeta` **opt-in per-tenant-group, default OFF**. NOT a separate engine process per tenant (too heavy; would fork the gate-preserved path). | A shared λ literally re-prices a neighbor's next decision (a correctness **and** confidentiality defect, verified `coverage.go:117/332`); the fleet prior leaks evidence (`conjugate.go:92`). Per-tenant buckets are the minimal change that drives the cross-tenant delta to **exactly zero**, not just "bounded." Per-tenant `tenants map[string]*tenantState` is **already isolated** (verified) — only λ + fleet-prior need fixing. |
| **Console / owner-lens** (the IP wall) | **Keep the shipped redaction-by-construction core** (`owner.go` whitelist + `redaction_test.go` gate); **replace demo-trust tenant-assertion with verified identity.** | The redaction boundary is already strong (whitelist, zero-sentinel-leak test); the only weakness is *who you are* (self-asserted `?tenant=`). So: "trusted redaction core + untrusted-until-authenticated edge." |
| **Actuation** | **Keep K8s-RBAC-per-namespace as the HARD boundary** (it already is one — verified `getPod` keys on `Namespace`); **add an explicit fail-fast tenant/namespace assertion at the `Actuate` boundary.** | Cross-tenant actuation is already prevented at the K8s API (per-namespace Role/RoleBinding/SA, P4c); the Phorvex layer just trusts a well-formed `Request`. Make the implicit backstop an explicit fail-fast control. |
| **Physics** | **Global scan is retained by design**; tenancy = **per-tenant *disclosure*, not per-tenant *computation*.** | Rarity / co-residency / scheduler-slack are *intrinsically fleet-relative* — computing them per-tenant makes them **wrong**. Each tenant filters the global witness to its own namespace (`manager.go:283`). |

---

## 2. Isolation-proof plan (each obligation is a runnable adversarial test — all currently RED)

| # | Obligation | Adversarial test |
|---|---|---|
| **O1** | **Byte-identical single-tenant default** (the gate-preserving obligation) | Golden-output: capture the full `Decision[]` + audit stream of the existing P3/lead-demo single-tenant run BEFORE the refactor; after, assert byte-identical decisions, λ trajectory, PHold, ratio. **Hard CI gate.** (This test does not exist yet.) |
| **O2** | **λ non-influence** | Tenant A floods K manufactured-high-coverage decoys; assert tenant B's λ + `Decision[]` are byte-identical to an A-idle run. (λ is already decoy-flood-capped in `dual.go`, but a *shared* λ still couples — buckets must make the delta exactly 0.) |
| **O3** | **Fleet-prior non-leak** | A `Observe`s 200 held-evidence events; assert a COLD tenant B's `PriorMean` is unchanged from the nil-data default (0.2). **Fails today by construction** (`conjugate.go:92`). |
| **O4** | **RLS/Conformal non-leak (pre-emptive)** | Wire `ObserveRotation` in a harness; A rotates expensive workloads; assert B's quantile/cost predictions unchanged. **Must pass BEFORE `ObserveRotation` is ever wired** (`p1cost.go:87` currently UNWIRED — a latent leak armed to fire). |
| **O5** | **Owner IP-wall regression** | Extend `redaction_test.go` to the SSE/streaming path + every new `OwnerEvent` field; rename an IP field, assert the whitelist still emits zero redacted tokens AND zero sentinel values. |
| **O6** | **Cross-tenant read denial** | Authenticated tenant A requests `?tenant=B`; assert 403/empty, never B's events. (Today demo-trust; the P4c fail-closed-on-empty stops the *empty* case, not the *named-other* case.) |
| **O7** | **Cross-tenant actuation denial** | Inject `Request{Tenant:A, Namespace:B-ns}`; assert rejected at the Phorvex boundary (new assertion) AND at K8s RBAC. Two-layer. |
| **O8** | **Co-residency count bound** | Assert a tenant's co-residency witness reveals at most the COARSE bucketed count, never co-tenant identities; GPU/MIG `FactSideChannel` stays AUDIT-ONLY (never actuates). |

**Adversarial harness:** reuse the production RL red-team (which already found the λ-starvation + dispersion-steer
attacks) as the cross-tenant attacker for O2/O3/O4.

---

## 3. Auth / write-path (unblocks the `[PENDING-P-VCLUSTER]` console items)

- **Identity (replaces demo-trust):** validate an **OIDC/JWT at console entry**, extract `tenant_id` from a
  *verified claim*, bind `audit.Record.Tenant` to it — never to `?tenant=` or the `X-Phorvex-Lens` hint (the
  lens becomes a post-auth routing choice, not the authz boundary). For actuation, `Request.Tenant` is derived
  from `pol.Tenant` (policy-bound) and asserted, never accepted raw.
- **Per-tenant RBAC:** a console authz scope keyed by the verified claim (read only your own audit/owner/SSE)
  + the existing per-namespace K8s Role/RoleBinding/SA for actuation (`config/rbac/phorvex-actuator-role.yaml`;
  P4c least-privilege — keep it).
- **The safe apply-fix write-path** (the most dangerous new surface; today records-only,
  `redteam.go:261,269` "[PENDING-P-VCLUSTER write-path]"). In order of trust: **(1)** apply-fix NEVER does a
  free-form cluster write — only flip a `PhorvexPolicy` CRD field within a **server-authored allowlist** of safe
  parameters, or move a finding's review status (no `kubectl apply` of arbitrary YAML, ever); **(2)** every
  apply is **gate-checked server-side** (O1 + 1.62×/P3/lead-demo) — an apply that would change the single-tenant
  default, drop the ratio, or harm the demo is REJECTED before touching the cluster; **(3)** two-key
  (record + confirm), and actuation still flows through the per-namespace SA (a forged apply cannot cross a
  namespace); **(4)** full audit (verified who, exact policy delta, gate-check result, reversible flag).

---

## 4. Per-tenant physics / context

- **Scan stays GLOBAL** (one `ingest.Snapshot` + `platform.Derive` per tick → `map[ns/pod]→PhysicsWitness`);
  each tenant **filters to its own namespace** (`manager.go:283`). Per-pod physics is a function of fleet
  topology (rarity = surprisal vs the whole fleet; slack = all pods' node requests) — it **cannot** be computed
  per-tenant without being wrong. "Per-tenant physics" = per-tenant **disclosure**, not computation.
- **Kill-chain priors:** per-tenant `ConjugateMemory.tenants[T]` is isolated (verified); the fleet hyperprior
  `gAlpha/gBeta` is the one coupling → OFF by default (O3).
- **The co-residency anonymized-count subtlety (load-bearing):** `CoResidency = 1 + clamp01((|nodeTenants| − 1)
  / CoResidencyCap)`, where `nodeTenants` is the **set of distinct namespaces on the node** (`platform.go:147`).
  **What leaks:** the COUNT (reversible to a coarse bucket — "how crowded is my node"); **what does NOT leak:**
  identities (only set *cardinality* is stored; namespace names are K8s-DNS-discoverable anyway). The design
  **accepts the anonymized count as a deliberate, disclosed residual** (the physics genuinely needs the capacity
  signal) while guaranteeing identity-freedom. O8 tests exactly this.

---

## 5. Requirement-coverage map (every requirement → where / when)

**Pass-1 (gate-safe core, byte-identical-by-construction):**
- O1 golden-output byte-identical gate → `coverage.go (Decide)` + new CI test + `ablation.go` ratio gate.
- Per-tenant DualSolver λ (O2) → `coverage.go:117,332` + `dual.go` (per-tenant keying).
- Fleet-prior cross-feed OFF by default (O3) → `conjugate.go:92,95`, `get()`.
- Per-tenant RLS/Conformal isolation in place even though `ObserveRotation` stays unwired (O4 structure) →
  `rls.go`, `conformal.go`, `p1cost.go:87`.
- Explicit fail-fast tenant/namespace assertion at `Actuate` (O7) → `internal/actuator` (`manager.go:457` site).
- Owner-lens regression extended to streaming/new fields (O5) → `owner.go`, `redaction_test.go`, `live.go`.
- Keep + assert per-namespace least-privilege RBAC (P4c, already shipped) → `config/rbac/`, `actuator/rbac.go`.

**Later passes:** OIDC/JWT verified identity + named-other read denial (O6) → `console/server.go:255`,
`audit` Record.Tenant; safe apply-fix write-path → `redteam.go`; co-residency count-only bound (O8) →
`platform.go:147`; per-tenant DoS quotas → `runs.go`.

**Deferred-disclosed (carried as residuals, not a pass):** GPU/MIG side-channel containment (AUDIT-ONLY);
multi-tenant + cross-restart-durable co-training/operator (`[PENDING-INFRA]`); shared-budget DoS hardening;
**independent premortem-survival verification of the whole model** (blocked — see caveat).

---

## 6. Premortem residuals (attacks NOT fully closed — disclosed, not claimed solved)

- **R1 — GPU/MIG co-residency side-channel (HIGH).** Inherently cross-tenant on shared hardware; timing/power/
  SM-util leakage is **not reset by any logical move — only physical separation**. Design **contains**
  (`FactSideChannel` AUDIT-ONLY, never actuates; Phase-2 mig-rebind/node-rotate as best-effort reset; deployment
  guidance: don't co-host hostile GPU tenants on one physical GPU) — does **not close** it. The most explicit residual.
- **R2 — Co-residency anonymized COUNT (MEDIUM).** Coarse, identity-free, but a multi-pod tenant can triangulate
  node placement. Accepted, bounded, disclosed — not eliminated.
- **R3 — IP read via owner-lens before real identity ships (MEDIUM, time-boxed).** Redaction core is strong;
  the edge is demo-trust until O6/OIDC land.
- **R4 — apply-fix privilege escalation (MEDIUM, mitigated-by-absence today).** Write-path doesn't exist yet
  (records-only); the allowlist + server-side gate-check + two-key + per-namespace-SA is the mitigation —
  unproven until built and red-teamed.
- **R5 — Shared-budget / operator DoS (MEDIUM).** `RunManager.guard` is a single shared rate-limit; no
  per-tenant quota yet. Deferred.
- **R6 — Forged `Request.Tenant` (LOW, K8s-backstopped).** Already fails at K8s RBAC; O7 makes it fail-fast.
- **R7 — Latent RLS/Conformal arming (LOW-now, HIGH-if-wired).** Shared learning state is UNWIRED today
  (`p1cost.go:87`); O4 must be green BEFORE `ObserveRotation` is connected.
- **R8 — UNVERIFIED-OVERALL (process residual).** The independent premortem-survival verification could not run
  (safeguard trip). Core leak claims independently re-verified by the main loop; the full model is **not**
  independently adversarially verified end-to-end.

---

## 7. Pass scope (multi-pass build) + gates-preserved plan

**Multi-pass.** Pass-1 = the gate-safe core (per-tenant brain buckets + O1 golden gate + actuate assertion +
owner-lens regression). Pass-2 = OIDC identity + named-other read denial. Pass-3 = safe apply-fix write-path.
Pass-4 = co-residency bound test + per-tenant DoS quotas. **Gate before each pass: re-run O1 + 1.62× ablation +
P3 + lead-demo; a pass that regresses any does not ship.**

**Gates preserved — DEFAULT-TO-THE-OLD-SCALAR.** Every new per-tenant structure is seeded so that, at nil-data
with one tenant, it reproduces the existing shared scalar **exactly** — precedent already in-tree:
`ConjugateMemory.gAlpha/gBeta` seed to `defAlpha/defBeta` ("cold == old constant"), `DualSolver` seeds λ=0.6 (P0
default), the λ-clamp + prov-floor fixes are "byte-UNCHANGED" for the P3/lead-demo regime. We extend this:
`map[tenant]*P1Cost` with one tenant + default seeds = the current singleton, bit-for-bit. **O1 (the golden
byte-identical test) is the mechanical guardian**, authored from a pre-refactor capture, run in CI as a hard
gate; the 1.62×/P3/lead-demo suite re-runs before each pass. Any change that perturbs the single-tenant default
decision, λ trajectory, PHold, ratio, or the redaction whitelist **fails closed**.

---

## 8. Honest scope

- **What this is:** a decision/plan from the baseline maps + main-loop re-verification of the core leaks.
  **Nothing is built.** Every pass is a proposal with a named test currently RED.
- **What is NOT solved:** GPU/MIG side-channel (R1, cannot be closed by any logical move); co-residency count
  (R2, deliberately disclosed); verified identity / named-other read denial / safe apply-fix / per-tenant DoS /
  cross-restart-durable multi-tenant operator are later-or-deferred.
- **Both products:** brain → per-tenant buckets, no fleet cross-feed; console → strong redaction + verified
  identity; actuation → K8s-RBAC-per-namespace + explicit assertion; physics → global scan + bounded per-tenant
  disclosure.
- **The biggest honesty flag:** the formal premortem-survival peer-verification was not satisfiable (safeguard
  trip → empty-input `survives=false`). **Correct next action before building:** re-run the Analyze/Premortem
  phase (rephrase the prompts / route via the Cyber Verification Program), then verify each obligation O1–O8
  against its named test. Until then P-VCLUSTER is `[PENDING]` with this plan as its input; **no requirement may
  be reported PASSED merely because it is listed pass-1 — pass-1 means "scheduled first," not "done."**

---

## Decision requested
Approve (a) the **split tenancy model** (per-tenant brain buckets / verified-identity console / RBAC-per-ns
actuation / global-scan-bounded-disclosure physics), (b) **Pass-1 scope** (the gate-safe core, O1 golden gate
first), and (c) the **deferred-disclosed residuals** (esp. R1 GPU side-channel — contained, not closed). I
recommend the premortem-verification re-run be the **first** action of the build pass (before any code), so the
design is adversarially verified end-to-end. **No code built this pass. STOP for approval.**
