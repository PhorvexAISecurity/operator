# Phorvex — Real-Environment Validation Checklist

**Audience:** the dev team running Phorvex on real infrastructure (a GPU cluster, an EKS/GKE cluster, a live
IdP, a deployed vLLM). Everything below is **real code, tested in CI with mocks**; this doc is the end-to-end
checklist to validate + calibrate each piece on real hardware and confirm it passes.

**How to read each item:** **(a)** what's built + what the mock proves · **(b)** the exact real-env step
(command) · **(c)** what to fine-tune/calibrate · **(d)** the acceptance criterion (how you know it passes).

> Labels: `[PENDING-GPU-VALIDATION]` (needs a real GPU + DCGM/NVML), `[PENDING-CLUSTER-VALIDATION]` (needs a real
> K8s cluster + CRDs + SA), `[PENDING-IDP-CONFIG]` (needs your IdP), `[PENDING-FULL-BENCH]` (needs the full
> head-to-head run). None of these are "unbuilt" — they are "unvalidated-on-real-hardware".

---

## 1. AI/GPU actuators — the vLLM control-plane ops `[PENDING-GPU-VALIDATION]`

Ops: `kv-reset` (prefix-cache flush), `adapter-rotate` (LoRA unload/load), `request-drain`, `guardrail-rotate`,
`kv-migrate-invalidate`, `warm-swap`.

- **(a) Built + mock proves:** each op is a real HTTP call to the vLLM admin route behind the `vLLMClient`
  interface; CI (`gpu_stack_test.go`, `vllm_routes_test.go`) proves the request is correctly formed, the
  reachable/failing/unreachable cases are distinguished (`errStackUnreachable`), and on kind (no vLLM) the calls
  fail-closed rather than fabricate. The handler-coverage invariant proves every declared action has a handler.
- **(b) Real-env step:** deploy vLLM (OpenAI server) with a model + ≥1 LoRA; annotate the pod with
  `phorvex.ai/serving-port` etc.; then drive each op via the actuator (or `phorvex --scan` + a scenario that
  triggers the AI actions) and watch DCGM + the vLLM logs.
- **(c) Calibrate:** confirm the route strings against YOUR vLLM version (see §5); confirm the prefix-cache reset
  is observable (cache-hit-rate drop) and the LoRA unload/load reflects in `/v1/models`.
- **(d) Acceptance:** each op returns HTTP 2xx on a real vLLM AND the intended effect is observed (cache flushed
  / adapter gone-then-present / requests drained) within the op timeout; no op silently no-ops.
- **Detector signals and steering (added 2026-09-13, source `d296799`; not a live result).** A detector reaches
  the brain through two doors, and the validation plan must exercise both as they are now, not as the August
  runs saw them: (i) a `SecurityEvent` becomes belief evidence only when its admission-stamped creator identity
  is on the `--trusted-detectors` allowlist (`internal/ingest/eventtrust.go`, M-94) — `spec.rule.source` is
  ignored, and an untrusted event is recorded with its verdict and supplies nothing; (ii) the pod marker
  `phorvex.ai/lora-adapter` on a pod labelled `phorvex.ai/lora-enabled=true` (→ `Pod.SuspectAdapter`,
  `internal/ingest/kube.go`) mints the `adapterIntegrity` fact, so whoever can patch the pod can steer selection
  toward adapter-rotate regardless of any event (M-95, open). A trusted event whose `type` is one of
  `phorvex.attack.{kv,guardrail,inflight}` additionally multiplies one serving fact's weight ×3 in `ucw-recon`
  (`phorvex.attack.adapter` does not); the boost grants no cover, is not attributed in the trace (M-153 pending),
  and is not aged by recon — it lasts while the CR exists. The kill-chain evidence weight of every event decays
  linearly to 0 at `spec.triggers.eventAgeHorizon`; omission uses an inherited, uncalibrated `1h` default that is
  independent of `spec.budget.proactiveFloor`. Operators who previously used a custom proactive floor as accidental
  event memory must set the new field explicitly to retain that duration. Current cover per action, with fixtures, is in
  `docs/recon-cover-map.generated.md` (`go run ./tools/covermap --check`); mechanics and the historical-trial
  caveats are in `build/test-harness/ACTUATOR_COVERAGE.md`. The 2026-08-21 detector runs in
  `workflow/attacks/reference/PHORVEX_RUNTIME_VALIDATION.md` predate the trust boundary and used self-declared
  sources; they are historical, not acceptance evidence for the current build.

## 2. Production applier — the apply-fix cluster write `[PENDING-CLUSTER-VALIDATION]`

`internal/applier/crd.go` — patches the tenant's `PhorvexPolicy` (phorvex.ai/v1alpha1) via a per-namespace SA.

- **(a) Built + mock proves:** `crd_test.go` (fake client) proves the patch is correctly constructed
  (NormSparsity/FlowDisruption/MaxMovesPerTick/ProactiveFloor), the **safety gate is RE-ASSERTED before the
  patch** (a gate-breaking delta never patches), ambiguous (0 or >1 policy) + wrong-namespace targets
  fail-closed, and a non-landing patch is **rolled back** (rollback-failure surfaced loudly).
- **(b) Real-env step:** install the `PhorvexPolicy` CRD; create one PhorvexPolicy in a tenant namespace; create
  a per-namespace SA with `get/list/patch` on `phorvexpolicies` in that namespace ONLY; wire the applier in the
  console deployment (`console.NewApplyFixManager(basePol, applier.NewCRDApplier(client, console.PolicySafetyGate,
  audit).Apply, audit)` with `ApplierMode="live"`); then run the apply-fix two-key flow from the dashboard.
- **(c) Calibrate:** confirm the SA RBAC is namespace-scoped (a cross-namespace patch must 403); confirm the
  PhorvexPolicy name resolution (exactly one per namespace) matches your install convention.
- **(d) Acceptance:** a gate-passing, two-key-approved delta lands on the real CRD (`kubectl get phorvexpolicy -o
  yaml` shows the new values); a delta in another namespace is refused; a malicious delta is rejected with 422
  and the CRD is untouched; the audit shows submitted→applying→applied exactly once. Until the applier is
  wired, an approval answers `501 applier-unavailable` and the request stays pending — `ApplierMode` is a
  label only (`docs/CONSOLE-APPLY-FIX.md`).

## 3. MIG node-exec transport — `mig-rebind` `[PENDING-GPU-VALIDATION]`

`internal/actuator/nodeexec.go` — the privileged `pods/exec` (remotecommand SPDY) into the MIG node-agent.

- **(a) Built + mock proves:** `nodeexec_test.go` proves the nvidia-smi MIG **sequence + ordering**
  (`-dci` → `-dgi` → `-cgi <profile> -C`), the agent-pod resolution on the target node, and **fail-closed** when
  the exec is unwired OR no agent pod is Running on the node (never deletes a pod it then cannot repartition).
- **(b) Real-env step:** deploy a privileged MIG node-agent DaemonSet (labeled `phorvex.ai/mig-agent=true`) with
  `nvidia-smi` available; call `actuator.WireRemoteNodeExec(actuator.RemoteExecConfig{Config: restCfg, Clientset:
  cs})` at startup; then trigger `mig-rebind` on a MIG-capable GPU node.
- **(c) Calibrate:** confirm the agent container name + the nvidia-smi MIG flags against your driver/GPU-Operator
  version; ensure CUDA contexts are drained (the caller drains BEFORE Repartition) — confirm no orphaned
  contexts; confirm the target GPU id (`-i <gpuID>`) maps to the intended physical GPU.
- **(d) Acceptance:** `nvidia-smi mig -lgip` shows the new geometry after `mig-rebind`; a node with no agent
  fail-closes WITHOUT evicting the workload; a partial repartition aborts at the failing step (no half-config).

## 4. OIDC verified identity — config `[PENDING-IDP-CONFIG]`

`internal/console/oidc.go` (verifier, proven in Pass 2) + `oidc_config.go` (config + JWKS loader).

- **(a) Built + mock proves:** `oidc_test.go` proves the RS256 verifier (forged/`alg=none`/expired/wrong-aud/iss
  rejected; tenant from the verified claim); `oidc_config_test.go` proves `LoadOIDCVerifier` builds a working
  verifier from a JWKS (mock fetch) and fail-closes on bad config / fetch error / empty JWKS.
- **(b) Real-env step:** set env on the console deployment:
  `PHORVEX_OIDC_ISSUER`, `PHORVEX_OIDC_AUDIENCE`, `PHORVEX_OIDC_JWKS_URL`, `PHORVEX_OIDC_TENANT_CLAIM`,
  `PHORVEX_OIDC_LENS_CLAIM` (see `console.ExampleOIDCConfig()`); restart; sign in via your IdP; the dashboard
  sends the `Authorization: Bearer <jwt>` and the apply-fix flows use the **verified** tenant/subject.
- **(c) Calibrate:** confirm the claim names carry tenant + lens (a custom claim like
  `https://phorvex.ai/tenant` is fine — set `PHORVEX_OIDC_TENANT_CLAIM` to it); confirm the audience matches the
  console's registered client id.
- **(d) Acceptance:** a valid IdP token authenticates with the right tenant; a forged/expired/wrong-audience
  token is rejected (401); a request that self-asserts `?tenant=` is IGNORED (the verified claim wins — O6).

## 5. vLLM route strings — per-deployment config `[PENDING-GPU-VALIDATION]`

Every route is a pod annotation with a documented default (no hardcoded literal reaches the wire):

| Route | Annotation | Default |
|---|---|---|
| prefix-cache reset | `phorvex.ai/kv-reset-path` | `/reset_prefix_cache` |
| liveness | `phorvex.ai/health-path` | `/health` |
| loaded models | `phorvex.ai/models-path` | `/v1/models` |
| LoRA unload | `phorvex.ai/lora-unload-path` | `/v1/unload_lora_adapter` |
| LoRA load | `phorvex.ai/lora-load-path` | `/v1/load_lora_adapter` |
| drain | `phorvex.ai/drain-path` | `/v1/drain` |
| serving port | `phorvex.ai/serving-port` | `8000` |

- **(a) Built + mock proves:** `vllm_routes_test.go` proves every route resolves from its annotation (else the
  default) and that `ModelReady` actually calls the CONFIGURED health/models routes on the wire.
- **(b) Real-env step:** `curl` your deployed vLLM for each route; if a route differs (version/flag), set the
  matching `phorvex.ai/*` annotation on the serving pods — **no code change**.
- **(c) Calibrate:** recent vLLM exposes prefix-cache reset behind a flag; `/v1/drain` is not standard — point
  `phorvex.ai/drain-path` at your deployment's drain/abort route (or disable the op).
- **(d) Acceptance:** every annotated route returns the expected response from your vLLM; `ModelReady` reports
  ready only when the model is actually loaded.

## 6. Full head-to-head benchmark `[PENDING-FULL-BENCH]`

- **(a) Built + mock proves:** the harness + arms exist; the recon-per-$ ratio + the audited oracles run in CI on
  fixtures (`ablation`/`optimality` tests). See `BENCHMARK-RUNBOOK.md`.
- **(b) Real-env step:** run `BENCHMARK-RUNBOOK.md` end-to-end on a real EKS cluster (the 6 arms, the full
  scenario suite, N≥ the runbook's trial count).
- **(c) Calibrate:** the recon-per-$ ratio is **fleet-dependent (ratio > 1.0)**, NOT a fixed "1.62×" — report the
  measured ratio for YOUR fleet; confirm the audited oracles (P-ORACLE-FIX / P-AUDIT) on your data.
- **(d) Acceptance:** Phorvex beats equal-budget random per-dollar (ratio > 1.0) on the real fleet; P3 zero-day
  proactive fires; the lead-demo no-harm invariant holds; results framed per the runbook (no overclaim).

---

## Wiring summary (deployment)

```
# OIDC (env on the console deployment)
PHORVEX_OIDC_ISSUER, PHORVEX_OIDC_AUDIENCE, PHORVEX_OIDC_JWKS_URL,
PHORVEX_OIDC_TENANT_CLAIM, PHORVEX_OIDC_LENS_CLAIM

# Production applier (in the console bootstrap, with a controller-runtime client + per-namespace SA)
console.NewApplyFixManager(basePol, applier.NewCRDApplier(client, console.PolicySafetyGate, audit).Apply, audit)
# set manager.ApplierMode = "live"

# MIG node-exec (at actuator startup, with the REST config + clientset)
actuator.WireRemoteNodeExec(actuator.RemoteExecConfig{Config: restCfg, Clientset: cs})

# vLLM routes — per serving-pod annotations (phorvex.ai/*), no code change
```

**Brain invariant (unchanged across all of the above):** the optimizer / cost / feasibility decision logic is
NOT touched by any real-env wiring. The gates (recon-per-$ ratio>1.0, P3 zero-day, lead-demo, the O1 golden, the
Pass-1 O1–O10) must stay green after wiring — re-run them (`/api/redteam/gates` from the dashboard, or
`go test ./internal/...`) on the real deployment.
