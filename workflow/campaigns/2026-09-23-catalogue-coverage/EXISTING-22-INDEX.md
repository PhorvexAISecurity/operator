# Original 22 catalogue items and live continuation map

This is the exact 22-ID set from the [September25 interim ledger](EXISTING-22-VERDICTS.md),
mapped to source on `main` at `f30cc64e1b4dbd9329153ff2c7058cc72213111b`.
The set contains benign, boundary, mechanism and security cases. It was **not**
22 completed live brain defenses. Historical results below come from that ledger;
they are not September29 reruns or current deployment claims. Source links are
portable; the ledger's private `R/` receipts may require a separate evidence export.

Use the [handoff](HANDOFF-20260929.md) for newer live implementations and ownership,
and the [runbook](../../operations/LIVE-CATALOGUE.md) for promotion and verification.
The final column is a continuation proposal, not an implemented or verified result.

## Voice and inference

| # | Frozen ID and implementation | What was built and historical result | How to continue |
| --- | --- | --- | --- |
| 1 | `limited-v1-voice-media` — [Voice suite](../../../phorvex/internal/cataloguev1/voice.go) | Benign direct WebSocket media; named `v1run-4` functional PASS. No attacker or brain claim. | Keep as the legitimate audio control for Voice live security cases. Measure actual STT/model/TTS and received audio as required; do not claim a telephone call was tested. |
| 2 | `limited-v1-voice-recovery` — [Voice suite](../../../phorvex/internal/cataloguev1/voice.go) | Exact-UID eviction and fresh-session recovery; `v1run-5` failed cleanup. Direct eviction was not a brain action. | Preserve the failed run; reverify current cleanup. For a security successor, use a real session threat and normal brain-selected defense, retaining recovery/availability as separate controls. |
| 3 | `limited-v1-vllm-request-drain` — [GPU suite](../../../phorvex/internal/cataloguev1/gpu.go) | Owned ordinary-GPU drain/reopen fixture; no named live defense in the frozen ledger. | Reuse current [typed request-drain](../../../phorvex/internal/console/vllm_drain_worker.go) for installed-brain trials; it has its own profile/stream/operation controls. Do not confuse this fixture ID with the live `request-drain` ID. |
| 6 | `limited-v1-vllm-guardrail-effect` — [conditional catalogue entry](../../../phorvex/internal/console/catalogue_v1.go) | Historical injected pgv1→pgv2 rotation effect; no threat result then. Current source selects output-v2 when configured, otherwise the guardrail effect path. | Follow the actual selected profile. Output-v2 measures scoped output-policy activation, not `guardrail-rotate`; old effect credit must not transfer to it. |
| 8 | `limited-v1-vllm-guardrail-calibration` — [classifier control](../../../phorvex/internal/cataloguev1/guardrail_calibration.go) | Two benign classifier requests; `v1run-12` functional PASS with a recorded pgv1 false positive. | Keep calibration as a control. Validate actual guarded serving separately; a classifier answer neither proves a rotation nor defeats a workload attack. |
| 17 | `ai-vllm-guardrail-confidentiality-static` — [static probe](../../../phorvex/internal/console/guardrail_static.go) | Raw/guarded synthetic-marker comparison. Named `run-15` was non-discriminating because the raw model withheld the marker; guarded stage was not attempted. | Qualify a reproducible baseline. Retain static filtering as static protection; only a separate event/decision/operation/replay chain earns brain-response credit. |
| 19 | `ai-vllm-guardrail-availability-recovery` — [availability runner](../../../phorvex/internal/console/guardrail_availability_runner.go) | Injected recovery changed benign Say OK from403 to200; canary was blocked both times. Availability effect, not a security defense. | Keep paired threat and benign controls. Reverify current variants/source; prove a newly stopped threat before adding a security claim. |

## Phorvex and Kubernetes credentials

| # | Frozen ID and implementation | What was built and historical result | How to continue |
| --- | --- | --- | --- |
| 4 | `limited-v1-console-unauthenticated` — [auth controls](../../../phorvex/internal/cataloguev1/auth.go) | Installed API auth boundary; `v1run-6`401/401/200/200. Static control, no brain response. | Keep as a negative/legitimate access control. A new adaptive security case needs its own owned data objective, observation and actual enforcement change. |
| 5 | `limited-v1-console-scoped-authorization` — [auth controls](../../../phorvex/internal/cataloguev1/auth.go) | Tenant/target grant boundary; `v1run-13`200/200/403/403/200. No detector or decision trial. | Reuse scoped principals and denied-target controls in every live route. Do not call existing403 responses brain defenses. |
| 18 | `c2-pod-bound-api-auth-response` — [token response scenario](../../../build/test-harness/scenarios/c2_pod_bound_token.go) | Historical owned Voice Pod-bound bearer still returned200 after seven injected-event-correlated NOOPs. No named CPU run. | Reconcile current telemetry, cost/availability constraints and token invalidation semantics. Measure the same stolen bearer, expiry and legitimate peer before/after the exact operation. Rotation cannot undo its earlier access. |
| 22 | `c2-pod-bound-api-auth-response-cpu` — [CPU Console integration](../../../phorvex/internal/console/pod_bound_token.go) | CPU-only successor/control path; frozen attempt was rejected before POST by node-name validation. Later source/config repairs exist. | Rebase on current code and freshly rendered CPU profile; inspect [retained deployment work](deployment/existing22-cpu-pr354/README.md). Verify brain choice and same bearer/peer/Service outcomes; do not blindly apply that dated bundle. |

## Messaging and data stores

| # | Frozen ID and implementation | What was built and historical result | How to continue |
| --- | --- | --- | --- |
| 9 | `c2-nats-uncredentialed-exposure` — [NATS exposure](../../../build/test-harness/scenarios/c2_nats_uncredentialed_exposure.go) | Historical unauthenticated client received an owned synthetic nonce. Baseline exposure, no named defense. | Refresh broker auth and subject/consumer boundaries. Define a scoped client/session/subject defense and repeat exposure with legitimate publisher/consumer ACKs; if current actuators cannot enforce it, design that missing broker integration. |
| 10 | `c2-nats-owned-client-response` — [NATS response](../../../build/test-harness/scenarios/c2_nats_client_response.go) | Prepared same-client/peer before/after response case; packet enforcement and same-run controls were unverified. | Establish current quorum, auth and CNI behavior first. A policy object or unrelated Voice quarantine is not a NATS containment result. Preserve legitimate messages and client continuity. |
| 11 | `c2-mongo-uncredentialed-service-exposure` — [Mongo exposure](../../../build/test-harness/scenarios/c2_mongo_uncredentialed_exposure.go) | Owned document-exposure design and historical projected observation; original raw reply missing in the frozen ledger. | Use fresh owned documents and preserve exact raw client evidence. Define a Mongo auth/network containment boundary and authorized read/write controls before attributing defense. |
| 12 | `catalogue-chroma-owned-vector` — [Chroma control](../../../phorvex/internal/cataloguev1/chroma_control.go) | Synthetic collection/document add/query/delete; `v1run-10` functional PASS. No adversarial principal. | Keep as the vector-state/cleanup control. A security extension needs distinct tenant authority or untrusted retrieval content and a measured forbidden read/use, then an enforcement mechanism. |

## LiteLLM

| # | Frozen ID and implementation | What was built and historical result | How to continue |
| --- | --- | --- | --- |
| 13 | `catalogue-litellm-route-health` — [listener controls](../../../phorvex/internal/cataloguev1/litellm_control.go) | Original `v1run-8` UNKNOWN; supplemental listener check passed. No inference/security result. | Keep route health as a prerequisite, preserving both original and supplemental findings. Use current live runners for client/output containment. |
| 14 | `catalogue-litellm-credential-boundary` — [credential control](../../../phorvex/internal/cataloguev1/litellm_control.go) | `v1run-9` configuration-limited: missing credential401, invalid credential400 `NO_CONNECTED_DB`; no valid denial/bypass conclusion for that invalid-key arm. | Recheck actual auth configuration. Current [client-revoke runner](../../../phorvex/internal/console/litellm_live.go) measures bounded owned gateway credentials, not global master-key compromise recovery. |
| 20 | `catalogue-litellm-inference-routing` — [routing control](../../../phorvex/internal/cataloguev1/litellm_routing.go) | `v1run-14` functional PASS on both serving Pods: known model200, unknown model400. No event or defense. | Reuse as legitimate-serving evidence for the four newer live cases in the handoff; test actual public Service and bypass paths required by each claim. |

## CRM and MCP

| # | Frozen ID and implementation | What was built and historical result | How to continue |
| --- | --- | --- | --- |
| 7 | `catalogue-mcp-session-baseline` — [MCP session control](../../../phorvex/internal/cataloguev1/mcp_session.go) | Synthetic tool read/session lifecycle; `v1run-11` functional PASS, no malicious tool or Voice behavior. | Keep real tool/session control; pair with current Voice MCP live tests and verify actual callbacks, not only model-selected tool text. |
| 15 | `c2-crm-refund-capability` — [CRM fixture](../../../phorvex/internal/cataloguev1/crm.go) | Local disposable A/B refund writes; A/B were records, not authenticated principals. No named security verdict. | Use current [Voice refund live runner](../../../phorvex/internal/console/voice_agency_live.go) as a derived slice: actual model callback, owned other-order write, exact-pair denial and own-order controls. State its caller-identity limitation. |
| 16 | `c2-crm-reset-capability` — [CRM fixture](../../../phorvex/internal/cataloguev1/crm.go) | Local disposable A/B reset writes with readback; no authenticated ownership or brain response. | Define the reset-specific principal/authority boundary and an independent effect oracle. Refund-pair denial is not proof of reset protection; a reset-specific application hook/action may be needed. |
| 21 | `catalogue-mcp-voice-model-continuation` — [model continuation](../../../phorvex/internal/cataloguev1/mcp_voice_model.go) | Normal versus substituted MCP result through actual model; historical attempt selected zero tools, no callback execution or defense. | Reuse current [Voice MCP live producer](../../../phorvex/internal/console/voice_mcp_live.go) and tool-pin actuator, while distinguishing tool-description poisoning from result substitution. Measure the forbidden behavior and real benign tool callback. |

## Coverage accounting

These tables enumerate 22 unique frozen IDs; their numbering preserves the old
ledger order even though they are grouped by stack. The separate
[coverage matrix](coverage.yaml) contains broader candidate cells, and the old
harness contains additional scenarios. Neither count equals 22 live defenses.

For each next round add its current source and deployment, runnable/configuration
state, input mode, actual stage results, raw evidence location and reviewer.
Do not overwrite the historical column with a current-looking PASS. New live
behavior derived from an existing control gets its own explicit claim and run
history. The goal is useful, repeatable coverage of the current workload and
trust boundaries, not a quota of Fire buttons or a forced binary verdict.
