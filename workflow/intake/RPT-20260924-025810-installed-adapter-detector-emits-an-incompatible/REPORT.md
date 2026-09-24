# Installed adapter detector → manager contract: offline reproduction

2026-09-24. **Confirmed producer/consumer contract failure in the exact installed source; no live finding, event, manager decision or mitigation was observed.** The actual installed `emit_event(pod, adapter)` function, invoked offline with a fake `kapi`, constructs a `SecurityEvent` whose target **name** is present, but whose metadata has **neither** `phorvex.ai/adapter-name` **nor** `phorvex.ai/target-pod-uid`. Its rule type is `lora.unauthorized_adapter`; the deployed and current manager require `phorvex.attack.adapter` for adapter-specific belief. All three mismatches independently prevent `bindAdapterObservation` from producing the UID-bound adapter fact that makes `adapter-rotate` eligible. The Pod marker written by another producer function cannot fill the event's missing fields: `ingest/adapter.go` explicitly requires the event values and does not backfill from Pod metadata.

## Exact source and bounded capture

`CAPTURE.json` records seven finite read-only Kubernetes calls: before/after Deployment, exact selected Pod and ConfigMap GETs, plus one `kubectl exec` that only hashes the mounted `/app/detector.py`. Before/after Deployment UID `b84512f0-0e7b-4da9-88fc-426a88176071` generation3, Pod UID `23b9b563-cb55-4d0d-b950-7c1e48a7986f` with the same ready container ID, and ConfigMap UID `19a4a901-e148-42b0-add2-52df9f30f3aa` RV `47082960` were unchanged. The ConfigMap key and mounted source were both 5,721 bytes with SHA-256 `5f37421809b883b537ffd3a913e223f56c7ae918a6b87430e7fa206db53012a8`. The raw source is retained privately as `installed-detector.py` mode0600 in this directory; no Secret API, token or logs were read, and no live inference request, external request or event mutation was issued. The reviewed finite transport SHA-256 is `c357d0bc4c3dcab0d3eab24e9c7dcf1bbcb562543231ae6ea423781ca9bc5fed`; it dispatches exec once with no application retry.

## Actual function, normal-shaped input, and envelope

`reproduce.py` compiled **only** the exact AST `emit_event` function from that pinned source. The source's top-level `while True` poll and imports were not executed. A fake `kapi` captured its sole POST to `/apis/amtd.r6security.com/v1beta1/securityevents` and returned synthetic201. Input was a harmless, normal-shaped unexpected adapter ID `owned-neutral-adapter`, a target Pod name `owned-vllm-0` in namespace `vllm`, empty expected set (matching the installed `EXPECTED_ADAPTERS` configuration), and fixed fake clock `1730000000`. This is an offline function argument, not a real Pod, loaded adapter or producer finding. `OFFLINE-REPRO.json` has the exact synthetic request body and an illustrative positive contrast.

| Manager-required field | Actual `emit_event` body | Illustrative repaired body |
| --- | --- | --- |
| `spec.targets` | `vllm/owned-vllm-0` | same |
| `spec.rule.type` | `lora.unauthorized_adapter` | `phorvex.attack.adapter` |
| `metadata.annotations[phorvex.ai/adapter-name]` | absent | `owned-neutral-adapter` |
| `metadata.annotations[phorvex.ai/target-pod-uid]` | absent | `owned-pod-uid-123` |

The contrast only satisfies those four static fields. It does not prove admission-stamped creator trust, event UID/creation time, target UID existence, policy eligibility, LoRA capability, route authority or actuator execution. The installed `get_pod` selects the first `phorvex.ai/role=leader` Pod by **name** and caches that name; the `/v1/models` inventory is read via configured service URL. Neither operation currently establishes that the inventory response and selected Pod UID represent the same serving incarnation. A name-only target and a stale cached name could make an event appear relevant to a replacement Pod.

## Real ingest consumer contrast (local Go overlay)

`consumer_overlay_test.go` is a private, additive test overlaid into `internal/ingest` by `OVERLAY.json`; no product file was changed. It decodes the exact `producerCall.body` from `OFFLINE-REPRO.json` into the real `SecurityEvent` type and calls the production `collectEventsAndReceipts` followed by `bindAdapterObservation`. Each subtest supplies the **best-case simulated** API-assigned Event UID/creation time and admission-stamped allowlisted creator `system:serviceaccount:vllm:detector-adapter-inv`. The fake client yields one trusted event in the exact Pod's `EventByPod` in every arm, so the test isolates adapter binding rather than a missing trust or target-name join.

| Envelope arm | Real ingest `AdapterObservation` |
| --- | --- |
| Captured installed producer body | absent |
| Add both required annotations, retain installed rule type | absent |
| Change only rule type to canonical adapter type | absent |
| Add both annotations and canonical type, exact target UID | present; exact synthetic adapter and Event UID bound |
| Full fields but wrong target UID | absent |

Command: `go test -overlay=R/detector-contract/OVERLAY.json ./internal/ingest -run '^TestCapturedDetectorProducerConsumerContract$' -count=1 -v` from `phorvex/`; all five subtests PASS, package reported 0.017s. This is local consumer source behavior with a fake API client, not a live admission decision or end-to-end defense. The deployed/current adapter binder is byte-identical; current `events.go` has additional console-specific UID handling, while its adapter type/annotation projection is unchanged from deployed source.

## Consumer pins and source repair

At deployed manager source `a50d796af128cd4109875e03eaf429d460126740`, `phorvex/internal/ingest/events.go` copies the raw rule type plus these two annotations into `SecurityEventInfo`; `phorvex/internal/ingest/adapter.go` requires trusted creator, fresh event, exact Pod target, canonical `AttackVectorAdapter`, valid adapter name and exact target UID before binding. The `adapter.go` file is byte-identical at current checkout HEAD (`c60c8b4887cb2dc012ba1912a1dc0fd3d206cde08d0fdd0b52a20e72768b75cc` SHA-256). Current `events.go` adds console target-UID checks but retains the same adapter field projection. The canonical rule constant remains `phorvex.attack.adapter` in both deployed and current `model/types.go`. `feasibility/actions_native.go` requires this bound observation for `adapter-rotate`; an event's high threat label or a Pod marker alone cannot make it eligible.

The live ConfigMap/Deployment source owner is **not identified in this checkout**: no tracked `adapter-inv-detector-script` or detector Python source was found under `phorvex/`, `deploy/` or `build/`. Do not edit the live ConfigMap as the repair. Locate its GitOps/Helm owner, then version the pinned detector source there and change the producer contract: derive one valid unexpected adapter ID and fresh exact Pod UID from the same target whose inventory was sampled; emit `phorvex.attack.adapter` with both required annotations and one target; reject target/inventory ambiguity and Pod reincarnation. The manager's admission and UID checks should remain strict. A **separate** owned-fixture detector instance needs explicit target namespace/selector/endpoint configuration and narrowly reviewed creator trust; it must not reuse the business detector's broad `vllm` target or alter the business Service. Test actual event-envelope construction with fake `kapi`, plus missing/mismatched UID, wrong type/name, stale and untrusted event controls before a future live admission. No source repair or deployment is authorized by this report.

Files: `capture.py`, `CAPTURE.json`, private `installed-detector.py`, `reproduce.py`, and `OFFLINE-REPRO.json`. The synthetic positive envelope is an offline source-contract illustration, not a cluster object or security result.
