# PHORVEXSEC-217 / M-13 — actuation notifications

DEV Milad, independent reviewer requested Hami. Independent DEVOPS/security review and named live verifier remain open. Base PR135 074e9f8, upstream ea5d5ca / v0.4.96, controller-runtime v0.21.0, resolved client-go v0.34.0, chart 0.1.4. No deployed image/digest change. Isolated API tests use Kubernetes 1.33.0.

## RECORD and coordinated CONTROL work

Baseline only ActionsSupported emits a core Kubernetes Event. Added a separate phorvex-actuation recorder from the existing manager provider and one shared notification point immediately after Actuate returns, before either error or emitted handling. Captures Pod namespace/name/v1/UID from the selected view before dispatch. Never refetches by name or adds Pod owner references. Missing original identity suppresses publication with a diagnostic. Native/delegated result paths share the same call. Group/shard actions notify about the request's original Pod target, not every possibly affected neighbor.

No Event for selection-only, dry-run, kill switch, missing view, feasibility veto or EnsurePolicy pre-dispatch failure. Existing audit/status remains authoritative at its actual evidence level. Error (including emitted+error) and ambiguous non-emission => OutcomeUnknown with partial-change caution. Emitted+nil error => Emitted, explicitly unconfirmed effect. Verified native rotate refusal, route missing configuration, declared disable => NotEmitted. Other non-emission remains unknown. No claimed confirmed-effect path added.

Payload contains allowlisted action and fixed outcome text. Raw errors, handler notes, detector data, scores, policy/tenant identifiers and touched-object lists are not published. Native refusal text is classified but never echoed. Target reference is minimal and original-UID bound. This binds the notification to the original request, not independently verified affected objects. Other native handlers such as identity-rotate still read by namespace/name without enforcing TargetUID, so name reuse can affect a replacement Pod. That pre-existing mutation-boundary gap remains outside this notification fix. No new correlation ID exists in the request contract, so none invented. Repeated attempts may aggregate and are not an audit ledger.

## CONTRACT / output-only checks

The actual sink is core/v1 Events, not events.k8s.io and not Phoenix SecurityEvent. Existing manager ClusterRole in raw and Helm profiles already grants core events create/patch, the actual pinned broadcaster operations. No new RBAC grants are needed or added. Dedicated raw actuator identity is not the recorder identity. Independent deployment review must verify actual bindings. The isolated fixture deliberately uses narrower namespace-only create/patch to verify these operations suffice.

internal/ingest/events.go lists amtd SecurityEvent CRs only, with self-event/trust filtering. It does not consume core Kubernetes Events. New notifications cannot enter that feed. No scoring, calibration, optimizer, handler or budget changes.

## Pinned delivery behavior and diagnostics

Manager's provider uses client-go record broadcaster. Event() does not acknowledge persistence. Queue is bounded at 1000, drop-on-full, diagnostic on queue overflow. Correlator aggregates/restricts repeated Events. Sink writes are asynchronous, Create then Patch for repetition. Transport failures have up to 12 attempts, normally 10-second retry sleep (first randomized). Forbidden StatusError is logged and not retried. No retry invokes the actuator. API retries/drops are not counted as attempted defenses.

Failure logs come from the existing broadcaster (Server rejected event / Unable to write event / too many queued events), not recursive Events. Manager shutdown tries to flush within its shutdown context; delivery at shutdown is not guaranteed. Saturation and partition soak are not certified by the local test. No zero-cost, exactly-once or retention guarantee.

## Predicted versus observed

Before test: emitted unknown-effect Event must survive target deletion with original UID, repeat via Patch, refuse sensitive disclosure, log denied sink writes promptly, recover after restored permission. Actual TestM013RealEventSink PASS: real RBAC-enabled envtest, namespace-scoped impersonated serviceaccount, deleted Pod replaced under the same name, Event still references original UID. Repeat count >=2 in the same Event. Denial logs observed while notification returns under 500ms, restored role binding permits another Event. No actuator is invoked by this notification fixture, so it proves delivery isolation rather than end-to-end live defense. Raw log retained.

Truthful matrix tests PASS for emitted, refusal, unknown, partial error, missing UID and sensitive dynamic input. Existing processTenant kill-switch test now verifies selected-but-suppressed produces zero Events, active positive control one Actuate/one notification, and dry-run no extra Actuate/Event. Runner/ingest/cmd regression PASS. Existing policy warning tests unchanged and passing.

Independent live active-mode verification, actual installed principal, queue/failure soak, operational upgrade/rollback review remain required. No fake-recorder result is presented as API persistence. Raw Events are ephemeral notifications and supplement existing audit data without certifying durability or protection.
