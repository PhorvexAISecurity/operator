# Wiring the `crm-refund-revoke` actuator

This package is the tested contract core (guard schema, idempotent deny-list CAS,
observation parse, app-facing encoding). It deliberately does **not** yet wire a new
`Action` into the live operator, because enabling a new actuator type is a reviewed
step: a wrong RBAC grant or an action enabled in a policy whose namespace is missing
from `values-eks actuatorNamespaces` wedges the operator at startup. The live operator
is unaffected until the steps below are done AND a new image is deployed AND the
action is enabled in `crm-defense`.

Mirror `litellm-client-revoke` exactly — it is the proven analog (ConfigMap-state
revoke with per-Pod readback and a protected journal). File by file:

1. **`phorvex/internal/model/types.go`** — add `ActionCRMRefundRevoke Action =
   "crm-refund-revoke"` and append it to the actions list, next to
   `ActionLiteLLMClientRevoke` / `ActionVoiceRefundPairDeny`.

2. **`phorvex/internal/model/decision_trace.go`** — append `ActionCRMRefundRevoke`
   to the appropriate tier(s), as the other application-scoped revokes are.

3. **`phorvex/internal/actuator/verbs.go`** — add the RBAC row:
   `model.ActionCRMRefundRevoke: {{Resource:"configmaps", Name: crmrefund.GuardConfigMapName, Verb:"get"},
   {..., Verb:"update"}, {Resource:"configmaps", Name: crmrefund.JournalName, Verb:"get", OperatorScoped:true},
   {..., Verb:"update", OperatorScoped:true}, {Resource:"pods", Verb:"get"}, {Resource:"pods", Verb:"list"},
   {Resource:"services", Verb:"get"}}` — same shape as the `ActionLiteLLMClientRevoke` row. Add the matching
   `m007_generated_test.go` expectation.

4. **`phorvex/internal/actuator/crm_refund_revoke.go`** — the handler, mirroring
   `litellm_client_revoke.go`: resolve the guard ConfigMap by UID, CAS-append the
   abused `Observation.OrderID` under the decision's operation id, write the
   app-facing `denied.json` via `Guard.EncodeAppGuard()`, append the protected
   journal receipt, then read back from every serving CRM Pod (label `app=crm`) and
   only report `Emitted` once every Pod denies the revoked order — the live drill
   showed enforcement is eventually-consistent over the ConfigMap mount sync (~86s),
   so partial propagation must return the pending sentinel, not success.

5. **`phorvex/internal/actuator/native.go`** — add the capability + dispatch cases
   for `ActionCRMRefundRevoke`, alongside the LiteLLM ones.

6. **`phorvex/internal/ingest/events.go`** — read the
   `crmrefund.ObservationAnnotation` into `SecurityEventInfo` (as `LiteLLMClientRaw`
   is read), gated on the admission-stamped trusted creator and `RuleType`.

7. **Console producer** — a `/api/crm/live/fire` producer mirroring
   `litellm_live.go`: seed owned A/B records, do a legitimate same-record refund
   (control), perform the cross-record refund (attack) and confirm it lands via
   `/audit`, inject the trusted `crm-refund-abuse` SecurityEvent with the
   `Observation`, wait for the brain to actuate, replay the cross-record refund and
   require 403 on every Pod, and confirm the control still refunds. Register it in
   `attack_compat.go` + `dashboard-web/lib/live-attack-dispatch.ts`.

8. **Enable (separate deploy PR, last):** add `crm-refund-revoke` to
   `deploy/policies/crm--crm-defense.yaml` `actions.enabled` and ensure `crm` is in
   `values-eks actuatorNamespaces`. Deploy the new operator image first, confirm
   startup preflight passes, then enable the action.

The enforcement mechanism this actuator drives (`deploy/apps/crm/app.py` deny-guard)
is already live and proven cross-Pod (see `test_coverage/evidence/` in PhorvexSecurity/operator@65af1c99).
