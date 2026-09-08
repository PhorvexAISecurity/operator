# PHORVEXSEC-218 / M-14

DEV Milad. Independent DEV/security reviewer requested Hami, independent UI/QA verification remains open. Base PR135 074e9f8 over ea5d5ca / v0.4.96. No production deployment changed. Primary RECORD correction with explicit SURFACE companion in dashboard-web owner panel/landing/API types.

## Current diagnosis

Historical clean-replacement sentence was already removed by earlier claim work/M-47. Remaining defects reproduced here: selected/false without a result says NOT carried out, quarantine emission implies workPreserved=true, most emissions imply attackPrevented=true, all records imply sloKept=true, counterfactual says an unobserved workload would have been destroyed, and the UI heading says activity helped. These are not supported by the record.

## Evidence-to-wording contract

Existing Record.Selected/Actuated/DryRun and DecisionTrace.DispatchOutcome/DispatchReason are the only execution evidence used. No confirmation producer or trusted effect contract is wired, therefore **all positive effect claims stay disabled**. Legacy actuated=true is a report of emission, never confirmation. Contradictory dry-run/emission, dispatch-error (including partial emitted+error), unknown future outcome, emitted-false with no proven refusal, and inconsistent flags render unknown. Selected-only renders no execution result recorded. Explicit not-attempted renders not dispatched by this attempt. M-47 exact refusal allowlist retains safe reasons. Raw reasons/errors are never echoed.

Owner projection outcomeEvidence now distinguishes emitted-unconfirmed / selected / dry-run / not-attempted / not-emitted / unknown. This is display normalization of existing records, not a new stored audit schema or execution result. Deprecated attackPrevented/workPreserved/sloKept remain present for wire compatibility but always false, meaning confirmation unavailable, not measured negative outcomes. New rollup dispatched/isolationAttempts are request counts. Existing historical JSONL is never rewritten.

Removed unsupported counterfactual reassurance. Owner panel uses new outcome classes for counts and dispatch badges, removes the helped heading and fabricated forward-only default, keeps confirmation-unavailable visible, and declines old cached success prose when outcome vocabulary is not recognized. Landing uses the new dispatch counters rather than legacy success-named flags. Tenant query filtering, SSE whitelist, claim scope and original decision fields are preserved. Existing demo-trust tenant limitation is unchanged, not represented as authenticated tenancy.

## Tests / evidence

Predicted before execution: legacy flags fail conservative checks, matrix branches remain meaningful and visible, no success inference from unsupported confirmation. Actual baseline overlay of owner.go from 074e9f8 fails TestM014OutcomeMatrix. Current tests pass across legacy, selection-only, dry-run, contradiction, refusal, uncertainty, partial error, new outcome and all action kinds. Unknown confirmation JSON including wrong action/attempt/policy/UID and malformed unsupported values cannot enable a branch because no confirmation branch exists.

Synthetic replay follows JSONL -> actual owner HTTP handler -> OwnerEvent/rollup JSON -> actual React EventRow server rendering. Four visible authorized outcomes, three emission reports, one isolation attempt, zero success claims. Other-tenant and raw-error sentinel excluded. UI rendering checks truthful prose, unavailable SLO, escaped script-like identifier, no fabricated forward-only chip, and stale-payload fallback. This is **synthetic replay**, not original live incident evidence or a browser/deployed confirmation test.

Commands: `GOMAXPROCS=2 go test -p 2 ./internal/console`; focused matrix/HTTP/M47/SSE/tenant/claim tests; esbuild bundle of dashboard-web/tests/owner-outcomes.tsx followed by Node against the HTTP fixture; tools/check-claim-language.py. Logs retained. The lightweight render uses locally available React/esbuild tooling and does not replace a full supported-version browser test. No full Next build or full TypeScript build run on the shared host.

Independent review and rendered-console QA remain required. Rollout must update backend and frontend, refresh stale browser assets; legacy payloads fall back to unknown in the new UI. Old API consumers must stop interpreting the deprecated false flags as measured outcomes. Reverting this correction restores unsupported claims. M-9 confirmation integration is a separate future capability, no Mostafa/MATH gate is required for this conservative correction.
