# M40 independent incident review

Lead: codex-lead. Baseline `669197bf025a446a87ed2923c04dbaa2237ca077`; accepted product candidate `b609df7d68a8b3d4b285f23b3eb4683753eae33d`.

The lead used the shipped HTTP drain producer against real local HTTP responses, then separately drove the actual handler through a real isolated Kubernetes API with current Pod, policy, Service and owned EndpointSlice objects. A small explicitly emulated endpoint controller mirrors serving labels through the API; it does not stand in as evidence of CNI/data-plane convergence. The valid Kubernetes Pod address is redirected by the test transport to the local HTTP server; production transport is unchanged.

| Producer/control | Baseline observation | Committed head observation |
| --- | --- | --- |
| HTTP200, integer aborted3 | Accepted, count3 | Accepted, count3 |
| HTTP202 empty, HTTP200 missing/null/malformed/negative count | Incorrectly accepted; expected-fixed RED assertions fail | Explicit error for every unconfirmed response |
| Actual API lifecycle with confirmed HTTP abort | One request, nil error, serving label left drained | One request, nil error, exact original serving label restored |
| Actual API lifecycle with HTTP202 unconfirmed abort | One request, nil error, label left drained | One request, non-nil error, label restored; partial mutation remains visible |

Baseline evidence: `lead/baseline-red.log`, `lead/api-baseline.log` and `lead/red.md`. The first API fixture attempt used a loopback Pod IP rejected by API validation; it is retained as `lead/api-fixture-rejected-loopback.log` and is not counted as defect evidence. The corrected valid-IP fixture actually reached the handler and HTTP endpoint.

Final committed-source execution: `lead/final-head.log`. Command: source the retained heavy/local API env scripts; `M040_EXPECT_FIXED=1 $GO_BIN -C phorvex test -overlay /home/mehrdad/operator/.git/phorvex-workflow/tier7-20260916/m040-head-overlay.json ./internal/actuator -run '^TestM040Lead(HTTPReceipt|ActualAPIDrainLifecycle)$' -count=1 -v`. Sources are retained as `lead/m040-lead-api.go` and `lead/m040-lead-protocol.go`.

All head cases PASS with no skips. Emitted=true on the unconfirmed-HTTP case means the stop/restore mutation was actually observed; the non-nil error prevents a successful action claim. The permanent runner consumer test checks that distinction, using explicit result fixtures joined to the separate real native/API/HTTP producer test. It is not claimed as a single end-to-end runner/serving-stack execution.

L3 remains pending for the supported real serving version, actual long-running request/benign follow-up, interruption and data-plane convergence controls in the Tier7 plan and central backlog LV-02. No live or durable attacker-exclusion claim is made.
