# Why guardrail rotation and the catalogue produce different results

Observed and independently reviewed on September 23, 2026. The shared manager and console run source `1a400d281b3350fcb72cbfc8559e1597bb1ff1ce`, image version 0.4.153. PR318's six new catalogue entries are not installed in this comparison.

The difference is real, but it does not establish that the other five new entries failed to defend an attack. They were implemented as functional checks that bypass the brain. That was a scope mismatch with the requested V1 evaluation. Existing generic catalogue live launches also have a separate classification defect that can manufacture LANDED without measuring the named attack.

| Path | What actually executes | Brain/actuator involvement | What the result establishes |
| --- | --- | --- | --- |
| Dedicated guardrail rotation | Exact-target synthetic detector event, then independent guardrail runtime reads | Installed manager evaluates its policy and may select and dispatch guardrail rotation | A variant transition can prove a mechanism effect. It does not prove an attack was stopped. |
| New Voice media | Real WebSocket exchange with the installed Voice service | No manager choice or actuator | Returned audio and session completion. Retained functional check passed. |
| New Voice recovery | Console directly requests one permitted Pod eviction and checks a new audio session | Bypasses manager choice | Replacement and fresh-session recovery. Retained functional check passed. |
| New GPU request drain | Harness directly invokes a dedicated owned fixture's drain/reopen operation | Bypasses installed manager choice | Bounded drain and recovery of that fixture. Retained functional check passed. |
| Two new console boundary checks | Missing/unsigned/scoped HTTP credentials | No manager choice or actuator | Authentication and authorization enforcement. Retained boundary checks passed. |
| Older generic catalogue live Fire | Creates a synthetic SecurityEvent carrying the scenario name; does not run the named scenario's behavior | Manager can react, but result watcher usually recognizes only replacement/quarantine | Current code can incorrectly label no observed response as LANDED, including failed observations. |

The sixth new entry is the same dedicated guardrail path shown in the first row. The functional checks used a temporary reviewed console against development dependencies; this is separate from installing PR318 in the shared console.

## What has genuinely worked for guardrail

Retained run `atk-dlmkge53e1ys` at 08:51 UTC has an exact event UID `1246ea33-29c7-4fbd-bb5c-674d309dedad` in the manager's trusted steering input. The audit row records selection of `guardrail-rotate`, dispatch `emitted`, and operation/journal identity. The console independently observed the same Pod UID change from `pgv1` to `pgv2` in 4.76 seconds. Root rechecked the raw audit row and its recorded SHA-256 on this review.

The decision explains the choice: guardrail was feasible, its modeled expected cost was approximately 0.133, and its positive gain was approximately 5.89. Dry-run and kill switch were both false. Lambda was zero in this successful mechanism run, so zero lambda alone cannot explain a universal failure to act.

This is positive evidence that the event, brain and actuator path can operate. Limits remain: this retained run used temporary reactive-only isolation that was restored afterward; the audit reports emitted-unconfirmed; the original journal body was overwritten before capture; and no before/after input demonstrated a bypass becoming blocked. It is not an unchanged-policy security benchmark or a behavioral DEFENDED verdict. A later 13:39 UTC console record observed `pgv2` to `pgv1` in 50.39 seconds, but its API result alone has no exact decision join.

## Why the older catalogue often says LANDED

`fireScenarioLive` maps the browser's expected actuator into a detector vector, applies a synthetic event, and registers it without an evidence kind. The generic watcher then treats it as a behavioral attack. If it does not see replacement/quarantine, it defaults the result to LANDED. An in-place guardrail rotation does neither, so this checker can miss a valid mechanism response. It also assigns LANDED before turning an observation error into partial status.

The fresh authenticated console read returned 82 retained records: 59 labeled LANDED, of which five were partial with observation errors; one labeled DEFENDED; and 22 with no behavioral verdict. These counts describe stored labels, not independently verified attacker successes or defenses. A local reproduction through the actual POST handler, watcher and exact-ID result API confirmed both the signal-only LANDED fallback and the partial-plus-LANDED defect. No new live attack was necessary to establish this bug.

## Other current barriers are separate

Fresh manager decisions around 19:22 UTC show KV reset/migration excluded by an unresolved dispatching journal, request drain excluded because no target Service selects on the serving label, and Voice rotation excluded because its worst-case availability cost (1.60) exceeds the configured ceiling (1.20). These are current preconditions, not event-bound explanations of every historical run. Deleting journals or relaxing availability constraints just to obtain a green result would invalidate the evaluation.

## Correction and remaining V1 work

The signal-classification correction is tracked by this fix. Synthetic alerts must report signal, decision/refusal, and observed response without claiming the named exploit landed or was defended. Observation failures must remain inconclusive. The guardrail dialog should expose its exact record and limitations.

The completed diagnostic V1 still requires realistic per-case stimuli, normal manager evaluation, actuator-specific observations, and a direct check of whether the same unwanted behavior persists after the response while legitimate service remains usable. Functional PASS and a changed annotation are supporting evidence, not substitutes for that outcome. PR318 is now described as functional groundwork; this report does not close V1.

Private raw evidence remains under the common Git workflow runtime, `post25-live-20260920/review/V1-END-TO-END-CORRECTION/`. No credentials or raw application data are published with this report.
