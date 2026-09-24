# Independent reproduction

Lead executed the actual fire-scenario handler against archived baseline a50d796 (including its own build module replacements) with the same portable exact-owned-Pod positive test. The serialized SecurityEvent incorrectly targeted `voice/voice-bot-0` despite the request naming `owned-0`. The failure is the intended target assertion, not a tool/setup failure. This is a source reproduction; no business Pod was signaled live. Baseline log: evidence/lead-baseline-red.log.

On integrated head af23ae2 the exact handler positive and rejection cases pass, along with real KubeSource same-name replacement/current-UID, diagnostic retention, stale outcome rejection and current covermap controls. Evidence: evidence/lead-head-green.log and execution.json. The selected decision package regex had no matching test; its general suite is covered by the separate preflight, not claimed here.

The root source deficiency is that the producer accepts no exact-target contract and emits only namespace/name, while ingest admits that reference without the selected Pod lifetime. It is distinct from token capability valuation and from UI guidance. Fix CAT-EXACT-TARGET binds every new signal to UID and validates against the actual decision Pod snapshot; exact mode fails closed for owner/policy/target changes. Legacy unbound external events remain compatible. Source PASS is not deployed end-to-end PASS.

Falsifier: baseline selects exact owned Pod with UID; not observed. Positive control: repaired handler serializes the owned target and UID, persists that same intent, and uses its owner availability; passes. Current UID and legacy-event positive ingest controls pass while replacement events are diagnostics only.
