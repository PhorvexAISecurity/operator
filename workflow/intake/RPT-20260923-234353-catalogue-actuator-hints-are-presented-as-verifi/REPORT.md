# Verified scope: catalogue guidance overstates response capability

At source `a50d796af128cd4109875e03eaf429d460126740`, Attack Lab says every expected actuator is enabled and the displayed actuator is what Phorvex should trigger. `expectedActuatorsFor` actually derives its list from scenario-name keywords. It does not inspect installed capabilities, policy, workload feasibility, decision evidence, execution, or mitigation. C1 includes quarantine even though isolating the source Pod does not revoke a copied bearer token used elsewhere.

This is a reporting/guidance defect, separate from whether any particular defense succeeds. Current exact-source NATS decisions provide a concrete counterexample: rotation is vetoed because ready replicas would fall below the minimum; quarantine capacity is exhausted. The catalogue name does not establish that either is available. See the campaign evidence/NATS-DECISION.md and evidence/CONSOLE-DEPLOYMENT.md.

Correct the guidance basis and both consuming panels while preserving legacy API fields and execution routing. The owner's campaign explicitly includes correcting misleading catalogue claims. No new live stimulus is necessary to verify this source-level unconditional promise is false.
