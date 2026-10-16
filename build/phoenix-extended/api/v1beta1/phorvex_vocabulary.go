package v1beta1

// Phorvex-controlled SecurityEvent vocabulary. Phorvex authors both a controlled
// SecurityEvent and the AMTD strategy that matches it, so its rule fields are
// Phorvex-private (Source=PhorvexController) and never collide with an
// integrator's events. The Phorvex actuator writes these values, Phorvex ingest
// recognises its own events and execution receipts by them, and this operator
// verifies the bound target identity before mutating a Pod.
const (
	// PhorvexRuleSource marks an event as authored by the Phorvex controller.
	PhorvexRuleSource = "PhorvexController"
	// PhorvexRuleThreatLevel is the canonical level Phorvex emits at.
	PhorvexRuleThreatLevel = ThreatLevelHigh
	// PhorvexRuleTypeRotate is the Phorvex-private rule type mapped to Delete.
	PhorvexRuleTypeRotate = "phorvex.rotate"
	// PhorvexRuleTypeQuarantine is the Phorvex-private rule type mapped to Quarantine.
	PhorvexRuleTypeQuarantine = "phorvex.quarantine"

	// PhorvexRotateTargetUIDAnnotation binds a controlled asynchronous rotate to
	// the exact Pod identity Phorvex selected.
	PhorvexRotateTargetUIDAnnotation = "phorvex.ai/rotate-target-uid"
	// PhorvexQuarantineTargetUIDAnnotation binds a controlled quarantine to the
	// exact Pod identity.
	PhorvexQuarantineTargetUIDAnnotation = "phorvex.ai/quarantine-target-uid"
	// PhorvexQuarantineNamespaceUIDAnnotation binds a controlled quarantine to the
	// exact namespace identity.
	PhorvexQuarantineNamespaceUIDAnnotation = "phorvex.ai/quarantine-namespace-uid"
	// PhorvexQuarantineOperationAnnotation carries the quarantine operation identity.
	PhorvexQuarantineOperationAnnotation = "phorvex.ai/quarantine-operation"
)
