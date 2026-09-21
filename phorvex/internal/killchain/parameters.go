package killchain

// ProductionParameters exposes the exact default values read by NewModel and
// AssessMode for provenance export. A fresh model prevents callers from mutating
// the shared representation of these defaults.
func ProductionParameters() map[string]float64 {
	m := NewModel()
	values := map[string]float64{
		"killchain.shape":                          m.Shape,
		"killchain.recover-scale-seconds":          m.RecoverScale,
		"killchain.confidence-k":                   m.ConfidenceK,
		"killchain.exposure-pressure-cap":          DefaultExposurePressureCap,
		"killchain.baseline-stage-urgency":         BaselineStageUrgency,
		"killchain.persistence.alpha":              DefaultPersistenceAlpha,
		"killchain.persistence.beta":               DefaultPersistenceBeta,
		"killchain.persistence.mass-cap":           PersistenceMassCap,
		"killchain.ai.endpoint-gpu-util-threshold": AIEndpointGPUUtilThreshold,
		"killchain.event.severity-maximum-rank":    EventSeverityMaximumRank,
		"killchain.event.held-evidence-base":       EventHeldEvidenceBase,
		"killchain.event.held-evidence-span":       EventHeldEvidenceSpan,
		"killchain.event.lateral-pressure-base":    LateralPressureBase,
		"killchain.event.lateral-pressure-span":    LateralPressureSpan,
		"killchain.stage-urgency.current-weight":   StageUrgencyCurrentWeight,
		"killchain.stage-urgency.next-weight":      StageUrgencyNextWeight,
		"killchain.projected-transition-target":    ProjectedTransitionTarget,
	}
	for stage, value := range m.SojournScale {
		values["killchain.sojourn."+stage.String()+".seconds"] = value
	}
	for stage := StageRecon; stage <= StagePromptInjectPersist; stage++ {
		values["killchain.consequence."+stage.String()] = consequence(stage)
	}
	return values
}
