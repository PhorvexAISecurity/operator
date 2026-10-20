package recon

import "github.com/phorvex/phorvex/internal/epssmeta"

// ProductionParameters exposes exact constants used by the fact-weighting path.
func ProductionParameters() map[string]float64 {
	return map[string]float64{
		"recon.dispersion.maximum":        MaxDispersionMult,
		"recon.vector-dominance":          vectorDominance,
		"recon.session-weight":            sessionWeight,
		"recon.network-identity-weight":   networkIdentityWeight,
		"recon.stage-urgency-base":        stageUrgencyBase,
		"recon.stage-urgency-span":        stageUrgencySpan,
		"recon.minimum-held-asset-weight": minimumHeldAssetWeight,
		"recon.epss.maximum":              epssmeta.EPSSMaximum,
		"recon.cvss.maximum":              epssmeta.CVSSMaximum,
		"recon.epss-multiplier.maximum":   epssmeta.EPSSMultiplierMaximum,
	}
}
