package audit

import "github.com/phorvex/phorvex/internal/model"

const (
	// SchemaVersionCurrent is the canonical contract written by this release.
	SchemaVersionCurrent = "phorvex.audit.v2"
	// SchemaVersionPrevious is the first explicitly versioned, pre-migration contract.
	SchemaVersionPrevious = "phorvex.audit.v1"
	// SchemaVersionLegacy identifies shipped records that predate schemaVersion.
	SchemaVersionLegacy = "phorvex.audit.v0"
	// ReadTranslationExpiresAt makes the old-to-new shim deliberately temporary. When v4
	// becomes current, support for translating v0/v1 records must be removed or renewed by
	// an explicit contract decision; there is no unbounded "eventually" compatibility path.
	ReadTranslationExpiresAt = "phorvex.audit.v4"
)

// Migration describes one settled v1-to-v2 public-contract change. Old and New are
// audit tokens, not Go implementation details. A same-token entry pins a semantic rescope.
type Migration struct {
	Category  string
	Old       string
	New       string
	Status    string
	Semantics string
}

// V1ToV2Migrations returns a copy of the published migration map. sideChannel is
// deliberately absent: its GPU taxonomy is held until one authoritative coversets
// annotation supersedes the conflicting proposals.
func V1ToV2Migrations() []Migration {
	return []Migration{
		{Category: "fact-kind", Old: "modelFingerprint", New: "modelIdentity", Status: "renamed", Semantics: "served model identity/version learned by the attacker"},
		{Category: "fact-kind", Old: "session", New: "session", Status: "rescoped", Semantics: "ephemeral in-process KV/agent-session state; not identity, route, or generic compromise"},
		{Category: "fact-kind", Old: "nodePlacement", New: "retired:nodePlacement", Status: "retired", Semantics: "historical attribution is preserved but cannot be interpreted as current cover"},
		{Category: "decision-field", Old: "risk", New: "coverageValue", Status: "renamed", Semantics: "P1 recon coverage value; legacy P0 threat risk translates to threatRisk instead"},
		{Category: "decision-field", Old: "belief", New: "pHold", Status: "consolidated", Semantics: "pHold is authoritative when both legacy fields are present"},
		{Category: "decision-field", Old: "threatPosture", New: "threatPosture", Status: "observational", Semantics: "recorded but not used by the default P1 selector"},
		{Category: "decision-field", Old: "residual", New: "residual", Status: "observational", Semantics: "recorded but not set or used by the default P1 selector"},
	}
}

func canonicalizeAttribution(in []model.AttributionTerm) []model.AttributionTerm {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.AttributionTerm, len(in))
	copy(out, in)
	for i := range out {
		switch out[i].Source {
		case "cover:modelFingerprint":
			out[i].Source = "cover:modelIdentity"
		case "cover:nodePlacement":
			// Preserve the historical contribution while removing the false implication
			// that the retired, producerless kind is current actionable cover.
			out[i].Source = "retired:nodePlacement"
		}
	}
	return out
}
