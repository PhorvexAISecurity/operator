package model

import "sort"

// ClaimScope describes the boundary of a reported objective, not attacker state.
// DetectorSet is the configured authenticated allowlist at record time; it does
// not assert connectivity, calibrated recall or independently confirmed effects.
type ClaimScope struct {
	Scope            string   `json:"scope"`
	DetectorSet      []string `json:"detectorSet"`
	DetectorSetKnown bool     `json:"detectorSetKnown"`
	RecallCap        string   `json:"recallCap"`
	Note             string   `json:"note"`
	BrainImage       string   `json:"brainImage"`
	GitSHA           string   `json:"gitSHA"`
}

func NewClaimScope(ids []string, known bool, image, sha string) ClaimScope {
	set := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		if id != "" && !set[id] {
			set[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if image == "" {
		image = "unavailable"
	}
	if sha == "" {
		sha = "unavailable"
	}
	cap := "unknown"
	note := "Modeled coverage of the detector-visible, reversible projection; not confirmation of security effect. Trusted detector configuration unavailable; recall unknown."
	if known {
		if len(out) == 0 {
			note = "Modeled coverage of the detector-visible, reversible projection; not confirmation of security effect. No trusted detector configured; recall unknown."
		} else {
			cap = "detector-bounded"
			note = "Modeled coverage of the detector-visible, reversible projection; not confirmation of security effect. Configured trusted detectors do not prove connectivity; recall is unmeasured."
		}
	}
	return ClaimScope{Scope: "modeled", DetectorSet: out, DetectorSetKnown: known, RecallCap: cap, Note: note, BrainImage: image, GitSHA: sha}
}
