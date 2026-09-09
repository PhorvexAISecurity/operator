package console

import (
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// OwnerRepresentation is an explicit allowlist. Never embed an audit snapshot,
// amounts, fact keys, rule/evidence payloads or engine final weights here.
type OwnerRepresentation struct {
	State                 string `json:"state"`
	RepresentationPresent bool   `json:"representationPresent"`
	LossHistoryStatus     string `json:"lossHistoryStatus"`
	LossAssessment        string `json:"lossAssessment"`
	OutOfBand             string `json:"outOfBand"`
	Note                  string `json:"note"`
}

func ownerAvailability(s string) string {
	if s == "available" || s == "partial" {
		return s
	}
	return "unavailable"
}
func ownerRepresentation(rec audit.Record) OwnerRepresentation {
	out := OwnerRepresentation{State: "unknown", LossHistoryStatus: "unavailable", LossAssessment: "unavailable", OutOfBand: "unmeasured", Note: "Representation unavailable; recall and out-of-band scope unmeasured. No confirmation of security effect."}
	r := rec.Representation
	if r == nil {
		return out
	}
	out.RepresentationPresent = true
	out.LossHistoryStatus = ownerAvailability(r.LossHistoryStatus)
	out.LossAssessment = ownerAvailability(r.LossAssessment)
	out.Note = "Modeled scoped representation; out-of-band scope unmeasured. No confirmation of security effect."
	scope := r.Snapshot.Scope
	if scope.Tenant != rec.Tenant || scope.Asset != rec.Namespace+"/"+rec.Pod || scope.Version == "" {
		return out
	}
	lost, risk, unknown := false, false, false
	for _, a := range r.AssetState {
		if a.Scope.Tenant != scope.Tenant || a.Scope.Asset != scope.Asset || a.Scope.Version != scope.Version || a.Scope.Property != scope.Property {
			continue
		}
		switch a.Primary {
		case model.RepresentationAlreadyLost:
			lost = true
		case model.RepresentationAtRisk:
			risk = true
		default:
			unknown = true
		}
		if len(a.Unresolved) > 0 {
			unknown = true
		}
	}
	if lost {
		out.State = "already-lost"
	} else if risk && !unknown {
		out.State = "at-risk"
	}
	return out
}
