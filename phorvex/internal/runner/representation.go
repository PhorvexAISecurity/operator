package runner

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/representation"
)

// representationSnapshotV1 is deliberately a narrow source adapter. The v3
// trace skips facts absent from the final-weight domain (coverage.go), so it is
// not the full inventory. ProtectedOutcome v1 is raw supplied annotation data:
// Qualified/StateBasis/OutcomeClass are NOT M100 event-to-loss predicates.
// No current source supplies a qualifying M100 mapping or durable loss ledger.
func representationSnapshotV1(d model.Decision, p model.Policy, version string, claim model.ClaimScope, inventory *model.ExistentialInventory) model.RepresentationSnapshot {
	scope := model.ProtectedScope{Tenant: p.Tenant, Asset: d.Namespace + "/" + d.Pod, Version: version}
	s := model.RepresentationSnapshot{
		Ref: p.TickID, Scope: scope, Aggregation: "per-decision", PopulationVersion: "runner-trace-observed-subset-v1", Claim: &claim,
		DetectorBasis: "configured-authenticated", CapabilityStatus: "unavailable", ActionBasis: "selected-modeled",
		HistoryStatus: "unavailable", LossAssessment: "unavailable",
		Limitations:  []string{"inventory-incomplete", "final-weight-population-binding-unavailable", "cover-snapshot-unavailable", "no-current-qualifying-event-to-loss-mapping", "retained-loss-history-source-unavailable", "detector-liveness-unmeasured", "recall-unmeasured"},
		UnknownKinds: []model.RepresentationGap{{Scope: scope, Reason: "applicable-detector-capability-map-unavailable"}},
	}
	if d.Trace != nil {
		for _, f := range d.Trace.Facts {
			fs := scope
			// No finer property/asset mapping is guessed from a kind or covering action.
			s.Facts = append(s.Facts, model.RepresentationFact{Key: f.FactKey, Kind: f.FactType, Scope: fs, RuleVersion: "trace-to-unresolved-v1", ObservationRef: d.Trace.DecisionID, Reason: "protected-assertion-semantics-unbound", Actionability: []string{"actionability-unavailable"}})
		}
	}
	if inventory != nil {
		for _, row := range inventory.Records {
			o := row.Outcome
			if o.DecisionAsset != "" && o.DecisionAsset != scope.Asset {
				continue
			}
			gapScope := model.ProtectedScope{Tenant: p.Tenant, Asset: o.ProtectedAsset, Version: o.Version, Property: o.Property}
			s.UnresolvedEntries = append(s.UnresolvedEntries, model.RepresentationGap{Scope: gapScope, Kind: "protected-outcome", Reason: "protected-outcomes-v1-unbound:" + row.Event + ":" + o.ID})
		}
		for _, reason := range inventory.Reasons {
			s.UnresolvedEntries = append(s.UnresolvedEntries, model.RepresentationGap{Scope: scope, Kind: "protected-outcome", Reason: reason})
		}
	}
	return representation.Freeze(s)
}

func appendRepresentation(d *model.Decision, frozen model.RepresentationSnapshot) {
	// Add only the dispatch observation to a value copy, never refresh source data.
	if d.Actuated {
		frozen.DispatchEvidence = "dispatch-only-unconfirmed"
	}
	d.Representation = representation.Build(frozen)
}
