package runner

import (
	"context"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/representation"
)

func withoutLimitation(in []string, remove ...string) []string {
	drop := make(map[string]struct{}, len(remove))
	for _, item := range remove {
		drop[item] = struct{}{}
	}
	out := in[:0]
	for _, item := range in {
		if _, ok := drop[item]; !ok {
			out = append(out, item)
		}
	}
	return out
}

// representationSnapshotV1 is deliberately a narrow source adapter. The v3
// trace skips facts absent from the final-weight domain (coverage.go), so it is
// not the full inventory. ProtectedOutcome v1 is raw supplied annotation data:
// Qualified/StateBasis/OutcomeClass are NOT M100 event-to-loss predicates.
// The opt-in completed-disclosure-v1 producer and durable ledger below qualify
// only their exact admitted synthetic observations; ProtectedOutcome v1 remains
// unbound and supplies no completed-loss mapping.
func representationSnapshotV1(d model.Decision, p model.Policy, version string, claim model.ClaimScope, inventory *model.ExistentialInventory, history ...representationHistoryInput) model.RepresentationSnapshot {
	scope := model.ProtectedScope{Tenant: p.Tenant, Asset: d.Namespace + "/" + d.Pod, Version: version}
	s := model.RepresentationSnapshot{
		Ref: p.TickID, Scope: scope, Aggregation: "per-decision", PopulationVersion: "runner-trace-observed-subset-v1", Claim: &claim,
		DetectorBasis: "configured-authenticated", CapabilityStatus: "unavailable", ActionBasis: "selected-modeled",
		HistoryStatus: "unavailable", LossAssessment: "unavailable",
		Limitations:  []string{"inventory-incomplete", "final-weight-population-binding-unavailable", "cover-snapshot-unavailable", "no-current-qualifying-event-to-loss-mapping", "retained-loss-history-source-unavailable", "detector-liveness-unmeasured", "recall-unmeasured"},
		UnknownKinds: []model.RepresentationGap{{Scope: scope, Reason: "applicable-detector-capability-map-unavailable"}},
	}
	if len(history) > 0 {
		h := history[0]
		s.HistoryStatus = h.result.Status
		s.HistoryPolicyUID = p.PolicyUID
		s.HistoryPolicyGeneration = p.PolicyGeneration
		s.HistoryStableOwnerUID = h.owner.UID
		s.Limitations = append(s.Limitations, "observer-coverage-unavailable")
		if h.result.Status == "available" || h.result.Status == "partial" {
			s.Limitations = withoutLimitation(s.Limitations, "retained-loss-history-source-unavailable")
		}
		for _, gap := range append(append([]string(nil), h.result.Gaps...), h.gaps...) {
			s.Limitations = append(s.Limitations, gap)
		}
		for _, record := range h.result.Records {
			w := admittedWitness(record)
			id := representation.LossID(w.Scope)
			s.History = append(s.History, model.RetainedLoss{ID: id, Scope: w.Scope, Witnesses: []model.LossWitness{w}})
		}
		lossScopes := map[model.ProtectedScope]struct{}{}
		for _, record := range h.result.Records {
			lossScopes[record.Disclosure.ProtectedScope] = struct{}{}
		}
		for _, record := range h.current.Records {
			inv := record.Inventory
			reason := ""
			if h.current.Status != "available" || len(h.current.Gaps) != 0 {
				reason = "current-inventory-authority-unavailable"
			}
			if h.result.Status != "available" || len(h.result.Gaps) != 0 || len(h.historyGaps) != 0 {
				reason = "completed-loss-history-unavailable"
			}
			if _, lost := lossScopes[inv.ProtectedScope]; lost {
				continue
			}
			ref := &model.CurrentInventoryProvenance{SchemaVersion: record.SchemaVersion, EvidenceID: inv.EvidenceID, PolicyUID: inv.PolicyEpoch.UID, PolicyGeneration: inv.PolicyEpoch.Generation, StableOwnerUID: inv.StableWorkloadOwner.UID, PodUID: inv.DecisionAsset.TargetUID, ConfigMapUID: inv.SourceBinding.ConfigMap.UID, ConfigMapResourceVersion: inv.SourceBinding.ResourceVersion, CanonicalPayloadSHA256: record.CanonicalPayloadSHA256, SecurityEventUID: record.SecurityEvent.UID}
			s.Facts = append(s.Facts, model.RepresentationFact{Key: "current:" + representation.LossID(inv.ProtectedScope), Kind: model.CurrentInventoryClass, Scope: inv.ProtectedScope, RuleVersion: model.CurrentInventoryRuleVersionV1, ObservationRef: record.SecurityEvent.UID + "/" + record.CanonicalPayloadSHA256, ReversibleCondition: "current-serving-binding-can-change", Reason: reason, Actionability: []string{"actionability-unavailable"}, CurrentInventory: ref})
		}
		s.UnresolvedEntries = append(s.UnresolvedEntries, h.currentUnknown...)
		for _, gap := range h.current.Gaps {
			s.Limitations = append(s.Limitations, gap)
		}
		if h.current.Status != "" && h.current.Status != "available" {
			s.Limitations = append(s.Limitations, "current-inventory-"+h.current.Status)
		}
		if len(h.current.Records) > 0 {
			s.PopulationVersion = "runner-trace-and-current-inventory-v1"
			s.Limitations = withoutLimitation(s.Limitations, "no-current-qualifying-event-to-loss-mapping")
			s.Limitations = append(s.Limitations, "synthetic-current-inventory-only", "inventory-coverage-unmeasured")
		}
		if len(h.result.Records) > 0 {
			s.LossMappingVersion = model.CompletedDisclosureSchemaV1
			s.LossAssessment = "available"
			s.Limitations = withoutLimitation(s.Limitations, "no-current-qualifying-event-to-loss-mapping")
			s.Limitations = append(s.Limitations, "completed-synthetic-disclosure-recorded", "recall-unmeasured", "total-loss-magnitude-unmeasured")
		}
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

func representationSnapshotsBeforeEffect(ctx context.Context, decisions []model.Decision, p model.Policy, versions map[string]string, claim model.ClaimScope, inventory *model.ExistentialInventory, histories ...map[string]representationHistoryInput) ([]model.RepresentationSnapshot, bool) {
	out := make([]model.RepresentationSnapshot, len(decisions))
	for i, d := range decisions {
		if ctx.Err() != nil {
			return nil, false
		}
		if len(histories) > 0 {
			history := histories[0][d.Namespace+"/"+d.Pod]
			out[i] = representationSnapshotV1(d, p, versions[d.Namespace+"/"+d.Pod], claim, inventory, history)
		} else {
			out[i] = representationSnapshotV1(d, p, versions[d.Namespace+"/"+d.Pod], claim, inventory)
		}
	}
	return out, true
}

func appendRepresentation(d *model.Decision, frozen model.RepresentationSnapshot) {
	// Add only the dispatch observation to a value copy, never refresh source data.
	if d.Actuated {
		frozen.DispatchEvidence = "dispatch-only-unconfirmed"
	}
	d.Representation = representation.Build(frozen)
}
