package console

import (
	"encoding/json"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/representation"
	"strings"
	"testing"
)

func TestM100OwnerWhitelistAndVersionedUnknownPrecedence(t *testing.T) {
	scope := model.ProtectedScope{Tenant: "t", Asset: "ns/p", Version: "v1"}
	r := audit.Record{Tenant: "t", Namespace: "ns", Pod: "p", Representation: &model.Representation{Snapshot: model.RepresentationSnapshot{Scope: scope, Weights: model.RepresentationWeights{Values: map[string]float64{"private-fact-key": 987654.321}}}, LossAssessment: "token=private-secret", LossHistoryStatus: "arbitrary-payload", AssetState: []model.RepresentationAsset{{Scope: scope, Primary: model.RepresentationAtRisk}, {Scope: scope, Primary: model.RepresentationUnknown}}}}
	out := ownerRepresentation(r)
	if out.State != "unknown" || out.LossAssessment != "unavailable" || out.LossHistoryStatus != "unavailable" {
		t.Fatal("unknown/status guard", out)
	}
	b, _ := json.Marshal(ToOwnerEvent(r))
	for _, s := range []string{"private-fact-key", "987654", "private-secret", "arbitrary-payload", "weights", "snapshot"} {
		if strings.Contains(string(b), s) {
			t.Fatal("owner leak", s)
		}
	}
	r.Representation.AssetState[1].Primary = model.RepresentationAlreadyLost
	r.Representation.AssetState[1].Scope.Version = "v0"
	if ownerRepresentation(r).State != "at-risk" {
		t.Fatal("old version contaminated current")
	}
	r.Representation.AssetState[1].Scope.Version = "v1"
	if ownerRepresentation(r).State != "already-lost" {
		t.Fatal("matching loss not primary")
	}
	r.Representation = nil
	if ownerRepresentation(r).RepresentationPresent || ownerRepresentation(r).State != "unknown" {
		t.Fatal("legacy projection")
	}
}

func TestReviewOwnerPropertyScopedLossFromClassifier(t *testing.T) {
	scope := model.ProtectedScope{Tenant: "t", Asset: "ns/p", Version: "v1", Property: "disclosure"}
	s := model.RepresentationSnapshot{Scope: scope, LossAssessment: "available", LossMappingVersion: "fixture-v1", Witnesses: []model.LossWitness{{Scope: scope, EventRef: "fixture-event", EventTime: "2026-09-08T00:00:00Z", IngestionTime: "2026-09-08T00:00:01Z", AuthenticatedIdentity: "fixture-creator", TrustAtIngestionRef: "fixture-stamp", RuleVersion: "fixture-rule", PayloadPredicateRef: "fixture-predicate", CompletedUnauthorizedOutcomeRef: "fixture-outcome", IrreversibilitySemantics: "fixture-irreversible-disclosure", ClassificationRef: "fixture-classification"}}}
	rec := audit.Record{Tenant: "t", Namespace: "ns", Pod: "p", Representation: representation.Build(s)}
	if ownerRepresentation(rec).State != "already-lost" {
		t.Fatal("owner lost property-scoped classifier result")
	}
	rec.Representation.Snapshot.Scope.Version = "replacement"
	if ownerRepresentation(rec).State != "unknown" {
		t.Fatal("loss followed replacement version")
	}
}
