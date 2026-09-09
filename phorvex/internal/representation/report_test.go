package representation

import (
	"bytes"
	"encoding/json"
	"github.com/phorvex/phorvex/internal/model"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// Positive rules/witnesses below are synthetic contract fixtures, not live evidence.
func fixture() model.RepresentationSnapshot {
	scope := model.ProtectedScope{Tenant: "t", Asset: "ns/p", Version: "v1", Property: "access"}
	c := model.NewClaimScope([]string{"fixture-detector"}, true, "fixture-build", "fixture-sha")
	k := Key("t", "fact")
	return model.RepresentationSnapshot{Ref: "tick", Scope: model.ProtectedScope{Tenant: "t", Asset: "ns/p"}, Aggregation: "per-decision", PopulationVersion: "fixture-v1", InventoryComplete: true, ClassificationComplete: true, Claim: &c, DetectorBasis: "configured-authenticated", CapabilityStatus: "available", CapabilityVersion: "fixture-v1", HistoryStatus: "available", LossAssessment: "available", LossMappingVersion: "fixture-outcomes-v1", ActionBasis: "selected-modeled",
		Facts:   []model.RepresentationFact{{Key: "fact", Kind: "access", Scope: scope, RuleVersion: "fixture-rule-v1", ObservationRef: "fixture-observation", ReversibleCondition: "fixture-current-revocable-access", Actionability: []string{"coverable-now"}}},
		Weights: model.RepresentationWeights{SnapshotRef: "tick", Basis: "fixture-final", ProvenanceRef: "fixture-weight-map", Values: map[string]float64{k: 3}},
		Covers:  model.RepresentationCovers{SnapshotRef: "tick", Available: true, Sets: [][]string{{k}}}, Candidates: model.RepresentationCovers{SnapshotRef: "tick", Available: true, Sets: [][]string{{k}}}}
}
func witness(s model.ProtectedScope) model.LossWitness {
	return model.LossWitness{Scope: s, EventRef: "fixture-event", EventTime: "2026-09-08T00:00:00Z", IngestionTime: "2026-09-08T00:00:01Z", AuthenticatedIdentity: "fixture-creator", TrustAtIngestionRef: "fixture-stamp", RuleVersion: "fixture-loss-v1", PayloadPredicateRef: "fixture-completed-disclosure-predicate", CompletedUnauthorizedOutcomeRef: "fixture-occurrence", IrreversibilitySemantics: "fixture-original-disclosure-cannot-be-undone", ClassificationRef: "fixture-classification"}
}
func wire(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func value(t *testing.T, a model.RepresentationAmount, w float64) {
	t.Helper()
	if !a.Present || a.Value == nil || *a.Value != w {
		t.Fatalf("want %v got %+v", w, a)
	}
}
func reason(t *testing.T, a model.RepresentationAmount, w string) {
	t.Helper()
	if a.Present || a.Value != nil || a.Reason != w {
		t.Fatalf("want unavailable %s got %+v", w, a)
	}
}
func replay(t *testing.T, r *model.Representation) {
	t.Helper()
	b := wire(t, r)
	var read model.Representation
	if e := json.Unmarshal(b, &read); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, wire(t, Build(read.Snapshot))) {
		t.Fatalf("replay mismatch\n%s\n%s", b, wire(t, Build(read.Snapshot)))
	}
}

func TestT01T02UnboundKindsAndInsufficientLossEvidence(t *testing.T) {
	for _, kind := range []string{"credential", "retrievalState", "artifactProvenance", "controlPlanePersistence", "inMemory"} {
		s := fixture()
		s.Facts[0].Kind = kind
		s.Facts[0].ReversibleCondition = ""
		r := Build(s)
		if r.KnownLossCount != 0 || r.FactStates[0].State != model.RepresentationUnknown {
			t.Fatal(kind)
		}
	}
	for _, change := range []func(*model.LossWitness){func(w *model.LossWitness) { w.AuthenticatedIdentity = "" }, func(w *model.LossWitness) { w.TrustAtIngestionRef = "" }, func(w *model.LossWitness) { w.Scope.Property = "" }, func(w *model.LossWitness) { w.Scope.Version = "" }, func(w *model.LossWitness) { w.RuleVersion = "" }, func(w *model.LossWitness) { w.PayloadPredicateRef = "" }, func(w *model.LossWitness) { w.CompletedUnauthorizedOutcomeRef = "" }, func(w *model.LossWitness) { w.IrreversibilitySemantics = "" }, func(w *model.LossWitness) { w.IngestionTime = "" }, func(w *model.LossWitness) { w.EventTime = "invalid" }, func(w *model.LossWitness) { w.ClassificationRef = "" }} {
		s := fixture()
		w := witness(s.Facts[0].Scope)
		change(&w)
		s.Witnesses = []model.LossWitness{w}
		if Build(s).KnownLossCount != 0 {
			t.Fatal("invalid evidence accepted")
		}
	}
}
func TestT03T06MixedRXLPartition(t *testing.T) {
	s := fixture()
	l := s.Facts[0]
	l.Key = "lost"
	l.Scope.Property = "disclosure"
	x := s.Facts[0]
	x.Key = "unknown"
	x.Scope.Property = "unknown"
	x.ReversibleCondition = ""
	x.Reason = "observation-unavailable"
	s.Facts = append(s.Facts, l, x)
	s.Witnesses = []model.LossWitness{witness(l.Scope)}
	s.Covers.Sets = append(s.Covers.Sets, []string{Key("t", l.Key), Key("t", x.Key)})
	s.Candidates.Sets = s.Covers.Sets
	r := Build(s)
	c := r.CoverageShare
	value(t, c.Representable, 3)
	value(t, c.Covered, 3)
	value(t, c.Coverable, 3)
	value(t, c.Share, 1)
	if c.KnownAtRisk != 1 || c.KnownLostEntries != 1 || c.KnownUnknown != 1 || r.KnownLossCount != 1 {
		t.Fatal(c)
	}
	replay(t, r)
}
func TestT04T05T16HistoricalLossRetention(t *testing.T) {
	s := fixture()
	w := witness(s.Facts[0].Scope)
	s.Witnesses = []model.LossWitness{w, w}
	r := Build(s)
	s.History = r.AlreadyLost
	s.Witnesses = nil
	s.Facts = nil
	c := model.NewClaimScope(nil, true, "fixture-build", "fixture-sha")
	s.Claim = &c
	s.LossAssessment = "unavailable"
	r = Build(s)
	if r.KnownLossCount != 1 || len(r.AlreadyLost[0].Witnesses) != 1 || r.AlreadyLost[0].Witnesses[0].TrustAtIngestionRef != w.TrustAtIngestionRef {
		t.Fatal("history lost")
	}
	f := fixture().Facts[0]
	f.Scope.Version = "v2"
	s.Facts = []model.RepresentationFact{f}
	r = Build(s)
	if r.FactStates[0].State != model.RepresentationAtRisk || r.KnownLossCount != 1 {
		t.Fatal("version conflated")
	}
	replay(t, r)
	s.History[0].Witnesses[0].TrustAtIngestionRef = "later"
	if r.AlreadyLost[0].Witnesses[0].TrustAtIngestionRef != w.TrustAtIngestionRef {
		t.Fatal("history alias")
	}
}
func TestT07T10PartialFunctionAndInvalidReplay(t *testing.T) {
	cases := []struct {
		name, want string
		change     func(*model.RepresentationSnapshot)
	}{
		{"missing", "missing-final-weights", func(s *model.RepresentationSnapshot) { delete(s.Weights.Values, Key("t", "fact")) }},
		{"negative", "invalid-weight", func(s *model.RepresentationSnapshot) { s.Weights.Values[Key("t", "fact")] = -1 }},
		{"nan", "invalid-weight", func(s *model.RepresentationSnapshot) { s.Weights.Values[Key("t", "fact")] = math.NaN() }},
		{"inf", "invalid-weight", func(s *model.RepresentationSnapshot) { s.Weights.Values[Key("t", "fact")] = math.Inf(1) }},
		{"inventory", "inventory-incomplete", func(s *model.RepresentationSnapshot) { s.InventoryComplete = false }},
		{"classification", "classification-incomplete", func(s *model.RepresentationSnapshot) { s.ClassificationComplete = false }},
		{"weights-snapshot", "snapshot-mismatch", func(s *model.RepresentationSnapshot) { s.Weights.SnapshotRef = "other" }},
		{"covers-snapshot", "snapshot-mismatch", func(s *model.RepresentationSnapshot) { s.Covers.SnapshotRef = "other" }},
		{"cover-unavailable", "cover-set-unavailable", func(s *model.RepresentationSnapshot) { s.Covers.Available = false }},
		{"legacy-metadata", "historical-metadata-unavailable", func(s *model.RepresentationSnapshot) { s.Claim = nil }},
		{"empty", "no-at-risk-facts", func(s *model.RepresentationSnapshot) { s.Facts = nil }},
		{"zero", "zero-weight-denominator", func(s *model.RepresentationSnapshot) { s.Weights.Values[Key("t", "fact")] = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture()
			tc.change(&s)
			r := Build(s)
			reason(t, r.CoverageShare.Share, tc.want)
			replay(t, r)
		})
	}
	s := fixture()
	s.Weights.Values["outside-R"] = math.NaN()
	r := Build(s)
	value(t, r.CoverageShare.Share, 1)
	replay(t, r)
	if !math.IsNaN(s.Weights.Values["outside-R"]) {
		t.Fatal("mutated invalid input")
	}
}
func TestT08ActionabilityDoesNotShrinkDenominator(t *testing.T) {
	for _, why := range []string{"unsupported", "policy-disabled", "infeasible-this-tick", "actionability-unavailable"} {
		s := fixture()
		s.Facts[0].Actionability = []string{why}
		s.Covers.Sets = nil
		s.Candidates.Sets = nil
		r := Build(s)
		value(t, r.CoverageShare.Representable, 3)
		value(t, r.CoverageShare.Share, 0)
		if len(r.UncoverableEntries) != 1 {
			t.Fatal(why)
		}
		delete(s.Weights.Values, Key("t", "fact"))
		reason(t, Build(s).CoverageShare.Share, "missing-final-weights")
	}
}
func TestT09UnionDedupAndTenantScope(t *testing.T) {
	s := fixture()
	s.Scope = model.ProtectedScope{Tenant: "*"}
	s.Aggregation = "fleet-union"
	f := s.Facts[0]
	f.Scope.Tenant = "other"
	s.Facts = append(s.Facts, f, s.Facts[0])
	s.Weights.Values[Key("other", "fact")] = 7
	s.Covers.Sets = append(s.Covers.Sets, []string{Key("t", "fact"), Key("other", "fact")})
	s.Candidates.Sets = s.Covers.Sets
	r := Build(s)
	value(t, r.CoverageShare.Representable, 10)
	value(t, r.CoverageShare.Covered, 10)
	s.Facts[0], s.Facts[1] = s.Facts[1], s.Facts[0]
	if !bytes.Equal(wire(t, r), wire(t, Build(s))) {
		t.Fatal("input order changes report")
	}
}
func TestT11T14Weighted100IsNotContainment(t *testing.T) {
	s := fixture()
	f := s.Facts[0]
	f.Key = "zero"
	f.Scope.Property = "zero"
	s.Facts = append(s.Facts, f)
	s.Weights.Values[Key("t", "zero")] = 0
	r := Build(s)
	value(t, r.CoverageShare.Share, 1)
	if r.CoverageShare.RequiredSetCovered == nil || *r.CoverageShare.RequiredSetCovered || r.OutOfBand != "unmeasured" || r.EffectEvidence != "unconfirmed" {
		t.Fatal("maximum upgraded claim")
	}
}
func TestT12RelevantGapAndEmptyTrust(t *testing.T) {
	for _, ids := range [][]string{nil, {"unrelated"}} {
		s := fixture()
		c := model.NewClaimScope(ids, true, "b", "s")
		s.Claim = &c
		s.UnknownKinds = []model.RepresentationGap{{Scope: s.Facts[0].Scope, Kind: "relevant", Reason: "no-applicable-observer"}}
		r := Build(s)
		for _, a := range r.AssetState {
			if a.Primary != model.RepresentationUnknown {
				t.Fatal("gap hidden")
			}
		}
	}
}
func TestT16ImmutableInputs(t *testing.T) {
	s := fixture()
	before := wire(t, s)
	r := Build(s)
	if !bytes.Equal(before, wire(t, s)) {
		t.Fatal("input mutated")
	}
	s.Facts[0].Actionability[0] = "later"
	s.Claim.DetectorSet[0] = "later"
	s.Weights.Values[Key("t", "fact")] = 9
	if r.Snapshot.Facts[0].Actionability[0] != "coverable-now" || r.Snapshot.Claim.DetectorSet[0] != "fixture-detector" {
		t.Fatal("aliased snapshot")
	}
	replay(t, r)
}
func TestMalformedRetainedHistoryIsPartial(t *testing.T) {
	s := fixture()
	s.Witnesses = []model.LossWitness{witness(s.Facts[0].Scope)}
	for _, change := range []func(*model.RetainedLoss){func(l *model.RetainedLoss) { l.Witnesses = nil }, func(l *model.RetainedLoss) { l.Witnesses[0].TrustAtIngestionRef = "" }, func(l *model.RetainedLoss) { l.Witnesses[0].Scope.Version = "other" }, func(l *model.RetainedLoss) { l.ID = "bad" }} {
		next := fixture()
		next.History = Build(s).AlreadyLost
		change(&next.History[0])
		r := Build(next)
		if r.LossHistoryStatus != "partial" || r.KnownLossCount != 0 {
			t.Fatal("malformed retained witness accepted")
		}
		replay(t, r)
	}
}
func TestAmbiguousBindingAndCandidateBasis(t *testing.T) {
	s := fixture()
	f := s.Facts[0]
	f.Scope.Property = "different"
	s.Facts = append(s.Facts, f)
	reason(t, Build(s).CoverageShare.Share, "classification-incomplete")
	s = fixture()
	s.Candidates.Sets = nil
	reason(t, Build(s).CoverageShare.Share, "candidate-basis-mismatch")
}

func TestReviewPropertyFilterCannotHideOriginalKeyAmbiguity(t *testing.T) {
	s := fixture()
	other := s.Facts[0]
	other.Scope.Property = "other"
	s.Facts = append(s.Facts, other)
	s.Scope.Property = "access"
	r := Build(s)
	reason(t, r.CoverageShare.Share, "classification-incomplete")
	if len(r.FactStates) != 1 || r.FactStates[0].State != model.RepresentationUnknown {
		t.Fatal("property filter manufactured a weighted assertion")
	}
	replay(t, r)
}
func TestReviewIncompleteClassificationAndBroadGapReachVersions(t *testing.T) {
	for _, classification := range []bool{false, true} {
		s := fixture()
		s.Scope.Version = "v1"
		s.ClassificationComplete = classification
		if classification {
			s.UnknownKinds = []model.RepresentationGap{{Scope: model.ProtectedScope{Tenant: "t", Asset: "ns/p"}, Reason: "broad-unresolved"}}
		}
		r := Build(s)
		for _, a := range r.AssetState {
			if a.Scope.Version == "v1" && a.Primary != model.RepresentationUnknown {
				t.Fatal("specific version escaped unresolved scope")
			}
		}
		replay(t, r)
	}
}
func TestReviewPropertyScopedLossSummary(t *testing.T) {
	s := fixture()
	s.Scope = s.Facts[0].Scope
	s.Witnesses = []model.LossWitness{witness(s.Scope)}
	r := Build(s)
	if len(r.AssetState) != 1 || r.AssetState[0].Scope != s.Scope || r.AssetState[0].Primary != model.RepresentationAlreadyLost {
		t.Fatal("property scope lost", r.AssetState)
	}
	replay(t, r)
}
func TestReviewCredentialWeightKeysDroppedWithoutMerge(t *testing.T) {
	s := fixture()
	s.Weights.Values["token=REVIEW_SENTINEL"] = 11
	s.Weights.Values["token=OTHER_SENTINEL"] = 13
	s.Weights.InvalidValues = map[string]string{"password=THIRD_SENTINEL": "NaN"}
	r := Build(s)
	reason(t, r.CoverageShare.Share, "weight-key-binding-unavailable")
	b := wire(t, r)
	for _, secret := range []string{"REVIEW_SENTINEL", "OTHER_SENTINEL", "THIRD_SENTINEL"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("credential key leak")
		}
	}
	if len(r.Snapshot.Weights.Values) != 1 || len(r.Snapshot.Weights.InvalidValues) != 0 || len(s.Weights.Values) != 3 {
		t.Fatal("keys merged or input mutated")
	}
	replay(t, r)
}

// Export the exact contract results for the no-code-access math review. No test
// artifacts are written unless the caller explicitly requests an output folder.
func TestM100ConformanceSamples(t *testing.T) {
	samples := map[string]*model.Representation{}
	s := fixture()
	lost := s.Facts[0]
	lost.Key = "lost"
	lost.Scope.Property = "disclosure"
	unknown := s.Facts[0]
	unknown.Key = "unknown"
	unknown.Scope.Property = "unobserved"
	unknown.ReversibleCondition = ""
	unknown.Reason = "observation-unavailable"
	s.Facts = append(s.Facts, lost, unknown)
	s.Witnesses = []model.LossWitness{witness(lost.Scope)}
	s.Covers.Sets = append(s.Covers.Sets, []string{Key("t", "lost"), Key("t", "unknown")})
	s.Candidates.Sets = s.Covers.Sets
	samples["mixed-r-l-x"] = Build(s)
	s = fixture()
	zero := s.Facts[0]
	zero.Key = "zero"
	zero.Scope.Property = "uncovered-zero-weight"
	s.Facts = append(s.Facts, zero)
	s.Weights.Values[Key("t", "zero")] = 0
	samples["weighted-maximum-uncovered-zero"] = Build(s)
	s = fixture()
	s.History = samples["mixed-r-l-x"].AlreadyLost
	s.Facts = nil
	s.LossMappingVersion = ""
	s.LossAssessment = "unavailable"
	s.Claim.DetectorSet = []string{}
	s.Claim.RecallCap = "unknown"
	s.Claim.Note = model.NewClaimScope(nil, true, "fixture-build", "fixture-sha").Note
	samples["retained-loss-empty-current-map"] = Build(s)
	for name, r := range samples {
		replay(t, r)
		if dir := os.Getenv("M100_EXAMPLES_DIR"); dir != "" {
			b, e := json.MarshalIndent(struct {
				EvidenceKind string                `json:"evidenceKind"`
				Report       *model.Representation `json:"report"`
			}{"synthetic-contract-fixture-not-live", r}, "", "  ")
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, name+".json"), append(b, '\n'), 0644); e != nil {
				t.Fatal(e)
			}
		}
	}
}

func TestReviewDisjointGapsDoNotChangeRequestedSummary(t *testing.T) {
	for _, field := range []string{"tenant", "asset", "version", "property"} {
		for _, entries := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "-kind", true: "-entry"}[entries], func(t *testing.T) {
				s := fixture()
				s.Scope = s.Facts[0].Scope
				gap := s.Scope
				switch field {
				case "tenant":
					gap.Tenant = "other"
				case "asset":
					gap.Asset = "ns/other"
				case "version":
					gap.Version = "v0"
				case "property":
					gap.Property = "other"
				}
				g := model.RepresentationGap{Scope: gap, Reason: "unrelated-observation-gap"}
				if entries {
					s.UnresolvedEntries = []model.RepresentationGap{g}
				} else {
					s.UnknownKinds = []model.RepresentationGap{g}
				}
				r := Build(s)
				value(t, r.CoverageShare.Share, 1)
				found := false
				for _, a := range r.AssetState {
					if a.Scope == s.Scope {
						found = true
						if a.Primary != model.RepresentationAtRisk || len(a.Unresolved) != 0 {
							t.Fatal("disjoint gap contaminated requested scope", a)
						}
					}
				}
				if !found {
					t.Fatal("requested summary missing")
				}
				replay(t, r)
			})
		}
	}
	// A property-disjoint gap must not manufacture a spurious specific-version
	// summary inside a request that spans versions of another property.
	s := fixture()
	s.Scope.Property = "access"
	s.UnknownKinds = []model.RepresentationGap{{Scope: model.ProtectedScope{Tenant: "t", Asset: "ns/p", Version: "v1", Property: "other"}, Reason: "unrelated-property"}}
	for _, a := range Build(s).AssetState {
		if a.Primary != model.RepresentationAtRisk {
			t.Fatal("unrelated property contaminated a version summary", a)
		}
	}
}
func TestReviewUnrelatedAmbiguousKeyDoesNotInvalidateScopedShare(t *testing.T) {
	s := fixture()
	s.Scope = s.Facts[0].Scope
	other := s.Facts[0]
	other.Key = "other-key"
	other.Scope.Asset = "ns/other"
	conflict := other
	conflict.Scope.Property = "conflicting-property"
	s.Facts = append(s.Facts, other, conflict)
	r := Build(s)
	value(t, r.CoverageShare.Share, 1)
	if len(r.FactStates) != 1 || r.FactStates[0].State != model.RepresentationAtRisk {
		t.Fatal("excluded key poisoned requested classification")
	}
	replay(t, r)
}
