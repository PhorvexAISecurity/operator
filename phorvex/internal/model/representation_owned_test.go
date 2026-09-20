package model

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"testing"
)

func post25RepresentationFixture() Representation {
	v := 2.5
	required := true
	badUTF := "bad\xffvalue"
	scope := ProtectedScope{Tenant: "tenant", Asset: "asset", Version: "v1", Property: "token=scope-secret"}
	witness := LossWitness{
		Scope: scope, EventRef: badUTF, EventTime: "2026-09-20T00:00:00Z", IngestionTime: "2026-09-20T00:00:01Z",
		AuthenticatedIdentity: "Bearer fixture-secret", TrustAtIngestionRef: "trust", RuleVersion: "rule",
		PayloadPredicateRef: "predicate", CompletedUnauthorizedOutcomeRef: "outcome", IrreversibilitySemantics: "irreversible", ClassificationRef: "classification",
	}
	fact := RepresentationFact{
		Key: "fact", Kind: "kind", Scope: scope, RuleVersion: "rule", ObservationRef: "https://user:pass@example.test/ref",
		ReversibleCondition: "condition", Reason: badUTF, Actionability: []string{"password=hunter2", "ready"},
	}
	claim := ClaimScope{Scope: "modeled", DetectorSet: []string{"detector", badUTF}, DetectorSetKnown: true, RecallCap: "cap", Note: "api_key=claim-secret", BrainImage: "image", GitSHA: "sha"}
	snapshot := RepresentationSnapshot{
		Ref: "ref", Scope: scope, Aggregation: "per-decision", PopulationVersion: "population", InventoryComplete: true, ClassificationComplete: true,
		Claim: &claim, DetectorBasis: "configured", CapabilityStatus: "available", CapabilityVersion: "capability",
		UnresolvedEntries: []RepresentationGap{{Scope: scope, Kind: "gap", Reason: "credential=gap-secret"}},
		UnknownKinds:      []RepresentationGap{{Scope: scope, Kind: "unknown", Reason: badUTF}}, Facts: []RepresentationFact{fact},
		Weights:     RepresentationWeights{SnapshotRef: "weights", Basis: "basis", ProvenanceRef: "provenance", InvalidValues: map[string]string{"invalid": "token=weight-secret"}, Values: map[string]float64{"fact": 2, "password=key-secret": 3}},
		ActionBasis: "selected", Covers: RepresentationCovers{SnapshotRef: "covers", Available: true, Sets: [][]string{{"fact", badUTF}}},
		Candidates: RepresentationCovers{SnapshotRef: "candidates", Available: true, Sets: [][]string{{"fact"}}}, HistoryStatus: "available",
		LossMappingVersion: "mapping", DispatchEvidence: "dispatch", LossAssessment: "available",
		History: []RetainedLoss{{ID: "loss", Scope: scope, Witnesses: []LossWitness{witness}}}, Witnesses: []LossWitness{witness},
		Limitations: []string{"Authorization: Basic fixture-secret", badUTF},
	}
	return Representation{
		Version: "representation-v1", Snapshot: snapshot,
		CoverageShare: RepresentationCoverage{
			Unit: "weight", Covered: RepresentationAmount{Present: true, Value: &v, Reason: "covered"},
			Representable: RepresentationAmount{Present: true, Value: &v}, Coverable: RepresentationAmount{Present: true, Value: &v},
			Share: RepresentationAmount{Present: true, Value: &v}, RequiredSetCovered: &required,
		},
		FactStates:  []ReportedFact{{RepresentationFact: fact, State: RepresentationAtRisk, LossRefs: []string{"loss"}}},
		AlreadyLost: []RetainedLoss{{ID: "loss", Scope: scope, Witnesses: []LossWitness{witness}}}, KnownLossCount: 1,
		LossHistoryStatus: "available", LossAssessment: "available",
		UnknownEntries: []RepresentationGap{{Scope: scope, Kind: "unknown", Reason: "reason"}},
		UnknownKinds:   []RepresentationGap{{Scope: scope, Kind: "kind", Reason: "reason"}}, UncoverableEntries: []string{"fact"},
		AssetState: []RepresentationAsset{{Scope: scope, Primary: RepresentationAtRisk, AtRiskKeys: []string{"fact"}, LossRefs: []string{"loss"}, Unresolved: []string{badUTF}}},
		OutOfBand:  "unmeasured", EffectEvidence: "unconfirmed", Note: "token=note-secret",
	}
}

func frozenRepresentationRedacted(in RepresentationSnapshot) RepresentationSnapshot {
	in, _ = in.withoutCredentialKeys()
	b, err := marshalOutcomeRedacted(in)
	if err != nil {
		return RepresentationSnapshot{Limitations: []string{"invalid-reporting-input"}}
	}
	var out RepresentationSnapshot
	if json.Unmarshal(b, &out) != nil {
		return RepresentationSnapshot{Limitations: []string{"invalid-reporting-input"}}
	}
	for i, f := range in.Facts {
		if f.Scope != out.Facts[i].Scope {
			out.Facts[i].Reason = "redacted-scope-binding-unavailable"
			out.ClassificationComplete = false
		}
	}
	for i, w := range in.Witnesses {
		if w.Scope != out.Witnesses[i].Scope {
			out.Witnesses[i].TrustAtIngestionRef = ""
		}
	}
	for i, l := range in.History {
		if l.Scope != out.History[i].Scope {
			out.HistoryStatus = "partial"
		}
	}
	return out
}

func frozenRepresentationMarshal(in Representation) ([]byte, error) {
	type plain Representation
	var removed bool
	in.Snapshot, removed = in.Snapshot.withoutCredentialKeys()
	if removed {
		missing := RepresentationAmount{Reason: "weight-key-binding-unavailable"}
		in.CoverageShare.Covered, in.CoverageShare.Coverable = missing, missing
		in.CoverageShare.Representable, in.CoverageShare.Share = missing, missing
	}
	return marshalOutcomeRedacted(plain(in))
}

func TestPost25M137TypedRepresentationPreservesLegacyWireAndRedaction(t *testing.T) {
	in := post25RepresentationFixture()
	wantSnapshot := frozenRepresentationRedacted(in.Snapshot)
	gotSnapshot := in.Snapshot.Redacted()
	if !reflect.DeepEqual(gotSnapshot, wantSnapshot) {
		t.Fatalf("snapshot redaction changed\nwant=%#v\n got=%#v", wantSnapshot, gotSnapshot)
	}
	want, err := frozenRepresentationMarshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("representation wire changed\nwant=%s\n got=%s", want, got)
	}
	var wantOwned Representation
	if err := json.Unmarshal(want, &wantOwned); err != nil {
		t.Fatal(err)
	}
	gotOwned, err := OwnedRedactedRepresentation(&in)
	if err != nil || !reflect.DeepEqual(*gotOwned, wantOwned) {
		t.Fatalf("owned representation object changed\nwant=%#v\n got=%#v err=%v", wantOwned, gotOwned, err)
	}
	if strconv.IntSize == 64 {
		in.KnownLossCount = int((uint64(1) << 54) + 1)
		want, err = frozenRepresentationMarshal(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err = json.Marshal(in)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("legacy numeric normalization changed\nwant=%s\n got=%s err=%v", want, got, err)
		}
	}
	in = post25RepresentationFixture()
	in.FactStates[0].State = RepresentationState(99)
	in.AssetState[0].Primary = RepresentationState(99)
	want, err = frozenRepresentationMarshal(in)
	if err != nil {
		t.Fatal(err)
	}
	wantOwned = Representation{}
	if err := json.Unmarshal(want, &wantOwned); err != nil {
		t.Fatal(err)
	}
	gotOwned, err = OwnedRedactedRepresentation(&in)
	if err != nil || !reflect.DeepEqual(*gotOwned, wantOwned) {
		t.Fatalf("unknown representation state normalization changed: want=%#v got=%#v err=%v", wantOwned, gotOwned, err)
	}
	for _, secret := range [][]byte{[]byte("hunter2"), []byte("scope-secret"), []byte("weight-secret"), []byte("note-secret"), {0xff}} {
		if bytes.Contains(got, secret) {
			t.Fatalf("representation leaked %q", secret)
		}
	}
}

func TestPost25M137TypedRepresentationOwnsNestedState(t *testing.T) {
	in := post25RepresentationFixture()
	clone := CloneRepresentationSnapshot(in.Snapshot)
	before, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	in.Snapshot.Claim.DetectorSet[0] = "changed"
	in.Snapshot.Facts[0].Actionability[0] = "changed"
	in.Snapshot.Weights.Values["fact"] = 99
	in.Snapshot.Weights.InvalidValues["invalid"] = "changed"
	in.Snapshot.Covers.Sets[0][0] = "changed"
	in.Snapshot.Candidates.Sets[0][0] = "changed"
	in.Snapshot.History[0].Witnesses[0].EventRef = "changed"
	in.Snapshot.Witnesses[0].EventRef = "changed"
	in.Snapshot.Limitations[0] = "changed"
	after, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("typed snapshot clone retained a nested alias\nbefore=%s\n after=%s", before, after)
	}

	in = post25RepresentationFixture()
	owned, raw, err := MarshalOwnedRedactedRepresentation(&in)
	if err != nil {
		t.Fatal(err)
	}
	in.FactStates[0].LossRefs[0] = "changed"
	in.AlreadyLost[0].Witnesses[0].EventRef = "changed"
	in.UnknownEntries[0].Reason = "changed"
	in.UncoverableEntries[0] = "changed"
	in.AssetState[0].AtRiskKeys[0] = "changed"
	*in.CoverageShare.Covered.Value = 99
	*in.CoverageShare.RequiredSetCovered = false
	again, err := json.Marshal(owned)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatalf("owned representation retained a nested alias\nwant=%s\n got=%s", raw, again)
	}
}

func TestPost25M137TypedRepresentationRetainsNonfiniteFailure(t *testing.T) {
	in := post25RepresentationFixture()
	in.Snapshot.Weights.Values["fact"] = math.NaN()
	if _, err := frozenRepresentationMarshal(in); err == nil {
		t.Fatal("frozen encoder unexpectedly accepted NaN")
	}
	if _, err := json.Marshal(in); err == nil {
		t.Fatal("typed encoder accepted NaN")
	}
	want := frozenRepresentationRedacted(in.Snapshot)
	got := in.Snapshot.Redacted()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nonfinite snapshot fallback changed: want=%#v got=%#v", want, got)
	}

	for _, field := range []string{"covered", "representable", "coverable", "share"} {
		t.Run(field, func(t *testing.T) {
			in := post25RepresentationFixture()
			delete(in.Snapshot.Weights.Values, "password=key-secret")
			bad := math.Inf(-1)
			switch field {
			case "covered":
				in.CoverageShare.Covered.Value = &bad
			case "representable":
				in.CoverageShare.Representable.Value = &bad
			case "coverable":
				in.CoverageShare.Coverable.Value = &bad
			case "share":
				in.CoverageShare.Share.Value = &bad
			}
			if _, err := frozenRepresentationMarshal(in); err == nil {
				t.Fatal("frozen encoder unexpectedly accepted nonfinite amount")
			}
			if _, err := json.Marshal(in); err == nil {
				t.Fatal("typed encoder accepted nonfinite amount")
			}
		})
	}
}

func TestPost25M137TypedRepresentationPreservesNormalizedMapCollisions(t *testing.T) {
	in := post25RepresentationFixture()
	in.Snapshot.Weights.Values = map[string]float64{"x\xfe": 1, "x\xff": 2}
	in.Snapshot.Weights.InvalidValues = map[string]string{"x\xfe": "first", "x\xff": "second"}
	wantSnapshot := frozenRepresentationRedacted(in.Snapshot)
	gotSnapshot := in.Snapshot.Redacted()
	if !reflect.DeepEqual(gotSnapshot, wantSnapshot) {
		t.Fatalf("normalized map collision changed snapshot\nwant=%#v\n got=%#v", wantSnapshot, gotSnapshot)
	}
	if len(gotSnapshot.Weights.Values) != 1 || gotSnapshot.Weights.Values["x�"] != 2 || gotSnapshot.Weights.InvalidValues["x�"] != "second" {
		t.Fatalf("normalized collision did not retain the legacy sorted last value: %#v", gotSnapshot.Weights)
	}
	want, err := frozenRepresentationMarshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(in)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("normalized map collision changed wire\nwant=%s\n got=%s err=%v", want, got, err)
	}
}

func TestPost25M137TypedRepresentationPreservesNilEmptyAndZeroShapes(t *testing.T) {
	zero := 0.0
	required := false
	cases := []Representation{
		{},
		{
			Snapshot: RepresentationSnapshot{
				Claim: &ClaimScope{}, UnresolvedEntries: []RepresentationGap{}, UnknownKinds: []RepresentationGap{}, Facts: []RepresentationFact{},
				Weights: RepresentationWeights{InvalidValues: map[string]string{}, Values: map[string]float64{}},
				Covers:  RepresentationCovers{Sets: [][]string{}}, Candidates: RepresentationCovers{Sets: [][]string{}},
				History: []RetainedLoss{}, Witnesses: []LossWitness{}, Limitations: []string{},
			},
			CoverageShare: RepresentationCoverage{
				Covered: RepresentationAmount{Present: true, Value: &zero}, Representable: RepresentationAmount{Value: nil},
				Coverable: RepresentationAmount{Present: true, Value: &zero}, Share: RepresentationAmount{Present: true, Value: &zero}, RequiredSetCovered: &required,
			},
			FactStates: []ReportedFact{}, AlreadyLost: []RetainedLoss{}, UnknownEntries: []RepresentationGap{}, UnknownKinds: []RepresentationGap{},
			UncoverableEntries: []string{}, AssetState: []RepresentationAsset{},
		},
	}
	for i, in := range cases {
		want, err := frozenRepresentationMarshal(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(in)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("case %d nil/empty/zero wire changed\nwant=%s\n got=%s err=%v", i, want, got, err)
		}
		var wantOwned Representation
		if err := json.Unmarshal(want, &wantOwned); err != nil {
			t.Fatal(err)
		}
		gotOwned, err := OwnedRedactedRepresentation(&in)
		if err != nil || !reflect.DeepEqual(*gotOwned, wantOwned) {
			t.Fatalf("case %d nil/empty/zero object changed\nwant=%#v\n got=%#v err=%v", i, wantOwned, gotOwned, err)
		}
	}
}
