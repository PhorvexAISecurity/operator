package audit

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/model"
)

func frozenRecordMarshal(r Record) ([]byte, error) {
	type recordAlias Record
	r.preparedRepresentation = nil
	r.SchemaVersion = SchemaVersionCurrent
	r.Attribution = canonicalizeAttribution(r.Attribution)
	if err := validateMeasurements(r.Measurements); err != nil {
		return nil, err
	}
	if err := measurementsMatch(r); err != nil {
		return nil, err
	}
	b, err := json.Marshal(recordAlias(r))
	if err != nil || r.Measurements == nil {
		return b, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	put := func(name string, present bool, value any) error {
		if !present {
			return nil
		}
		v, err := json.Marshal(value)
		if err == nil {
			fields[name] = v
		}
		return err
	}
	m := r.Measurements
	for _, item := range []struct {
		name    string
		present bool
		value   any
	}{
		{"threatRisk", m.ThreatRisk.Present, r.ThreatRisk}, {"perDollar", m.PerDollar.Present, r.PerDollar},
		{"coveredWeight", m.CoveredWeight.Present, r.CoveredWeight}, {"coveredFacts", m.CoveredFacts.Present, r.CoveredFacts},
		{"stageHazard", m.StageHazard.Present, r.StageHazard}, {"lambda", m.Lambda.Present, r.Lambda},
		{"proactiveRate", m.ProactiveRate.Present, r.ProactiveRate}, {"preemptMargin", m.PreemptMargin.Present, r.PreemptMargin},
		{"projectedNextStageSec", m.ProjectedNextStageSec.Present, r.ProjectedNextStageSec}, {"killSwitch", m.KillSwitch.Present, r.KillSwitch},
		{"aiClassified", m.AIClassified.Present, r.AIClassified}, {"eventEvidence", m.EventEvidence.Present, r.EventEvidence},
		{"provenance", m.Provenance.Present, r.Provenance},
	} {
		if err := put(item.name, item.present, item.value); err != nil {
			return nil, err
		}
	}
	return json.Marshal(fields)
}

func post25AuditDecision() model.Decision {
	v := 0.0
	required := false
	scope := model.ProtectedScope{Tenant: "tenant-a", Asset: "ns/pod", Version: "uid", Property: "password=scope-secret"}
	claim := model.NewClaimScope([]string{"detector"}, true, "image", "sha")
	representation := &model.Representation{
		Version: "m100-representation-v1",
		Snapshot: model.RepresentationSnapshot{
			Ref: "tick", Scope: scope, Aggregation: "per-decision", PopulationVersion: "population", Claim: &claim,
			Facts:   []model.RepresentationFact{{Key: "fact", Kind: "kind", Scope: scope, RuleVersion: "rule", ObservationRef: "bad\xffvalue", ReversibleCondition: "ready", Actionability: []string{"coverable-now"}}},
			Weights: model.RepresentationWeights{Values: map[string]float64{"fact": 1}, InvalidValues: map[string]string{"other": "token=secret"}},
			Covers:  model.RepresentationCovers{Sets: [][]string{{"fact,{quoted}:\\value"}}}, Candidates: model.RepresentationCovers{Sets: [][]string{{"fact"}}},
			Limitations: []string{"Authorization: Basic fixture-secret"},
		},
		CoverageShare: model.RepresentationCoverage{
			Covered: model.RepresentationAmount{Present: true, Value: &v}, Representable: model.RepresentationAmount{Present: true, Value: &v},
			Coverable: model.RepresentationAmount{Present: true, Value: &v}, Share: model.RepresentationAmount{Present: true, Value: &v}, RequiredSetCovered: &required,
		},
		FactStates: []model.ReportedFact{{RepresentationFact: model.RepresentationFact{Key: "fact", Scope: scope}, LossRefs: []string{"loss"}}},
		AssetState: []model.RepresentationAsset{{Scope: scope, AtRiskKeys: []string{"fact"}}}, Note: "credential=note-secret",
	}
	presentFloat := model.OptionalFloat{Present: true, Value: 0}
	return model.Decision{
		Tenant: "tenant-a", Namespace: "ns", Pod: "pod,{quoted}", DecidedAt: time.Unix(10, 20).UTC(),
		Representation: representation,
		Measurements: &model.DecisionMeasurementsV1{
			SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "optimizer",
			ThreatRisk: presentFloat, PerDollar: presentFloat, CoveredWeight: presentFloat,
			CoveredFacts: model.OptionalInt{Present: true}, StageHazard: presentFloat, Lambda: presentFloat,
			ProactiveRate: presentFloat, PreemptMargin: presentFloat, ProjectedNextStageSec: presentFloat,
			KillSwitch: model.OptionalBool{Present: true}, AIClassified: model.OptionalBool{Present: true},
			EventEvidence: presentFloat, Provenance: presentFloat,
		},
	}
}

func TestPost25M137PreparedRecordMatchesFrozenWire(t *testing.T) {
	d := post25AuditDecision()
	want, err := frozenRecordMarshal(ToRecord(d))
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(toRecord(d, true))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("prepared record wire changed\nwant=%s\n got=%s", want, got)
	}
	public, err := json.Marshal(ToRecord(d))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(public, want) {
		t.Fatalf("public record wire changed\nwant=%s\n got=%s", want, public)
	}
	for _, field := range []string{"threatRisk", "perDollar", "coveredWeight", "coveredFacts", "killSwitch", "aiClassified", "eventEvidence", "provenance"} {
		needle := []byte(`"` + field + `":0`)
		if field == "killSwitch" || field == "aiClassified" {
			needle = []byte(`"` + field + `":false`)
		}
		if !bytes.Contains(got, needle) {
			t.Fatalf("present zero %s omitted from %s", field, got)
		}
	}
	for _, secret := range []string{"scope-secret", "fixture-secret", "note-secret", "token=secret"} {
		if bytes.Contains(got, []byte(secret)) {
			t.Fatalf("prepared record leaked %q", secret)
		}
	}
}

func TestPost25M137PreparedRecordOwnsRepresentationAndSyncsOnce(t *testing.T) {
	d := post25AuditDecision()
	rec := toRecord(d, true)
	want, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	d.Representation.Snapshot.Facts[0].Actionability[0] = "changed"
	d.Representation.Snapshot.Weights.Values["fact"] = 99
	d.Representation.CoverageShare.Share.Value = func() *float64 { v := 99.0; return &v }()
	got, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("prepared record aliases producer state\nwant=%s\n got=%s", want, got)
	}

	sink := &faultSink{}
	l := New(logr.Discard(), sink)
	if err := l.Record(post25AuditDecision()); err != nil {
		t.Fatal(err)
	}
	if sink.calls != "wfs" {
		t.Fatalf("persistence sequence = %q, want wfs", sink.calls)
	}
	if !bytes.Equal(bytes.TrimSpace(sink.Bytes()), want) {
		t.Fatalf("logger wire changed\nwant=%s\n got=%s", want, bytes.TrimSpace(sink.Bytes()))
	}
}

func TestPost25M137PreparedRecordRetainsErrorsAndLegacyRead(t *testing.T) {
	d := post25AuditDecision()
	d.Representation.Snapshot.Weights.Values["fact"] = math.Inf(1)
	want, wantErr := frozenRecordMarshal(ToRecord(d))
	got, gotErr := json.Marshal(toRecord(d, true))
	if wantErr != nil || gotErr != nil || !bytes.Equal(got, want) || !bytes.Contains(got, []byte("invalid-retained-representation")) {
		t.Fatalf("nonfinite result changed: old=(%q,%v) new=(%q,%v)", want, wantErr, got, gotErr)
	}

	legacy := []byte(`{"kind":"phorvex.decision","time":"2026-09-20T00:00:00Z","tenant":"t","namespace":"n","pod":"p","action":"noop","selected":false,"feasible":true,"dryRun":false,"actuated":false,"risk":0,"cost":0,"net":0,"residual":0,"threatPosture":0,"exposure":0,"belief":0,"assetValue":0,"blastRadius":0,"sloHeadroom":0,"phase":"steady","reason":"fixture","r6Counterfactual":"noop"}`)
	var read Record
	if err := json.Unmarshal(legacy, &read); err != nil {
		t.Fatal(err)
	}
	if read.SourceSchemaVersion != SchemaVersionLegacy || read.SchemaVersion != SchemaVersionCurrent {
		t.Fatalf("legacy translation changed: source=%q current=%q", read.SourceSchemaVersion, read.SchemaVersion)
	}
	if _, err := json.Marshal(read); err != nil {
		t.Fatalf("translated legacy record no longer writes: %v", err)
	}
}

type post25DiscardSyncSink struct {
	writes int
	syncs  int
}

func (s *post25DiscardSyncSink) Write(p []byte) (int, error) {
	s.writes++
	return len(p), nil
}
func (*post25DiscardSyncSink) Flush() error { return nil }
func (s *post25DiscardSyncSink) Sync() error {
	s.syncs++
	return nil
}

func BenchmarkPost25M137RecordSyncSink(b *testing.B) {
	sink := &post25DiscardSyncSink{}
	logger := New(logr.Discard(), sink)
	decision := post25AuditDecision()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := logger.Record(decision); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink.writes != b.N || sink.syncs != b.N {
		b.Fatalf("durability calls writes=%d syncs=%d, want %d each", sink.writes, sink.syncs, b.N)
	}
}
