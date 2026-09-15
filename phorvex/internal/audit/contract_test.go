package audit

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestMeasurementsPreserveZeroAndUnavailable(t *testing.T) {
	d := model.Decision{Engine: "p1-coverage", Measurements: &model.DecisionMeasurementsV1{
		SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "p1-coverage",
		Lambda: model.OptionalFloat{Present: true}, PerDollar: model.OptionalFloat{},
		AIClassified: model.OptionalBool{Present: true}, CoveredFacts: model.OptionalInt{},
	}}
	b, err := json.Marshal(ToRecord(d))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["lambda"]) != "0" || string(fields["aiClassified"]) != "false" {
		t.Fatalf("measured zeros omitted: %s", b)
	}
	if _, ok := fields["perDollar"]; ok {
		t.Fatalf("unavailable ratio invented: %s", b)
	}
	if _, ok := fields["coveredFacts"]; ok {
		t.Fatalf("unavailable count invented: %s", b)
	}
	var got Record
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Measurements == nil || !got.Measurements.Lambda.Present || got.Measurements.PerDollar.Present {
		t.Fatalf("presence lost: %+v", got.Measurements)
	}
}

func TestLegacyScalarPresenceRoundTripIsRecordedOnly(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		present   bool
	}{
		{"absent", `{"schemaVersion":"phorvex.audit.v2"}`, false},
		{"null", `{"schemaVersion":"phorvex.audit.v2","lambda":null}`, false},
		{"zero", `{"schemaVersion":"phorvex.audit.v2","lambda":0}`, true},
		{"positive", `{"schemaVersion":"phorvex.audit.v2","lambda":1.25}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r Record
			if err := json.Unmarshal([]byte(tc.raw), &r); err != nil {
				t.Fatal(err)
			}
			if (r.Measurements != nil) != tc.present {
				t.Fatalf("presence=%v", r.Measurements)
			}
			if tc.present && (r.Measurements.Source != "legacy-recorded" || !r.Measurements.Lambda.Present || r.Measurements.Lambda.Value != r.Lambda) {
				t.Fatalf("legacy evidence changed: %+v", r.Measurements)
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(b, &fields)
			_, ok := fields["lambda"]
			if ok != tc.present {
				t.Fatalf("round trip presence=%v: %s", ok, b)
			}
		})
	}
}

func TestMeasurementPresenceRequiresTopLevelValue(t *testing.T) {
	raw := `{"schemaVersion":"phorvex.audit.v2","measurements":{"schemaVersion":"phorvex.decision-measurements.v1","source":"p1-coverage","lambda":{"present":true,"value":0}}}`
	var r Record
	if err := json.Unmarshal([]byte(raw), &r); err == nil {
		t.Fatal("presence envelope legitimized a missing top-level scalar")
	}
}

func TestMeasurementsRejectNonFiniteProducerValue(t *testing.T) {
	r := ToRecord(model.Decision{Lambda: math.NaN(), Measurements: &model.DecisionMeasurementsV1{SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "p1-coverage", Lambda: model.OptionalFloat{Present: true, Value: math.NaN()}}})
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("non-finite measurement was laundered through audit rounding")
	}
}

func TestNewWriterEmitsOnlyCanonicalV2(t *testing.T) {
	rec := ToRecord(model.Decision{
		Engine: "p1-coverage", CoverageValue: 2.5, PHold: 0.6,
		Attribution: []model.AttributionTerm{{Source: "cover:modelFingerprint", Contribution: 2.5}},
	})
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"schemaVersion":"phorvex.audit.v2"`, `"coverageValue":2.5`, `"pHold":0.6`, "cover:modelIdentity"} {
		if !strings.Contains(text, want) {
			t.Errorf("new writer omitted canonical token %q: %s", want, text)
		}
	}
	for _, old := range []string{`"risk":`, `"belief":`, "modelFingerprint"} {
		if strings.Contains(text, old) {
			t.Errorf("new writer emitted retired token %q: %s", old, text)
		}
	}
}

func TestV1ReadShimTranslatesFieldsAndFactKinds(t *testing.T) {
	old := `{
		"schemaVersion":"phorvex.audit.v1",
		"kind":"phorvex.decision",
		"engine":"p1-coverage",
		"risk":4.25,
		"belief":0.2,
		"pHold":0.75,
		"attribution":[
			{"source":"cover:modelFingerprint","contribution":1.1},
			{"source":"cover:nodePlacement","contribution":0.4},
			{"source":"cover:session","contribution":0.3},
			{"source":"cover:sideChannel","contribution":0.2}
		]
	}`

	var rec Record
	if err := json.Unmarshal([]byte(old), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SchemaVersion != SchemaVersionCurrent || rec.SourceSchemaVersion != SchemaVersionPrevious {
		t.Fatalf("translated versions = %q from %q", rec.SchemaVersion, rec.SourceSchemaVersion)
	}
	if rec.CoverageValue != 4.25 || rec.ThreatRisk != 0 {
		t.Fatalf("risk translation = coverage %.2f / threat %.2f", rec.CoverageValue, rec.ThreatRisk)
	}
	if rec.PHold != 0.75 {
		t.Fatalf("pHold = %.2f; authoritative pHold must win over legacy belief", rec.PHold)
	}
	wantSources := []string{"cover:modelIdentity", "retired:nodePlacement", "cover:session", "cover:sideChannel"}
	for i, want := range wantSources {
		if rec.Attribution[i].Source != want {
			t.Errorf("attribution[%d] = %q, want %q", i, rec.Attribution[i].Source, want)
		}
	}
	if rec.Attribution[1].Contribution != 0.4 {
		t.Fatal("retired nodePlacement contribution was dropped instead of translated")
	}
	if rec.Attribution[3].Source != "cover:sideChannel" {
		t.Fatal("sideChannel was mapped before the authoritative GPU taxonomy was published")
	}

	canonical, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	text := string(canonical)
	for _, retired := range []string{`"risk":`, `"belief":`, "modelFingerprint", "cover:nodePlacement"} {
		if strings.Contains(text, retired) {
			t.Errorf("canonical v2 still contains retired token %q: %s", retired, text)
		}
	}
	for _, current := range []string{`"schemaVersion":"phorvex.audit.v2"`, `"coverageValue":4.25`, `"pHold":0.75`, "cover:modelIdentity", "retired:nodePlacement", "cover:sideChannel"} {
		if !strings.Contains(text, current) {
			t.Errorf("canonical v2 is missing %q: %s", current, text)
		}
	}
}

func TestLegacyP0RiskAndBeliefTranslateWithoutChangingMeaning(t *testing.T) {
	old := `{"kind":"phorvex.decision","engine":"p0-greedy","risk":0.8,"belief":0.3}`
	var rec Record
	if err := json.Unmarshal([]byte(old), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SourceSchemaVersion != SchemaVersionLegacy || rec.CoverageValue != 0 || rec.ThreatRisk != 0.8 {
		t.Fatalf("legacy P0 risk changed meaning: %+v", rec)
	}
	if rec.PHold != 0.3 {
		t.Fatalf("legacy belief fallback did not become pHold: %.2f", rec.PHold)
	}
	canonical, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), `"risk":`) || !strings.Contains(string(canonical), `"threatRisk":0.8`) {
		t.Fatalf("legacy P0 value was not emitted under its distinct v2 field: %s", canonical)
	}
}

func TestCurrentSchemaRejectsRetiredTokens(t *testing.T) {
	for _, field := range []string{"risk", "belief"} {
		raw := `{"schemaVersion":"phorvex.audit.v2","` + field + `":1}`
		var rec Record
		if err := json.Unmarshal([]byte(raw), &rec); err == nil {
			t.Fatalf("v2 accepted retired field %q", field)
		}
	}
	for _, source := range []string{"cover:modelFingerprint", "cover:nodePlacement"} {
		var rec Record
		oldFact := `{"schemaVersion":"phorvex.audit.v2","attribution":[{"source":"` + source + `","contribution":1}]}`
		if err := json.Unmarshal([]byte(oldFact), &rec); err == nil {
			t.Fatalf("v2 accepted retired attribution source %q", source)
		}
	}
}

func TestPublishedMigrationMapIsSettledAndShimExpires(t *testing.T) {
	migrations := V1ToV2Migrations()
	want := map[string]string{
		"fact-kind:modelFingerprint":   "modelIdentity",
		"fact-kind:session":            "session",
		"fact-kind:nodePlacement":      "retired:nodePlacement",
		"decision-field:risk":          "coverageValue",
		"decision-field:belief":        "pHold",
		"decision-field:threatPosture": "threatPosture",
		"decision-field:residual":      "residual",
	}
	for _, migration := range migrations {
		key := migration.Category + ":" + migration.Old
		if migration.Old == "sideChannel" || migration.New == "gpuContentionChannel" || migration.New == "gpuCoresidency" {
			t.Fatalf("unsettled GPU migration was published: %+v", migration)
		}
		if got, ok := want[key]; !ok || got != migration.New {
			t.Fatalf("unexpected migration %+v", migration)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("migration map is incomplete: %v", want)
	}
	if ReadTranslationExpiresAt != "phorvex.audit.v4" {
		t.Fatalf("read shim has no fixed version expiry: %q", ReadTranslationExpiresAt)
	}
}
