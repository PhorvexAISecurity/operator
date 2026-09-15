package console

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestAuditFieldAvailableHonorsMeasurementEnvelope(t *testing.T) {
	b, err := json.Marshal(audit.ToRecord(model.Decision{PerDollar: 0, Measurements: &model.DecisionMeasurementsV1{SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "test", PerDollar: model.OptionalFloat{Present: true}}}))
	if err != nil {
		t.Fatal(err)
	}
	var measuredZero map[string]any
	if err = json.Unmarshal(b, &measuredZero); err != nil {
		t.Fatal(err)
	}
	if !auditFieldAvailable(measuredZero, "perDollar") {
		t.Fatal("measured zero reported unavailable")
	}
	unavailable := map[string]any{"schemaVersion": "phorvex.audit.v2", "measurements": map[string]any{"schemaVersion": model.DecisionMeasurementsSchemaV1, "source": "test", "perDollar": map[string]any{"present": false, "value": float64(0)}}}
	if auditFieldAvailable(unavailable, "perDollar") {
		t.Fatal("unavailable field reported as measured zero")
	}
	legacy := map[string]any{"perDollar": float64(2)}
	if !auditFieldAvailable(legacy, "perDollar") {
		t.Fatal("explicit legacy scalar was discarded")
	}
	legacyNull := map[string]any{"perDollar": nil}
	if auditFieldAvailable(legacyNull, "perDollar") {
		t.Fatal("legacy null was treated as a measurement")
	}
}

func TestRedteamLivePreservesMeasuredZeroThroughHTTPAndRender(t *testing.T) {
	type proof struct {
		PerDollar          float64 `json:"perDollar"`
		PerDollarAvailable bool    `json:"perDollarAvailable"`
		LambdaMax          float64 `json:"lambdaMax"`
		LambdaAvailable    bool    `json:"lambdaAvailable"`
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out-redteam-live-pump")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	record := audit.ToRecord(model.Decision{Pod: "target-fh", Action: model.ActionRotate, Actuated: true, DecidedAt: time.Unix(1, 0), Measurements: &model.DecisionMeasurementsV1{SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "test", PerDollar: model.OptionalFloat{Present: true}, Lambda: model.OptionalFloat{Present: true}}})
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	run := func(raw []byte) []proof {
		if err := os.WriteFile(filepath.Join(path, "phorvex-audit-d-phorvex.jsonl"), append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		NewServer(Config{HarnessDir: dir}).redteamLive(w, httptest.NewRequest("GET", "/api/redteam/live", nil))
		var body struct {
			Proofs []proof `json:"proofs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Proofs
	}
	proofs := run(line)
	if len(proofs) != 1 || !proofs[0].PerDollarAvailable || !proofs[0].LambdaAvailable || proofs[0].PerDollar != 0 || proofs[0].LambdaMax != 0 {
		t.Fatalf("measured zero lost at HTTP boundary: %+v", proofs)
	}
	for name, bad := range map[string]string{
		"missing-top-level": `{"schemaVersion":"phorvex.audit.v2","pod":"target-fh","action":"rotate","actuated":true,"measurements":{"schemaVersion":"phorvex.decision-measurements.v1","source":"test","lambda":{"present":true,"value":0}}}`,
		"mismatched":        `{"schemaVersion":"phorvex.audit.v2","pod":"target-fh","action":"rotate","actuated":true,"lambda":1,"measurements":{"schemaVersion":"phorvex.decision-measurements.v1","source":"test","lambda":{"present":true,"value":0}}}`,
		"unsupported":       `{"schemaVersion":"phorvex.audit.v2","pod":"target-fh","action":"rotate","actuated":true,"lambda":0,"measurements":{"schemaVersion":"future","source":"test","lambda":{"present":true,"value":0}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := run([]byte(bad))
			if len(got) != 1 || got[0].LambdaAvailable {
				t.Fatalf("malformed evidence exposed as available: %+v", got)
			}
		})
	}
	for _, want := range []string{"p.perDollarAvailable?p.perDollar.toFixed(2):'—'", "p.lambdaAvailable?p.lambdaMax.toFixed(2):'—'", "p.perDollarAvailable?p.perDollar.toFixed(2):\"unavailable\""} {
		if !strings.Contains(redteamHTML, want) {
			t.Fatalf("render path ignores availability token %q", want)
		}
	}
}
