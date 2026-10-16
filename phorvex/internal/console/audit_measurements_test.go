package console

import (
	"encoding/json"
	"testing"

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
