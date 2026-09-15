package decision

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM146ProducerPreservesComputedZero(t *testing.T) {
	zeroPolicy := covPolicy(1)
	zeroPolicy.Lambda = 0
	zero := NewCoverageEngine().Decide([]*model.WorkloadView{covView("zero", true, 3*time.Hour, false)}, zeroPolicy)[0]
	b, err := json.Marshal(audit.ToRecord(zero))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if raw, ok := fields["lambda"]; !ok || string(raw) != "0" {
		t.Fatalf("computed lambda zero absent: %s", b)
	}

	positivePolicy := covPolicy(1)
	positive := NewCoverageEngine().Decide([]*model.WorkloadView{covView("positive", true, 3*time.Hour, false)}, positivePolicy)[0]
	b, err = json.Marshal(audit.ToRecord(positive))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if raw, ok := fields["lambda"]; !ok || string(raw) == "0" {
		t.Fatalf("positive control missing: %s", b)
	}
}
