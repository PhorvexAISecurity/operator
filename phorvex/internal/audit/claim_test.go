package audit

import (
	"bytes"
	"encoding/json"
	"github.com/phorvex/phorvex/internal/model"
	"testing"
)

func TestClaimRecordDoesNotChangeDecisionAndPreservesRecordTime(t *testing.T) {
	for _, action := range []model.Action{model.ActionNoop, model.ActionRotate, model.ActionQuarantine} {
		claim := model.NewClaimScope([]string{"record-detector"}, true, "record-image", "record-sha")
		d := model.Decision{Action: action, Selected: action != model.ActionNoop, Cost: 2.5, Net: 7.3, CoverageValue: 9.8, Claim: &claim}
		before, _ := json.Marshal(d)
		rec := ToRecord(d)
		after, _ := json.Marshal(d)
		if !bytes.Equal(before, after) {
			t.Fatal("reporting mutated decision")
		}
		claim.DetectorSet[0] = "later-detector"
		if rec.Claim.DetectorSet[0] != "record-detector" || rec.Claim.GitSHA != "record-sha" {
			t.Fatal("record aliases current configuration")
		}
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		var replay Record
		if err = json.Unmarshal(data, &replay); err != nil {
			t.Fatal(err)
		}
		if replay.Claim == nil || replay.Claim.DetectorSet[0] != "record-detector" {
			t.Fatal("claim lost in replay")
		}
	}
}

func TestHistoricalRecordNeverGetsTodaysDetectorSet(t *testing.T) {
	var historical Record
	if err := json.Unmarshal([]byte(`{"action":"noop","pod":"old"}`), &historical); err != nil {
		t.Fatal(err)
	}
	if historical.Claim != nil {
		t.Fatal("historical claim invented")
	}
	data, _ := json.Marshal(historical)
	if bytes.Contains(data, []byte(`"claim"`)) {
		t.Fatal("historical record backfilled")
	}
	rec := ToRecord(model.Decision{Trace: &model.DecisionTraceV2{BrainImage: "old-image", GitSHA: "old-sha"}})
	if rec.Claim.DetectorSetKnown || rec.Claim.RecallCap != "unknown" || rec.Claim.GitSHA != "old-sha" {
		t.Fatal("missing evidence misrepresented")
	}
}
