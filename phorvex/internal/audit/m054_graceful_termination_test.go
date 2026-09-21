package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestM054GracefulTerminationReceiptSurvivesAuditAndOwnsCopy(t *testing.T) {
	receipt := &model.GracefulTerminationReceipt{
		PolicyNamespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 7,
		PolicyGraceCapSeconds: 30, WorkloadGraceSeconds: 90, WorkloadGraceExplicit: true,
		EffectiveGracePeriodSeconds: 30, PodUID: "pod-uid", PodResourceVersion: "12",
		TerminationStatus: "unconfirmed",
	}
	record := ToRecord(model.Decision{Action: model.ActionRotate, Actuated: true, GracefulTermination: receipt})
	if record.GracefulTermination == nil || record.GracefulTermination == receipt || *record.GracefulTermination != *receipt {
		t.Fatalf("record receipt=%+v input=%+v", record.GracefulTermination, receipt)
	}
	receipt.TerminationStatus = "mutated"
	if record.GracefulTermination.TerminationStatus != "unconfirmed" {
		t.Fatal("audit record aliases mutable decision receipt")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Record
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GracefulTermination == nil || decoded.GracefulTermination.EffectiveGracePeriodSeconds != 30 || decoded.GracefulTermination.TerminationStatus != "unconfirmed" {
		t.Fatalf("decoded receipt=%+v raw=%s", decoded.GracefulTermination, raw)
	}

	without := ToRecord(model.Decision{Action: model.ActionRotate})
	raw, err = json.Marshal(without)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "gracefulTermination") {
		t.Fatalf("absent receipt serialized: %s", raw)
	}
}
