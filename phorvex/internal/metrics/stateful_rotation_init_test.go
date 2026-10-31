package metrics

import (
	"testing"

	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/internal/model"
)

// Every stateful rotation series exists at zero before the first dispatch, so increase()
// and rate() see that dispatch.
func TestInitStatefulRotationCreatesZeroSeries(t *testing.T) {
	InitStatefulRotation([]string{"init-a", "init-b"})

	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	counters, histograms := map[string]bool{}, map[string]bool{}
	for _, family := range families {
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			switch family.GetName() {
			case "phorvex_stateful_rotations_total":
				if (labels["namespace"] == "init-a" || labels["namespace"] == "init-b") && metric.GetCounter().GetValue() == 0 {
					counters[labels["namespace"]+"/"+labels["action"]+"/"+labels["outcome"]] = true
				}
			case "phorvex_stateful_rotation_recovery_seconds":
				histograms[labels["action"]] = true
			}
		}
	}
	for _, namespace := range []string{"init-a", "init-b"} {
		for _, action := range model.StatefulRotationActions {
			for _, outcome := range statefulRotationOutcomes {
				if !counters[namespace+"/"+string(action)+"/"+string(outcome)] {
					t.Errorf("missing zero series %s/%s/%s", namespace, action, outcome)
				}
			}
		}
	}
	for _, action := range model.StatefulRotationActions {
		if !histograms[string(action)] {
			t.Errorf("missing recovery histogram for %s", action)
		}
	}
	if len(statefulRotationOutcomes) != 5 {
		t.Fatalf("outcomes = %v", statefulRotationOutcomes)
	}
}
