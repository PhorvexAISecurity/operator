package metrics

import (
	"testing"

	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestCostSafetyMetricsCarryMeasuredValues(t *testing.T) {
	RecordCostNaNUnactionable("metrics-test", "ns", "nan-pod", "rotate", "telemetry.reqRate")
	RecordRequestDrainAborted("metrics-test", "ns", "drain-pod", 7)

	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	foundNaN, foundDrain := false, false
	for _, family := range families {
		switch family.GetName() {
		case "phorvex_cost_nan_unactionable_total":
			for _, metric := range family.Metric {
				pod := ""
				for _, label := range metric.Label {
					if label.GetName() == "pod" {
						pod = label.GetValue()
					}
				}
				if pod == "nan-pod" && metric.GetCounter().GetValue() == 1 {
					foundNaN = true
				}
			}
		case "phorvex_request_drain_aborted_requests":
			for _, metric := range family.Metric {
				pod := ""
				for _, label := range metric.Label {
					if label.GetName() == "pod" {
						pod = label.GetValue()
					}
				}
				if pod == "drain-pod" &&
					metric.GetHistogram().GetSampleCount() == 1 &&
					metric.GetHistogram().GetSampleSum() == 7 {
					foundDrain = true
				}
			}
		}
	}
	if !foundNaN || !foundDrain {
		t.Fatalf("metric evidence missing: nan=%v requestDrain=%v", foundNaN, foundDrain)
	}
}
