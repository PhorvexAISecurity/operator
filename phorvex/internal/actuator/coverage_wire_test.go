package actuator

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestM032RawCoverageWireAndExactMatcher(t *testing.T) {
	for _, value := range []float64{0, 0.125, 1, 2.25, 9.87654321012345, math.NaN(), math.Inf(1), -1} {
		t.Run(strconv.FormatFloat(value, 'g', -1, 64), func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
			_, err := NewPhoenixActuator(c).Actuate(context.Background(), Request{Namespace: "ns", Pod: "pod", TargetUID: "pod-uid", TargetNamespaceUID: "namespace-uid", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: model.ActionQuarantine, Score: 0.9, CoverageValue: &value})
			if err != nil {
				t.Fatal(err)
			}
			var list amtd.SecurityEventList
			if err = c.List(context.Background(), &list); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(list.Items[0])
			if err != nil {
				t.Fatal(err)
			}
			var ev amtd.SecurityEvent
			if err = json.Unmarshal(raw, &ev); err != nil {
				t.Fatal(err)
			}
			if ev.Spec.AnomalyScore != nil {
				t.Fatal("coverage leaked into anomaly score")
			}
			invalid := math.IsNaN(value) || math.IsInf(value, 0) || value < 0
			if invalid {
				if _, ok := ev.Spec.Metrics["coverageValue"]; ok {
					t.Fatal("invalid value serialized")
				}
				if ev.Annotations["phorvex.ai/coverage-status"] != "invalid-source-value" {
					t.Fatal("missing invalid diagnostic")
				}
			} else {
				got, err := strconv.ParseFloat(ev.Spec.Metrics["coverageValue"], 64)
				if err != nil || got != value {
					t.Fatalf("lost precision: %v -> %v (%v)", value, got, err)
				}
			}
			for _, strategy := range buildStrategies(nil) {
				if strategy.Rule.Type == amtdv1beta1.PhorvexRuleTypeQuarantine && !amtd.MatchStrategy(strategy.Rule, ev.Spec) {
					t.Fatal("generated strategy no longer matches")
				}
			}
			// The generated exact-match rule remains identical without an anomaly score.
			if ev.Spec.Rule.Type != amtdv1beta1.PhorvexRuleTypeQuarantine || ev.Spec.Rule.Source != amtdv1beta1.PhorvexRuleSource || ev.Spec.Rule.ThreatLevel != amtdv1beta1.PhorvexRuleThreatLevel {
				t.Fatal("action contract changed")
			}
		})
	}
}
