package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

func TestM99OutcomeIngestPreservesRawUntrustedInventory(t *testing.T) {
	trustEvents(t, trustedSA)
	scheme := runtime.NewScheme()
	_ = amtdv1beta1.AddToScheme(scheme)
	trusted := seEvent("trusted", trustedSA, "detector", "ns/p")
	forged := seEvent("forged", untrustedSA, "TrustedDetector", "ns/p")
	broken := seEvent("broken", trustedSA, "detector", "ns/p")
	r := model.ProtectedOutcome{ID: "r", LossState: "unknown", RequiredKeys: []string{"audit-only"}}
	raw, _ := json.Marshal([]model.ProtectedOutcome{r})
	trusted.Annotations["phorvex.ai/protected-outcomes-v1"] = string(raw)
	forged.Annotations["phorvex.ai/protected-outcomes-v1"] = string(raw)
	broken.Annotations["phorvex.ai/protected-outcomes-v1"] = "[broken"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(trusted, forged, broken).Build()
	all, byPod, err := collectEvents(context.Background(), c, time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || len(byPod["ns/p"]) != 2 {
		t.Fatalf("inventory=%d belief=%d", len(all), len(byPod["ns/p"]))
	}
	for _, ev := range all {
		switch ev.Name {
		case "trusted", "forged":
			if len(ev.Outcomes) != 1 || ev.Outcomes[0].RequiredKeys[0] != "audit-only" {
				t.Fatal("raw outcome dropped")
			}
		case "broken":
			if ev.OutcomeParseError == "" {
				t.Fatal("malformed outcome silently ignored")
			}
		}
	}
}
