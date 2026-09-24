package console

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsedCatalogueGuidanceSurvivesCompatProjection(t *testing.T) {
	rows := []struct {
		label    string
		line     string
		name     string
		basis    string
		wantHint bool
	}{
		{"current-credential", "  - c1-credtheft-rbac [ClassicChain] R6=R6CannotRespond realism=executable-mechanism benign=false declared=[T1528] exercised=[] caps=[]", "c1-credtheft-rbac", "name-heuristic", true},
		{"legacy-credential", "  - c1-credtheft-rbac [ClassicChain] R6=R6CannotRespond techniques=[T1528] caps=[]", "c1-credtheft-rbac", "name-heuristic", true},
		{"benign-control", "  - c2-voice-websocket-continuity [Application] R6=R6Partial realism=executable-mechanism benign=true declared=[] exercised=[] caps=[]", "c2-voice-websocket-continuity", "none", false},
	}
	for _, tc := range rows {
		t.Run(tc.label, func(t *testing.T) {
			items := parseCatalog([]byte("Registered scenarios:\n"+tc.line+"\n"), nil)
			if len(items) != 1 {
				t.Fatalf("parsed items=%d", len(items))
			}
			item := items[0]
			if item.Name != tc.name || item.ResponseGuidanceBasis != tc.basis || (len(item.ExpectedActuators) > 0) != tc.wantHint {
				t.Fatalf("parsed guidance=%+v", item)
			}
			projection := catalogueCompatProjection(item, true, "stack supports this scenario")
			body, err := json.Marshal(projection)
			if err != nil {
				t.Fatal(err)
			}
			var api map[string]any
			if err := json.Unmarshal(body, &api); err != nil {
				t.Fatal(err)
			}
			if api["responseGuidanceBasis"] != tc.basis || api["responseGuidance"] != item.ResponseGuidance {
				t.Fatalf("compat guidance lost: %s", body)
			}
			apiHints, ok := api["expectedActuators"].([]any)
			if !ok || len(apiHints) != len(item.ExpectedActuators) {
				t.Fatalf("compat actuator hints lost: %s", body)
			}
			if tc.name == "c1-credtheft-rbac" {
				if len(apiHints) != 1 || apiHints[0] != "rotate" {
					t.Fatalf("off-Pod credential replay offered unrelated API actuator: %v", apiHints)
				}
				for _, bound := range []string{"Pod-bound", "off-Pod bearer", "No automatic detector", "initial disclosure persists"} {
					if !strings.Contains(item.ResponseGuidance, bound) {
						t.Errorf("missing credential boundary %q", bound)
					}
				}
				if strings.Contains(item.MeaningfulWhen, "invalidates the foothold") {
					t.Fatal("credential case inherited a foothold guarantee")
				}
			} else if len(item.ExpectedActuators) != 0 {
				t.Fatal("benign control received actuator hint")
			}
		})
	}
}

func TestLimitedV1EffectGuidanceIsExplicitAndBounded(t *testing.T) {
	items := (Config{}).limitedV1Catalogue()
	for _, item := range items {
		if item.EntryID == limitedV1GuardrailID {
			if item.ResponseGuidanceBasis != "explicit-effect" || len(item.ExpectedActuators) != 1 || item.ExpectedActuators[0] != "guardrail-rotate" || !strings.Contains(item.ResponseGuidance, "does not establish behavioral bypass or mitigation") {
				t.Fatalf("guardrail guidance=%+v", item)
			}
			return
		}
		if item.ResponseGuidanceBasis != "none" || len(item.ExpectedActuators) != 0 {
			t.Fatalf("functional guidance=%+v", item)
		}
	}
	t.Fatal("limited V1 guardrail item missing")
}
