package console

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestPodBoundTokenSignalIntentExactNamedRunRoute(t *testing.T) {
	const nonce = "60bf41c9878d9056727f1b15"
	const sourceUID = "95c1b8ab-ffd1-4f95-ba9e-c166c0f120c0"
	base := attackStimulusEvidence{
		Kind: "synthetic-catalogue-signal", TargetUID: sourceUID,
		EventName: "phorvex-e2e-" + nonce, EventRule: model.AttackVectorPodBoundAPIAuth,
		Correlation: nonce, Limitation: "private-secret-marker-must-not-persist",
	}
	for _, profile := range []string{podBoundTokenCPUConfig, podBoundTokenConfig} {
		t.Run(profile, func(t *testing.T) {
			s := &Server{cfg: Config{StateDir: t.TempDir()}}
			if err := s.persistCatalogueSignalIntent("/api/runs/start", "pod-bound-token", podBoundNamespace(profile), profile, sourceUID, &base); err != nil {
				t.Fatalf("actual named-run signal intent refused: %v", err)
			}
			raw, err := os.ReadFile(s.cfg.statePath("effect-intents.jsonl"))
			if err != nil || strings.Contains(string(raw), base.Limitation) {
				t.Fatalf("intent missing or private field persisted: %v", err)
			}
			var record catalogueSignalFailureRecord
			if err := json.Unmarshal(raw, &record); err != nil || record.Endpoint != "/api/runs/start" ||
				record.Scenario != profile || record.Namespace != podBoundNamespace(profile) ||
				record.TargetUID != sourceUID || record.EventName != base.EventName ||
				record.Correlation != nonce || record.Phase != "stimulus-create-intent" ||
				record.Mutated || record.EventUID != "" || record.Restoration != "pending-dispatch" {
				t.Fatalf("named-run pre-create lookup authority differs: %+v, err=%v", record, err)
			}
		})
	}
	for name, change := range map[string]func(*string, *string, *string, *string, *attackStimulusEvidence){
		"noncanonical route": func(route, _, _, _ *string, _ *attackStimulusEvidence) { *route = "/api/runs" },
		"other runs route":   func(route, _, _, _ *string, _ *attackStimulusEvidence) { *route = "/api/runs/scenario" },
		"unrelated route":    func(route, _, _, _ *string, _ *attackStimulusEvidence) { *route = "/api/policy/edit" },
		"other actor":        func(_, actor, _, _ *string, _ *attackStimulusEvidence) { *actor = "operator" },
		"wrong namespace":    func(_, _, namespace, _ *string, _ *attackStimulusEvidence) { *namespace = podBoundTokenNamespace },
		"other config":       func(_, _, _, scenario *string, _ *attackStimulusEvidence) { *scenario = natsResponseConfig },
		"other signal":       func(_, _, _, _ *string, candidate *attackStimulusEvidence) { candidate.EventRule = "quarantine" },
		"other kind":         func(_, _, _, _ *string, candidate *attackStimulusEvidence) { candidate.Kind = "natural" },
		"changed name":       func(_, _, _, _ *string, candidate *attackStimulusEvidence) { candidate.EventName = "foreign" },
		"bad nonce":          func(_, _, _, _ *string, candidate *attackStimulusEvidence) { candidate.Correlation = "not-a-nonce" },
		"observed effect":    func(_, _, _, _ *string, candidate *attackStimulusEvidence) { candidate.Observed = true },
		"event UID present":  func(_, _, _, _ *string, candidate *attackStimulusEvidence) { candidate.EventUID = "already-created" },
	} {
		t.Run(name, func(t *testing.T) {
			s := &Server{cfg: Config{StateDir: t.TempDir()}}
			route, actor, namespace, scenario := "/api/runs/start", "pod-bound-token", podBoundTokenCPUNamespace, podBoundTokenCPUConfig
			candidate := base
			change(&route, &actor, &namespace, &scenario, &candidate)
			if err := s.persistCatalogueSignalIntent(route, actor, namespace, scenario, sourceUID, &candidate); err == nil {
				t.Fatal("unrelated or ambiguous named-run intent accepted")
			}
			if _, err := os.Stat(s.cfg.statePath("effect-intents.jsonl")); !os.IsNotExist(err) {
				t.Fatalf("rejected intent still persisted: %v", err)
			}
		})
	}
}
