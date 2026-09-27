package console

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestScanGraphNodeKeepsPodUIDForDecisionJoin(t *testing.T) {
	cfg := Config{Exec: func(time.Duration, string, ...string) (string, error) {
		return "platform-adapter: eks-gpu\nnodes: 1   pods: 2\n" +
			"  NODE vllm/current blast=0.949 ai=1 uid=72e72077-8358-46d5-836c-f8472409c292\n" +
			"  NODE vllm/legacy blast=0.500 ai=0\n", nil
	}}
	result, err := cfg.Scan("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.GraphNodes) != 2 {
		t.Fatalf("graph nodes = %d, want 2", len(result.GraphNodes))
	}
	if result.GraphNodes[0].UID != "72e72077-8358-46d5-836c-f8472409c292" || result.GraphNodes[0].Blast != 0.949 {
		t.Fatalf("current node lost UID or blast: %+v", result.GraphNodes[0])
	}
	if result.GraphNodes[1].UID != "" {
		t.Fatalf("legacy scan invented a Pod UID: %+v", result.GraphNodes[1])
	}
	encoded, err := json.Marshal(result.GraphNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"uid":"72e72077-8358-46d5-836c-f8472409c292"`) {
		t.Fatalf("scan API omitted current Pod UID: %s", encoded)
	}
}
