package console

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVLLMRecordBaselineUsesExactPodOwnerNotFirstDeployment(t *testing.T) {
	var pod vllmPodState
	if err := json.Unmarshal([]byte(`{"metadata":{"name":"vllm-0","uid":"pod-vllm","ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"vllm-rs","uid":"rs-vllm","controller":true}]}}`), &pod); err != nil {
		t.Fatal(err)
	}
	wrongFirstRead := false
	s := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", fmt.Errorf("unexpected binary %q", bin)
		}
		command := strings.Join(args, " ")
		switch command {
		case "-n vllm get replicaset vllm-rs -o json":
			return `{"metadata":{"namespace":"vllm","name":"vllm-rs","uid":"rs-vllm","resourceVersion":"2","ownerReferences":[{"apiVersion":"apps/v1","kind":"Deployment","name":"vllm","uid":"dep-vllm","controller":true}]}}`, nil
		case "-n vllm get deployment vllm -o json":
			return `{"metadata":{"namespace":"vllm","name":"vllm","uid":"dep-vllm","resourceVersion":"3"},"spec":{"replicas":2},"status":{"readyReplicas":2}}`, nil
		case "-n vllm get deploy -o name":
			wrongFirstRead = true
			return "deployment.apps/detector-adapter-inv\ndeployment.apps/vllm", nil
		default:
			return "", nil
		}
	}}}
	base := s.snapshotVLLMBaseline(pod)
	if wrongFirstRead || base.uid != "pod-vllm" || base.ownerKind != "Deployment" || base.deploy != "vllm" || base.ownerUID != "dep-vllm" || base.uptime != 100 {
		t.Fatalf("target owner/baseline misbound: %+v; namespace-first read=%v", base, wrongFirstRead)
	}
	pod.Metadata.OwnerReferences[0].UID = "foreign-rs"
	base = s.snapshotVLLMBaseline(pod)
	if wrongFirstRead || base.deploy != "" || base.ownerUID != "" || base.uptime != -1 {
		t.Fatalf("mismatched owner should leave availability unknown: %+v", base)
	}
}
