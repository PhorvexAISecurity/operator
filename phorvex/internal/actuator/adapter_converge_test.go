package actuator

import (
	"context"
	"fmt"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestAdapterRotateConvergesWhenAdapterAlreadyAbsent pins the old marker path's
// fail-closed migration: a Pod annotation alone may no longer authorize eviction.
//
// A stale poison marker (phorvex.ai/lora-adapter=evil) named an adapter vLLM did not have.
// adapter-rotate treated the resulting 404 as a hard failure, so it never emitted and never
// cleared the marker — and because adapter-rotate outranks kv-reset on coverage, the brain
// re-selected it every tick forever, starving kv-reset on that pod and scoring every
// prefix-cache attack LANDED. An eviction whose target is already gone has SUCCEEDED.
func TestAdapterRotateConvergesWhenAdapterAlreadyAbsent(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelLoRAEnabled: "true"})
	pod.Annotations = map[string]string{annoLoRAAdapter: "evil"}
	c := fakeC(pod)

	absent := &mockVLLM{unloadErr: fmt.Errorf("%w: %q (HTTP 404)", errAdapterAbsent, "evil")}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: absent},
		Request{Namespace: "ns", Pod: "infer", Action: model.ActionAdapterRotate})
	if err != nil {
		t.Fatalf("an already-absent adapter is the goal state, not an error: %v", err)
	}
	if hr.Emitted {
		t.Error("tenant marker alone must not authorize adapter eviction")
	}

	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err != nil {
		t.Fatal(err)
	}
	// The operational annotation remains independent of detector evidence.
	if p.Annotations[annoLoRAAdapter] != "evil" {
		t.Error("operational adapter name was mutated by a refused dispatch")
	}
	// DETECTION: the attack watcher reads the epoch as an ANNOTATION, not a label.
	if p.Annotations["phorvex.ai/adapter-epoch"] != "" {
		t.Error("refused dispatch wrote an adapter epoch")
	}
}
