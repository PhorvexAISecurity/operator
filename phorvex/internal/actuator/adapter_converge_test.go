package actuator

import (
	"context"
	"fmt"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestAdapterRotateRefusesMarkerOnlyWhenServingAdapterAlreadyAbsent pins the old
// marker path's fail-closed migration: a Pod annotation alone may no longer
// authorize eviction. TestM071SameUIDEndpointDriftUsesOnlyAuthoritativeServingConfig
// covers the trusted-observation path when authoritative inventory reports that
// the adapter is already absent.
//
// A stale poison marker (phorvex.ai/lora-adapter=evil) once caused adapter-rotate
// to reach vLLM. The marker is now operational metadata only: without a trusted
// detector observation the handler refuses before the serving boundary, regardless
// of whether the serving stack would report that adapter absent.
func TestAdapterRotateRefusesMarkerOnlyWhenServingAdapterAlreadyAbsent(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelLoRAEnabled: "true"})
	pod.Annotations = map[string]string{annoLoRAAdapter: "evil"}
	c := fakeC(pod)

	absent := &mockVLLM{unloadErr: fmt.Errorf("%w: %q (HTTP 404)", errAdapterAbsent, "evil")}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: absent},
		Request{Namespace: "ns", Pod: "infer", Action: model.ActionAdapterRotate})
	if err != nil {
		t.Fatalf("marker-only refusal returned an error: %v", err)
	}
	if hr.Emitted {
		t.Error("tenant marker alone must not authorize adapter eviction")
	}
	if absent.unloadCalls != 0 {
		t.Fatalf("marker-only refusal reached serving boundary %d time(s)", absent.unloadCalls)
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
