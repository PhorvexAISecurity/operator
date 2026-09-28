package actuator

import (
	"context"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Both preparation and the final gate use the actual authenticated HTTP decoder.
// Change the producer only after the protected claim exists, reproducing work
// disappearing during Kubernetes preparation without any routing mutation.
type finalCapabilityBackend struct {
	*capacityHTTPBackend
	reads       int
	beforeFinal func()
}

func TestDrainV11FinalCapabilityPolicyDisabledDuringRead(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	backend := &finalCapabilityBackend{capacityHTTPBackend: capacityBackend(t, pod)}
	patches := 0
	controller.patchErr = func(*corev1.Pod) error { patches++; return nil }
	backend.beforeFinal = func() {
		policy := &v1alpha1.PhorvexPolicy{}
		if err := controller.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "policy"}, policy); err != nil {
			t.Fatal(err)
		}
		policy.Spec.Actions.Enabled = nil
		if err := controller.Update(context.Background(), policy); err != nil {
			t.Fatal(err)
		}
	}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
	current := getDrainPod(t, controller)
	if err == nil || !IsNoEffectRefusal(err) || result.Emitted || result.DrainOperation != nil || backend.reads != 2 || backend.creates != 0 || patches != 0 ||
		current.Labels[labelServing] != "true" || current.Labels[labelDrainEpoch] != "" || len(drainCapacityReceipts(t, controller)) != 0 {
		t.Fatalf("disabled policy during final read changed route: result=%+v pod=%v reads=%d creates=%d patches=%d err=%v", result, current.Labels, backend.reads, backend.creates, patches, err)
	}
}

func (b *finalCapabilityBackend) DrainV11Capability(ctx context.Context, ep servingEndpoint) (drainV11CapabilityResponse, error) {
	b.reads++
	if b.reads == 2 && b.beforeFinal != nil {
		b.beforeFinal()
	}
	return b.capacityHTTPBackend.DrainV11Capability(ctx, ep)
}

func TestDrainV11FinalCapabilityRefusesBeforePodMutation(t *testing.T) {
	for name, change := range map[string]func(*drainV11CapabilityResponse){
		"work-ended":          func(c *drainV11CapabilityResponse) { c.NextOperationGeneration = "" },
		"closed":              func(c *drainV11CapabilityResponse) { c.Admission = "CLOSED" },
		"generation-changed":  func(c *drainV11CapabilityResponse) { c.GenerationHighWater, c.NextOperationGeneration = "65", "66" },
		"incarnation-changed": func(c *drainV11CapabilityResponse) { c.IncarnationDigest = strings.Repeat("f", 64) },
		"engine-restarted":    func(c *drainV11CapabilityResponse) { c.EngineBootID = strings.Repeat("f", 32) },
		"source-changed":      func(c *drainV11CapabilityResponse) { c.ProxySource = "sha256:" + strings.Repeat("f", 64) },
		"wrong-pod":           func(c *drainV11CapabilityResponse) { c.PodUID = "another-pod" },
	} {
		t.Run(name, func(t *testing.T) {
			pod, _, _, controller := requestDrainFixture(t, "true")
			backend := &finalCapabilityBackend{capacityHTTPBackend: capacityBackend(t, pod)}
			patches := 0
			controller.patchErr = func(*corev1.Pod) error { patches++; return nil }
			backend.beforeFinal = func() {
				receipts := drainCapacityReceipts(t, controller)
				if len(receipts) != 1 || !strings.Contains(receipts[0].Data["receipt"], `"phase":"claimed"`) {
					t.Fatal("final read did not occur after the protected claim")
				}
				change(&backend.cap)
			}
			result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
			current := getDrainPod(t, controller)
			if err == nil || !IsNoEffectRefusal(err) || result.Emitted || result.DrainOperation != nil || backend.reads != 2 || backend.creates != 0 || patches != 0 ||
				current.Labels[labelServing] != "true" || current.Labels[labelDrainEpoch] != "" || len(drainCapacityReceipts(t, controller)) != 0 ||
				!strings.Contains(result.Note, "unavailable before routing mutation") {
				t.Fatalf("final unavailable capability mutated routing: result=%+v pod=%v reads=%d creates=%d patches=%d err=%v", result, current.Labels, backend.reads, backend.creates, patches, err)
			}
		})
	}
}

func TestDrainV11FinalCapabilityAvailableKeepsDispatchAndFailureAccounting(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	backend := &finalCapabilityBackend{capacityHTTPBackend: capacityBackend(t, pod)}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
	current := getDrainPod(t, controller)
	// The exact unchanged producer permits dispatch. Its existing precise capacity
	// refusal is still a mutation/failure, restored without abort or defense credit.
	if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.DrainOperation != nil || backend.reads < 2 || backend.creates != 1 ||
		current.Labels[labelServing] != "true" || current.Labels[labelDrainEpoch] == "" || len(drainCapacityReceipts(t, controller)) != 0 {
		t.Fatalf("available gate changed dispatch/refusal accounting: result=%+v pod=%v reads=%d creates=%d err=%v", result, current.Labels, backend.reads, backend.creates, err)
	}
}

func TestDrainV11FinalCapabilityCleanupFailureRetainsUntouchedClaim(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	backend := &finalCapabilityBackend{capacityHTTPBackend: capacityBackend(t, pod)}
	backend.beforeFinal = func() { backend.cap.NextOperationGeneration = "" }
	fault := &finishFaultClient{Client: controller, failOnce: true}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(fault, backend), requestDrainReq(pod))
	current := getDrainPod(t, controller)
	receipts := drainCapacityReceipts(t, controller)
	if err == nil || IsNoEffectRefusal(err) || result.Emitted || result.DrainOperation != nil || backend.creates != 0 ||
		current.Labels[labelServing] != "true" || current.Labels[labelDrainEpoch] != "" || len(receipts) != 1 ||
		!strings.Contains(receipts[0].Data["receipt"], `"phase":"claimed"`) || !strings.Contains(err.Error(), "cleanup unconfirmed") {
		t.Fatalf("uncertain cleanup lost untouched authority: result=%+v pod=%v receipts=%d creates=%d err=%v", result, current.Labels, len(receipts), backend.creates, err)
	}
}
