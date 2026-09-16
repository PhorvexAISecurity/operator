package actuator

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/podresources"
)

func TestMIGCapabilityUsesAuthoritativeNodeGroupedEvidence(t *testing.T) {
	pod := migPod("ns", "infer")
	scheme := newScheme(t)
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	ds, agent := testAgentObjects("agent-a")
	agent.Spec.NodeName = "node-a"
	clientset := kubefake.NewSimpleClientset(ds, agent)
	snapshot, err := podresources.Encode(podresources.Snapshot{Version: 1, Allocations: []podresources.Allocation{{Namespace: "ns", Pod: "infer", Container: "model", Resource: "nvidia.com/mig-1g.10gb", DeviceIDs: []string{"MIG-11111111-2222-3333-4444-555555555555"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	helperCalls, inventoryCalls := 0, 0
	exec := func(_ context.Context, _, _, container string, argv []string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if container == "allocation-helper" {
			helperCalls++
			return string(snapshot), nil
		}
		if len(argv) == 2 && argv[0] == "nvidia-smi" && argv[1] == "-L" {
			inventoryCalls++
			return testInventory, nil
		}
		return "", nil
	}
	old := pkgNodeRunner
	pkgNodeRunner = &execNodeRunner{client: clientset, exec: exec, policy: testAgentPolicy(), cache: &migObservationCache{allocations: map[string]cachedAllocations{}, inventories: map[string]cachedInventory{}}}
	t.Cleanup(func() { pkgNodeRunner = old })
	n := NewNativeActuator(c)
	n.Reader = c
	n.SetMIGProfiles(testMIGProfiles())
	target := Target{Namespace: "ns", Pod: "infer", UID: string(pod.UID), NodeName: "node-a", HasGPU: true, MIGResource: "nvidia.com/mig-1g.10gb"}
	for i := 0; i < 2; i++ {
		if ok, why := n.SupportsAction(t.Context(), model.ActionMIGRebind, target); !ok {
			t.Fatalf("probe %d: %s", i, why)
		}
	}
	if helperCalls != 1 || inventoryCalls != 1 {
		t.Fatalf("same-node evidence was not grouped: helper=%d inventory=%d", helperCalls, inventoryCalls)
	}
}

func TestMIGCapabilityRejectsStalePodUIDAndMissingProfile(t *testing.T) {
	pod := migPod("ns", "infer")
	scheme := newScheme(t)
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	n := NewNativeActuator(c)
	n.Reader = c
	n.SetMIGProfiles(testMIGProfiles())
	old := pkgNodeRunner
	pkgNodeRunner = &execNodeRunner{}
	t.Cleanup(func() { pkgNodeRunner = old })
	target := Target{Namespace: "ns", Pod: "infer", UID: "stale", NodeName: "node-a", MIGResource: "nvidia.com/mig-1g.10gb"}
	if ok, _ := n.SupportsAction(t.Context(), model.ActionMIGRebind, target); ok {
		t.Fatal("stale Pod UID admitted")
	}
	n.SetMIGProfiles(nil)
	target.UID = string(pod.UID)
	if ok, _ := n.SupportsAction(t.Context(), model.ActionMIGRebind, target); ok {
		t.Fatal("missing operator profile admitted")
	}
}

func TestMIGObservationCacheBoundsIdentityChurnAndPrunesExpired(t *testing.T) {
	cache := &migObservationCache{allocations: map[string]cachedAllocations{}, inventories: map[string]cachedInventory{}}
	snapshot := podresources.Snapshot{Version: podresources.Version, Allocations: []podresources.Allocation{{
		Namespace: "ns", Pod: "pod", Container: "model", Resource: "nvidia.com/mig-1g.10gb", DeviceIDs: []string{"MIG-device"},
	}}}
	for i := 0; i < maxMIGObservationCacheEntries+10; i++ {
		key := fmt.Sprintf("node\x00ds\x00agent-%d", i)
		cache.storeAllocation(key, snapshot)
		cache.storeInventory(key, testInventory)
	}
	if len(cache.allocations) != maxMIGObservationCacheEntries || len(cache.inventories) != maxMIGObservationCacheEntries {
		t.Fatalf("identity churn escaped cache bounds: allocations=%d inventories=%d", len(cache.allocations), len(cache.inventories))
	}
	cache.mu.Lock()
	for key, value := range cache.allocations {
		value.at = time.Now().Add(-2 * migObservationCacheTTL)
		cache.allocations[key] = value
	}
	for key, value := range cache.inventories {
		value.at = time.Now().Add(-2 * migObservationCacheTTL)
		cache.inventories[key] = value
	}
	cache.mu.Unlock()
	cache.storeAllocation("fresh", snapshot)
	cache.storeInventory("fresh", testInventory)
	if len(cache.allocations) != 1 || len(cache.inventories) != 1 {
		t.Fatalf("expired identities retained: allocations=%d inventories=%d", len(cache.allocations), len(cache.inventories))
	}
}
