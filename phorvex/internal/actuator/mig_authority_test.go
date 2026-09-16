package actuator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/podresources"
)

const testInventory = `GPU 0: NVIDIA A100 (UUID: GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)
  MIG 1g.10gb Device 0: (UUID: MIG-11111111-2222-3333-4444-555555555555)
  MIG 1g.10gb Device 1: (UUID: MIG-GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/2/0)
GPU 1: NVIDIA A100 (UUID: GPU-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee)
  MIG 1g.10gb Device 0: (UUID: MIG-99999999-2222-3333-4444-555555555555)
`

func authorityFixture(t *testing.T) (map[string]string, map[string]struct{}, migAllocationTarget, MIGProfileRule) {
	t.Helper()
	migs, gpus, err := parseNVIDIAInventory(testInventory)
	if err != nil {
		t.Fatal(err)
	}
	return migs, gpus,
		migAllocationTarget{Namespace: "tenant", Pod: "target", UID: "uid-a", Node: "gpu-a", Resource: "nvidia.com/mig-1g.10gb"},
		MIGProfileRule{Namespace: "tenant", Resource: "nvidia.com/mig-1g.10gb", Profile: "2g.20gb"}
}

func TestBindAllocationPositiveAndConflicts(t *testing.T) {
	migs, gpus, target, rule := authorityFixture(t)
	base := podresources.Snapshot{Version: 1, Allocations: []podresources.Allocation{{Namespace: "tenant", Pod: "target", Container: "model", Resource: target.Resource, DeviceIDs: []string{"MIG-11111111-2222-3333-4444-555555555555"}}}}
	b, err := bindAllocation(base, migs, gpus, target, rule)
	if err != nil {
		t.Fatal(err)
	}
	if b.GPUUUID != "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" || b.PodUID != "uid-a" || b.TargetProfile != "2g.20gb" {
		t.Fatalf("wrong binding: %#v", b)
	}

	tests := map[string]podresources.Allocation{
		"same-node foreign slice":  {Namespace: "other", Pod: "foreign", Container: "model", Resource: target.Resource, DeviceIDs: []string{"MIG-GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/2/0"}},
		"same-node whole GPU":      {Namespace: "other", Pod: "foreign", Container: "model", Resource: nvidiaGPUResource, DeviceIDs: []string{"GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}},
		"unknown GPU allocation":   {Namespace: "other", Pod: "foreign", Container: "model", Resource: target.Resource, DeviceIDs: []string{"MIG-unknown"}},
		"unsupported NVIDIA alias": {Namespace: "other", Pod: "foreign", Container: "model", Resource: "nvidia.com/gpu.shared", DeviceIDs: []string{"GPU-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"}},
		"extra target GPU":         {Namespace: "tenant", Pod: "target", Container: "sidecar", Resource: nvidiaGPUResource, DeviceIDs: []string{"GPU-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"}},
		"duplicate device tuple":   {Namespace: "other", Pod: "foreign", Container: "model", Resource: target.Resource, DeviceIDs: []string{"MIG-11111111-2222-3333-4444-555555555555"}},
	}
	for name, conflict := range tests {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Allocations = append(append([]podresources.Allocation(nil), base.Allocations...), conflict)
			if _, err := bindAllocation(s, migs, gpus, target, rule); err == nil {
				t.Fatal("conflicting allocation accepted")
			}
		})
	}
}

func TestBindAllocationRejectsAmbiguousTarget(t *testing.T) {
	migs, gpus, target, rule := authorityFixture(t)
	for name, allocations := range map[string][]podresources.Allocation{
		"missing":             nil,
		"multiple devices":    {{Namespace: "tenant", Pod: "target", Container: "model", Resource: target.Resource, DeviceIDs: []string{"MIG-11111111-2222-3333-4444-555555555555", "MIG-GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/2/0"}}},
		"multiple containers": {{Namespace: "tenant", Pod: "target", Container: "a", Resource: target.Resource, DeviceIDs: []string{"MIG-11111111-2222-3333-4444-555555555555"}}, {Namespace: "tenant", Pod: "target", Container: "b", Resource: target.Resource, DeviceIDs: []string{"MIG-GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/2/0"}}},
		"index device":        {{Namespace: "tenant", Pod: "target", Container: "model", Resource: target.Resource, DeviceIDs: []string{"0"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := bindAllocation(podresources.Snapshot{Version: 1, Allocations: allocations}, migs, gpus, target, rule); err == nil {
				t.Fatal("ambiguous target accepted")
			}
		})
	}
}

func TestInventoryRejectsUntrustedOrAmbiguousRows(t *testing.T) {
	for _, inventory := range []string{"GPU 0: NVIDIA A100 (UUID: GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)\nmalformed", "  MIG 1g Device 0: (UUID: MIG-abc)", "GPU 0: A (UUID: GPU-aaaaaaaa)\nGPU 1: B (UUID: GPU-aaaaaaaa)"} {
		if _, _, err := parseNVIDIAInventory(inventory); err == nil {
			t.Fatalf("accepted %q", inventory)
		}
	}
}

func TestRevalidateAllocationRejectsInventoryParentDriftAfterRelease(t *testing.T) {
	binding := migAllocationBinding{
		Version: 1, Namespace: "tenant", Pod: "target", PodUID: "uid-a", Node: "gpu-a", Container: "model",
		Resource: "nvidia.com/mig-1g.10gb", DeviceID: "MIG-11111111-2222-3333-4444-555555555555",
		GPUUUID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ProfileRule: "tenant/nvidia.com/mig-1g.10gb", TargetProfile: "2g.20gb", SnapshotVersion: 1, SnapshotDigest: strings.Repeat("a", 64),
	}
	r := &authorityPreparedRunner{
		snapshot: podresources.Snapshot{Version: podresources.Version, Allocations: []podresources.Allocation{}},
		inventory: `GPU 0: NVIDIA A100 (UUID: GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)
GPU 1: NVIDIA A100 (UUID: GPU-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee)
  MIG 1g.10gb Device 0: (UUID: MIG-11111111-2222-3333-4444-555555555555)
`,
	}
	if err := (&preparedNVIDIASMIMIG{run: r}).RevalidateAllocation(t.Context(), binding, false); err == nil || !strings.Contains(err.Error(), "changed physical parent") {
		t.Fatalf("inventory parent drift accepted: %v", err)
	}
}

type authorityPreparedRunner struct {
	snapshot  podresources.Snapshot
	inventory string
}

func (r *authorityPreparedRunner) Run(_ context.Context, argv ...string) (string, error) {
	if len(argv) == 2 && argv[0] == "nvidia-smi" && argv[1] == "-L" {
		return r.inventory, nil
	}
	return "", fmt.Errorf("unexpected command %v", argv)
}

func (r *authorityPreparedRunner) Allocations(context.Context) (podresources.Snapshot, error) {
	return r.snapshot, nil
}
