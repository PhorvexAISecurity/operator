package actuator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/podresources"
)

const (
	nvidiaGPUResource      = "nvidia.com/gpu"
	maxMIGInventoryBytes   = 1 << 20
	defaultAllocationWait  = 45 * time.Second
	allocationPollInterval = 250 * time.Millisecond
)

type migAllocationTarget struct {
	Namespace string
	Pod       string
	UID       string
	Node      string
	Resource  string
}

type migAllocationBinding struct {
	Version         int    `json:"version"`
	Namespace       string `json:"namespace"`
	Pod             string `json:"pod"`
	PodUID          string `json:"podUID"`
	Node            string `json:"node"`
	Container       string `json:"container"`
	Resource        string `json:"resource"`
	DeviceID        string `json:"deviceID"`
	GPUUUID         string `json:"gpuUUID"`
	ProfileRule     string `json:"profileRule"`
	TargetProfile   string `json:"targetProfile"`
	SnapshotVersion int    `json:"snapshotVersion"`
	SnapshotDigest  string `json:"snapshotDigest"`
}

func (b migAllocationBinding) valid() bool {
	return b.Version == 1 && b.Namespace != "" && b.Pod != "" && b.PodUID != "" && b.Node != "" && b.Container != "" &&
		isCanonicalMIGResource(b.Resource) && migDeviceIDPattern.MatchString(b.DeviceID) && gpuUUIDPattern.MatchString(b.GPUUUID) &&
		b.ProfileRule == b.Namespace+"/"+b.Resource && profilePattern.MatchString(b.TargetProfile) &&
		b.SnapshotVersion == podresources.Version && snapshotDigestPattern.MatchString(b.SnapshotDigest)
}

func isCanonicalMIGResource(resource string) bool {
	const prefix = "nvidia.com/mig-"
	return strings.HasPrefix(resource, prefix) && profilePattern.MatchString(strings.TrimPrefix(resource, prefix))
}

type migAllocationAuthority interface {
	BindAllocation(context.Context, migAllocationTarget, MIGProfileRule) (migAllocationBinding, error)
	RevalidateAllocation(context.Context, migAllocationBinding, bool) error
}

type allocationSnapshotReader interface {
	Allocations(context.Context) (podresources.Snapshot, error)
}

type allocationReleaseTimeoutReader interface{ allocationReleaseTimeout() time.Duration }

func allocationReleaseTimeout(m *preparedNVIDIASMIMIG) time.Duration {
	if r, ok := m.run.(allocationReleaseTimeoutReader); ok {
		return r.allocationReleaseTimeout()
	}
	return defaultAllocationWait
}

func (m *preparedNVIDIASMIMIG) allocationReleaseTimeout() time.Duration {
	return allocationReleaseTimeout(m)
}

var (
	errTargetAllocationPresent = errors.New("target allocation remains present")
	gpuInventoryLine           = regexp.MustCompile(`^GPU\s+[0-9]+:\s+.+\(UUID:\s*(GPU-[0-9A-Fa-f-]{8,})\)\s*$`)
	migInventoryLine           = regexp.MustCompile(`^\s+MIG\s+.+\(UUID:\s*(MIG-(?:GPU-)?[0-9A-Za-z_./-]+)\)\s*$`)
	migDeviceIDPattern         = regexp.MustCompile(`^MIG-(?:GPU-)?[0-9A-Za-z_./-]+$`)
	snapshotDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func parseNVIDIAInventory(out string) (map[string]string, map[string]struct{}, error) {
	if len(out) == 0 || len(out) > maxMIGInventoryBytes {
		return nil, nil, fmt.Errorf("nvidia-smi inventory size outside bounds")
	}
	migs := map[string]string{}
	gpus := map[string]struct{}{}
	current := ""
	for _, raw := range strings.Split(out, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if m := gpuInventoryLine.FindStringSubmatch(raw); m != nil {
			current = m[1]
			if _, exists := gpus[current]; exists {
				return nil, nil, fmt.Errorf("duplicate physical GPU UUID %q", current)
			}
			gpus[current] = struct{}{}
			continue
		}
		if m := migInventoryLine.FindStringSubmatch(raw); m != nil {
			if current == "" {
				return nil, nil, fmt.Errorf("MIG device appears before physical GPU")
			}
			if _, exists := migs[m[1]]; exists {
				return nil, nil, fmt.Errorf("duplicate MIG device UUID %q", m[1])
			}
			migs[m[1]] = current
			continue
		}
		return nil, nil, fmt.Errorf("unrecognized nvidia-smi inventory row")
	}
	if len(gpus) == 0 {
		return nil, nil, fmt.Errorf("nvidia-smi inventory contains no physical GPUs")
	}
	return migs, gpus, nil
}

func (m *preparedNVIDIASMIMIG) allocationEvidence(ctx context.Context) (podresources.Snapshot, map[string]string, map[string]struct{}, error) {
	r, ok := m.run.(allocationSnapshotReader)
	if !ok {
		return podresources.Snapshot{}, nil, nil, fmt.Errorf("trusted MIG agent has no PodResources reader")
	}
	s, err := r.Allocations(ctx)
	if err != nil {
		return podresources.Snapshot{}, nil, nil, err
	}
	out, err := m.run.Run(ctx, "nvidia-smi", "-L")
	if err != nil {
		return podresources.Snapshot{}, nil, nil, fmt.Errorf("read nvidia-smi inventory: %w", err)
	}
	migs, gpus, err := parseNVIDIAInventory(out)
	return s, migs, gpus, err
}

func bindAllocation(s podresources.Snapshot, migs map[string]string, gpus map[string]struct{}, target migAllocationTarget, rule MIGProfileRule) (migAllocationBinding, error) {
	if !isCanonicalMIGResource(target.Resource) {
		return migAllocationBinding{}, fmt.Errorf("target resource %q is not a canonical NVIDIA MIG resource", target.Resource)
	}
	if err := s.Validate(); err != nil {
		return migAllocationBinding{}, fmt.Errorf("invalid PodResources snapshot: %w", err)
	}
	wire, err := podresources.Encode(s)
	if err != nil {
		return migAllocationBinding{}, fmt.Errorf("encode PodResources snapshot binding: %w", err)
	}
	snapshotDigest := fmt.Sprintf("%x", sha256.Sum256(wire))
	var matches []podresources.Allocation
	for _, a := range s.Allocations {
		if a.Namespace == target.Namespace && a.Pod == target.Pod && strings.HasPrefix(a.Resource, "nvidia.com/") {
			if a.Resource != target.Resource {
				return migAllocationBinding{}, fmt.Errorf("target has an extra NVIDIA allocation in container %s resource %s", a.Container, a.Resource)
			}
			matches = append(matches, a)
		}
	}
	if len(matches) != 1 || len(matches[0].DeviceIDs) != 1 {
		return migAllocationBinding{}, fmt.Errorf("target allocation must contain exactly one container tuple and one MIG device; got %d tuples", len(matches))
	}
	id := matches[0].DeviceIDs[0]
	parent, ok := migs[id]
	if !ok {
		return migAllocationBinding{}, fmt.Errorf("allocated device %q is absent or ambiguous in nvidia-smi inventory", id)
	}
	assigned := map[string]string{}
	for _, a := range s.Allocations {
		for _, allocated := range a.DeviceIDs {
			allocationParent := ""
			switch {
			case strings.HasPrefix(a.Resource, "nvidia.com/mig-"):
				allocationParent = migs[allocated]
			case a.Resource == nvidiaGPUResource:
				if _, exists := gpus[allocated]; exists {
					allocationParent = allocated
				}
			case strings.HasPrefix(a.Resource, "nvidia.com/"):
				return migAllocationBinding{}, fmt.Errorf("unsupported NVIDIA allocation resource %q cannot prove physical GPU exclusivity", a.Resource)
			default:
				continue
			}
			owner := a.Namespace + "/" + a.Pod + "/" + a.Container + "/" + a.Resource
			if prior, exists := assigned[allocated]; exists {
				return migAllocationBinding{}, fmt.Errorf("device %q appears in multiple allocation tuples (%s and %s)", allocated, prior, owner)
			}
			assigned[allocated] = owner
			if allocationParent == "" {
				return migAllocationBinding{}, fmt.Errorf("GPU allocation %s/%s container %s has unknown device %q", a.Namespace, a.Pod, a.Container, allocated)
			}
			isTarget := a.Namespace == target.Namespace && a.Pod == target.Pod && a.Container == matches[0].Container && a.Resource == target.Resource && allocated == id
			if allocationParent == parent && !isTarget {
				return migAllocationBinding{}, fmt.Errorf("physical GPU %s is shared by %s/%s container %s", parent, a.Namespace, a.Pod, a.Container)
			}
		}
	}
	return migAllocationBinding{Version: 1, Namespace: target.Namespace, Pod: target.Pod, PodUID: target.UID, Node: target.Node, Container: matches[0].Container, Resource: target.Resource, DeviceID: id, GPUUUID: parent, ProfileRule: rule.Namespace + "/" + rule.Resource, TargetProfile: rule.Profile, SnapshotVersion: s.Version, SnapshotDigest: snapshotDigest}, nil
}

func (m *preparedNVIDIASMIMIG) BindAllocation(ctx context.Context, target migAllocationTarget, rule MIGProfileRule) (migAllocationBinding, error) {
	s, migs, gpus, err := m.allocationEvidence(ctx)
	if err != nil {
		return migAllocationBinding{}, err
	}
	b, err := bindAllocation(s, migs, gpus, target, rule)
	if err != nil {
		return migAllocationBinding{}, err
	}
	if !b.valid() {
		return migAllocationBinding{}, fmt.Errorf("derived MIG allocation binding is invalid")
	}
	return b, nil
}

func (m *preparedNVIDIASMIMIG) RevalidateAllocation(ctx context.Context, b migAllocationBinding, targetPresent bool) error {
	if !b.valid() {
		return fmt.Errorf("MIG allocation binding is invalid")
	}
	s, migs, gpus, err := m.allocationEvidence(ctx)
	if err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("invalid PodResources snapshot: %w", err)
	}
	// While the allocated MIG identity remains in inventory, it must keep mapping to
	// the physical GPU captured in the binding. After the first destroy step the MIG
	// identity can legitimately disappear, so absence is accepted only when the target
	// allocation is also expected to be absent.
	if parent, exists := migs[b.DeviceID]; exists && parent != b.GPUUUID {
		return fmt.Errorf("bound device %q changed physical parent from %s to %s", b.DeviceID, b.GPUUUID, parent)
	} else if targetPresent && !exists {
		return fmt.Errorf("bound device %q disappeared from nvidia-smi inventory", b.DeviceID)
	}
	seenTarget := false
	assigned := map[string]string{}
	for _, a := range s.Allocations {
		for _, id := range a.DeviceIDs {
			parent := ""
			if strings.HasPrefix(a.Resource, "nvidia.com/mig-") {
				parent = migs[id]
			} else if a.Resource == nvidiaGPUResource {
				if _, ok := gpus[id]; ok {
					parent = id
				}
			} else if strings.HasPrefix(a.Resource, "nvidia.com/") {
				return fmt.Errorf("unsupported NVIDIA allocation resource %q cannot prove physical GPU exclusivity", a.Resource)
			} else {
				continue
			}
			owner := a.Namespace + "/" + a.Pod + "/" + a.Container + "/" + a.Resource
			if prior, exists := assigned[id]; exists {
				return fmt.Errorf("device %q appears in multiple allocation tuples (%s and %s)", id, prior, owner)
			}
			assigned[id] = owner
			if parent == "" {
				return fmt.Errorf("GPU allocation has unknown device %q", id)
			}
			isTarget := a.Namespace == b.Namespace && a.Pod == b.Pod && a.Container == b.Container && a.Resource == b.Resource && id == b.DeviceID
			if isTarget {
				if parent != b.GPUUUID {
					return fmt.Errorf("target device %q changed physical parent from %s to %s", id, b.GPUUUID, parent)
				}
				seenTarget = true
			}
			if a.Namespace == b.Namespace && a.Pod == b.Pod && !isTarget {
				return fmt.Errorf("target pod name gained a different NVIDIA allocation")
			}
			if parent == b.GPUUUID && !isTarget {
				return fmt.Errorf("physical GPU %s gained a foreign allocation", b.GPUUUID)
			}
		}
	}
	if seenTarget != targetPresent {
		if seenTarget {
			return fmt.Errorf("%w: require released", errTargetAllocationPresent)
		}
		return fmt.Errorf("target allocation presence=%t, require %t", seenTarget, targetPresent)
	}
	return nil
}

func waitAllocationRelease(ctx context.Context, a migAllocationAuthority, b migAllocationBinding, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultAllocationWait
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		err := a.RevalidateAllocation(deadline, b, false)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errTargetAllocationPresent) {
			return err
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("wait for target allocation release: %w", deadline.Err())
		case <-time.After(allocationPollInterval):
		}
	}
}
