// Package podresources reads the kubelet's node-local PodResources API through a
// fixed Unix socket and exposes a small, bounded wire format for the MIG agent.
package podresources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
)

const (
	Version        = 1
	MaxWireBytes   = 1 << 20
	MaxAllocations = 4096
	MaxDevices     = 256
	DefaultTimeout = 3 * time.Second
)

type Snapshot struct {
	Version     int          `json:"version"`
	Allocations []Allocation `json:"allocations"`
}

type Allocation struct {
	Namespace string   `json:"namespace"`
	Pod       string   `json:"pod"`
	Container string   `json:"container"`
	Resource  string   `json:"resource"`
	DeviceIDs []string `json:"deviceIDs"`
}

func (s Snapshot) Validate() error {
	if s.Version != Version {
		return fmt.Errorf("pod-resources snapshot version %d unsupported", s.Version)
	}
	if len(s.Allocations) > MaxAllocations {
		return fmt.Errorf("pod-resources allocation count %d exceeds %d", len(s.Allocations), MaxAllocations)
	}
	tuples := map[string]struct{}{}
	for i, a := range s.Allocations {
		if a.Namespace == "" || a.Pod == "" || a.Container == "" || a.Resource == "" {
			return fmt.Errorf("pod-resources allocation %d has a blank identity field", i)
		}
		if len(a.DeviceIDs) == 0 || len(a.DeviceIDs) > MaxDevices {
			return fmt.Errorf("pod-resources allocation %d has invalid device count %d", i, len(a.DeviceIDs))
		}
		tuple := a.Namespace + "\x00" + a.Pod + "\x00" + a.Container + "\x00" + a.Resource
		if _, exists := tuples[tuple]; exists {
			return fmt.Errorf("pod-resources allocation %d duplicates an allocation tuple", i)
		}
		tuples[tuple] = struct{}{}
		seen := map[string]struct{}{}
		for _, id := range a.DeviceIDs {
			if id != strings.TrimSpace(id) || id == "" || strings.ContainsAny(id, "\x00\r\n") {
				return fmt.Errorf("pod-resources allocation %d has invalid device ID", i)
			}
			if _, ok := seen[id]; ok {
				return fmt.Errorf("pod-resources allocation %d duplicates device ID %q", i, id)
			}
			seen[id] = struct{}{}
		}
	}
	return nil
}

func Encode(s Snapshot) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxWireBytes {
		return nil, fmt.Errorf("pod-resources snapshot is %d bytes; limit is %d", len(b), MaxWireBytes)
	}
	return b, nil
}

func Decode(b []byte) (Snapshot, error) {
	if len(b) == 0 || len(b) > MaxWireBytes {
		return Snapshot{}, fmt.Errorf("pod-resources response size %d is outside 1..%d", len(b), MaxWireBytes)
	}
	if err := rejectDuplicateJSONKeys(b); err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Snapshot{}, fmt.Errorf("decode pod-resources snapshot: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return Snapshot{}, fmt.Errorf("decode pod-resources snapshot: trailing JSON")
	}
	if err := s.Validate(); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

type jsonFrame struct {
	object    bool
	keys      map[string]struct{}
	expectKey bool
}

func rejectDuplicateJSONKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var stack []jsonFrame
	valueDone := func() {
		if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
			stack[len(stack)-1].expectKey = true
		}
	}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decode pod-resources snapshot: %w", err)
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, jsonFrame{object: true, keys: map[string]struct{}{}, expectKey: true})
			case '[':
				stack = append(stack, jsonFrame{})
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("decode pod-resources snapshot: unmatched delimiter")
				}
				stack = stack[:len(stack)-1]
				valueDone()
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				f := &stack[len(stack)-1]
				if _, exists := f.keys[v]; exists {
					return fmt.Errorf("decode pod-resources snapshot: duplicate JSON field %q", v)
				}
				f.keys[v] = struct{}{}
				f.expectKey = false
			} else {
				valueDone()
			}
		default:
			valueDone()
		}
	}
}

func Read(ctx context.Context, socket string, timeout time.Duration) (Snapshot, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return Snapshot{}, fmt.Errorf("pod-resources socket must be a clean absolute path")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return Snapshot{}, fmt.Errorf("pod-resources timeout must be positive and at most 30s")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "unix://"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxWireBytes)),
		grpc.WithBlock(),
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("connect pod-resources socket: %w", err)
	}
	defer conn.Close()
	resp, err := podresourcesv1.NewPodResourcesListerClient(conn).List(ctx, &podresourcesv1.ListPodResourcesRequest{})
	if err != nil {
		return Snapshot{}, fmt.Errorf("list pod resources: %w", err)
	}
	s := Snapshot{Version: Version}
	for _, p := range resp.PodResources {
		if p == nil || p.Namespace == "" || p.Name == "" {
			return Snapshot{}, fmt.Errorf("pod-resources producer returned an incomplete pod identity")
		}
		for _, c := range p.Containers {
			if c == nil || c.Name == "" {
				return Snapshot{}, fmt.Errorf("pod-resources producer returned an incomplete container identity")
			}
			for _, d := range c.Devices {
				if d == nil {
					return Snapshot{}, fmt.Errorf("pod-resources producer returned a nil device allocation")
				}
				s.Allocations = append(s.Allocations, Allocation{Namespace: p.Namespace, Pod: p.Name, Container: c.Name, Resource: d.ResourceName, DeviceIDs: append([]string(nil), d.DeviceIds...)})
				if len(s.Allocations) > MaxAllocations {
					return Snapshot{}, fmt.Errorf("pod-resources allocation count exceeds %d", MaxAllocations)
				}
			}
		}
	}
	sort.Slice(s.Allocations, func(i, j int) bool {
		a, b := s.Allocations[i], s.Allocations[j]
		return a.Namespace+"\x00"+a.Pod+"\x00"+a.Container+"\x00"+a.Resource < b.Namespace+"\x00"+b.Pod+"\x00"+b.Container+"\x00"+b.Resource
	})
	if err := s.Validate(); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}
