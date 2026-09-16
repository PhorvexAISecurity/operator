package podresources

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
)

type testServer struct {
	podresourcesv1.UnimplementedPodResourcesListerServer
	response *podresourcesv1.ListPodResourcesResponse
}

type blockingTestServer struct {
	podresourcesv1.UnimplementedPodResourcesListerServer
}

func (blockingTestServer) List(ctx context.Context, _ *podresourcesv1.ListPodResourcesRequest) (*podresourcesv1.ListPodResourcesResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s testServer) List(context.Context, *podresourcesv1.ListPodResourcesRequest) (*podresourcesv1.ListPodResourcesResponse, error) {
	return s.response, nil
}

func serveTestSocket(t *testing.T, response *podresourcesv1.ListPodResourcesResponse) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "podres-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "kubelet.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	podresourcesv1.RegisterPodResourcesListerServer(s, testServer{response: response})
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)
	return socket
}

func TestReadRealUnixGRPCProducer(t *testing.T) {
	socket := serveTestSocket(t, &podresourcesv1.ListPodResourcesResponse{PodResources: []*podresourcesv1.PodResources{{
		Name: "target", Namespace: "tenant", Containers: []*podresourcesv1.ContainerResources{{Name: "model", Devices: []*podresourcesv1.ContainerDevices{{ResourceName: "nvidia.com/mig-1g.10gb", DeviceIds: []string{"MIG-abc"}}}}},
	}}})
	s, err := Read(t.Context(), socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Allocations) != 1 || s.Allocations[0].DeviceIDs[0] != "MIG-abc" {
		t.Fatalf("unexpected snapshot: %#v", s)
	}
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decode(b); err != nil || len(got.Allocations) != 1 {
		t.Fatalf("round trip: %#v %v", got, err)
	}
}

func TestReadRejectsUnavailableMalformedAndOversized(t *testing.T) {
	if _, err := Read(t.Context(), filepath.Join(t.TempDir(), "absent.sock"), 20*time.Millisecond); err == nil {
		t.Fatal("unavailable socket accepted")
	}
	bad := serveTestSocket(t, &podresourcesv1.ListPodResourcesResponse{PodResources: []*podresourcesv1.PodResources{{Name: "", Namespace: "tenant"}}})
	if _, err := Read(t.Context(), bad, time.Second); err == nil {
		t.Fatal("malformed producer response accepted")
	}
	largeID := "MIG-" + strings.Repeat("a", MaxWireBytes)
	large := serveTestSocket(t, &podresourcesv1.ListPodResourcesResponse{PodResources: []*podresourcesv1.PodResources{{
		Name: "p", Namespace: "n", Containers: []*podresourcesv1.ContainerResources{{
			Name: "c", Devices: []*podresourcesv1.ContainerDevices{{ResourceName: "nvidia.com/mig-1g.10gb", DeviceIds: []string{largeID}}},
		}},
	}}})
	if _, err := Read(t.Context(), large, time.Second); err == nil {
		t.Fatal("oversized producer response accepted")
	}
	if _, err := Decode(append([]byte(`{"version":1}`), make([]byte, MaxWireBytes)...)); err == nil {
		t.Fatal("oversized helper response accepted")
	}
	for _, raw := range []string{`{"version":1,"allocations":[]} ]`, `{"version":1,"allocations":[]} }`, `{"version":1,"allocations":[]} {}`} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatalf("trailing delimiter accepted: %q", raw)
		}
	}
	for _, raw := range []string{
		`{"version":1,"version":1,"allocations":[]}`,
		`{"version":1,"allocations":[{"namespace":"n","pod":"p","container":"c","resource":"r","deviceIDs":["a","a"]}]}`,
		`{"version":1,"allocations":[{"namespace":"n","pod":"p","container":"c","resource":"r","deviceIDs":["a"]},{"namespace":"n","pod":"p","container":"c","resource":"r","deviceIDs":["b"]}]}`,
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatalf("duplicate evidence accepted: %s", raw)
		}
	}
}

func TestReadEnforcesDeadlineAndReconnectsAfterSocketReplacement(t *testing.T) {
	dir, err := os.MkdirTemp("", "podres-replace-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "kubelet.sock")

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	blocked := grpc.NewServer()
	podresourcesv1.RegisterPodResourcesListerServer(blocked, blockingTestServer{})
	go func() { _ = blocked.Serve(listener) }()
	if _, err := Read(t.Context(), socket, 20*time.Millisecond); err == nil {
		blocked.Stop()
		_ = listener.Close()
		t.Fatal("producer deadline was not enforced")
	}
	blocked.Stop()
	_ = listener.Close()
	_ = os.Remove(socket)

	listener, err = net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	replacement := grpc.NewServer()
	podresourcesv1.RegisterPodResourcesListerServer(replacement, testServer{response: &podresourcesv1.ListPodResourcesResponse{PodResources: []*podresourcesv1.PodResources{{
		Name: "replacement", Namespace: "tenant", Containers: []*podresourcesv1.ContainerResources{{Name: "model", Devices: []*podresourcesv1.ContainerDevices{{ResourceName: "nvidia.com/mig-1g.10gb", DeviceIds: []string{"MIG-replacement"}}}}},
	}}}})
	go func() { _ = replacement.Serve(listener) }()
	t.Cleanup(func() {
		replacement.Stop()
		_ = listener.Close()
	})
	snapshot, err := Read(t.Context(), socket, time.Second)
	if err != nil || len(snapshot.Allocations) != 1 || snapshot.Allocations[0].Pod != "replacement" {
		t.Fatalf("replacement socket was not observed: snapshot=%+v err=%v", snapshot, err)
	}
}
