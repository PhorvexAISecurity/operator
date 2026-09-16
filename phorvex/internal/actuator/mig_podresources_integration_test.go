package actuator

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kubefake "k8s.io/client-go/kubernetes/fake"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/podresources"
)

type dynamicPodResourcesServer struct {
	podresourcesv1.UnimplementedPodResourcesListerServer
	list func() *podresourcesv1.ListPodResourcesResponse
}

func (s dynamicPodResourcesServer) List(context.Context, *podresourcesv1.ListPodResourcesRequest) (*podresourcesv1.ListPodResourcesResponse, error) {
	return s.list(), nil
}

func serveDynamicPodResources(t *testing.T, list func() *podresourcesv1.ListPodResourcesResponse) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "m83-pr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "kubelet.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	podresourcesv1.RegisterPodResourcesListerServer(server, dynamicPodResourcesServer{list: list})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		_ = os.Remove(socket)
	})
	return socket
}

func podResourcesResponse(allocations ...podresources.Allocation) *podresourcesv1.ListPodResourcesResponse {
	byPod := map[string]*podresourcesv1.PodResources{}
	order := make([]string, 0)
	for _, allocation := range allocations {
		key := allocation.Namespace + "\x00" + allocation.Pod
		pod := byPod[key]
		if pod == nil {
			pod = &podresourcesv1.PodResources{Name: allocation.Pod, Namespace: allocation.Namespace}
			byPod[key] = pod
			order = append(order, key)
		}
		var container *podresourcesv1.ContainerResources
		for _, existing := range pod.Containers {
			if existing.Name == allocation.Container {
				container = existing
				break
			}
		}
		if container == nil {
			container = &podresourcesv1.ContainerResources{Name: allocation.Container}
			pod.Containers = append(pod.Containers, container)
		}
		container.Devices = append(container.Devices, &podresourcesv1.ContainerDevices{
			ResourceName: allocation.Resource,
			DeviceIds:    append([]string(nil), allocation.DeviceIDs...),
		})
	}
	response := &podresourcesv1.ListPodResourcesResponse{}
	for _, key := range order {
		response.PodResources = append(response.PodResources, byPod[key])
	}
	return response
}

type migIntegrationExec struct {
	t           *testing.T
	socket      string
	helperPath  string
	helperCalls int
	configured  bool
	destructive [][]string
	mu          sync.Mutex
}

func (e *migIntegrationExec) run(ctx context.Context, _, _, container string, argv []string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if container == "allocation-helper" {
		want := []string{e.helperPath, "--socket", e.socket, "--timeout", "1s"}
		if !reflect.DeepEqual(argv, want) {
			return "", fmt.Errorf("unexpected helper argv: got %v want %v", argv, want)
		}
		e.helperCalls++
		snapshot, err := podresources.Read(ctx, e.socket, time.Second)
		if err != nil {
			return "", err
		}
		encoded, err := podresources.Encode(snapshot)
		return string(encoded), err
	}
	if container != "agent" {
		return "", fmt.Errorf("unexpected exec container %q", container)
	}
	command := strings.Join(argv, " ")
	switch {
	case len(argv) == 2 && argv[0] == "nvidia-smi" && argv[1] == "-L":
		return testInventory, nil
	case strings.Contains(command, "--query-gpu=uuid"):
		return testGPUUUID + "\n", nil
	case strings.HasSuffix(command, "-lgip"):
		return testProfiles, nil
	case strings.HasSuffix(command, "-lgi"):
		if e.configured {
			return oneGITable("|  0  MIG 2g.20gb  14  8  0:2  |"), nil
		}
		return testGI, nil
	case strings.HasSuffix(command, "-lci"):
		if e.configured {
			return oneCITable("|  0  8  MIG 2g.20gb  5  0  |"), nil
		}
		return testCI, nil
	case strings.Contains(command, " -dci"), strings.Contains(command, " -dgi"):
		e.destructive = append(e.destructive, append([]string(nil), argv...))
		return "", nil
	case strings.Contains(command, " -cgi 2g.20gb -C"):
		e.destructive = append(e.destructive, append([]string(nil), argv...))
		e.configured = true
		return "", nil
	default:
		return "", fmt.Errorf("unexpected GPU command %v", argv)
	}
}

func TestMIGHandlerUsesRealUnixPodResourcesHelperPath(t *testing.T) {
	pod := migPod("ns", "infer")
	pod.Spec.NodeName = "node-1"
	c := fakeC(pod)
	targetAllocation := podresources.Allocation{
		Namespace: pod.Namespace, Pod: pod.Name, Container: "model", Resource: "nvidia.com/mig-1g.10gb",
		DeviceIDs: []string{"MIG-11111111-2222-3333-4444-555555555555"},
	}
	socket := serveDynamicPodResources(t, func() *podresourcesv1.ListPodResourcesResponse {
		current := &corev1.Pod{}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), current); apierrors.IsNotFound(err) {
			return podResourcesResponse()
		}
		return podResourcesResponse(targetAllocation)
	})
	ds, agent := testAgentObjects("agent-a")
	policy := testAgentPolicy()
	policy.AllocationSocket = socket
	exec := &migIntegrationExec{t: t, socket: socket, helperPath: policy.AllocationHelper}
	runner := execNodeRunner{client: kubefake.NewSimpleClientset(ds, agent), exec: exec.run, policy: policy}

	result, err := (migRebindHandler{}).Enact(t.Context(), EnactCtx{
		Client: c, Reader: c, JournalNamespace: "operator", MIG: &nvidiaSMIMIG{run: runner},
		VLLM: &mockVLLM{}, MIGProfiles: testMIGProfiles(),
	}, boundReq(pod, model.ActionMIGRebind))
	if err != nil || !result.Emitted || result.MutationKind != "swap" {
		t.Fatalf("real producer/helper/handler result=%+v err=%v", result, err)
	}
	if exec.helperCalls < 5 {
		t.Fatalf("handler bypassed repeated production PodResources reads: calls=%d", exec.helperCalls)
	}
	if len(exec.destructive) != 3 {
		t.Fatalf("unexpected destructive transcript: %v", exec.destructive)
	}
	for _, command := range exec.destructive {
		if len(command) < 4 || command[3] != testGPUUUID {
			t.Fatalf("destructive command was not bound to allocated parent UUID: %v", command)
		}
	}
}

func TestMIGHandlerRealUnixPodResourcesNegativeControls(t *testing.T) {
	for _, tc := range []struct {
		name       string
		annotation string
		foreign    *podresources.Allocation
		want       string
	}{
		{
			name:    "foreign-sibling-slice",
			foreign: &podresources.Allocation{Namespace: "other", Pod: "sibling", Container: "model", Resource: "nvidia.com/mig-1g.10gb", DeviceIDs: []string{"MIG-GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/2/0"}},
			want:    "physical GPU",
		},
		{
			name:       "foreign-valid-tenant-assertion",
			annotation: "GPU-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee",
			want:       "conflicts with allocated device",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := migPod("ns", "infer")
			pod.Spec.NodeName = "node-1"
			if tc.annotation != "" {
				pod.Annotations[annoGPUID] = tc.annotation
			}
			c := fakeC(pod)
			allocations := []podresources.Allocation{{
				Namespace: pod.Namespace, Pod: pod.Name, Container: "model", Resource: "nvidia.com/mig-1g.10gb",
				DeviceIDs: []string{"MIG-11111111-2222-3333-4444-555555555555"},
			}}
			if tc.foreign != nil {
				allocations = append(allocations, *tc.foreign)
			}
			socket := serveDynamicPodResources(t, func() *podresourcesv1.ListPodResourcesResponse {
				return podResourcesResponse(allocations...)
			})
			ds, agent := testAgentObjects("agent-a")
			policy := testAgentPolicy()
			policy.AllocationSocket = socket
			exec := &migIntegrationExec{t: t, socket: socket, helperPath: policy.AllocationHelper}
			runner := execNodeRunner{client: kubefake.NewSimpleClientset(ds, agent), exec: exec.run, policy: policy}
			result, err := (migRebindHandler{}).Enact(t.Context(), EnactCtx{
				Client: c, Reader: c, JournalNamespace: "operator", MIG: &nvidiaSMIMIG{run: runner},
				VLLM: &mockVLLM{}, MIGProfiles: testMIGProfiles(),
			}, boundReq(pod, model.ActionMIGRebind))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("negative control result=%+v err=%v", result, err)
			}
			if result.Emitted || len(exec.destructive) != 0 || exec.helperCalls == 0 {
				t.Fatalf("refusal crossed effect boundary or bypassed helper: result=%+v helper=%d destructive=%v", result, exec.helperCalls, exec.destructive)
			}
		})
	}
}
