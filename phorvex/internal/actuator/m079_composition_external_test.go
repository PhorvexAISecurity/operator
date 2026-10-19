package actuator_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/podresources"
)

const (
	m079ScenarioEnv = "PHORVEX_M079_COMPOSITION_SCENARIO"
	m079GPUUUID     = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	m079MIGUUID     = "MIG-11111111-2222-3333-4444-555555555555"
	m079Resource    = "nvidia.com/mig-1g.10gb"
)

const m079EnabledValues = `
phorvex:
  actuator: native
  servingSecurity:
    mode: legacy-plaintext
  mig:
    profiles:
      content: |
        {"version":1,"rules":[{"namespace":"tenant","resource":"nvidia.com/mig-1g.10gb","profile":"2g.20gb"}]}
    nodeExec:
      enabled: true
      exclusiveMaintenance: true
      namespace: gpu-system
      daemonSetName: phorvex-mig-agent
      serviceAccountName: phorvex-mig-agent
      gpuContainer: gpu-tools
      helperContainer: allocation-helper
      gpuImage:
        repository: vendor.example/gpu-tools
        digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      gpuCommand: ["/gpu-agent"]
      allocationHelperPath: /phorvex-mig-allocation-helper
      podResourcesMountPath: /var/lib/kubelet/pod-resources
      execTimeout: 5s
      allocationReadTimeout: 3s
      allocationReleaseTimeout: 45s
`

// The subprocesses make the package-global node transport start from a new process
// for each default/opt-in control. The opt-in path scripts only remotecommand streams;
// chart rendering, profile loading, Kubernetes discovery, PodResources gRPC decoding,
// capability predicates, handler dispatch, receipt creation, and Pod update are real.
func TestM079RenderedDefaultAndOptInComposition(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires pinned local envtest API-server binaries")
	}
	for _, scenario := range []string{"default", "enabled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestM079CompositionWorker$", "-test.v")
			cmd.Env = append(os.Environ(), m079ScenarioEnv+"="+scenario)
			out, err := cmd.CombinedOutput()
			if err != nil {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Fatalf("scenario %s exceeded 90s deadline:\n%s", scenario, out)
				}
				t.Fatalf("scenario %s: %v\n%s", scenario, err, out)
			}
			if !strings.Contains(string(out), "--- PASS: TestM079CompositionWorker") {
				t.Fatalf("scenario %s did not execute worker:\n%s", scenario, out)
			}
		})
	}
}

func TestM079CompositionWorker(t *testing.T) {
	switch os.Getenv(m079ScenarioEnv) {
	case "":
		return
	case "default":
		m079DefaultComposition(t)
	case "enabled":
		m079EnabledComposition(t)
	default:
		t.Fatal("unknown composition scenario")
	}
}

func m079DefaultComposition(t *testing.T) {
	rendered := actuator.M079RenderChartForTest(t, "{}\n")
	args, _, _ := m079RenderedMIG(t, rendered)
	for _, arg := range args {
		if strings.HasPrefix(arg, "--mig-node-exec") || strings.HasPrefix(arg, "--mig-agent-") {
			t.Fatalf("default chart rendered trusted-node argument %q", arg)
		}
	}
	security, err := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	if err != nil {
		t.Fatal(err)
	}
	native := actuator.NewNativeActuator(nil)
	native.SetServingSecurity(security)
	target := actuator.Target{Namespace: "tenant", Pod: "model", UID: "target-uid", NodeName: "node-1", HasGPU: true, MIGResource: m079Resource}
	if ok, why := native.SupportsAction(t.Context(), model.ActionMIGRebind, target); ok || why != actuator.ReasonTransportUnwired {
		t.Fatalf("default direct capability ok=%v why=%q", ok, why)
	}
	view := m079View()
	witness := capability.BuildWitness(t.Context(), capability.BuildIndex(nil, nil, nil), nil, nil, localActuator(native))
	if ok, why := witness.Capable(view, model.ActionMIGRebind); ok || why != actuator.ReasonTransportUnwired {
		t.Fatalf("default witness capability ok=%v why=%q", ok, why)
	}
	reason := witness.Eligible(view, model.ActionMIGRebind, []string{"gpu-contention"})
	if reason == nil || !reason.Excluded || reason.Kind != capability.ReasonCapability || reason.Detail != actuator.ReasonTransportUnwired {
		t.Fatalf("default generator verdict=%+v", reason)
	}
}

func m079EnabledComposition(t *testing.T) {
	rendered := actuator.M079RenderChartForTest(t, m079EnabledValues)
	args, profileJSON, renderedDS := m079RenderedMIG(t, rendered)
	arg := m079ArgMap(args)
	wantArgs := map[string]string{
		"--mig-node-exec":                  "true",
		"--mig-agent-namespace":            "gpu-system",
		"--mig-agent-service-accounts":     "phorvex-mig-agent",
		"--mig-agent-daemonset":            "phorvex-mig-agent",
		"--mig-agent-gpu-container":        "gpu-tools",
		"--mig-agent-helper-container":     "allocation-helper",
		"--mig-allocation-helper":          "/phorvex-mig-allocation-helper",
		"--mig-allocation-socket":          "/var/lib/kubelet/pod-resources/kubelet.sock",
		"--mig-agent-exec-timeout":         "5s",
		"--mig-allocation-read-timeout":    "3s",
		"--mig-allocation-release-timeout": "45s",
		"--mig-exclusive-maintenance":      "true",
		"--mig-profiles-file":              "/etc/phorvex-mig/profiles.json",
	}
	for key, want := range wantArgs {
		if got := arg[key]; got != want {
			t.Fatalf("rendered %s=%q, want %q", key, got, want)
		}
	}
	profilePath := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	profiles, err := actuator.LoadMIGProfilesFile(profilePath)
	if err != nil {
		t.Fatalf("load rendered exact profile: %v", err)
	}

	restConfig, clientset, targetPod, phorvexPolicy, apiClient, agent := m079APIObjects(t, &renderedDS)
	socket := m079ServePodResources(t)
	recorder := &m079RemoteRecorder{socket: socket}
	policy := actuator.MIGAgentPolicy{
		Namespace: "gpu-system", ServiceAccounts: []string{"phorvex-mig-agent"}, DaemonSet: "phorvex-mig-agent",
		Container: "gpu-tools", AllocationContainer: "allocation-helper", AllocationHelper: "/phorvex-mig-allocation-helper",
		AllocationSocket: socket, ExecTimeout: 5 * time.Second, AllocationReadTimeout: 3 * time.Second,
		AllocationReleaseTimeout: 45 * time.Second, ExclusiveMaintenance: true,
	}
	restore, err := actuator.M079WireRemoteNodeExecForTest(actuator.RemoteExecConfig{Config: restConfig, Clientset: clientset, Agent: policy}, recorder.factory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)

	security, err := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	if err != nil {
		t.Fatal(err)
	}
	ackLoss := errors.New("injected route update acknowledgement loss")
	writeClient := interceptor.NewClient(apiClient, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		if pod, ok := obj.(*corev1.Pod); ok && pod.Labels["phorvex.ai/role"] == "retiring" {
			if err := c.Update(ctx, obj, opts...); err != nil {
				return err
			}
			return ackLoss
		}
		return c.Update(ctx, obj, opts...)
	}})
	native := actuator.NewNativeActuator(writeClient)
	native.SetBoundaryReader(apiClient)
	native.JournalNamespace = "operator"
	native.SetMIGProfiles(profiles)
	native.SetServingSecurity(security)
	target := actuator.Target{
		Namespace: targetPod.Namespace, Pod: targetPod.Name, UID: string(targetPod.UID), NodeName: targetPod.Spec.NodeName,
		HasGPU: true, MIGResource: m079Resource, PolicyName: phorvexPolicy.Name, PolicyUID: string(phorvexPolicy.UID), ServiceAccount: targetPod.Spec.ServiceAccountName,
	}
	if ok, why := native.SupportsAction(t.Context(), model.ActionMIGRebind, target); !ok {
		t.Fatalf("enabled direct capability: %s", why)
	}
	view := m079View()
	view.Pod.UID, view.Pod.ServiceAccount = string(targetPod.UID), targetPod.Spec.ServiceAccountName
	witness := capability.BuildWitness(t.Context(), capability.BuildIndex(nil, nil, nil), nil, nil, localActuator(native)).WithPolicyIdentity(phorvexPolicy.Name, string(phorvexPolicy.UID))
	if reason := witness.Eligible(view, model.ActionMIGRebind, []string{"gpu-contention"}); reason != nil {
		t.Fatalf("enabled generator exclusion=%+v", reason)
	}

	request := actuator.Request{
		TargetUID: string(targetPod.UID), OperationID: "m079-operation", TickID: "m079-tick",
		PolicyName: phorvexPolicy.Name, PolicyUID: string(phorvexPolicy.UID), Tenant: "tenant",
		Namespace: targetPod.Namespace, Pod: targetPod.Name, Action: model.ActionMIGRebind,
	}
	result, err := native.Actuate(t.Context(), request)
	if err == nil || !result.Emitted || result.MutationKind != "partial" || !strings.Contains(err.Error(), "route removal failed") {
		t.Fatalf("registered handler preparation result=%+v err=%v", result, err)
	}
	var receipts corev1.ConfigMapList
	if err := apiClient.List(t.Context(), &receipts, client.InNamespace("operator")); err != nil {
		t.Fatal(err)
	}
	if len(receipts.Items) != 1 || receipts.Items[0].Labels["phorvex.ai/mig-recovery"] != "v2" {
		t.Fatalf("registered handler did not retain its protected receipt: %+v", receipts.Items)
	}
	recorder.assertBoundaries(t, agent.Name)
}

func m079View() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{
		Namespace: "tenant", Name: "model", UID: "target-uid", Node: "node-1", HasGPU: true,
		MIGDevice: m079Resource, ModelID: "m079-model", ServingDeclared: true,
	}}
}

func m079RenderedMIG(t *testing.T, rendered string) ([]string, string, appsv1.DaemonSet) {
	t.Helper()
	decoder := kyaml.NewYAMLOrJSONDecoder(strings.NewReader(rendered), 4096)
	var args []string
	var profile string
	var daemonSet appsv1.DaemonSet
	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			continue
		}
		kind, _ := raw["kind"].(string)
		metadata, _ := raw["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		switch kind {
		case "Deployment":
			spec := raw["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			containers := spec["containers"].([]any)
			for _, item := range containers {
				container := item.(map[string]any)
				if container["name"] != "manager" {
					continue
				}
				for _, value := range container["args"].([]any) {
					args = append(args, value.(string))
				}
			}
		case "ConfigMap":
			if strings.HasSuffix(name, "-mig-profiles") {
				profile = raw["data"].(map[string]any)["profiles.json"].(string)
			}
		case "DaemonSet":
			b, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &daemonSet); err != nil {
				t.Fatalf("decode rendered DaemonSet: %v", err)
			}
		}
	}
	return args, profile, daemonSet
}

func m079ArgMap(args []string) map[string]string {
	result := make(map[string]string, len(args))
	for _, value := range args {
		key, val, ok := strings.Cut(value, "=")
		if ok {
			result[key] = val
		}
	}
	return result
}

func m079AgentPod(ds *appsv1.DaemonSet) *corev1.Pod {
	controller := true
	spec := ds.Spec.Template.Spec.DeepCopy()
	spec.NodeName = "node-1"
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ds.Namespace, Name: "agent-a",
			Labels:          ds.Spec.Template.Labels,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: ds.Name, UID: ds.UID, Controller: &controller}},
		},
		Spec:   *spec,
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func m079APIObjects(t *testing.T, ds *appsv1.DaemonSet) (*rest.Config, kubernetes.Interface, *corev1.Pod, *v1alpha1.PhorvexPolicy, client.WithWatch, *corev1.Pod) {
	t.Helper()
	environment := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = environment.Stop() })
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	apiClient, err := client.NewWithWatch(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"operator", "tenant", "gpu-system"} {
		if err := apiClient.Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
			t.Fatal(err)
		}
	}
	ds = ds.DeepCopy()
	ds.UID, ds.ResourceVersion = "", ""
	createdDS, err := clientset.AppsV1().DaemonSets(ds.Namespace).Create(t.Context(), ds, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent := m079AgentPod(createdDS)
	desiredAgentStatus := agent.Status
	agent.Status = corev1.PodStatus{}
	agent, err = clientset.CoreV1().Pods(agent.Namespace).Create(t.Context(), agent, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent.Status = desiredAgentStatus
	agent, err = clientset.CoreV1().Pods(agent.Namespace).UpdateStatus(t.Context(), agent, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	target, policy := m079WorkloadObjects()
	desiredTargetStatus := target.Status
	target.Status = corev1.PodStatus{}
	if err := apiClient.Create(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	target.Status = desiredTargetStatus
	if err := apiClient.Status().Update(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	if err := apiClient.Create(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if target.UID == "" || target.ResourceVersion == "" || policy.UID == "" || policy.ResourceVersion == "" || createdDS.UID == "" || agent.UID == "" {
		t.Fatal("API server did not assign complete workload, policy, DaemonSet and agent identities")
	}
	return config, clientset, target, policy, apiClient, agent
}

type m079PodResourcesServer struct {
	podresourcesv1.UnimplementedPodResourcesListerServer
}

func (m079PodResourcesServer) List(context.Context, *podresourcesv1.ListPodResourcesRequest) (*podresourcesv1.ListPodResourcesResponse, error) {
	return &podresourcesv1.ListPodResourcesResponse{PodResources: []*podresourcesv1.PodResources{{
		Namespace: "tenant", Name: "model", Containers: []*podresourcesv1.ContainerResources{{
			Name: "model", Devices: []*podresourcesv1.ContainerDevices{{ResourceName: m079Resource, DeviceIds: []string{m079MIGUUID}}},
		}},
	}}}, nil
}

func m079ServePodResources(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "kubelet.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	podresourcesv1.RegisterPodResourcesListerServer(server, m079PodResourcesServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return socket
}

type m079ExecCall struct {
	method, path, container string
	argv                    []string
	hasDeadline             bool
}

type m079RemoteRecorder struct {
	mu     sync.Mutex
	socket string
	calls  []m079ExecCall
}

func (r *m079RemoteRecorder) factory(_ *rest.Config, method string, target *url.URL) (remotecommand.Executor, error) {
	return m079RemoteExecutor{record: r, method: method, target: target}, nil
}

type m079RemoteExecutor struct {
	record *m079RemoteRecorder
	method string
	target *url.URL
}

func (e m079RemoteExecutor) Stream(options remotecommand.StreamOptions) error {
	return e.StreamWithContext(context.Background(), options)
}

func (e m079RemoteExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	query := e.target.Query()
	call := m079ExecCall{method: e.method, path: e.target.Path, container: query.Get("container"), argv: append([]string(nil), query["command"]...)}
	_, call.hasDeadline = ctx.Deadline()
	e.record.mu.Lock()
	e.record.calls = append(e.record.calls, call)
	e.record.mu.Unlock()
	var output string
	if call.container == "allocation-helper" {
		want := []string{"/phorvex-mig-allocation-helper", "--socket", e.record.socket, "--timeout", "3s"}
		if !reflect.DeepEqual(call.argv, want) {
			return fmt.Errorf("helper argv=%v, want %v", call.argv, want)
		}
		snapshot, err := podresources.Read(ctx, e.record.socket, 3*time.Second)
		if err != nil {
			return err
		}
		encoded, err := podresources.Encode(snapshot)
		if err != nil {
			return err
		}
		output = string(encoded)
	} else if call.container == "gpu-tools" {
		joined := strings.Join(call.argv, " ")
		switch {
		case reflect.DeepEqual(call.argv, []string{"nvidia-smi", "-L"}):
			output = "GPU 0: NVIDIA A100 (UUID: " + m079GPUUUID + ")\n  MIG 1g.10gb Device 0: (UUID: " + m079MIGUUID + ")\n"
		case strings.Contains(joined, "--query-gpu=uuid"):
			output = m079GPUUUID + "\n"
		case strings.HasSuffix(joined, "-lgip"):
			output = m079ProfileTable
		case strings.HasSuffix(joined, "-lgi"):
			output = m079GITable
		case strings.HasSuffix(joined, "-lci"):
			output = m079CITable
		default:
			return fmt.Errorf("unexpected GPU argv %v", call.argv)
		}
	} else {
		return fmt.Errorf("unexpected exec container %q", call.container)
	}
	_, err := io.WriteString(options.Stdout, output)
	return err
}

func (r *m079RemoteRecorder) assertBoundaries(t *testing.T, agent string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) < 7 {
		t.Fatalf("remotecommand calls=%d, want helper, inventory and geometry reads", len(r.calls))
	}
	helper, inventory, geometry := false, false, false
	for _, call := range r.calls {
		if call.method != http.MethodPost || call.path != "/api/v1/namespaces/gpu-system/pods/"+agent+"/exec" || !call.hasDeadline {
			t.Fatalf("unbound remotecommand call=%+v", call)
		}
		switch {
		case call.container == "allocation-helper":
			helper = true
		case reflect.DeepEqual(call.argv, []string{"nvidia-smi", "-L"}):
			inventory = true
		case strings.Contains(strings.Join(call.argv, " "), "--query-gpu=uuid"):
			geometry = true
		}
	}
	if !helper || !inventory || !geometry {
		t.Fatalf("missing composed boundaries helper=%v inventory=%v geometry=%v calls=%+v", helper, inventory, geometry, r.calls)
	}
}

func m079WorkloadObjects() (*corev1.Pod, *v1alpha1.PhorvexPolicy) {
	target := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant", Name: "model",
			Labels:      map[string]string{"app": "model", "phorvex.ai/role": "leader"},
			Annotations: map[string]string{"phorvex.ai/model-id": "m079-model", "phorvex.ai/serving-port": "8000"},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1", ServiceAccountName: "model-sa",
			Containers: []corev1.Container{{Name: "model", Image: "model:test", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceName(m079Resource): resource.MustParse("1")}}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "policy"},
		Spec: v1alpha1.PhorvexPolicySpec{
			Mode:     v1alpha1.ModeActive,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "model"}},
			Budget: v1alpha1.BudgetSpec{
				TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour},
			},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionMIGRebind)}},
		},
	}
	return target, policy
}

const m079ProfileTable = `+--------------------------------------------------------------------------------------+
| GPU instance profiles:                                                               |
| GPU   Name             ID    Instances   Memory     P2P    SM    DEC   ENC             |
|                             Free/Total   GiB              CE    JPEG  OFA             |
|======================================================================================|
|  0  MIG 2g.20gb  14  1/3  19.50  No  28  1  0  |
|                                                             2     0     0           |
+--------------------------------------------------------------------------------------+
`

const m079GITable = `+----------------------------------------------------+
| GPU instances:                                     |
| GPU   Name          Profile  Instance   Placement  |
|                       ID       ID       Start:Size |
|====================================================|
|  0  MIG 1g.10gb  19  7  0:1  |
+----------------------------------------------------+
`

const m079CITable = `+-------------------------------------------------------+
| Compute instances:                                    |
| GPU     GPU       Name             Profile   Instance |
|       Instance                       ID        ID     |
|         ID                                            |
|=======================================================|
|  0  7  MIG 1g.10gb  7  0  |
+-------------------------------------------------------+
`
