package routecatalogue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

type boundedLog struct {
	mu sync.Mutex
	b  []byte
}

type acceptedWriteLostAckClient struct {
	client.Client
	method string
	once   atomic.Bool
}

func (c *acceptedWriteLostAckClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	err := c.Client.Patch(ctx, obj, patch, opts...)
	if err == nil && c.method == "PATCH" && c.once.CompareAndSwap(false, true) {
		return errors.New("injected accepted Pod patch lost acknowledgement")
	}
	return err
}

func (c *acceptedWriteLostAckClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	err := c.Client.Update(ctx, obj, opts...)
	if err == nil && c.method == "UPDATE" {
		if _, ok := obj.(*corev1.Service); ok && c.once.CompareAndSwap(false, true) {
			return errors.New("injected accepted Service update lost acknowledgement")
		}
	}
	return err
}

func (l *boundedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, p...)
	if len(l.b) > 64<<10 {
		l.b = append([]byte(nil), l.b[len(l.b)-(64<<10):]...)
	}
	return len(p), nil
}

func (l *boundedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(append([]byte(nil), l.b...))
}

func testKubeconfig(t *testing.T, cfg *rest.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	k := clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"local": {Server: cfg.Host, CertificateAuthority: cfg.CAFile, CertificateAuthorityData: cfg.CAData, InsecureSkipTLSVerify: cfg.Insecure}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {ClientCertificate: cfg.CertFile, ClientCertificateData: cfg.CertData, ClientKey: cfg.KeyFile, ClientKeyData: cfg.KeyData, Token: cfg.BearerToken}}, Contexts: map[string]*clientcmdapi.Context{"local": {Cluster: "local", AuthInfo: "admin"}}, CurrentContext: "local"}
	if err := clientcmd.WriteToFile(k, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool, diagnostic func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", diagnostic())
}

func identityServer(t *testing.T, identity HTTPIdentity) *httptest.Server {
	t.Helper()
	raw, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/identity" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
}

func TestRouteEndpointCatalogueEntrypointActualAPIKCMHTTP(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if kcm == "" {
		var err error
		kcm, err = exec.LookPath("kube-controller-manager")
		if err != nil {
			t.Skip("requires pinned Kubernetes v1.34.0 kube-controller-manager")
		}
	}
	version, err := exec.Command(kcm, "--version").Output()
	if err != nil || !strings.Contains(string(version), "v1.34.0") {
		t.Fatalf("kube-controller-manager must be v1.34.0: %q err=%v", version, err)
	}
	localOnly := false
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, UseExistingCluster: &localOnly}
	restConfig, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	kubeconfig := testKubeconfig(t, restConfig)
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+kubeconfig, "--controllers=endpointslice", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	var kcmLog boundedLog
	cmd.Stdout, cmd.Stderr = &kcmLog, &kcmLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })

	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-catalogue"}}
	journalNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-catalogue-journal"}}
	for _, object := range []client.Object{ns, journalNS, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "route-node"}}} {
		if err := c.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	rootCA := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: journalNS.Name, Name: "kube-root-ca.crt"}, Data: map[string]string{"ca.crt": "public test CA metadata"}}
	if err := c.Create(ctx, rootCA); err != nil {
		t.Fatal(err)
	}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "route", Labels: map[string]string{"fixture": "route-catalogue"}}, Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, Selector: map[string]string{"fixture": "route-catalogue", routeKey: "initial"}, Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}}}
	if err := c.Create(ctx, service); err != nil {
		t.Fatal(err)
	}
	pods := []*corev1.Pod{}
	for i, role := range []string{"target", "peer"} {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: role, Labels: map[string]string{"fixture": "route-catalogue", routeKey: "initial"}, Annotations: map[string]string{routeServiceAnnotation: service.Name, "phorvex.ai/model-id": "benign-route-fixture", "unrelated": "keep"}}, Spec: corev1.PodSpec{NodeName: "route-node", AutomountServiceAccountToken: ptr(false), Containers: []corev1.Container{{Name: "http", Image: "registry.k8s.io/pause:3.10"}}}}
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.PodIP = fmt.Sprintf("10.44.0.%d", i+10)
		pod.Status.PodIPs = []corev1.PodIP{{IP: pod.Status.PodIP}}
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "http", Ready: true, RestartCount: 0, ContainerID: "containerd://" + strings.Repeat(fmt.Sprintf("%d", i+1), 64)}}
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		if err := c.Status().Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			t.Fatal(err)
		}
		pods = append(pods, pod)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "route-policy"}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: ns.Name, Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"fixture": "route-catalogue"}}, Objective: v1alpha1.ObjectiveSpec{Lambda: "0.6"}, Budget: v1alpha1.BudgetSpec{MaxMovesPerTick: ptr(1), TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: 1}, AssetValue: v1alpha1.AssetValueSpec{BlastRadiusFromGraph: false}, Triggers: v1alpha1.TriggersSpec{EventDriven: false}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRouteRotate, v1alpha1.ActionEndpointRotate}}}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}
	wantMembers := []string{string(pods[0].UID), string(pods[1].UID)}
	sort.Strings(wantMembers)
	waitFor(t, 20*time.Second, func() bool {
		members, err := endpointMembers(ctx, c, service)
		return err == nil && fmt.Sprint(members) == fmt.Sprint(wantMembers)
	}, kcmLog.String)

	nonce := "route-catalogue"
	targetIdentity := HTTPIdentity{Schema: IdentitySchema, Nonce: nonce, Role: "target", PodUID: string(pods[0].UID), ProcessMarker: "target-process"}
	peerIdentity := HTTPIdentity{Schema: IdentitySchema, Nonce: nonce, Role: "peer", PodUID: string(pods[1].UID), ProcessMarker: "peer-process"}
	targetServer, peerServer := identityServer(t, targetIdentity), identityServer(t, peerIdentity)
	t.Cleanup(targetServer.Close)
	t.Cleanup(peerServer.Close)
	servers := map[string]string{string(pods[0].UID): targetServer.URL, string(pods[1].UID): peerServer.URL}
	var routeCounter atomic.Uint64
	var failNextServiceSample atomic.Bool
	serviceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failNextServiceSample.CompareAndSwap(true, false) {
			http.Error(w, "injected bounded outage", http.StatusServiceUnavailable)
			return
		}
		members, err := endpointMembers(r.Context(), c, service)
		if err != nil || len(members) == 0 {
			http.Error(w, "route unavailable", http.StatusServiceUnavailable)
			return
		}
		uid := members[int(routeCounter.Add(1)-1)%len(members)]
		base := servers[uid]
		if base == "" {
			http.Error(w, "foreign route", http.StatusBadGateway)
			return
		}
		response, err := http.Get(base + "/identity")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(serviceServer.Close)

	adapter, err := New(c, c, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	base := RunConfig{Schema: ConfigSchema, SourceRevision: "43352fb41fbb1c87cb0e1c954dbfb1eeb2e51c61", Fixture: Fixture{Nonce: nonce, Tenant: ns.Name, Namespace: ns.Name, NamespaceUID: string(ns.UID), JournalNamespace: journalNS.Name, JournalNamespaceUID: string(journalNS.UID), PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, TargetName: pods[0].Name, TargetUID: string(pods[0].UID), PeerName: pods[1].Name, PeerUID: string(pods[1].UID), ServiceName: service.Name, ServiceUID: string(service.UID)}, Observation: ObservationConfig{TargetURL: targetServer.URL + "/identity", PeerURL: peerServer.URL + "/identity", ServiceURL: serviceServer.URL + "/identity", SampleIntervalMillis: 10, RequestTimeoutMillis: 500, MinSamplesPerEndpointPhase: 2}}

	t.Run("foreign-read-and-write-authority-refused", func(t *testing.T) {
		bounded := newBoundedClient(c, c, base.Fixture, time.Now)
		if err := bounded.Get(ctx, client.ObjectKeyFromObject(rootCA), &corev1.ConfigMap{}); err == nil {
			t.Fatal("namespace infrastructure ConfigMap was readable through product journal authority")
		}
		foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: journalNS.Name, Name: "foreign", Labels: map[string]string{operationJournalLabel: "v1"}}}
		if err := bounded.Create(ctx, foreign); err == nil {
			t.Fatal("foreign journal-shaped name was admitted")
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(foreign), &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
			t.Fatalf("foreign ConfigMap write reached API: %v", err)
		}
		peerBefore := pods[1].DeepCopy()
		peerMutation := pods[1].DeepCopy()
		peerMutation.Labels[routeKey] = "foreign"
		if err := bounded.Patch(ctx, peerMutation, client.MergeFrom(peerBefore)); err == nil {
			t.Fatal("peer Pod write was admitted")
		}
		peerAfter := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pods[1]), peerAfter); err != nil || peerAfter.Labels[routeKey] != "initial" {
			t.Fatalf("peer Pod changed after refused write: labels=%v err=%v", peerAfter.Labels, err)
		}
	})

	for i, action := range []Action{ActionRouteRotate, ActionEndpointRotate} {
		t.Run(string(action), func(t *testing.T) {
			cfg := base
			cfg.Action = action
			cfg.Fixture.OperationID = fmt.Sprintf("%064x", i+1)
			if i == 0 {
				failNextServiceSample.Store(true)
			}
			receipt, err := adapter.Run(ctx, cfg)
			if err != nil || receipt.Status != "COMPLETE" || receipt.ForwardResult == nil || receipt.Forward == nil || receipt.Restored == nil || !receipt.RollbackAttempted || receipt.RollbackError != "" {
				t.Fatalf("receipt status=%s result=%+v rollback=%q err=%v kcm=%s", receipt.Status, receipt.ForwardResult, receipt.RollbackError, err, kcmLog.String())
			}
			if len(receipt.HTTP) < 18 || len(receipt.Writes) == 0 || len(receipt.Forward.Journal) != 1 || len(receipt.Restored.Journal) != 0 {
				t.Fatalf("receipt evidence is incomplete: http=%d writes=%d forwardJournal=%d restoredJournal=%d", len(receipt.HTTP), len(receipt.Writes), len(receipt.Forward.Journal), len(receipt.Restored.Journal))
			}
			for _, write := range receipt.Writes {
				if write.Error != "" {
					t.Fatalf("successful producer retained failed write: %+v", write)
				}
			}
			if i == 0 && !receipt.AvailabilityInterrupted {
				t.Fatal("real HTTP failure was not retained as an availability interruption")
			}
		})
	}

	t.Run("wrong-rollback-authority-refuses-without-write", func(t *testing.T) {
		cfg := base
		cfg.Action = ActionRouteRotate
		cfg.Fixture.OperationID = strings.Repeat("9", 64)
		baseline, livePolicy, target, err := adapter.readState(ctx, cfg, "baseline")
		if err != nil {
			t.Fatal(err)
		}
		bounded := newBoundedClient(c, c, cfg.Fixture, time.Now)
		native := actuator.NewNativeActuator(bounded)
		native.SetBoundaryReader(bounded.reader)
		native.JournalNamespace = cfg.Fixture.JournalNamespace
		native.RouteObservationTimeout, native.RouteObservationInterval, native.StrictTenantNamespace = 15*time.Second, 100*time.Millisecond, true
		action, _ := cfg.Action.modelAction()
		if err := native.EnsurePolicy(ctx, actuator.TenantTarget{Tenant: cfg.Fixture.Tenant, Namespace: cfg.Fixture.Namespace, PolicyName: cfg.Fixture.PolicyName, PolicyUID: cfg.Fixture.PolicyUID, Generation: cfg.Fixture.PolicyGeneration, Selector: livePolicy.Spec.Selector.DeepCopy(), EnabledActions: map[model.Action]bool{action: true}, PolicyOwnerCount: 1}); err != nil {
			t.Fatal(err)
		}
		req := actuator.Request{TargetUID: cfg.Fixture.TargetUID, TargetNamespaceUID: cfg.Fixture.NamespaceUID, OperationID: cfg.Fixture.OperationID, PolicyName: cfg.Fixture.PolicyName, PolicyUID: cfg.Fixture.PolicyUID, PolicyGeneration: cfg.Fixture.PolicyGeneration, Tenant: cfg.Fixture.Tenant, Namespace: cfg.Fixture.Namespace, Pod: target.Name, Action: action, Reason: "rollback refusal producer", Score: -1}
		result, err := native.Actuate(ctx, req)
		if err != nil || result.RollbackRef == "" {
			t.Fatalf("forward for rollback refusals failed: result=%+v err=%v", result, err)
		}
		forward, _, _, err := adapter.readState(ctx, cfg, "forward")
		if err != nil || len(forward.Journal) != 1 {
			t.Fatalf("forward authority missing: state=%+v err=%v", forward, err)
		}
		wrongReceiptRef := result.RollbackRef[:len(result.RollbackRef)-1] + "0"
		if wrongReceiptRef == result.RollbackRef {
			wrongReceiptRef = result.RollbackRef[:len(result.RollbackRef)-1] + "1"
		}
		wrongUIDRef := strings.Replace(result.RollbackRef, forward.Journal[0].UID, "00000000-0000-4000-8000-000000000000", 1)
		for name, candidate := range map[string]struct {
			req actuator.Request
			ref string
		}{
			"operation":     {req: func() actuator.Request { x := req; x.OperationID = strings.Repeat("8", 64); return x }(), ref: result.RollbackRef},
			"action":        {req: func() actuator.Request { x := req; x.Action = model.ActionEndpointRotate; return x }(), ref: result.RollbackRef},
			"policy":        {req: func() actuator.Request { x := req; x.PolicyUID = "00000000-0000-4000-8000-000000000000"; return x }(), ref: result.RollbackRef},
			"target":        {req: func() actuator.Request { x := req; x.TargetUID = "00000000-0000-4000-8000-000000000000"; return x }(), ref: result.RollbackRef},
			"receipt-id":    {req: req, ref: wrongReceiptRef},
			"configmap-uid": {req: req, ref: wrongUIDRef},
		} {
			beforeWrites := len(bounded.snapshot())
			if err := native.Rollback(ctx, candidate.req, candidate.ref); err == nil {
				t.Fatalf("wrong rollback %s authority accepted", name)
			}
			if got := len(bounded.snapshot()); got != beforeWrites {
				t.Fatalf("wrong rollback %s sent writes: before=%d after=%d", name, beforeWrites, got)
			}
			current, _, _, readErr := adapter.readState(ctx, cfg, "forward")
			if readErr != nil || !reflect.DeepEqual(current.Target.Labels, forward.Target.Labels) || !reflect.DeepEqual(current.Target.Annotations, forward.Target.Annotations) || !reflect.DeepEqual(current.Service.Selector, forward.Service.Selector) || !reflect.DeepEqual(current.ReadyMembers, forward.ReadyMembers) || !reflect.DeepEqual(current.Journal, forward.Journal) {
				t.Fatalf("wrong rollback %s changed forward authority: current=%+v err=%v", name, current, readErr)
			}
		}
		if err := native.Rollback(ctx, req, result.RollbackRef); err != nil {
			t.Fatal(err)
		}
		restored, _, _, err := adapter.readState(ctx, cfg, "restored")
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRestored(baseline, restored); err != nil {
			t.Fatal(err)
		}
	})

	for name, mutate := range map[string]func(*RunConfig){
		"wrong-target-uid":        func(cfg *RunConfig) { cfg.Fixture.TargetUID = "00000000-0000-4000-8000-000000000000" },
		"wrong-policy-uid":        func(cfg *RunConfig) { cfg.Fixture.PolicyUID = "00000000-0000-4000-8000-000000000000" },
		"wrong-policy-generation": func(cfg *RunConfig) { cfg.Fixture.PolicyGeneration++ },
		"wrong-namespace-uid":     func(cfg *RunConfig) { cfg.Fixture.NamespaceUID = "00000000-0000-4000-8000-000000000000" },
	} {
		t.Run(name+"-refuses-before-write", func(t *testing.T) {
			cfg := base
			cfg.Action = ActionRouteRotate
			cfg.Fixture.OperationID = strings.Repeat("f", 64)
			mutate(&cfg)
			receipt, err := adapter.Run(ctx, cfg)
			if err == nil || len(receipt.Writes) != 0 || receipt.ForwardResult != nil {
				t.Fatalf("wrong authority was not pre-write refused: receipt=%+v err=%v", receipt, err)
			}
		})
	}

	for i, method := range []string{"PATCH", "UPDATE"} {
		t.Run("accepted-"+strings.ToLower(method)+"-lost-ack-safe-restoration", func(t *testing.T) {
			fault := &acceptedWriteLostAckClient{Client: c, method: method}
			faultAdapter, err := New(fault, c, &http.Client{})
			if err != nil {
				t.Fatal(err)
			}
			cfg := base
			if i == 0 {
				cfg.Action = ActionRouteRotate
			} else {
				cfg.Action = ActionEndpointRotate
			}
			cfg.Fixture.OperationID = fmt.Sprintf("%064x", 100+i)
			receipt, runErr := faultAdapter.Run(ctx, cfg)
			if !fault.once.Load() {
				t.Fatalf("%s lost-ack fault was not reached", method)
			}
			if receipt.Restored == nil || receipt.RollbackError != "" || len(receipt.Restored.Journal) != 0 {
				t.Fatalf("%s lost-ack did not safely restore: status=%s reconciliation=%v/%q rollback=%q err=%v", method, receipt.Status, receipt.ReconciliationAttempted, receipt.ReconciliationError, receipt.RollbackError, runErr)
			}
			if err := validateRestored(*receipt.Baseline, *receipt.Restored); err != nil {
				t.Fatalf("%s lost-ack restoration differs: %v", method, err)
			}
			foundInjected := false
			for _, write := range receipt.Writes {
				if strings.Contains(write.Error, "injected accepted") {
					foundInjected = true
				}
			}
			if !foundInjected {
				t.Fatalf("%s lost-ack write error was not retained", method)
			}
		})
	}

	t.Run("same-name-service-successor-refuses-before-write", func(t *testing.T) {
		oldUID := service.UID
		if err := c.Delete(ctx, service); err != nil {
			t.Fatal(err)
		}
		replacement := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: service.Name, Labels: map[string]string{"fixture": "route-catalogue"}}, Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, Selector: map[string]string{"fixture": "route-catalogue", routeKey: "initial"}, Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}}}
		if err := c.Create(ctx, replacement); err != nil {
			t.Fatal(err)
		}
		cfg := base
		cfg.Action = ActionRouteRotate
		cfg.Fixture.OperationID = strings.Repeat("d", 64)
		receipt, err := adapter.Run(ctx, cfg)
		if err == nil || len(receipt.Writes) != 0 || receipt.ForwardResult != nil {
			t.Fatalf("same-name Service successor was adopted: receipt=%+v err=%v", receipt, err)
		}
		current := &corev1.Service{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(replacement), current); err != nil || current.UID == oldUID || !reflect.DeepEqual(current.Spec.Selector, replacement.Spec.Selector) {
			t.Fatalf("Service successor was changed: current=%+v err=%v", current, err)
		}
		service = replacement
		base.Fixture.ServiceUID = string(replacement.UID)
	})

	t.Run("same-name-target-successor-refuses-before-write", func(t *testing.T) {
		oldUID := pods[0].UID
		if err := c.Delete(ctx, pods[0], client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 5*time.Second, func() bool {
			return apierrors.IsNotFound(c.Get(ctx, client.ObjectKeyFromObject(pods[0]), &corev1.Pod{}))
		}, func() string { return "original target Pod was not deleted" })
		replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: pods[0].Name, Labels: map[string]string{"fixture": "route-catalogue", routeKey: "initial"}, Annotations: map[string]string{routeServiceAnnotation: service.Name, "phorvex.ai/model-id": "benign-route-fixture", "unrelated": "keep"}}, Spec: corev1.PodSpec{NodeName: "route-node", AutomountServiceAccountToken: ptr(false), Containers: []corev1.Container{{Name: "http", Image: "registry.k8s.io/pause:3.10"}}}}
		if err := c.Create(ctx, replacement); err != nil {
			t.Fatal(err)
		}
		replacement.Status.Phase = corev1.PodRunning
		replacement.Status.PodIP, replacement.Status.PodIPs = "10.44.0.30", []corev1.PodIP{{IP: "10.44.0.30"}}
		replacement.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "http", Ready: true, ContainerID: "containerd://" + strings.Repeat("3", 64)}}
		replacement.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		if err := c.Status().Update(ctx, replacement); err != nil {
			t.Fatal(err)
		}
		cfg := base
		cfg.Action = ActionEndpointRotate
		cfg.Fixture.OperationID = strings.Repeat("e", 64)
		receipt, err := adapter.Run(ctx, cfg)
		if err == nil || len(receipt.Writes) != 0 || receipt.ForwardResult != nil {
			t.Fatalf("same-name Pod successor was adopted: receipt=%+v err=%v", receipt, err)
		}
		current := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(replacement), current); err != nil || current.UID == oldUID || current.Labels[routeKey] != "initial" {
			t.Fatalf("Pod successor was changed: current=%+v err=%v", current, err)
		}
	})

	journal, err := readJournal(ctx, c, journalNS.Name)
	if err != nil || len(journal) != 0 {
		t.Fatalf("producer retained protected journal: count=%d err=%v", len(journal), err)
	}
	retainedCA := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(rootCA), retainedCA); err != nil || retainedCA.UID != rootCA.UID || retainedCA.Data["ca.crt"] != rootCA.Data["ca.crt"] {
		t.Fatalf("namespace infrastructure ConfigMap was changed: current=%+v err=%v", retainedCA, err)
	}
}

func ptr[T any](value T) *T { return &value }

func TestHTTPProducerRefusesStaleServiceMemberAndChangedProcessMarker(t *testing.T) {
	fixture := Fixture{Nonce: "http-counterexample", TargetUID: "target-uid", PeerUID: "peer-uid"}
	target := HTTPIdentity{Schema: IdentitySchema, Nonce: fixture.Nonce, Role: "target", PodUID: fixture.TargetUID, ProcessMarker: "target-process"}
	peer := HTTPIdentity{Schema: IdentitySchema, Nonce: fixture.Nonce, Role: "peer", PodUID: fixture.PeerUID, ProcessMarker: "peer-process"}

	for name, change := range map[string]func(*atomic.Value){
		"stale-peer-after-forward": func(service *atomic.Value) { service.Store(peer) },
		"changed-target-process-marker": func(targetValue *atomic.Value) {
			changed := target
			changed.ProcessMarker = "different-process"
			targetValue.Store(changed)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var targetValue, peerValue, serviceValue atomic.Value
			targetValue.Store(target)
			peerValue.Store(peer)
			serviceValue.Store(target)
			server := func(value *atomic.Value) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_ = json.NewEncoder(w).Encode(value.Load().(HTTPIdentity))
				}))
			}
			targetServer, peerServer, serviceServer := server(&targetValue), server(&peerValue), server(&serviceValue)
			defer targetServer.Close()
			defer peerServer.Close()
			defer serviceServer.Close()
			cfg := RunConfig{Fixture: fixture, Observation: ObservationConfig{TargetURL: targetServer.URL + "/identity", PeerURL: peerServer.URL + "/identity", ServiceURL: serviceServer.URL + "/identity", SampleIntervalMillis: 10, RequestTimeoutMillis: 250, MinSamplesPerEndpointPhase: 2}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			sampler := newHTTPSampler(&http.Client{}, cfg, time.Now)
			sampler.start(ctx)
			defer sampler.stop()
			if err := sampler.waitPhase(ctx, "baseline", 2); err != nil {
				t.Fatal(err)
			}
			markers, err := bindHTTPIdentities(sampler.snapshot(), "baseline", fixture)
			if err != nil {
				t.Fatal(err)
			}
			sampler.setPhase("forward-stable")
			if name == "stale-peer-after-forward" {
				change(&serviceValue)
			} else {
				change(&targetValue)
			}
			if err := sampler.waitPhase(ctx, "forward-stable", 2); err != nil {
				t.Fatal(err)
			}
			if err := validateStableIdentities(sampler.snapshot(), "forward-stable", fixture, markers, map[string]bool{fixture.TargetUID: true}); err == nil {
				t.Fatal("HTTP identity counterexample was accepted")
			}
		})
	}
}

func TestSamplerTerminalCancellationIsRetainedButNotAnObservedOutage(t *testing.T) {
	identity := HTTPIdentity{Schema: IdentitySchema, Nonce: "stop", Role: "target", PodUID: "target", ProcessMarker: "process"}
	quick := identityServer(t, identity)
	defer quick.Close()
	blocked := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer blocked.Close()
	cfg := RunConfig{Observation: ObservationConfig{TargetURL: quick.URL + "/identity", PeerURL: quick.URL + "/identity", ServiceURL: blocked.URL + "/identity", SampleIntervalMillis: 10, RequestTimeoutMillis: 1000}}
	sampler := newHTTPSampler(&http.Client{}, cfg, time.Now)
	sampler.start(context.Background())
	time.Sleep(30 * time.Millisecond)
	sampler.stop()
	found := false
	for _, row := range sampler.snapshot() {
		if row.Endpoint == "service" && row.Error != "" && row.TerminalCancellation {
			found = true
		}
	}
	if !found {
		t.Fatal("sampler shutdown did not retain a typed terminal cancellation row")
	}
}

func TestRollbackCleanupContextSurvivesCanceledRunContext(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	stop()
	cleanup, cancel := freshCleanupContext(parent)
	defer cancel()
	select {
	case <-cleanup.Done():
		t.Fatalf("fresh rollback cleanup context inherited cancellation: %v", cleanup.Err())
	default:
	}
}
