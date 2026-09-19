package runner

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type m034RecordingActuator struct {
	inner  actuator.Actuator
	result actuator.Result
	err    error
}

type m034BoundedLog struct {
	mu   sync.Mutex
	tail []byte
}

const m034KCMLogLimit = 64 * 1024

func (l *m034BoundedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(p) >= m034KCMLogLimit {
		l.tail = append(l.tail[:0], p[len(p)-m034KCMLogLimit:]...)
		return len(p), nil
	}
	l.tail = append(l.tail, p...)
	if len(l.tail) > m034KCMLogLimit {
		l.tail = append([]byte(nil), l.tail[len(l.tail)-m034KCMLogLimit:]...)
	}
	return len(p), nil
}

func (l *m034BoundedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(append([]byte(nil), l.tail...))
}

func m034NonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		var ip net.IP
		switch parsed := address.(type) {
		case *net.IPNet:
			ip = parsed.IP
		case *net.IPAddr:
			ip = parsed.IP
		}
		if ip4 := ip.To4(); ip4 != nil && ip4.IsGlobalUnicast() && !ip4.IsLoopback() {
			return ip4.String()
		}
	}
	t.Fatal("isolated EndpointSlice fixture requires a non-loopback local IPv4 address")
	return ""
}

func (r *m034RecordingActuator) Name() string { return r.inner.Name() }
func (r *m034RecordingActuator) EnsurePolicy(ctx context.Context, target actuator.TenantTarget) error {
	return r.inner.EnsurePolicy(ctx, target)
}
func (r *m034RecordingActuator) SupportsAction(ctx context.Context, action model.Action, target actuator.Target) (bool, string) {
	return r.inner.SupportsAction(ctx, action, target)
}
func (r *m034RecordingActuator) Actuate(ctx context.Context, req actuator.Request) (actuator.Result, error) {
	r.result, r.err = r.inner.Actuate(ctx, req)
	return r.result, r.err
}

func m034Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func m034Poll(t *testing.T, d time.Duration, f func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ok, err := f()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for isolated controller fixture")
}

func TestM034M078SnapshotOptimizerRunnerNativeAndReplicaSetEndpointControllers(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" || os.Getenv("KUBE_CONTROLLER_MANAGER") == "" {
		t.Skip("requires pinned envtest and kube-controller-manager")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if out, err := exec.Command(kcm, "--version").Output(); err != nil || !strings.Contains(string(out), "v1.34.0") {
		t.Fatalf("kube-controller-manager must be v1.34.0: %q %v", out, err)
	}
	local := false
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, UseExistingCluster: &local}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	kcfg := clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"local": {Server: cfg.Host, CertificateAuthorityData: cfg.CAData}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {ClientCertificateData: cfg.CertData, ClientKeyData: cfg.KeyData}}, Contexts: map[string]*clientcmdapi.Context{"local": {Cluster: "local", AuthInfo: "admin"}}, CurrentContext: "local"}
	if err := clientcmd.WriteToFile(kcfg, kubeconfig); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+kubeconfig, "--controllers=replicaset,endpointslice", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	var kcmLog m034BoundedLog
	cmd.Stdout, cmd.Stderr = &kcmLog, &kcmLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("bounded kube-controller-manager log:\n%s", kcmLog.String())
		}
		cancel()
		_ = cmd.Wait()
	})
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: m034Scheme(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		var failedPods corev1.PodList
		var failedSlices discoveryv1.EndpointSliceList
		_ = c.List(context.Background(), &failedPods)
		_ = c.List(context.Background(), &failedSlices)
		podState := make([]string, 0, len(failedPods.Items))
		for i := range failedPods.Items {
			pod := &failedPods.Items[i]
			podState = append(podState, fmt.Sprintf("%s/%s uid=%s role=%s IPs=%v deleting=%t", pod.Namespace, pod.Name, pod.UID, pod.Labels["phorvex.ai/role"], pod.Status.PodIPs, pod.DeletionTimestamp != nil))
		}
		sliceState := make([]string, 0, len(failedSlices.Items))
		for i := range failedSlices.Items {
			slice := &failedSlices.Items[i]
			for j := range slice.Endpoints {
				endpoint := &slice.Endpoints[j]
				target := ""
				if endpoint.TargetRef != nil {
					target = endpoint.TargetRef.Namespace + "/" + endpoint.TargetRef.Name + " uid=" + string(endpoint.TargetRef.UID)
				}
				sliceState = append(sliceState, fmt.Sprintf("%s/%s addresses=%v target=%s", slice.Namespace, slice.Name, endpoint.Addresses, target))
			}
		}
		t.Logf("failure-state Pods=%v EndpointSlices=%v", podState, sliceState)
	})

	var servingMu sync.Mutex
	servingCalls := make([]string, 0, 5)
	loadedInventoryEnabled := false
	stack := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servingMu.Lock()
		servingCalls = append(servingCalls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		loadedInventory := loadedInventoryEnabled
		servingMu.Unlock()
		if r.Header.Get("Authorization") != "Bearer m078-trusted-token" {
			http.Error(w, "missing trusted credential", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && (r.URL.Path == "/models-empty" || !loadedInventory) {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "models") {
			_, _ = w.Write([]byte(`{"data":[{"id":"model"}]}`))
			return
		}
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"aborted":1}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	if err := stack.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(m034NonLoopbackIPv4(t), "0"))
	if err != nil {
		t.Fatal(err)
	}
	stack.Listener = listener
	stack.StartTLS()
	t.Cleanup(stack.Close)
	stackURL, err := url.Parse(stack.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(stackURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	cert := stack.Certificate()
	serverName := host
	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) > 0 {
		serverName = cert.IPAddresses[0].String()
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	for _, name := range []string{"m034-pool", "m034-operator"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	ns := "m034-pool"
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "m034-node"}}
	if err := c.Create(ctx, node); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "serving"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "m034", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "leader"}, Ports: []corev1.ServicePort{{Port: int32(port)}}}}
	if err := c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Tenant: "m034", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m034"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Second}, ProactiveFloor: metav1.Duration{Duration: time.Minute}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "m034-operator", Name: "serving-admin"}, Data: map[string][]byte{"bearer": []byte("m078-trusted-token"), "ca.crt": ca}}
	if err := c.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	replicas := int32(3)
	zero := int64(0)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "pool"}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "m034", "phorvex.ai/swap-group": "g"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "m034", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "warm-shadow", "phorvex.ai/model-loaded": "false"}, Annotations: map[string]string{"phorvex.ai/route-service": svc.Name, "phorvex.ai/model-id": "model", "phorvex.ai/serving-port": portText}}, Spec: corev1.PodSpec{NodeName: node.Name, ServiceAccountName: "model-sa", TerminationGracePeriodSeconds: &zero, Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}}}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	var pods corev1.PodList
	m034Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &pods, client.InNamespace(ns)); err != nil {
			return false, err
		}
		return len(pods.Items) == 3, nil
	})
	sort.Slice(pods.Items, func(i, j int) bool {
		a, b := &pods.Items[i], &pods.Items[j]
		if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
			return a.CreationTimestamp.Before(&b.CreationTimestamp)
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return string(a.UID) < string(b.UID)
	})
	old, emptyShadow, shadow := pods.Items[0].DeepCopy(), pods.Items[1].DeepCopy(), pods.Items[2].DeepCopy()
	old.Labels["phorvex.ai/role"] = "leader"
	emptyShadow.Labels["phorvex.ai/model-loaded"] = "true"
	emptyShadow.Annotations["phorvex.ai/health-path"] = "/health-empty"
	emptyShadow.Annotations["phorvex.ai/models-path"] = "/models-empty"
	shadow.Labels["phorvex.ai/model-loaded"] = "true"
	shadow.Annotations["phorvex.ai/health-path"] = "/health-loaded"
	shadow.Annotations["phorvex.ai/models-path"] = "/models-loaded"
	for _, p := range []*corev1.Pod{old, emptyShadow, shadow} {
		if err := c.Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		p.Status.Phase = corev1.PodRunning
		p.Status.PodIP = host
		p.Status.PodIPs = []corev1.PodIP{{IP: host}}
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(old), old); err != nil {
		t.Fatal(err)
	}
	oldUID := old.UID
	m034Poll(t, 20*time.Second, func() (bool, error) {
		var slices discoveryv1.EndpointSliceList
		if err := c.List(ctx, &slices, client.InNamespace(ns), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}); err != nil {
			return false, err
		}
		for i := range slices.Items {
			for j := range slices.Items[i].Endpoints {
				ref := slices.Items[i].Endpoints[j].TargetRef
				if ref != nil && ref.UID == oldUID {
					return true, nil
				}
			}
		}
		return false, nil
	})

	var snap *ingest.Snapshot
	var p *model.Pod
	m034Poll(t, 20*time.Second, func() (bool, error) {
		current, collectErr := ingest.CollectSnapshot(ctx, c, time.Now(), func(*model.Pod) float64 { return 1 }, c)
		if collectErr != nil {
			return false, collectErr
		}
		candidate := current.PodByKey[ns+"/"+old.Name]
		if candidate == nil || candidate.UID != string(oldUID) || !candidate.WarmPoolConfigured || candidate.WarmPoolOwnerUID != string(rs.UID) {
			return false, nil
		}
		snap, p = current, candidate
		return true, nil
	})
	view := &model.WorkloadView{Pod: *p, Phase: model.PhaseWarm, Physics: model.NeutralPhysics(), ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour, model.VarSession: 2 * time.Hour}}
	native := actuator.NewNativeActuator(c)
	native.Reader = c
	native.JournalNamespace = "m034-operator"
	native.SetServingSecurity(m064RunnerSecurity(t, "m034-operator", actuator.ServingSecurityBinding{
		Namespace: ns, PolicyName: policy.Name, PolicyUID: string(policy.UID), ServiceAccount: "model-sa",
		ProfileID: "m078-model-admin", SecretName: secret.Name, BearerKey: "bearer", CAKey: "ca.crt", ServerName: serverName,
	}))
	emptyResult, emptyErr := native.Actuate(ctx, actuator.Request{
		Tenant: "m034", Namespace: ns, Pod: old.Name, TargetUID: string(oldUID),
		PolicyName: policy.Name, PolicyUID: string(policy.UID), Action: model.ActionWarmSwap,
		TickID: "m180-all-empty", ServingObservation: &actuator.ServingSelectionObservation{},
	})
	if emptyErr == nil || !strings.Contains(emptyErr.Error(), "no Ready model-loaded shadow") || emptyResult.Emitted {
		t.Fatalf("all-empty Native phase did not refuse without effect: result=%+v err=%v", emptyResult, emptyErr)
	}
	for _, expected := range []*corev1.Pod{old, emptyShadow, shadow} {
		var current corev1.Pod
		if err := c.Get(ctx, client.ObjectKeyFromObject(expected), &current); err != nil {
			t.Fatalf("all-empty phase removed exact Pod %s/%s UID=%s: %v", expected.Namespace, expected.Name, expected.UID, err)
		}
		if current.UID != expected.UID || current.Labels["phorvex.ai/role"] != expected.Labels["phorvex.ai/role"] {
			t.Fatalf("all-empty phase changed Pod identity/role: got=%s/%s UID=%s role=%q want UID=%s role=%q", current.Namespace, current.Name, current.UID, current.Labels["phorvex.ai/role"], expected.UID, expected.Labels["phorvex.ai/role"])
		}
	}
	var emptyReceipts corev1.ConfigMapList
	if err := c.List(ctx, &emptyReceipts, client.InNamespace("m034-operator")); err != nil || len(emptyReceipts.Items) != 0 {
		t.Fatalf("all-empty phase persisted a protected receipt: count=%d err=%v", len(emptyReceipts.Items), err)
	}
	servingMu.Lock()
	emptyCalls := append([]string(nil), servingCalls...)
	servingCalls = servingCalls[:0]
	loadedInventoryEnabled = true
	servingMu.Unlock()
	wantEmptyCalls := []string{
		"GET /health-empty Bearer m078-trusted-token", "GET /models-empty Bearer m078-trusted-token",
		"GET /health-loaded Bearer m078-trusted-token", "GET /models-loaded Bearer m078-trusted-token",
	}
	if strings.Join(emptyCalls, ",") != strings.Join(wantEmptyCalls, ",") {
		t.Fatalf("all-empty phase requests=%v, want exact authenticated readiness pairs=%v", emptyCalls, wantEmptyCalls)
	}
	recording := &m034RecordingActuator{inner: native}
	wit := capability.BuildWitness(ctx, capability.BuildIndex(snap.Pods, snap.Nodes, snap.Services), nil, nil, native).
		WithPolicyIdentity(policy.Name, string(policy.UID))
	engine := decision.NewCoverageEngine()
	wireCapabilityGates(engine, wit, true, func(*model.WorkloadView) bool { return false })
	pol := model.Policy{Tenant: "m034", Namespace: ns, Mode: "active", Lambda: cost.DefaultLambdaSeed, MaxMovesPerTick: 1, ProactiveFloor: time.Minute, AntiOverRotationWindow: time.Second, MinAvailableReplicas: 1, PolicyName: policy.Name, PolicyUID: string(policy.UID), EnabledActions: map[model.Action]bool{model.ActionWarmSwap: true}}
	ds, err := engine.DecideChecked([]*model.WorkloadView{view}, pol)
	if err != nil || len(ds) != 1 || ds[0].Action != model.ActionWarmSwap || !ds[0].Selected {
		t.Fatalf("optimizer decision=%+v err=%v", ds, err)
	}

	releaseReplacementReady := make(chan struct{})
	readyDone := make(chan error, 1)
	go func() {
		<-releaseReplacementReady
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			var current corev1.PodList
			if e := c.List(ctx, &current, client.InNamespace(ns)); e != nil {
				readyDone <- e
				return
			}
			for i := range current.Items {
				q := current.Items[i].DeepCopy()
				if q.UID == oldUID || q.UID == emptyShadow.UID || q.UID == shadow.UID {
					continue
				}
				q.Labels["phorvex.ai/model-loaded"] = "true"
				if e := c.Update(ctx, q); e != nil {
					continue
				}
				q.Status.Phase = corev1.PodRunning
				q.Status.PodIP = host
				q.Status.PodIPs = []corev1.PodIP{{IP: host}}
				q.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
				if e := c.Status().Update(ctx, q); e == nil {
					readyDone <- nil
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		readyDone <- fmt.Errorf("replacement never appeared")
	}()
	m := &Manager{policies: map[string]*policyEntry{}, emits: map[string]*emissionHistory{}, Client: c, BoundaryReader: c, Optimizer: engine, Actuator: recording, Clock: exposure.NewClock(), Intents: exposure.NewIntents(), Log: logr.Discard()}
	entry := &policyEntry{key: types.NamespacedName{Namespace: ns, Name: policy.Name}, uid: string(policy.UID), tenant: "m034", namespace: ns, spec: policy.Spec}
	if n := m.actuate(ctx, entry, pol, ds, map[string]*model.WorkloadView{ns + "/" + old.Name: view}); n != 0 || ds[0].Actuated || recording.err == nil || recording.result.Emitted {
		t.Fatalf("runner must retain the controller-readiness interval as partial: n=%d result=%+v err=%v decision=%+v", n, recording.result, recording.err, ds[0])
	}
	close(releaseReplacementReady)
	if e := <-readyDone; e != nil {
		t.Fatal(e)
	}
	m034Poll(t, 10*time.Second, func() (bool, error) {
		events, recoverErr := native.RecoverOperations(ctx, false)
		if recoverErr != nil {
			return false, recoverErr
		}
		return len(events) == 1 && events[0].Outcome == "confirmed", nil
	})
	var after corev1.PodList
	if err := c.List(ctx, &after, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	foundOld := false
	var retainedEmpty, survivor, replacement *corev1.Pod
	for i := range after.Items {
		if after.Items[i].UID == oldUID {
			foundOld = true
		}
		if after.Items[i].UID == shadow.UID {
			survivor = after.Items[i].DeepCopy()
		}
		if after.Items[i].UID == emptyShadow.UID {
			retainedEmpty = after.Items[i].DeepCopy()
		}
		if after.Items[i].UID != oldUID && after.Items[i].UID != emptyShadow.UID && after.Items[i].UID != shadow.UID {
			replacement = after.Items[i].DeepCopy()
		}
	}
	ready := func(p *corev1.Pod) bool {
		if p == nil || p.DeletionTimestamp != nil {
			return false
		}
		for _, condition := range p.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				return true
			}
		}
		return false
	}
	if foundOld || survivor == nil || survivor.Labels["phorvex.ai/role"] != "leader" || !ready(survivor) {
		t.Fatalf("exact old UID not retired or survivor not a Ready leader: old=%t survivor=%+v", foundOld, survivor)
	}
	if survivor.UID != shadow.UID {
		t.Fatalf("Native selected a different warm candidate UID: got=%s want=%s", survivor.UID, shadow.UID)
	}
	if retainedEmpty == nil || retainedEmpty.Labels["phorvex.ai/role"] != "warm-shadow" || !ready(retainedEmpty) {
		t.Fatalf("older empty-inventory candidate was mutated or removed: %+v", retainedEmpty)
	}
	if replacement == nil {
		t.Fatalf("controller did not create an exact replacement: pods=%+v", after.Items)
	}
	owner := metav1.GetControllerOf(replacement)
	if owner == nil || owner.UID != rs.UID || replacement.Labels["phorvex.ai/role"] != "warm-shadow" ||
		replacement.Labels["phorvex.ai/model-loaded"] != "true" || !ready(replacement) || len(replacement.Spec.EphemeralContainers) != 0 {
		t.Fatalf("controller replacement is not the exact clean Ready warm shadow: replacement=%+v owner=%+v", replacement, owner)
	}
	var journals corev1.ConfigMapList
	if err := c.List(ctx, &journals, client.InNamespace("m034-operator")); err != nil || len(journals.Items) != 0 {
		t.Fatalf("completed recovery retained operation journals: count=%d err=%v", len(journals.Items), err)
	}
	m034Poll(t, 20*time.Second, func() (bool, error) {
		var slices discoveryv1.EndpointSliceList
		if err := c.List(ctx, &slices, client.InNamespace(ns), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}); err != nil {
			return false, err
		}
		for i := range slices.Items {
			for j := range slices.Items[i].Endpoints {
				ref := slices.Items[i].Endpoints[j].TargetRef
				if ref != nil && ref.UID == survivor.UID {
					return true, nil
				}
			}
		}
		return false, nil
	})
	servingMu.Lock()
	defer servingMu.Unlock()
	if len(servingCalls) == 0 {
		t.Fatal("authenticated loopback serving backend was not reached")
	}
	for _, call := range servingCalls {
		if !strings.HasSuffix(call, " Bearer m078-trusted-token") {
			t.Fatalf("serving request escaped the trusted binding: %q", call)
		}
	}
	modelGets := make([]string, 0, 2)
	gets, posts := 0, 0
	for _, call := range servingCalls {
		if strings.HasPrefix(call, "GET ") {
			gets++
		}
		if strings.HasPrefix(call, "GET /models-") {
			modelGets = append(modelGets, strings.Fields(call)[1])
		}
		if strings.HasPrefix(call, "POST ") {
			posts++
		}
	}
	if strings.Join(modelGets, ",") != "/models-empty,/models-loaded" || gets != 4 || posts != 1 {
		t.Fatalf("readiness/drain requests do not prove empty-oldest then loaded-younger selection: calls=%v modelGETs=%v GETs=%d POSTs=%d", servingCalls, modelGets, gets, posts)
	}
}
