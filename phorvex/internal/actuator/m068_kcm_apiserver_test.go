package actuator

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM068RegisteredScalarModelShardUsesReplicaSetController(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if kcm == "" {
		var lookupErr error
		kcm, lookupErr = exec.LookPath("kube-controller-manager")
		if lookupErr != nil {
			t.Skip("requires local Kubernetes v1.34.0 kube-controller-manager via KUBE_CONTROLLER_MANAGER or PATH")
		}
	}
	if _, err := os.Stat(kcm); err != nil {
		t.Skip("configured kube-controller-manager unavailable")
	}
	version, err := exec.Command(kcm, "--version").Output()
	if err != nil || !strings.Contains(string(version), "v1.34.0") {
		t.Fatalf("local kube-controller-manager must be v1.34.0: output=%q err=%v", string(version), err)
	}

	localOnly := false
	environment := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, UseExistingCluster: &localOnly}
	cfg, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = environment.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	privateKubeconfig := m066Kubeconfig(t, cfg)
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+privateKubeconfig, "--controllers=replicaset,endpointslice", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = []string{"KUBECONFIG=" + privateKubeconfig}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KUBECONFIG=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	var kcmLog m066BoundedLog
	cmd.Stdout, cmd.Stderr = &kcmLog, &kcmLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "m068-node"}}); err != nil {
		t.Fatal(err)
	}
	m068AssertRealAPIParallelGroupRefusal(t, ctx, c)

	// model-shard-replace drains through the operation-bound v11 protocol, which
	// requires secure serving credentials and a bound guardrail+vllm participant
	// (b9f738cb). The shared M067 TLS producer serves readiness and v11 drain.
	scalarBackend, scalarEndpoint := m067StartBackend(t, "confirmed")
	scalarHost, scalarPortText := scalarEndpoint.host, scalarEndpoint.portText

	const (
		tenantNS = "m068-scalar-shard"
		operator = "m068-operator"
		shard    = "shard-a"
	)
	for _, namespace := range []string{tenantNS, operator} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
			t.Fatal(err)
		}
	}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: "serving"}, Spec: corev1.ServiceSpec{
		Selector: map[string]string{"app": "m068", labelModelShard: shard, labelRole: roleLeader},
		Ports:    []corev1.ServicePort{{Port: 8000}},
	}}
	if err := c.Create(ctx, service); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode:     v1alpha1.ModeActive,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m068"}},
		Budget: v1alpha1.BudgetSpec{
			TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionModelShardReplace)}},
	}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	count := int32(2)
	zero := int64(0)
	replicaSet := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: "pool"}, Spec: appsv1.ReplicaSetSpec{
		Replicas: &count,
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "m068", labelModelShard: shard}},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{"app": "m068", labelModelShard: shard, labelRole: roleShadow, labelModelLoaded: "false"},
			Annotations: map[string]string{annoRouteService: service.Name, annoServingPort: scalarPortText, "phorvex.ai/model-id": "declared-model", annoDrainProxySource: m067DrainProxySource, annoDrainEngineSource: m067DrainEngineSource},
		}, Spec: corev1.PodSpec{NodeName: "m068-node", ServiceAccountName: "model-sa", TerminationGracePeriodSeconds: &zero, Containers: []corev1.Container{{Name: "guardrail", Image: "registry.k8s.io/pause:3.10"}, {Name: "vllm", Image: "registry.k8s.io/pause:3.10"}}}},
	}}
	if err := c.Create(ctx, replicaSet); err != nil {
		t.Fatal(err)
	}
	var members corev1.PodList
	m066Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &members, client.InNamespace(tenantNS)); err != nil {
			return false, err
		}
		current := &appsv1.ReplicaSet{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: replicaSet.Name}, current); err != nil {
			return false, err
		}
		return len(members.Items) == 2 && current.Status.ObservedGeneration == current.Generation && current.Status.Replicas == count, nil
	})
	leader, shadow := members.Items[0].DeepCopy(), members.Items[1].DeepCopy()
	leader.Labels[labelRole] = roleLeader
	if err := c.Update(ctx, leader); err != nil {
		t.Fatal(err)
	}
	shadow.Labels[labelModelLoaded] = "true"
	if err := c.Update(ctx, shadow); err != nil {
		t.Fatal(err)
	}
	m067SetDrainParticipantReady(t, ctx, c, leader, scalarHost)
	m067SetDrainParticipantReady(t, ctx, c, shadow, scalarHost)
	scalarBackend.mu.Lock()
	scalarBackend.podUID = string(leader.UID)
	scalarBackend.mu.Unlock()
	if err := c.Get(ctx, client.ObjectKeyFromObject(service), service); err != nil {
		t.Fatal(err)
	}
	m066WaitExactRoute(t, ctx, c, service, leader)
	if _, registered := HandlerRegistry.Get(string(model.ActionModelShardReplace)); !registered {
		t.Fatal("model-shard-replace handler is not registered")
	}
	guard := &m066NoPodCreate{WithWatch: c}
	native := NewNativeActuator(guard)
	native.Reader, native.JournalNamespace = c, operator
	servingSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: operator, Name: "serving-admin"}, Data: map[string][]byte{"bearer": []byte("m067-token"), "ca.crt": scalarEndpoint.ca}}
	if err := c.Create(ctx, servingSecret); err != nil {
		t.Fatal(err)
	}
	native.SetServingSecurity(writeServingSecurityConfig(t, ServingSecuritySecureRequired, operator, []ServingSecurityBinding{{
		Namespace: tenantNS, PolicyName: policy.Name, PolicyUID: string(policy.UID), ServiceAccount: "model-sa",
		ProfileID: "m068", SecretName: servingSecret.Name, BearerKey: "bearer", CAKey: "ca.crt", ServerName: scalarEndpoint.serverName,
	}}))
	if err := native.EnsurePolicy(ctx, TenantTarget{Tenant: "tenant-a", Namespace: tenantNS, PolicyName: policy.Name, PolicyUID: string(policy.UID)}); err != nil {
		t.Fatal(err)
	}
	request := Request{Tenant: "tenant-a", Namespace: tenantNS, Pod: leader.Name, TargetUID: string(leader.UID), Action: model.ActionModelShardReplace, PolicyName: policy.Name, PolicyUID: string(policy.UID)}
	result, enactErr := native.Actuate(ctx, request)
	if guard.attempts != 0 {
		t.Fatalf("registered Native dispatch attempted competing Pod Create: %d", guard.attempts)
	}
	if enactErr == nil || result.MutationKind != "swap" || result.Handler != string(model.ActionModelShardReplace) {
		t.Fatalf("scalar registered dispatch did not reach protected pending lifecycle: result=%+v err=%v kcm=%s", result, enactErr, kcmLog.String())
	}
	if posts, requests := scalarBackend.counts(); posts != 1 {
		t.Fatalf("scalar registered Native positive did not reach exactly one operation-bound drain create: posts=%d requests=%v", posts, requests)
	}

	var replacement *corev1.Pod
	m066Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &members, client.InNamespace(tenantNS)); err != nil {
			return false, err
		}
		var candidate *corev1.Pod
		oldPresent, survivorPresent, controlled := false, false, 0
		for i := range members.Items {
			pod := &members.Items[i]
			if pod.UID == leader.UID {
				oldPresent = true
			}
			owner := metav1.GetControllerOf(pod)
			if owner == nil || owner.UID != replicaSet.UID || pod.DeletionTimestamp != nil {
				continue
			}
			controlled++
			if pod.UID == shadow.UID {
				survivorPresent = true
			} else if pod.UID != leader.UID {
				if candidate != nil {
					return false, fmt.Errorf("multiple new scalar shard members")
				}
				candidate = pod
			}
		}
		if oldPresent || !survivorPresent || candidate == nil || controlled != int(count) {
			return false, nil
		}
		replacement = candidate.DeepCopy()
		return true, nil
	})
	if replacement.Labels[labelParallelGroup] != "" || replacement.Labels[labelRole] != roleShadow {
		t.Fatalf("controller replacement is not a clean scalar shadow: %+v", replacement.Labels)
	}
	if owner := metav1.GetControllerOf(replacement); owner == nil || owner.UID != replicaSet.UID {
		t.Fatalf("controller replacement owner = %+v", replacement.OwnerReferences)
	}
	replacement.Labels[labelModelLoaded] = "true"
	if err := c.Update(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	m067SetDrainParticipantReady(t, ctx, c, replacement, scalarHost)
	native.RecoveryVLLM = &mockVLLM{loaded: true}
	var events []RecoveryEvent
	m066Poll(t, 10*time.Second, func() (bool, error) {
		var recoverErr error
		events, recoverErr = native.RecoverOperations(ctx, false)
		if recoverErr != nil {
			return false, recoverErr
		}
		return len(events) == 1 && events[0].Outcome == "confirmed", nil
	})
	if guard.attempts != 0 {
		t.Fatalf("scalar recovery attempted competing Pod Create: %d", guard.attempts)
	}
	if events[0].TargetUID != string(leader.UID) || !strings.Contains(events[0].Effect, "controller pool replenished") {
		t.Fatalf("scalar recovery event = %+v", events[0])
	}
	t.Logf("M068 scalar positive: registered Native dispatch confirmed controller replacement UID %s", replacement.UID)
}

func m068AssertRealAPIParallelGroupRefusal(t *testing.T, ctx context.Context, c client.WithWatch) {
	t.Helper()
	const namespace = "m068-group-refusal"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode:     v1alpha1.ModeActive,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m068-group"}},
		Budget: v1alpha1.BudgetSpec{
			TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionModelShardReplace)}},
	}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}

	var httpCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"data":[{"id":"model"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(server.Close)
	host, rawPort, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace,
		Name:      "leader",
		Labels: map[string]string{
			"app": "m068-group", labelModelShard: "shard-a", labelParallelGroup: "parallel-a", labelRank: "0", labelRole: roleLeader,
		},
		Annotations: map[string]string{annoServingPort: strconv.Itoa(port), "phorvex.ai/model-id": "model", annoParallelSize: "1"},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}
	if err := c.Create(ctx, target); err != nil {
		t.Fatal(err)
	}
	target.Status.Phase = corev1.PodRunning
	target.Status.PodIP = host
	target.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := c.Status().Update(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(target), target); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(policy), policy); err != nil {
		t.Fatal(err)
	}

	spy := &m087Spy{}
	writer := m087WrappedClient{Client: c, spy: spy}
	native := NewNativeActuator(writer)
	native.SetBoundaryReader(c)
	native.SetServingSecurity(legacyServingSecurityForTest(t))
	if err := native.EnsurePolicy(ctx, TenantTarget{Tenant: "tenant-a", Namespace: namespace, PolicyName: policy.Name, PolicyUID: string(policy.UID)}); err != nil {
		t.Fatal(err)
	}
	request := Request{
		Tenant: "tenant-a", Namespace: namespace, Pod: target.Name, TargetUID: string(target.UID), Action: model.ActionModelShardReplace,
		PolicyName: policy.Name, PolicyUID: string(policy.UID),
	}
	result, err := native.Actuate(ctx, request)
	if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || result.Handler != string(model.ActionModelShardReplace) || !strings.Contains(result.Note, ReasonParallelGroupUnavailable) {
		t.Fatalf("real API grouped refusal = %+v, %v", result, err)
	}
	if spy.writes != 0 {
		t.Fatalf("real API grouped refusal crossed Kubernetes write boundary: %d", spy.writes)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("real API grouped refusal crossed serving HTTP boundary: %d", got)
	}
	current := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(target), current); err != nil {
		t.Fatal(err)
	}
	if current.UID != target.UID || current.Labels[labelRole] != roleLeader || current.Labels[labelParallelGroup] != "parallel-a" {
		t.Fatalf("real API grouped target changed after refusal: uid=%s labels=%v", current.UID, current.Labels)
	}
}
