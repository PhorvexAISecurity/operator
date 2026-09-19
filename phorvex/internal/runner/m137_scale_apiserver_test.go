//go:build phorvex_scale

package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/scaleprobe"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type m137HTTPCounts struct {
	mu     sync.Mutex
	counts map[string]int64
}

func newM137HTTPCounts() *m137HTTPCounts { return &m137HTTPCounts{counts: map[string]int64{}} }

func (c *m137HTTPCounts) wrap(origin string, prior func(http.RoundTripper) http.RoundTripper) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		if prior != nil {
			next = prior(next)
		}
		return m137CountingRoundTripper{next: next, origin: origin, counts: c}
	}
}

func (c *m137HTTPCounts) reset() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	before := make(map[string]int64, len(c.counts))
	for key, value := range c.counts {
		before[key] = value
	}
	c.counts = map[string]int64{}
	return before
}

func (c *m137HTTPCounts) snapshot() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.counts))
	for key, value := range c.counts {
		out[key] = value
	}
	return out
}

type m137CountingRoundTripper struct {
	next   http.RoundTripper
	origin string
	counts *m137HTTPCounts
}

func (r m137CountingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	key := r.origin + "|" + m137RequestClass(req)
	r.counts.mu.Lock()
	r.counts.counts[key]++
	r.counts.mu.Unlock()
	return r.next.RoundTrip(req)
}

func m137RequestClass(req *http.Request) string {
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	resourceIndex := -1
	for i, part := range parts {
		switch part {
		case "api":
			resourceIndex = i + 2
		case "apis":
			resourceIndex = i + 3
		}
	}
	if resourceIndex < 0 || resourceIndex >= len(parts) {
		return req.Method + "|unknown|-"
	}
	if parts[resourceIndex] == "namespaces" {
		resourceIndex += 2
	}
	if resourceIndex >= len(parts) {
		return req.Method + "|unknown|-"
	}
	resource, subresource := parts[resourceIndex], "-"
	collection := len(parts) == resourceIndex+1
	if len(parts) > resourceIndex+2 {
		subresource = parts[resourceIndex+2]
	}
	verb := req.Method
	if req.Method == http.MethodGet {
		switch {
		case req.URL.Query().Get("watch") == "true":
			verb = "WATCH"
		case collection:
			verb = "LIST"
		default:
			verb = "GET"
		}
	}
	return verb + "|" + resource + "|" + subresource
}

func m137CountedConfig(base *rest.Config, origin string, counts *m137HTTPCounts) *rest.Config {
	cfg := rest.CopyConfig(base)
	cfg.WrapTransport = counts.wrap(origin, cfg.WrapTransport)
	return cfg
}

func m137RESTBinding(cfg *rest.Config) scaleprobe.RESTConfig {
	rateLimiter := fmt.Sprintf("configured:%T", cfg.RateLimiter)
	qps, burst := cfg.QPS, cfg.Burst
	if cfg.RateLimiter == nil {
		if qps == 0 {
			qps = rest.DefaultQPS
		}
		if burst == 0 {
			burst = rest.DefaultBurst
		}
		if qps > 0 {
			rateLimiter = "client-go-token-bucket-effective-qps-burst"
		} else {
			rateLimiter = "none"
		}
	}
	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = rest.DefaultKubernetesUserAgent()
	}
	return scaleprobe.RESTConfig{Server: cfg.Host, QPS: qps, Burst: burst, Timeout: cfg.Timeout.String(), RateLimiter: rateLimiter, UserAgent: userAgent}
}

type m137BoundedAudit struct {
	mu               sync.Mutex
	maxBytes         int
	retained         bytes.Buffer
	decisions        int
	selectedFeasible int
	dropped          int
	lastByAsset      map[string]m137DecisionWitness
}

type m137DecisionWitness struct {
	AssetUID      string
	Selected      bool
	Feasible      bool
	Action        string
	Reason        string
	InfeasibleWhy string
}

func (w *m137BoundedAudit) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if bytes.Contains(p, []byte(`"kind":"phorvex.decision"`)) {
		w.decisions++
		if bytes.Contains(p, []byte(`"selected":true`)) && bytes.Contains(p, []byte(`"feasible":true`)) {
			w.selectedFeasible++
		}
		var record struct {
			Namespace     string `json:"namespace"`
			Pod           string `json:"pod"`
			Action        string `json:"action"`
			Selected      bool   `json:"selected"`
			Feasible      bool   `json:"feasible"`
			Reason        string `json:"reason"`
			InfeasibleWhy string `json:"infeasibleWhy"`
			DecisionTrace struct {
				AssetUID string `json:"assetUID"`
			} `json:"decisionTrace"`
		}
		if json.Unmarshal(p, &record) == nil && record.Namespace != "" && record.Pod != "" {
			if w.lastByAsset == nil {
				w.lastByAsset = map[string]m137DecisionWitness{}
			}
			w.lastByAsset[record.Namespace+"/"+record.Pod] = m137DecisionWitness{AssetUID: record.DecisionTrace.AssetUID, Selected: record.Selected, Feasible: record.Feasible, Action: record.Action, Reason: record.Reason, InfeasibleWhy: record.InfeasibleWhy}
		}
	}
	remaining := w.maxBytes - w.retained.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = w.retained.Write(p[:remaining])
	}
	if remaining < len(p) {
		w.dropped += len(p) - remaining
	}
	return len(p), nil
}

func (w *m137BoundedAudit) decisionWitness(key string) m137DecisionWitness {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastByAsset[key]
}

func (w *m137BoundedAudit) resetDecisionWitnesses() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastByAsset = map[string]m137DecisionWitness{}
}

func (w *m137BoundedAudit) decisionStats() (decisions, selectedFeasible int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.decisions, w.selectedFeasible
}

func (w *m137BoundedAudit) storage() (retained, dropped int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.retained.Len(), w.dropped
}

type m137ScaleConfig struct {
	name, selector                              string
	pods, namespaces, policies, samples, warmup int
	timeout                                     time.Duration
}

func m137FixtureReport(cfg m137ScaleConfig, auditLimit int) scaleprobe.Fixture {
	report := scaleprobe.Fixture{Case: cfg.name, Backend: "native-dry-run", CacheReader: "controller-runtime-cache", ReceiptReader: "direct-api-reader", OwnerReader: "snapshot-local deduplicated direct-api-reader", TransportCoverage: "fixture/cache/manager/direct/convergence REST transports counted; convergence traffic reported separately; envtest control-plane internals and metric gathers uncounted", Optimizer: "production decision.CoverageEngine", TelemetrySource: "honest-absent local source; no external Prometheus transport", Calibration: "production calibration runtime enabled; warm-up establishes current schedule", Readiness: "Deployment, ReplicaSet and Pod readiness/status manually seeded consistently; no kube-controller-manager or scheduler", SelectorMode: cfg.selector, Deployments: cfg.namespaces, ReplicaSets: cfg.namespaces, Pods: cfg.pods, Namespaces: cfg.namespaces, Policies: cfg.policies, PoliciesPerNS: cfg.policies / cfg.namespaces, Nodes: 2, ServiceAccounts: cfg.namespaces, Services: cfg.namespaces, PDBs: cfg.namespaces, NetworkPolicies: cfg.namespaces, Roles: cfg.namespaces, RoleBindings: cfg.namespaces, ClusterRoles: 1, ClusterBindings: 1, SecurityEvents: 2, Receipts: 1, BrakeConfigMaps: cfg.namespaces, WarmupTicks: cfg.warmup, RequestedAttempts: cfg.samples, TickTimeoutMS: cfg.timeout.Milliseconds(), TickIntervalMS: 20000, AntiOverRotationMS: 1, ProactiveFloorMS: (10 * time.Minute).Milliseconds(), SampleCadence: "fixed attempt budget, forced due after cached policy resourceVersion/status exactly match authoritative post-tick reads; no retry-to-success and convergence waits/GETs excluded from measured manager duration and sampled producer traffic", AuditByteLimit: auditLimit, MetricsSink: "controller-runtime process registry with a bounded instrumented audit sink; fixed outcome and declared tenant labels", TrustFixture: "source-shaped synthetic creator annotation; admission stamp/policy not installed"}
	if cfg.selector == "partitioned" {
		report.PodsPerPolicy = cfg.pods / cfg.policies
	} else {
		report.PodsPerPolicy = cfg.pods / cfg.namespaces
	}
	return report
}

func m137ScaleConfigFromEnv(t *testing.T) m137ScaleConfig {
	t.Helper()
	integer := func(name string, fallback int) int {
		if os.Getenv(name) == "" {
			return fallback
		}
		value, err := strconv.Atoi(os.Getenv(name))
		if err != nil || value <= 0 {
			t.Fatalf("%s=%q must be a positive integer", name, os.Getenv(name))
		}
		return value
	}
	selector := os.Getenv("PHORVEX_M137_SELECTOR_MODE")
	if selector == "" {
		selector = "partitioned"
	}
	if selector != "partitioned" && selector != "overlapping" {
		t.Fatalf("PHORVEX_M137_SELECTOR_MODE=%q", selector)
	}
	cfg := m137ScaleConfig{
		name: os.Getenv("PHORVEX_M137_CASE"), selector: selector,
		pods: integer("PHORVEX_M137_PODS", 32), namespaces: integer("PHORVEX_M137_NAMESPACES", 2),
		policies: integer("PHORVEX_M137_POLICIES", 2), samples: integer("PHORVEX_M137_SAMPLES", 20),
		warmup: integer("PHORVEX_M137_WARMUP", 2), timeout: time.Duration(integer("PHORVEX_M137_TIMEOUT_MS", 30000)) * time.Millisecond,
	}
	if cfg.name == "" {
		cfg.name = fmt.Sprintf("pods-%d-policies-%d-%s", cfg.pods, cfg.policies, cfg.selector)
	}
	if cfg.samples < 20 || cfg.namespaces < 2 || cfg.policies < cfg.namespaces || cfg.policies%cfg.namespaces != 0 || cfg.pods < cfg.policies || cfg.pods%cfg.namespaces != 0 || cfg.pods/cfg.namespaces < 2 {
		t.Fatalf("invalid predeclared case: %+v", cfg)
	}
	if cfg.selector == "partitioned" && cfg.pods%cfg.policies != 0 {
		t.Fatalf("partitioned case must divide pods evenly across policies: %+v", cfg)
	}
	return cfg
}

type m137Fixture struct {
	policies                           []*v1alpha1.PhorvexPolicy
	firstPod                           client.ObjectKey
	firstUID                           string
	receiptPod                         client.ObjectKey
	receiptTargetUID                   string
	eventName, receiptName, receiptUID string
	ownerUIDByNamespace                map[string]string
}

func m137ExactRBAC(cfg m137ScaleConfig, roles []rbacv1.Role, bindings []rbacv1.RoleBinding, clusterRoles []rbacv1.ClusterRole, clusterBindings []rbacv1.ClusterRoleBinding) bool {
	rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"get", "list"}}}
	for nsIndex := 0; nsIndex < cfg.namespaces; nsIndex++ {
		ns := fmt.Sprintf("m137-%02d", nsIndex)
		roleOK, bindingOK := false, false
		for i := range roles {
			roleOK = roleOK || roles[i].Namespace == ns && roles[i].Name == "scale" && reflect.DeepEqual(roles[i].Rules, rules)
		}
		expectedRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "scale"}
		expectedSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: "scale"}}
		for i := range bindings {
			bindingOK = bindingOK || bindings[i].Namespace == ns && bindings[i].Name == "scale" && bindings[i].RoleRef == expectedRef && reflect.DeepEqual(bindings[i].Subjects, expectedSubjects)
		}
		if !roleOK || !bindingOK {
			return false
		}
	}
	expectedClusterRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "m137-scale"}
	expectedClusterSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "m137-00", Name: "scale"}}
	clusterRoleOK, clusterBindingOK := false, false
	for i := range clusterRoles {
		clusterRoleOK = clusterRoleOK || clusterRoles[i].Name == "m137-scale" && reflect.DeepEqual(clusterRoles[i].Rules, rules)
	}
	for i := range clusterBindings {
		clusterBindingOK = clusterBindingOK || clusterBindings[i].Name == "m137-scale" && clusterBindings[i].RoleRef == expectedClusterRef && reflect.DeepEqual(clusterBindings[i].Subjects, expectedClusterSubjects)
	}
	return clusterRoleOK && clusterBindingOK
}

func m137ContainsNeighbor(neighbors []string, expected string) bool {
	for _, neighbor := range neighbors {
		if neighbor == expected {
			return true
		}
	}
	return false
}

func TestM137CorrectnessWitnessRejectsCounterexamples(t *testing.T) {
	cfg := m137ScaleConfig{namespaces: 2}
	rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"get", "list"}}}
	roles := []rbacv1.Role{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "m137-00", Name: "scale"}, Rules: rules},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "m137-01", Name: "scale"}, Rules: rules},
	}
	bindings := []rbacv1.RoleBinding{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "m137-00", Name: "scale"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "scale"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "m137-00", Name: "scale"}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "m137-01", Name: "scale"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "scale"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "m137-01", Name: "scale"}}},
	}
	clusterRoles := []rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: "m137-scale"}, Rules: rules}}
	clusterBindings := []rbacv1.ClusterRoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "m137-scale"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "m137-scale"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "m137-00", Name: "scale"}}}}
	if !m137ExactRBAC(cfg, roles, bindings, clusterRoles, clusterBindings) {
		t.Fatal("exact RBAC witness rejected")
	}
	bindings[1].Subjects[0].Name = "unrelated"
	if m137ExactRBAC(cfg, roles, bindings, clusterRoles, clusterBindings) {
		t.Fatal("unrelated RoleBinding subject accepted")
	}
	bindings[1].Subjects[0].Name = "scale"
	bindings[1].RoleRef.Name = "unrelated"
	if m137ExactRBAC(cfg, roles, bindings, clusterRoles, clusterBindings) {
		t.Fatal("unrelated RoleBinding roleRef accepted")
	}
	if m137ContainsNeighbor([]string{"m137-00/pod-0001"}, "m137-01/pod-0000") {
		t.Fatal("same-namespace edge satisfied cross-namespace witness")
	}
}

func m137CreateFixture(t *testing.T, ctx context.Context, c client.Client, cfg m137ScaleConfig) m137Fixture {
	t.Helper()
	create := func(obj client.Object) {
		t.Helper()
		if err := c.Create(ctx, obj); err != nil {
			t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
		}
	}
	fixture := m137Fixture{eventName: "m137-trusted-event", receiptName: "m137-receipt", ownerUIDByNamespace: map[string]string{}}
	policiesPerNS := cfg.policies / cfg.namespaces
	podsPerNS := cfg.pods / cfg.namespaces
	for nsIndex := 0; nsIndex < cfg.namespaces; nsIndex++ {
		ns := fmt.Sprintf("m137-%02d", nsIndex)
		desiredReplicas := int32(podsPerNS)
		create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"m137-scale": "true"}}})
		create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultKillSwitchName}, Data: map[string]string{"engaged": "false", "calibrationFrozen": "false"}})
		create(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "scale"}})
		deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "scale"}, Spec: appsv1.DeploymentSpec{Replicas: &desiredReplicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "m137"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "m137"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "serve", Image: "fixture.invalid/m137"}}}}}}
		create(deployment)
		deployment.Status.ObservedGeneration = deployment.Generation
		deployment.Status.Replicas = desiredReplicas
		deployment.Status.UpdatedReplicas = desiredReplicas
		deployment.Status.ReadyReplicas = desiredReplicas
		deployment.Status.AvailableReplicas = desiredReplicas
		if err := c.Status().Update(ctx, deployment); err != nil {
			t.Fatal(err)
		}
		controller := true
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "scale", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name, UID: deployment.UID, Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Replicas: &desiredReplicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "m137"}}, Template: deployment.Spec.Template}}
		create(rs)
		fixture.ownerUIDByNamespace[ns] = string(rs.UID)
		var currentRS appsv1.ReplicaSet
		if err := c.Get(ctx, client.ObjectKeyFromObject(rs), &currentRS); err != nil {
			t.Fatal(err)
		}
		currentRS.Status.ObservedGeneration = currentRS.Generation
		currentRS.Status.Replicas, currentRS.Status.ReadyReplicas = desiredReplicas, desiredReplicas
		if err := c.Status().Update(ctx, &currentRS); err != nil {
			t.Fatal(err)
		}
		create(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "scale"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "m137"}, Ports: []corev1.ServicePort{{Port: 80}}}})
		minAvailable := intstr.FromInt(1)
		create(&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "scale"}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailable, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "m137"}}}})
		create(&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "cross-namespace"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m137"}}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"m137-scale": "true"}}}}}}}})
		create(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "scale"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"get", "list"}}}})
		create(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "scale"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "scale"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: "scale"}}})

		for localPolicy := 0; localPolicy < policiesPerNS; localPolicy++ {
			selector := map[string]string{"app": "m137"}
			if cfg.selector == "partitioned" {
				selector["m137-policy"] = strconv.Itoa(localPolicy)
			}
			policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: fmt.Sprintf("policy-%02d", localPolicy)}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: fmt.Sprintf("tenant-%02d-%02d", nsIndex, localPolicy), Selector: metav1.LabelSelector{MatchLabels: selector}, Mode: v1alpha1.ModeDryRun, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Millisecond}, ProactiveFloor: metav1.Duration{Duration: 10 * time.Minute}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}}}}
			create(policy)
			policy.Status.Conditions = []metav1.Condition{{Type: "ValidationError", Status: metav1.ConditionFalse, Reason: "M137Preserve", Message: "scale fixture controller-owned preservation marker", ObservedGeneration: policy.Generation, LastTransitionTime: metav1.Now()}}
			if err := c.Status().Update(ctx, policy); err != nil {
				t.Fatal(err)
			}
			fixture.policies = append(fixture.policies, policy)
		}
		for podIndex := 0; podIndex < podsPerNS; podIndex++ {
			labels := map[string]string{"app": "m137", "m137-policy": strconv.Itoa(podIndex % policiesPerNS)}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: fmt.Sprintf("pod-%04d", podIndex), Labels: labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: fmt.Sprintf("node-%02d", podIndex%2), ServiceAccountName: "scale", Containers: []corev1.Container{{Name: "serve", Image: "fixture.invalid/m137"}}}}
			create(pod)
			var currentPod corev1.Pod
			if err := c.Get(ctx, client.ObjectKeyFromObject(pod), &currentPod); err != nil {
				t.Fatal(err)
			}
			now := metav1.Now()
			currentPod.Status.Phase = corev1.PodRunning
			currentPod.Status.StartTime = &now
			currentPod.Status.PodIP = fmt.Sprintf("10.%d.%d.%d", nsIndex+1, podIndex/250, podIndex%250+1)
			currentPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: now}}
			currentPod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "serve", Ready: true, Image: "fixture.invalid/m137", ImageID: "fixture.invalid/m137@sha256:137"}}
			if err := c.Status().Update(ctx, &currentPod); err != nil {
				t.Fatal(err)
			}
			if nsIndex == 0 && podIndex == 0 {
				fixture.firstPod = client.ObjectKeyFromObject(pod)
				fixture.firstUID = string(pod.UID)
			}
			if nsIndex == 0 && podIndex == 1 {
				fixture.receiptPod = client.ObjectKeyFromObject(pod)
				fixture.receiptTargetUID = string(pod.UID)
			}
		}
	}
	for i := 0; i < 2; i++ {
		create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("node-%02d", i), Labels: map[string]string{"m137-scale": "true"}}})
	}
	create(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "m137-scale"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"get", "list"}}}})
	create(&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "m137-scale"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "m137-scale"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "m137-00", Name: "scale"}}})

	score := "0.95"
	trusted := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: fixture.eventName, Annotations: map[string]string{ingest.CreatorIdentityAnnotation: "system:serviceaccount:m137-00:detector"}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{fixture.firstPod.String()}, Rule: amtdv1beta1.Rule{Type: "Panic", ThreatLevel: "high", Source: "m137-source-shaped-detector"}, Description: "source-shaped synthetic scale fixture; no admission chain installed", AnomalyScore: &score}}
	create(trusted)
	receipt := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: fixture.receiptName, Annotations: map[string]string{actuator.PhoenixRotateTargetUIDAnnotation: fixture.receiptTargetUID}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{fixture.receiptPod.String()}, Rule: amtdv1beta1.Rule{Type: actuator.RuleTypeRotate, ThreatLevel: "high", Source: actuator.RuleSource}, Description: "real receipt structure scale fixture distinct from the trusted incident target"}}
	create(receipt)
	fixture.receiptUID = string(receipt.UID)
	var currentReceipt amtdv1beta1.SecurityEvent
	if err := c.Get(ctx, client.ObjectKey{Name: receipt.Name}, &currentReceipt); err != nil {
		t.Fatal(err)
	}
	currentReceipt.Status.AppliedAction = string(model.ActionRotate)
	currentReceipt.Status.ProcessedAt = metav1.Now()
	if err := c.Status().Update(ctx, &currentReceipt); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func m137ForceDue(m *Manager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.policies {
		entry.lastTick = time.Time{}
	}
}

func m137WaitPolicyCache(ctx context.Context, reader, authoritative client.Reader, policies []*v1alpha1.PhorvexPolicy) error {
	type observation struct {
		resourceVersion string
		status          v1alpha1.PhorvexPolicyStatus
	}
	wanted := make(map[client.ObjectKey]observation, len(policies))
	for _, policy := range policies {
		key := client.ObjectKeyFromObject(policy)
		var current v1alpha1.PhorvexPolicy
		if err := authoritative.Get(ctx, key, &current); err != nil {
			return fmt.Errorf("read authoritative policy %s: %w", key, err)
		}
		wanted[key] = observation{resourceVersion: current.ResourceVersion, status: *current.Status.DeepCopy()}
	}
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		converged := true
		for _, policy := range policies {
			key := client.ObjectKeyFromObject(policy)
			var current v1alpha1.PhorvexPolicy
			if err := reader.Get(waitCtx, key, &current); err != nil {
				converged = false
				break
			}
			expected := wanted[key]
			if current.ResourceVersion != expected.resourceVersion || !reflect.DeepEqual(current.Status, expected.status) {
				converged = false
				break
			}
		}
		if converged {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("policy cache did not converge to authoritative resourceVersion/status: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func m137PrimeCache(ctx context.Context, c client.Client) error {
	lists := []client.ObjectList{
		&corev1.PodList{}, &corev1.NamespaceList{}, &corev1.NodeList{}, &corev1.ServiceList{}, &corev1.ConfigMapList{},
		&networkingv1.NetworkPolicyList{}, &policyv1.PodDisruptionBudgetList{},
		&rbacv1.RoleList{}, &rbacv1.RoleBindingList{}, &rbacv1.ClusterRoleList{}, &rbacv1.ClusterRoleBindingList{},
		&v1alpha1.PhorvexPolicyList{},
	}
	for _, list := range lists {
		if err := c.List(ctx, list); err != nil {
			return fmt.Errorf("prime cache for %T: %w", list, err)
		}
	}
	return nil
}

func m137RSS(pid int) int64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				return value * 1024
			}
		}
	}
	return 0
}

func m137ChildProcesses() map[string]int {
	out := map[string]int{}
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil || m137ParentPID(status) != os.Getpid() {
			continue
		}
		cmdline, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		command := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))
		switch {
		case strings.Contains(command, "kube-apiserver"):
			out["apiserver"] = pid
		case strings.Contains(command, "etcd"):
			out["etcd"] = pid
		}
	}
	return out
}

func m137ParentPID(status []byte) int {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 {
			parent, _ := strconv.Atoi(fields[1])
			return parent
		}
	}
	return 0
}

func m137SystemMemory() (total, limit int64) {
	data, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				total, _ = strconv.ParseInt(fields[1], 10, 64)
				total *= 1024
			}
		}
	}
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		value, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(value)) == "max" {
			continue
		}
		limit, _ = strconv.ParseInt(strings.TrimSpace(string(value)), 10, 64)
		if limit > 0 {
			break
		}
	}
	return total, limit
}

func m137GitSHA(t *testing.T) string {
	t.Helper()
	if value := os.Getenv("PHORVEX_M137_SOURCE_SHA"); value != "" {
		return value
	}
	cmd := exec.Command("git", "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}

func m137WriteReport(path string, report scaleprobe.Report) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(report)
	syncErr := file.Sync()
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporary, path)
}

func m137ExecutableSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func m137Slope(values []int64) float64 {
	if len(values) < 2 {
		return 0
	}
	n := float64(len(values))
	var sumX, sumY, sumXY, sumXX float64
	for i, value := range values {
		x, y := float64(i), float64(value)
		sumX, sumY = sumX+x, sumY+y
		sumXY, sumXX = sumXY+x*y, sumXX+x*x
	}
	return (n*sumXY - sumX*sumY) / (n*sumXX - sumX*sumX)
}

type m137DeadlineSource struct {
	once    sync.Once
	entered chan struct{}
}

func (*m137DeadlineSource) Name() string { return "m137-deadline" }
func (s *m137DeadlineSource) PodMetrics(ctx context.Context, _ string, _ []string) (map[string]model.Telemetry, error) {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}

type m137ControlledDeadline struct {
	context.Context
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newM137ControlledDeadline(parent context.Context) *m137ControlledDeadline {
	return &m137ControlledDeadline{Context: parent, done: make(chan struct{})}
}

func (c *m137ControlledDeadline) Done() <-chan struct{} { return c.done }
func (c *m137ControlledDeadline) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
func (c *m137ControlledDeadline) trigger(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.done)
	})
}

func m137Outcome(result tickResult, ctxErr error) string {
	switch result {
	case tickSnapshotSucceeded:
		return "finished-full-snapshot"
	case tickNoSnapshot:
		return "no-snapshot"
	case tickSnapshotFailed:
		return "snapshot-failed"
	default:
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return "deadline"
		}
		return "canceled"
	}
}

func TestM137ScaleHarness(t *testing.T) {
	if os.Getenv("PHORVEX_M137_SCALE") != "1" {
		t.Fatal("PHORVEX_M137_SCALE=1 is required with the phorvex_scale build tag")
	}
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("KUBEBUILDER_ASSETS is required; live-cluster fallback is forbidden")
	}
	if !filepath.IsAbs(os.Getenv("KUBEBUILDER_ASSETS")) {
		t.Fatal("KUBEBUILDER_ASSETS must be an absolute source-bound asset directory")
	}
	if os.Getenv("USE_EXISTING_CLUSTER") != "false" {
		t.Fatal("USE_EXISTING_CLUSTER=false is required")
	}
	output := os.Getenv("PHORVEX_M137_OUTPUT")
	if output == "" {
		t.Fatal("PHORVEX_M137_OUTPUT is required")
	}
	cfg := m137ScaleConfigFromEnv(t)
	local := false
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases", "../../../build/phoenix-extended/config/crd/bases"}, ErrorIfCRDPathMissing: true, UseExistingCluster: &local}
	base, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	report := scaleprobe.Report{SchemaVersion: scaleprobe.SchemaVersion, Fixture: scaleprobe.Fixture{Case: cfg.name, RequestedAttempts: cfg.samples}, ProbeErrors: []string{"harness exited after API start before final report"}}
	reportWritten := false
	defer func() {
		if !reportWritten {
			_ = m137WriteReport(output, report)
		}
	}()
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})

	scheme := kruntime.NewScheme()
	for _, add := range []func(*kruntime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, networkingv1.AddToScheme, policyv1.AddToScheme, rbacv1.AddToScheme, apiextensionsv1.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	counts := newM137HTTPCounts()
	fixtureREST := m137CountedConfig(base, "fixture", counts)
	fixtureClient, err := client.New(fixtureREST, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	previousTrust := ingest.EventTrust()
	ingest.ConfigureEventTrust(ingest.NewTrustedDetectors([]string{"system:serviceaccount:m137-00:detector"}))
	t.Cleanup(func() { ingest.ConfigureEventTrust(previousTrust) })
	fixture := m137CreateFixture(t, ctx, fixtureClient, cfg)

	cacheREST := m137CountedConfig(base, "cache", counts)
	informerCache, err := cache.New(cacheREST, cache.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	cacheCtx, stopCache := context.WithCancel(context.Background())
	cacheDone := make(chan error, 1)
	go func() { cacheDone <- informerCache.Start(cacheCtx) }()
	t.Cleanup(func() {
		stopCache()
		select {
		case err := <-cacheDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("cache shutdown timed out")
		}
	})
	managerREST := m137CountedConfig(base, "manager", counts)
	managerClient, err := client.New(managerREST, client.Options{Scheme: scheme, Cache: &client.CacheOptions{Reader: informerCache}})
	if err != nil {
		t.Fatal(err)
	}
	directREST := m137CountedConfig(base, "direct", counts)
	direct, err := client.New(directREST, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	convergenceREST := m137CountedConfig(base, "convergence", counts)
	convergence, err := client.New(convergenceREST, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManagerWithBackend(managerClient, logr.Discard(), actuator.BackendResolution{Backend: actuator.BackendNative, Source: actuator.SourceExplicit, Raw: "native", Present: true})
	if err != nil {
		t.Fatal(err)
	}
	native := actuator.NewNativeActuator(managerClient)
	native.Reader, native.DryRun = direct, true
	m.Actuator, m.OwnershipReader, m.BoundaryReader, m.VocabularyReader = native, direct, direct, direct
	m.KillSwitch = &KillSwitch{Client: direct, Namespace: "m137-00"}
	m.MetricsSource = nil
	auditSink := &m137BoundedAudit{maxBytes: 2 << 20}
	m.Audit = audit.New(logr.Discard(), auditSink)
	for _, policy := range fixture.policies {
		var current v1alpha1.PhorvexPolicy
		if err := direct.Get(ctx, client.ObjectKeyFromObject(policy), &current); err != nil {
			t.Fatal(err)
		}
		if err := m.Upsert(&current); err != nil {
			t.Fatal(err)
		}
	}
	if err := m137PrimeCache(ctx, managerClient); err != nil {
		t.Fatal(err)
	}
	if !informerCache.WaitForCacheSync(ctx) {
		t.Fatal("cache did not synchronize before warmup")
	}
	children := m137ChildProcesses()
	if children["apiserver"] == 0 || children["etcd"] == 0 {
		t.Fatalf("could not identify separate envtest API server and etcd processes: %v", children)
	}
	totalMemory, limitMemory := m137SystemMemory()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableSHA, err := m137ExecutableSHA256(executable)
	if err != nil {
		t.Fatal(err)
	}
	fixtureReport := m137FixtureReport(cfg, auditSink.maxBytes)
	startupHTTP := counts.reset()
	report = scaleprobe.Report{
		SchemaVersion: scaleprobe.SchemaVersion,
		Environment:   scaleprobe.Environment{GitSHA: m137GitSHA(t), Executable: executable, ExecutableSHA256: executableSHA, GoVersion: runtime.Version(), KubernetesAssets: os.Getenv("KUBEBUILDER_ASSETS"), CPUCount: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), MemoryTotalBytes: totalMemory, MemoryLimitBytes: limitMemory, HarnessPID: os.Getpid(), APIProcessPID: children["apiserver"], EtcdProcessPID: children["etcd"], APIProcessRSSBytes: m137RSS(children["apiserver"]), EtcdProcessRSSBytes: m137RSS(children["etcd"])},
		Fixture:       fixtureReport,
		StartupHTTP:   startupHTTP,
		RESTConfigs:   map[string]scaleprobe.RESTConfig{"fixture": m137RESTBinding(fixtureREST), "cache": m137RESTBinding(cacheREST), "manager": m137RESTBinding(managerREST), "direct": m137RESTBinding(directREST), "convergence": m137RESTBinding(convergenceREST)},
		ProbeErrors:   []string{fmt.Sprintf("harness incomplete before %d post-cache-sync warmups", cfg.warmup)},
	}
	if err := m137WriteReport(output, report); err != nil {
		t.Fatal(err)
	}
	warmups := make([]scaleprobe.Warmup, 0, cfg.warmup)
	for i := 0; i < cfg.warmup; i++ {
		m137ForceDue(m)
		started := time.Now()
		tickCtx, tickCancel := context.WithTimeout(ctx, cfg.timeout)
		result := m.tick(tickCtx)
		ctxErr := tickCtx.Err()
		tickCancel()
		outcome := m137Outcome(result, ctxErr)
		warmupError := ""
		if result != tickSnapshotSucceeded {
			warmupError = fmt.Sprintf("result=%v context=%v", result, ctxErr)
		} else if err := m137WaitPolicyCache(ctx, managerClient, convergence, fixture.policies); err != nil {
			warmupError = "cache convergence: " + err.Error()
		}
		warmups = append(warmups, scaleprobe.Warmup{Index: i, Phase: "post-cache-sync", Outcome: outcome, DurationSec: time.Since(started).Seconds(), Error: warmupError, HTTP: counts.reset()})
		report.Warmups = append([]scaleprobe.Warmup(nil), warmups...)
		report.ProbeErrors = []string{fmt.Sprintf("harness incomplete after %d/%d post-cache-sync warmups", len(warmups), cfg.warmup)}
		if err := m137WriteReport(output, report); err != nil {
			t.Fatal(err)
		}
		if result != tickSnapshotSucceeded {
			t.Fatalf("post-cache-sync warmup %d %s", i, warmupError)
		}
		if warmupError != "" {
			t.Fatalf("post-cache-sync warmup %d %s", i, warmupError)
		}
	}
	var cachedPods corev1.PodList
	if err := managerClient.List(ctx, &cachedPods); err != nil || len(cachedPods.Items) != cfg.pods {
		t.Fatalf("cache convergence pods=%d err=%v", len(cachedPods.Items), err)
	}
	snap, err := ingest.CollectSnapshotForRotationTargetsWithReceiptReader(ctx, managerClient, time.Now(), genericAssetValue, direct, direct, func(*corev1.Pod) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	trustedPresent, receiptPresent := false, false
	for _, event := range snap.Events {
		trustedPresent = trustedPresent || event.Name == fixture.eventName && event.Trust == ingest.TrustTrusted
	}
	if receipt, ok := snap.PhoenixReceipts[fixture.receiptName]; ok {
		receiptPresent = snap.PhoenixReceiptInventoryComplete && receipt.EventName == fixture.receiptName && receipt.EventUID == fixture.receiptUID &&
			receipt.RuleType == actuator.RuleTypeRotate && receipt.ThreatLevel == "high" && receipt.RuleSource == actuator.RuleSource &&
			reflect.DeepEqual(receipt.Targets, []string{fixture.receiptPod.String()}) && receipt.TargetUID == fixture.receiptTargetUID &&
			receipt.AppliedAction == string(model.ActionRotate) && !receipt.CreatedAt.IsZero() && !receipt.ProcessedAt.IsZero() && !receipt.ProcessedAt.Before(receipt.CreatedAt)
	}
	ownerEligible := len(snap.Pods) == cfg.pods
	observedOwnerUIDs := map[string]struct{}{}
	for i := range snap.Pods {
		ownership := snap.Pods[i].RotationOwnership
		expectedUID := fixture.ownerUIDByNamespace[snap.Pods[i].Namespace]
		if !ownership.Eligible || expectedUID == "" || ownership.OwnerUID != expectedUID || ownership.OwnerResourceVersion == "" {
			ownerEligible = false
		}
		observedOwnerUIDs[ownership.OwnerUID] = struct{}{}
	}
	ownerEligible = ownerEligible && len(observedOwnerUIDs) == cfg.namespaces
	var cachedRoles rbacv1.RoleList
	var cachedBindings rbacv1.RoleBindingList
	var cachedClusterRoles rbacv1.ClusterRoleList
	var cachedClusterBindings rbacv1.ClusterRoleBindingList
	if err := managerClient.List(ctx, &cachedRoles); err != nil {
		t.Fatal(err)
	}
	if err := managerClient.List(ctx, &cachedBindings); err != nil {
		t.Fatal(err)
	}
	if err := managerClient.List(ctx, &cachedClusterRoles); err != nil {
		t.Fatal(err)
	}
	if err := managerClient.List(ctx, &cachedClusterBindings); err != nil {
		t.Fatal(err)
	}
	expectedCrossNamespaceNeighbor := "m137-01/pod-0000"
	graphEdges := snap.Graph != nil && m137ContainsNeighbor(snap.Graph.Neighbors(fixture.firstPod.Namespace, fixture.firstPod.Name), expectedCrossNamespaceNeighbor)
	rbacPresent := m137ExactRBAC(cfg, cachedRoles.Items, cachedBindings.Items, cachedClusterRoles.Items, cachedClusterBindings.Items)
	m137MergeHTTP(startupHTTP, counts.reset())
	auditDecisionsBefore, auditSelectedBefore := auditSink.decisionStats()
	auditSink.resetDecisionWitnesses()
	apiRSSBefore := m137RSS(children["apiserver"])
	etcdRSSBefore := m137RSS(children["etcd"])

	var memBefore kruntimeMemStats
	readM137MemStats(&memBefore)
	rssBefore := m137RSS(os.Getpid())
	samples := make([]scaleprobe.Sample, 0, cfg.samples)
	probeErrors := []string{}
	rssValues := make([]int64, 0, cfg.samples)
	heapValues := make([]int64, 0, cfg.samples)
	apiRSSValues := make([]int64, 0, cfg.samples)
	etcdRSSValues := make([]int64, 0, cfg.samples)
	for i := 0; i < cfg.samples; i++ {
		m137ForceDue(m)
		managerBefore := map[string][2]float64{}
		for _, outcome := range []string{"finished-full-snapshot", "no-snapshot", "snapshot-failed", "deadline", "canceled"} {
			count, sum, err := m137HistogramValue("phorvex_manager_tick_duration_seconds", map[string]string{"outcome": outcome})
			if err != nil {
				probeErrors = append(probeErrors, fmt.Sprintf("sample %d manager metric baseline %s: %v", i, outcome, err))
			}
			managerBefore[outcome] = [2]float64{float64(count), sum}
		}
		policyBefore := map[string][2]float64{}
		for _, policy := range fixture.policies {
			count, sum, err := m137HistogramValue("phorvex_tick_duration_seconds", map[string]string{"tenant": policy.Spec.Tenant})
			if err != nil {
				probeErrors = append(probeErrors, fmt.Sprintf("sample %d policy metric baseline %s: %v", i, policy.Spec.Tenant, err))
			}
			policyBefore[policy.Spec.Tenant] = [2]float64{float64(count), sum}
		}
		statusBefore := m137PolicyStatusWrites(counts.snapshot())
		started := time.Now()
		tickCtx, tickCancel := context.WithTimeout(ctx, cfg.timeout)
		result := m.tick(tickCtx)
		ctxErr := tickCtx.Err()
		tickCancel()
		elapsed := time.Since(started).Seconds()
		outcome := m137Outcome(result, ctxErr)
		managerCountAfter, managerSumAfter, managerMetricErr := m137HistogramValue("phorvex_manager_tick_duration_seconds", map[string]string{"outcome": outcome})
		if managerMetricErr != nil {
			probeErrors = append(probeErrors, fmt.Sprintf("sample %d manager metric result %s: %v", i, outcome, managerMetricErr))
		}
		before := managerBefore[outcome]
		metricDuration := managerSumAfter - before[1]
		if managerMetricErr != nil || float64(managerCountAfter)-before[0] != 1 || metricDuration <= 0 || metricDuration > elapsed*1.25 {
			probeErrors = append(probeErrors, fmt.Sprintf("sample %d metric mismatch: result=%v outcome=%s observations=%v duration=%v elapsed=%v", i, result, outcome, float64(managerCountAfter)-before[0], metricDuration, elapsed))
			metricDuration = elapsed
		}
		policySeconds := map[string]float64{}
		for _, policy := range fixture.policies {
			count, sum, err := m137HistogramValue("phorvex_tick_duration_seconds", map[string]string{"tenant": policy.Spec.Tenant})
			if err != nil {
				probeErrors = append(probeErrors, fmt.Sprintf("sample %d policy metric result %s: %v", i, policy.Spec.Tenant, err))
				continue
			}
			prior := policyBefore[policy.Spec.Tenant]
			if float64(count) > prior[0] {
				policySeconds[policy.Spec.Tenant] = sum - prior[1]
			}
		}
		var memory kruntimeMemStats
		readM137MemStats(&memory)
		rss := m137RSS(os.Getpid())
		rssValues = append(rssValues, rss)
		heapValues = append(heapValues, int64(memory.HeapAlloc))
		apiRSSValues = append(apiRSSValues, m137RSS(children["apiserver"]))
		etcdRSSValues = append(etcdRSSValues, m137RSS(children["etcd"]))
		sampleError := ""
		if outcome != "finished-full-snapshot" {
			sampleError = fmt.Sprintf("workload attempt did not finish: result=%v context=%v", result, ctxErr)
		}
		samples = append(samples, scaleprobe.Sample{Index: i, Outcome: outcome, DurationSec: metricDuration, PolicySeconds: policySeconds, HeapBytes: memory.HeapAlloc, RSSBytes: rss, StatusWrites: m137PolicyStatusWrites(counts.snapshot()) - statusBefore, Error: sampleError})
		// Persist every completed measured attempt before any post-sample
		// convergence work so process interruption cannot erase slow outcomes.
		report.Samples = append([]scaleprobe.Sample(nil), samples...)
		report.ProbeErrors = append(append([]string(nil), probeErrors...), fmt.Sprintf("harness incomplete after %d/%d captured attempts", len(samples), cfg.samples))
		if err := m137WriteReport(output, report); err != nil {
			t.Fatal(err)
		}
		if outcome == "finished-full-snapshot" {
			beforeConvergenceErrors := len(probeErrors)
			if err := m137WaitPolicyCache(ctx, managerClient, convergence, fixture.policies); err != nil {
				probeErrors = append(probeErrors, fmt.Sprintf("sample %d cache convergence: %v", i, err))
			}
			if len(probeErrors) != beforeConvergenceErrors {
				report.ProbeErrors = append(append([]string(nil), probeErrors...), fmt.Sprintf("harness incomplete after %d/%d captured attempts", len(samples), cfg.samples))
				if err := m137WriteReport(output, report); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	controllerStatusPreserved := true
	for _, policy := range fixture.policies {
		var current v1alpha1.PhorvexPolicy
		if err := managerClient.Get(ctx, client.ObjectKeyFromObject(policy), &current); err != nil {
			probeErrors = append(probeErrors, fmt.Sprintf("read cached policy preservation marker %s/%s: %v", policy.Namespace, policy.Name, err))
			controllerStatusPreserved = false
			continue
		}
		condition := meta.FindStatusCondition(current.Status.Conditions, "ValidationError")
		if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "M137Preserve" || condition.Message != "scale fixture controller-owned preservation marker" || condition.ObservedGeneration != current.Generation {
			controllerStatusPreserved = false
		}
	}
	sampledHTTP, convergenceHTTP := m137PartitionHTTP(counts.reset(), "convergence")
	wantStatusWrites := int64(0)
	finishedAttempts := 0
	for _, sample := range samples {
		wantStatusWrites += sample.StatusWrites
		if sample.Outcome == "finished-full-snapshot" {
			finishedAttempts++
		}
	}
	if got := m137PolicyStatusWrites(sampledHTTP); got != wantStatusWrites {
		probeErrors = append(probeErrors, fmt.Sprintf("sampled policy status traffic=%d retained attempts=%d", got, wantStatusWrites))
	}
	for key, value := range sampledHTTP {
		if strings.HasPrefix(key, "cache|LIST|") && value != 0 {
			probeErrors = append(probeErrors, fmt.Sprintf("cache inventory LIST recurred during warm samples: %s=%d", key, value))
		}
	}
	if m137HTTPResourceCount(sampledHTTP, "direct", "LIST", "securityevents") < int64(finishedAttempts) {
		probeErrors = append(probeErrors, "authoritative direct SecurityEvent reads missing")
	}
	if finishedAttempts > 0 && (m137HTTPResourceCount(sampledHTTP, "direct", "GET", "replicasets") == 0 || m137HTTPResourceCount(sampledHTTP, "direct", "GET", "deployments") == 0) {
		probeErrors = append(probeErrors, "native current-owner reads missing")
	}

	m137ForceDue(m)
	deadlineSource := &m137DeadlineSource{entered: make(chan struct{})}
	m.MetricsSource = deadlineSource
	deadlineCountBefore, deadlineSumBefore, err := m137HistogramValue("phorvex_manager_tick_duration_seconds", map[string]string{"outcome": "deadline"})
	if err != nil {
		probeErrors = append(probeErrors, "deadline metric baseline: "+err.Error())
	}
	deadlineOuter, deadlineOuterCancel := context.WithTimeout(ctx, 30*time.Second)
	deadlineCtx := newM137ControlledDeadline(deadlineOuter)
	deadlineResultCh := make(chan tickResult, 1)
	go func() { deadlineResultCh <- m.tick(deadlineCtx) }()
	select {
	case <-deadlineSource.entered:
		deadlineCtx.trigger(context.DeadlineExceeded)
	case <-deadlineOuter.Done():
		deadlineCtx.trigger(deadlineOuter.Err())
		probeErrors = append(probeErrors, "deadline control did not enter the blocking metrics producer")
	}
	var deadlineResult tickResult
	select {
	case deadlineResult = <-deadlineResultCh:
	case <-deadlineOuter.Done():
		deadlineCtx.trigger(deadlineOuter.Err())
		deadlineResult = tickInterrupted
		probeErrors = append(probeErrors, "deadline control did not return within its outer timeout")
	}
	deadlineErr := deadlineCtx.Err()
	deadlineOuterCancel()
	deadlineCountAfter, deadlineSumAfter, err := m137HistogramValue("phorvex_manager_tick_duration_seconds", map[string]string{"outcome": "deadline"})
	if err != nil {
		probeErrors = append(probeErrors, "deadline metric result: "+err.Error())
	}
	deadlineOutcome := m137Outcome(deadlineResult, deadlineErr)
	if deadlineResult != tickInterrupted || deadlineErr == nil || deadlineCountAfter-deadlineCountBefore != 1 {
		probeErrors = append(probeErrors, fmt.Sprintf("deadline control result=%v err=%v metric observations=%d", deadlineResult, deadlineErr, deadlineCountAfter-deadlineCountBefore))
	}
	noFalseCadence := true
	m.mu.RLock()
	for _, entry := range m.policies {
		noFalseCadence = noFalseCadence && entry.lastTick.IsZero()
	}
	m.mu.RUnlock()
	deadlineError := "deadline control did not expose context error"
	if deadlineErr != nil {
		deadlineError = deadlineErr.Error()
	}
	deadlineControl := scaleprobe.Control{Purpose: "deadline-exclusion-and-no-cadence-after-producer-entry", Sample: scaleprobe.Sample{Index: cfg.samples, Outcome: deadlineOutcome, DurationSec: deadlineSumAfter - deadlineSumBefore, PolicySeconds: map[string]float64{}, RSSBytes: m137RSS(os.Getpid()), Error: deadlineError}}
	controlHTTP := counts.snapshot()

	var memAfter kruntimeMemStats
	readM137MemStats(&memAfter)
	peakRSS := rssBefore
	peakHeap := memBefore.HeapAlloc
	peakAPIRSS := apiRSSBefore
	peakEtcdRSS := etcdRSSBefore
	for i := range rssValues {
		if rssValues[i] > peakRSS {
			peakRSS = rssValues[i]
		}
		if uint64(heapValues[i]) > peakHeap {
			peakHeap = uint64(heapValues[i])
		}
		if apiRSSValues[i] > peakAPIRSS {
			peakAPIRSS = apiRSSValues[i]
		}
		if etcdRSSValues[i] > peakEtcdRSS {
			peakEtcdRSS = etcdRSSValues[i]
		}
	}
	auditRetained, auditDropped := auditSink.storage()
	auditDecisionsAfter, auditSelectedAfter := auditSink.decisionStats()
	measuredDecisions := auditDecisionsAfter - auditDecisionsBefore
	measuredSelected := auditSelectedAfter - auditSelectedBefore
	incidentWitness := auditSink.decisionWitness(fixture.firstPod.String())
	if finishedAttempts > 0 && (measuredDecisions < finishedAttempts || measuredSelected <= 0) {
		probeErrors = append(probeErrors, fmt.Sprintf("measured audit decisions=%d selected-feasible=%d, want at least one decision per %d finished attempts and a non-vacuous selected/feasible positive; incident-target=%+v", measuredDecisions, measuredSelected, finishedAttempts, incidentWitness))
	}
	incidentTargetSelected := incidentWitness.AssetUID == fixture.firstUID && incidentWitness.Selected && incidentWitness.Feasible
	if !incidentTargetSelected {
		probeErrors = append(probeErrors, fmt.Sprintf("incident target %s@%s lacks an exact selected/feasible audit decision: %+v", fixture.firstPod.String(), fixture.firstUID, incidentWitness))
	}
	fixtureReport.AuditRetained, fixtureReport.AuditDropped = auditRetained, auditDropped
	report = scaleprobe.Report{
		SchemaVersion: scaleprobe.SchemaVersion,
		Environment:   scaleprobe.Environment{GitSHA: m137GitSHA(t), Executable: executable, ExecutableSHA256: executableSHA, GoVersion: runtime.Version(), KubernetesAssets: os.Getenv("KUBEBUILDER_ASSETS"), CPUCount: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), MemoryTotalBytes: totalMemory, MemoryLimitBytes: limitMemory, HarnessPID: os.Getpid(), APIProcessPID: children["apiserver"], EtcdProcessPID: children["etcd"], APIProcessRSSBytes: m137RSS(children["apiserver"]), EtcdProcessRSSBytes: m137RSS(children["etcd"])},
		Fixture:       fixtureReport, Samples: samples, Warmups: warmups, Controls: []scaleprobe.Control{deadlineControl}, StartupHTTP: startupHTTP, SampleHTTP: sampledHTTP, ConvergenceHTTP: convergenceHTTP, ControlHTTP: controlHTTP,
		RESTConfigs: map[string]scaleprobe.RESTConfig{"fixture": m137RESTBinding(fixtureREST), "cache": m137RESTBinding(cacheREST), "manager": m137RESTBinding(managerREST), "direct": m137RESTBinding(directREST), "convergence": m137RESTBinding(convergenceREST)},
		Memory:      scaleprobe.Memory{Scope: "sampled post-tick harness/cache/manager and separate envtest kube-apiserver/etcd snapshots; max and slope are not continuous within-tick peaks", HarnessBaseline: rssBefore, HarnessPeak: peakRSS, HarnessFinal: m137RSS(os.Getpid()), HarnessSlopeBytes: m137Slope(rssValues), HeapBaseline: memBefore.HeapAlloc, HeapPeak: peakHeap, HeapFinal: memAfter.HeapAlloc, HeapSlopeBytes: m137Slope(heapValues), GCCount: memAfter.NumGC - memBefore.NumGC, APIBaseline: apiRSSBefore, APIPeak: peakAPIRSS, APIFinal: m137RSS(children["apiserver"]), EtcdBaseline: etcdRSSBefore, EtcdPeak: peakEtcdRSS, EtcdFinal: m137RSS(children["etcd"])},
		Correctness: scaleprobe.Correctness{CacheConverged: len(cachedPods.Items) == cfg.pods, ProtectedObjectCount: len(snap.Pods), GraphEdgesPresent: graphEdges, RBACPresent: rbacPresent, TrustedEventPresent: trustedPresent, ReceiptPresent: receiptPresent, DecisionRecords: measuredDecisions, SelectedFeasibleRecords: measuredSelected, IncidentTargetSelected: incidentTargetSelected, CurrentOwnerEligible: ownerEligible, ControllerStatusPreserved: controllerStatusPreserved, NoFalseCadence: noFalseCadence},
		ProbeErrors: probeErrors,
	}
	report.Summary = scaleprobe.Summarize(report.Samples, 1)
	report.NFRVerdict = "OBSERVATION"
	report.NFRDetail = "case is outside the predeclared 1000-pod NFR acceptance point"
	if report.Summary.Incomplete > 0 {
		report.NFRVerdict = "INCOMPLETE"
		report.NFRDetail = fmt.Sprintf("%d/%d fixed-budget workload attempts did not finish; successful-only percentiles retain %d completed attempts", report.Summary.Incomplete, cfg.samples, report.Summary.Successful)
	}
	report.Limitations = []string{
		"isolated local envtest with source-shaped synthetic trust; no admission chain, deployment traffic or live behavior",
		"the per-origin REST QPS, burst, timeout and rate limiter are bound in this report and may differ from deployed controller client settings",
		"intended deployment hardware, workload mix, scheduler cadence, API QPS/latency, process lifetime, memory retention and claimed maximum fleet remain LV25 debt",
		"manager residual is computed by subtraction and combines shared ingest/graph with later audit summary, retained-state cleanup, status writes and cadence credit; it is not a causal stage profile",
		"memory maxima and slopes use baseline/post-tick samples; transient within-tick spikes and OOM headroom are not established",
	}
	if cfg.pods == 1000 {
		report.NFRVerdict = "PASS"
		report.NFRDetail = fmt.Sprintf("all %d successful full ticks were below the predeclared one-second target", report.Summary.Successful)
		if report.Summary.BreachCount > 0 || report.Summary.Incomplete > 0 {
			report.NFRVerdict = "FAIL"
			report.NFRDetail = fmt.Sprintf("%d/%d fixed-budget workload attempts did not finish and %d/%d successful full ticks breached one second; successful-only percentiles retain %d attempts; observed dominant p95 component=%s (manager residual=%0.6fs measured policy portion=%0.6fs); residual includes shared ingest/graph plus later audit summary, retained-state cleanup, status and cadence work; largest sampled HTTP producer=%s; direct owner GETs=%d, direct SecurityEvent LISTs=%d, policy status writes=%d", report.Summary.Incomplete, cfg.samples, report.Summary.BreachCount, report.Summary.Successful, report.Summary.Successful, report.Summary.ObservedDominant, report.Summary.ResidualP95Seconds, report.Summary.PolicyP95Seconds, m137LargestHTTPProducer(sampledHTTP), m137HTTPResourceCount(sampledHTTP, "direct", "GET", "replicasets")+m137HTTPResourceCount(sampledHTTP, "direct", "GET", "deployments"), m137HTTPResourceCount(sampledHTTP, "direct", "LIST", "securityevents"), m137PolicyStatusWrites(sampledHTTP))
		}
	}
	if cfg.pods == 1000 && (report.Summary.BreachCount > 0 || report.Summary.Incomplete > 0) {
		t.Logf("M137 NFR FAIL: predeclared <1s/1000-pod target breached %d/%d times; p95=%v max=%v; traffic=%v", report.Summary.BreachCount, report.Summary.Successful, report.Summary.P95Seconds, report.Summary.MaxSeconds, report.SampleHTTP)
	}
	if err := m137WriteReport(output, report); err != nil {
		t.Fatal(err)
	}
	reportWritten = true
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Alias runtime.MemStats behind a local name so the Kubernetes runtime import stays clear.
type kruntimeMemStats = runtime.MemStats

func readM137MemStats(stats *kruntimeMemStats) { runtime.ReadMemStats(stats) }

func m137PolicyStatusWrites(counts map[string]int64) int64 {
	var total int64
	for key, value := range counts {
		if strings.HasPrefix(key, "manager|") && strings.Contains(key, "|phorvexpolicies|status") && (strings.Contains(key, "|PUT|") || strings.Contains(key, "|PATCH|")) {
			total += value
		}
	}
	return total
}

func m137HTTPResourceCount(counts map[string]int64, origin, verb, resource string) int64 {
	var total int64
	prefix := origin + "|" + verb + "|" + resource + "|"
	for key, value := range counts {
		if strings.HasPrefix(key, prefix) {
			total += value
		}
	}
	return total
}

func m137PartitionHTTP(counts map[string]int64, origin string) (map[string]int64, map[string]int64) {
	remaining := make(map[string]int64, len(counts))
	selected := map[string]int64{}
	prefix := origin + "|"
	for key, value := range counts {
		if strings.HasPrefix(key, prefix) {
			selected[key] = value
			continue
		}
		remaining[key] = value
	}
	return remaining, selected
}

func m137MergeHTTP(into, from map[string]int64) {
	for key, value := range from {
		into[key] += value
	}
}

func m137LargestHTTPProducer(counts map[string]int64) string {
	key := "none"
	var count int64
	for candidate, value := range counts {
		if value > count || value == count && candidate < key {
			key, count = candidate, value
		}
	}
	return fmt.Sprintf("%s=%d", key, count)
}
