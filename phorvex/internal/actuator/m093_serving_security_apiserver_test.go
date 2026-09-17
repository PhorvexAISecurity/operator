package actuator

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m093APIServing struct {
	mu       sync.Mutex
	loaded   bool
	failLoad bool
	tokens   []string
	unloads  int
	loads    int
}

func (s *m093APIServing) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, r.Header.Get("Authorization"))
	switch r.URL.Path {
	case defaultModelsPath:
		w.Header().Set("Content-Type", "application/json")
		if s.loaded {
			_, _ = w.Write([]byte(`{"data":[{"id":"actual-poison"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"data":[{"id":"base"}]}`))
		}
	case defaultUnloadPath:
		s.unloads++
		s.loaded = false
		w.WriteHeader(http.StatusNoContent)
	case defaultLoadPath:
		s.loads++
		// Model the M77 ambiguous-after-send boundary: the backend installs the
		// adapter, then the caller receives an error instead of a trustworthy ack.
		s.loaded = true
		if s.failLoad {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`backend must not enter diagnostics`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (s *m093APIServing) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unloads, s.loads
}

func (s *m093APIServing) observedTokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tokens...)
}

// This test uses an isolated real kube-apiserver/etcd and a custom-CA TLS server.
// It proves the source-side API/TLS contract; backend auth deployment and CNI
// isolation remain deployment acceptance conditions.
func TestM093RealAPISecretAuthorizationAndProtectedTLSRecovery(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	localOnly := false
	env := &envtest.Environment{
		UseExistingCluster: &localOnly,
		CRDDirectoryPaths: []string{
			"../../config/crd/bases",
			"../../../build/phoenix-extended/config/crd/bases",
		},
		ErrorIfCRDPathMissing: true,
	}
	env.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	scheme := p4bScheme()
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	create := func(obj client.Object) {
		t.Helper()
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	for _, namespace := range []string{"m093-operator", "m093-tenant"} {
		create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
	}

	backend := &m093APIServing{loaded: true, failLoad: true}
	server := httptest.NewTLSServer(http.HandlerFunc(backend.handler))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cert := server.Certificate()
	serverName := host
	if len(cert.DNSNames) != 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) != 0 {
		serverName = cert.IPAddresses[0].String()
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "m093-tenant", Name: "infer", Labels: map[string]string{"app": "m093", labelLoRAEnabled: "true"}, Annotations: map[string]string{annoServingPort: strconv.Itoa(port), annoServingTok: "untrusted-annotation"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "model-sa", Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}},
	}
	create(pod)
	pod.Status.PodIP = host
	if err := admin.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "policy"},
		Spec: v1alpha1.PhorvexPolicySpec{
			Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m093"}},
			Budget:  v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionAdapterRotate)}},
		},
	}
	create(policy)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "m093-operator", Name: "model-admin"}, Data: map[string][]byte{"bearer": []byte("token-one"), "ca.crt": caPEM}}
	create(secret)

	binding := ServingSecurityBinding{Namespace: pod.Namespace, PolicyName: policy.Name, PolicyUID: string(policy.UID), ServiceAccount: pod.Spec.ServiceAccountName, ProfileID: "model-admin-v1", SecretName: secret.Name, BearerKey: "bearer", CAKey: "ca.crt", ServerName: serverName}
	security := writeServingSecurityConfig(t, ServingSecuritySecureRequired, secret.Namespace, []ServingSecurityBinding{binding})

	for _, name := range []string{"allowed", "denied"} {
		create(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "m093-tenant", Name: name}})
	}
	create(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: secret.Namespace, Name: "exact-serving-secret"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{secret.Name}, Verbs: []string{"get"}}}})
	create(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: secret.Namespace, Name: "exact-serving-secret"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "exact-serving-secret"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "m093-tenant", Name: "allowed"}}})
	identityClient := func(name string) client.Client {
		t.Helper()
		restricted := rest.CopyConfig(cfg)
		restricted.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:m093-tenant:" + name, Groups: []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:m093-tenant"}}
		c, err := client.New(restricted, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if _, err := security.snapshotForBinding(ctx, identityClient("allowed"), binding); err != nil {
		t.Fatalf("exact authorized Secret read failed: %v", err)
	}
	if _, err := security.snapshotForBinding(ctx, identityClient("denied"), binding); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("unbound identity Secret read error=%v, want forbidden", err)
	}

	const creator = "system:serviceaccount:m093-tenant:detector"
	event := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]interface{}{"name": "detected", "annotations": map[string]interface{}{"phorvex.ai/creator-identity": creator, "phorvex.ai/target-pod-uid": string(pod.UID), "phorvex.ai/adapter-name": "actual-poison"}},
		"spec":     map[string]interface{}{"description": "trusted adapter fixture", "rule": map[string]interface{}{"type": model.AttackVectorAdapter, "source": "fixture-detector"}, "targets": []interface{}{pod.Namespace + "/" + pod.Name}},
	}}
	create(event)
	ConfigureAdapterDetectorIdentities([]string{creator})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	req := Request{
		Tenant: "tenant", Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), PolicyName: policy.Name, PolicyUID: string(policy.UID), Action: model.ActionAdapterRotate,
		AdapterObservation: &model.AdapterObservation{EventName: event.GetName(), EventUID: string(event.GetUID()), CreatorIdentity: creator, TargetPodUID: string(pod.UID), AdapterName: "actual-poison", CreatedAt: event.GetCreationTimestamp().Time},
	}
	native := NewNativeActuator(admin)
	native.Reader, native.JournalNamespace = admin, "m093-operator"
	native.SetAdapterSources(AdapterSources{adapterSourceKey(pod.Namespace, "actual-poison"): "/models/clean"})
	native.SetServingSecurity(security)
	if err := native.EnsurePolicy(ctx, TenantTarget{Tenant: req.Tenant, Namespace: req.Namespace}); err != nil {
		t.Fatal(err)
	}
	result, err := native.Actuate(ctx, req)
	if err == nil || !result.Emitted || result.MutationKind != "partial" {
		t.Fatalf("failed clean reload did not retain a partial protected operation: result=%+v err=%v", result, err)
	}

	if err := admin.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
		t.Fatal(err)
	}
	secret.Data["bearer"] = []byte("token-two")
	if err := admin.Update(ctx, secret); err != nil {
		t.Fatal(err)
	}
	restarted := NewNativeActuator(admin)
	restarted.Reader, restarted.JournalNamespace = admin, "m093-operator"
	restarted.SetAdapterSources(AdapterSources{adapterSourceKey(pod.Namespace, "actual-poison"): "/models/clean"})
	restarted.SetServingSecurity(security)
	events, err := restarted.RecoverOperations(ctx, false)
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" || events[0].Err != nil {
		t.Fatalf("protected TLS recovery did not converge: events=%+v err=%v", events, err)
	}
	if unloads, loads := backend.counts(); unloads != 1 || loads != 1 {
		t.Fatalf("recovery repeated an ambiguous serving mutation: unloads=%d loads=%d", unloads, loads)
	}
	tokens := backend.observedTokens()
	var first, rotated bool
	for _, token := range tokens {
		first = first || token == "Bearer token-one"
		rotated = rotated || token == "Bearer token-two"
		if token == "Bearer untrusted-annotation" {
			t.Fatal("tenant annotation supplied authentication during API/TLS operation")
		}
	}
	if !first || !rotated {
		t.Fatalf("credential rotation was not observed across operation/recovery: %v", tokens)
	}
}
