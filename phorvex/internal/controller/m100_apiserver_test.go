package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/lossobserver"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type m100BoundaryReader struct {
	client.Reader
	boundary admissionv1.MutatingWebhookConfiguration
}

func (r m100BoundaryReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if boundaries, ok := list.(*admissionv1.MutatingWebhookConfigurationList); ok {
		boundaries.Items = []admissionv1.MutatingWebhookConfiguration{*r.boundary.DeepCopy()}
		return nil
	}
	return r.Reader.List(ctx, list, opts...)
}

func m100InstalledWebhook() *admissionv1.MutatingWebhookConfiguration {
	failure, sideEffects, scope := admissionv1.Fail, admissionv1.SideEffectClassNone, admissionv1.ClusterScope
	path := securityEventStampPath
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "m100-completed-disclosure", Annotations: map[string]string{disclosure.BoundaryContractAnnotation: disclosure.BoundaryContract}},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name: "stamp-completed-disclosures.phorvex.ai", FailurePolicy: &failure, SideEffects: &sideEffects,
			AdmissionReviewVersions: []string{"v1"}, MatchConditions: []admissionv1.MatchCondition{{Name: "completed", Expression: ingest.CompletedDisclosureMatch}},
			ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: "system", Name: "phorvex-webhook", Path: &path}},
			Rules: []admissionv1.RuleWithOperations{{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
				Rule: admissionv1.Rule{APIGroups: []string{"amtd.r6security.com"}, APIVersions: []string{"v1beta1"}, Resources: []string{"securityevents"}, Scope: &scope}}},
		}},
	}
}

func m100ImpersonatedClient(t *testing.T, cfg *rest.Config, scheme *runtime.Scheme, username string) client.Client {
	t.Helper()
	copy := rest.CopyConfig(cfg)
	copy.Impersonate = rest.ImpersonationConfig{UserName: username}
	c, err := client.New(copy, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestM100ActualAPIObserverAdmissionIngestAndDurableHistory(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	observerIdentity := "system:serviceaccount:ns:loss-observer"
	ingest.ConfigureCompletedDisclosureTrust(ingest.NewTrustedDetectors([]string{observerIdentity, "system:serviceaccount:ns:other-observer"}))
	t.Cleanup(func() { ingest.ConfigureCompletedDisclosureTrust(ingest.NewTrustedDetectors(nil)) })

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	installed := m100InstalledWebhook()
	localOnly := false
	env := &envtest.Environment{
		UseExistingCluster:    &localOnly,
		CRDDirectoryPaths:     []string{"../../config/crd/bases", "../../../build/phoenix-extended/config/crd/bases"},
		ErrorIfCRDPathMissing: true,
		WebhookInstallOptions: envtest.WebhookInstallOptions{MutatingWebhooks: []*admissionv1.MutatingWebhookConfiguration{installed}},
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	server := webhook.NewServer(webhook.Options{Host: env.WebhookInstallOptions.LocalServingHost,
		Port: env.WebhookInstallOptions.LocalServingPort, CertDir: env.WebhookInstallOptions.LocalServingCertDir})
	server.Register(securityEventStampPath, &webhook.Admission{Handler: SecurityEventStamper{Reader: admin}})
	serverCtx, cancelServer := context.WithCancel(context.Background())
	t.Cleanup(cancelServer)
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start(serverCtx) }()
	deadline := time.Now().Add(5 * time.Second)
	for server.StartedChecker()(nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("admission webhook server did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx := context.Background()
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}); err != nil {
		t.Fatal(err)
	}
	observerName := "loss-observer"
	otherObserverName := "other-observer"
	untrustedName := "untrusted-writer"
	for _, name := range []string{observerName, otherObserverName, untrustedName} {
		if err := admin.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "m100-observer"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets", "deployments", "statefulsets", "daemonsets"}, Verbs: []string{"get"}},
	}}
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "m100-observer"},
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role.Name},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "ns", Name: observerName}, {Kind: "ServiceAccount", Namespace: "ns", Name: otherObserverName}}}
	clusterRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "m100-observer"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{"amtd.r6security.com"}, Resources: []string{"securityevents"}, Verbs: []string{"create", "get", "update"}},
	}}
	clusterBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "m100-observer"},
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: clusterRole.Name},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "ns", Name: observerName}, {Kind: "ServiceAccount", Namespace: "ns", Name: otherObserverName}, {Kind: "ServiceAccount", Namespace: "ns", Name: untrustedName}}}
	for _, object := range []client.Object{role, roleBinding, clusterRole, clusterBinding} {
		if err := admin.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	yes := true
	labels := map[string]string{"app": "m100"}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app"},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "canary", Image: "example.invalid/canary"}}}}}}
	if err := admin.Create(ctx, dep); err != nil {
		t.Fatal(err)
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app-rs",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &yes}}},
		Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "canary", Image: "example.invalid/canary"}}}}}}
	if err := admin.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-pod", Labels: labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "canary", Image: "example.invalid/canary"}}}}
	if err := admin.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	policyObject := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Tenant: "tenant", Selector: metav1.LabelSelector{MatchLabels: labels},
		Budget:  v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	if err := admin.Create(ctx, policyObject); err != nil {
		t.Fatal(err)
	}

	body := []byte("synthetic-canary-v1")
	sum := sha256.Sum256(body)
	canary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/canary/v1" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer canary.Close()
	observerClient := m100ImpersonatedClient(t, cfg, scheme, observerIdentity)
	// Start comfortably inside a UTC second so the completed observation keeps
	// non-zero nanoseconds while the API object's CreationTimestamp is serialized
	// to the beginning of that same second.
	for frac := time.Now().Nanosecond(); frac < 200_000_000 || frac > 500_000_000; frac = time.Now().Nanosecond() {
		time.Sleep(5 * time.Millisecond)
	}
	now := time.Now
	event, err := lossobserver.ObserveOnce(ctx, observerClient, canary.Client(), lossobserver.ObserverConfig{
		URL: canary.URL + "/canary/v1", PolicyEpoch: model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: string(policyObject.UID), Generation: policyObject.Generation},
		TargetNamespace: "ns", TargetName: pod.Name, TargetUID: string(pod.UID),
		ProtectedScope: model.ProtectedScope{Tenant: "tenant", Asset: "synthetic/customer-row", Version: "data-v1", Property: "confidentiality"},
		EvidenceID:     "copy-1", RuleVersion: "rule-v1", RuleDigest: strings.Repeat("a", 64), ObserverIdentity: observerIdentity,
		ExpectedBytes: int64(len(body)), ExpectedSHA256: hex.EncodeToString(sum[:]), Timeout: 10 * time.Second,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if event.UID == "" || event.CreationTimestamp.IsZero() || event.Annotations[ingest.CreatorIdentityAnnotation] != observerIdentity ||
		event.Annotations[disclosure.AdmissionContractAnnotation] != disclosure.BoundaryContract {
		t.Fatalf("API/admission identity missing: uid=%q created=%v annotations=%v", event.UID, event.CreationTimestamp, event.Annotations)
	}
	payload, _, _, err := disclosure.Parse(event.Annotations[disclosure.Annotation])
	if err != nil {
		t.Fatal(err)
	}
	admittedAt, err := time.Parse(time.RFC3339Nano, event.Annotations[disclosure.AdmissionTimeAnnotation])
	if err != nil || !payload.Observation.CompletedAt.After(event.CreationTimestamp.Time) || admittedAt.Before(payload.Observation.CompletedAt) ||
		admittedAt.Before(event.CreationTimestamp.Time) || !admittedAt.Before(event.CreationTimestamp.Add(time.Second)) {
		t.Fatalf("same-second admission precision was not retained: completed=%v created=%v admitted=%v err=%v", payload.Observation.CompletedAt, event.CreationTimestamp, admittedAt, err)
	}

	// The dedicated fail-closed hook matches OLD payloads too. Neither the
	// original observer nor an unrelated API writer can remove accepted evidence.
	for name, c := range map[string]client.Client{
		"original observer": observerClient,
		"untrusted writer":  m100ImpersonatedClient(t, cfg, scheme, "system:serviceaccount:ns:"+untrustedName),
	} {
		current := &amtdv1beta1.SecurityEvent{}
		if err := c.Get(ctx, client.ObjectKey{Name: event.Name}, current); err != nil {
			t.Fatal(err)
		}
		delete(current.Annotations, disclosure.Annotation)
		if err := c.Update(ctx, current); err == nil {
			t.Fatalf("%s removed completed disclosure", name)
		}
	}
	// A second allowlisted API identity cannot submit the first observer's
	// payload while every other authoritative binding is still current.
	other := m100ImpersonatedClient(t, cfg, scheme, "system:serviceaccount:ns:other-observer")
	forged := event.DeepCopy()
	forged.ResourceVersion, forged.UID, forged.Name, forged.GenerateName = "", "", "", "forged-loss-"
	if err := other.Create(ctx, forged); err == nil {
		t.Fatal("allowlisted identity substituted another observer's payload")
	}

	// The original Pod may be deleted immediately after authoritative admission;
	// the frozen owner binding must still reach durable history on the first tick.
	if err := admin.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}

	snapshot, err := ingest.CollectSnapshot(ctx, admin, time.Now().Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) != 1 || snapshot.Events[0].CompletedDisclosureRaw == "" || snapshot.Events[0].CreatorIdentity != observerIdentity {
		t.Fatalf("actual SecurityEvent projection missing: %+v", snapshot.Events)
	}
	var actualBoundary admissionv1.MutatingWebhookConfiguration
	if err := admin.Get(ctx, client.ObjectKey{Name: installed.Name}, &actualBoundary); err != nil {
		t.Fatal(err)
	}
	// envtest rewrites Service clientConfig to a loopback URL. Restore only the
	// production endpoint shape for the boundary transaction; UID, RV, creation
	// time, fail-closed policy and the event itself all came from the real API.
	productionBoundary := *actualBoundary.DeepCopy()
	productionBoundary.Webhooks[0].ClientConfig = m100InstalledWebhook().Webhooks[0].ClientConfig
	productionBoundary.Webhooks[0].ClientConfig.CABundle = env.WebhookInstallOptions.LocalServingCAData
	reader := m100BoundaryReader{Reader: admin, boundary: productionBoundary}
	store, err := losshistory.New(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: string(policyObject.UID), PolicyGeneration: policyObject.Generation}
	if gaps := ingest.AdmitCompletedDisclosures(ctx, reader, store, snapshot.Events, policy, time.Now().Add(2*time.Second), logr.Discard()); len(gaps) != 0 {
		t.Fatalf("actual producer admission gaps: %v", gaps)
	}
	result := store.Query(policy.PolicyUID, string(dep.UID))
	if result.Status != "available" || len(result.Records) != 1 || result.Records[0].SecurityEvent.UID != string(event.UID) {
		t.Fatalf("durable API observation missing: %+v", result)
	}

	if got := store.Query(policy.PolicyUID, string(dep.UID)); len(got.Records) != 1 {
		t.Fatalf("rejected API write changed retained history: %+v", got)
	}

	cancelServer()
	select {
	case err := <-serverErr:
		if err != nil {
			t.Errorf("webhook server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("webhook server did not stop")
	}
}
