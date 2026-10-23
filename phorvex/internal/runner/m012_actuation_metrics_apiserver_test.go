package runner

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/inprocess"
	metricspkg "github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
)

type m012AuthorizationClient struct {
	client.Client
	evictionCalls     int
	evictionForbidden bool
}

type m012AuthorizationSubresource struct {
	client.SubResourceClient
	parent *m012AuthorizationClient
}

func (c *m012AuthorizationClient) SubResource(name string) client.SubResourceClient {
	return &m012AuthorizationSubresource{SubResourceClient: c.Client.SubResource(name), parent: c}
}

func (s *m012AuthorizationSubresource) Create(ctx context.Context, obj client.Object, sub client.Object, opts ...client.SubResourceCreateOption) error {
	s.parent.evictionCalls++
	err := s.SubResourceClient.Create(ctx, obj, sub, opts...)
	s.parent.evictionForbidden = apierrors.IsForbidden(err)
	return err
}

// TestM012RealAPIAuthorizationDenialCountsOneAttempt proves that an API-server
// authorization denial is an actual backend attempt, while a manager identity
// with the same read authority and Pod eviction authority reaches the positive
// native path. The restricted identity can read only the exact Namespace, Pod,
// and owner used by the dispatch; it receives no Pod mutation permission.
func TestM012RealAPIAuthorizationDenialCountsOneAttempt(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	useExistingCluster := false
	env := &envtest.Environment{
		UseExistingCluster:    &useExistingCluster,
		CRDDirectoryPaths:     []string{"../../config/crd/bases"},
		ErrorIfCRDPathMissing: true,
	}
	env.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})

	scheme := m034Scheme(t)
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	create := func(obj client.Object) {
		t.Helper()
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}

	const (
		namespace  = "m012-authz"
		ownerName  = "owner"
		podName    = "target"
		policyName = "policy"
		saName     = "read-only-runner"
	)
	create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
	create(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: saName}})
	replicas := int32(1)
	owner := &corev1.ReplicationController{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: ownerName},
		Spec: corev1.ReplicationControllerSpec{
			Replicas: &replicas,
			Selector: map[string]string{"app": "demo"},
			Template: &corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "demo"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "fixture"}}},
			},
		},
	}
	create(owner)
	owner.Status.Replicas = 1
	if err := admin.Status().Update(ctx, owner); err != nil {
		t.Fatal(err)
	}
	controller := true
	target := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      podName,
			Labels:    map[string]string{"app": "demo"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "ReplicationController", Name: owner.Name,
				UID: owner.UID, Controller: &controller,
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "fixture"}}},
	}
	create(target)
	cap := int64(30)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: policyName}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}},
		Budget: v1alpha1.BudgetSpec{
			MaxGracePeriodSeconds:  &cap,
			TickInterval:           metav1.Duration{Duration: 20 * time.Second},
			AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
			ProactiveFloor:         metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	create(policy)

	roleName := "m012-read-exact-dispatch-inputs"
	create(&rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: roleName},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{namespace}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{podName}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"replicationcontrollers"}, ResourceNames: []string{ownerName}, Verbs: []string{"get"}},
			{APIGroups: []string{v1alpha1.GroupVersion.Group}, Resources: []string{"phorvexpolicies"}, ResourceNames: []string{policyName}, Verbs: []string{"get"}},
		},
	})
	create(&rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: roleName},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: roleName},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: namespace, Name: saName}},
	})

	restrictedConfig := rest.CopyConfig(cfg)
	restrictedConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + namespace + ":" + saName,
		Groups:   []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + namespace},
	}
	restricted, err := client.New(restrictedConfig, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	// Wait until all exact read grants are effective. A Forbidden during RBAC
	// propagation is expected here; other API failures remain fatal.
	m034Poll(t, 8*time.Second, func() (bool, error) {
		objects := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: podName}},
			&corev1.ReplicationController{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: ownerName}},
			&v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: policyName}},
		}
		for _, obj := range objects {
			if err := restricted.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				if apierrors.IsForbidden(err) {
					return false, nil
				}
				return false, err
			}
		}
		return true, nil
	})

	entry := &policyEntry{key: client.ObjectKeyFromObject(policy), uid: string(policy.UID), generation: policy.Generation, namespace: namespace, spec: policy.Spec}
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: namespace, Name: podName, UID: string(target.UID), Ready: true,
		DesiredReplicas: 1, ReadyReplicas: 1,
	}}
	views := map[string]*model.WorkloadView{namespace + "/" + podName: view}
	decision := func() []model.Decision {
		return []model.Decision{{Namespace: namespace, Pod: podName, Action: model.ActionRotate, Selected: true, Feasible: true}}
	}

	deniedTenant := "m012-real-api-denied"
	deniedPolicy := model.Policy{Tenant: deniedTenant, PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, MaxGracePeriodSeconds: cap, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	observedRestricted := &m012AuthorizationClient{Client: restricted}
	deniedNative := actuator.NewNativeActuator(observedRestricted)
	deniedNative.SetBoundaryReader(restricted)
	deniedManager := &Manager{Local: &inprocess.Services{Actuator: deniedNative}, BoundaryReader: restricted, Intents: exposure.NewIntents(), Log: logr.Discard()}
	deniedAttemptLabels := map[string]string{"tenant": deniedTenant, "action": string(model.ActionRotate), "outcome": string(metricspkg.AttemptRefused)}
	deniedFailureLabels := map[string]string{"tenant": deniedTenant, "action": string(model.ActionRotate), "reason": string(metricspkg.AttemptRefused)}
	deniedAcceptedLabels := map[string]string{"tenant": deniedTenant, "action": string(model.ActionRotate)}
	deniedAttemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", deniedAttemptLabels)
	deniedFailuresBefore := m012Counter(t, "phorvex_actuation_failures_total", deniedFailureLabels)
	deniedAcceptedBefore := m012Counter(t, "phorvex_actuations_total", deniedAcceptedLabels)
	deniedDecision := decision()
	if got := deniedManager.actuate(ctx, entry, deniedPolicy, deniedDecision, views); got != 0 {
		t.Fatalf("restricted identity actuations = %d", got)
	}
	if deniedDecision[0].DispatchOutcome != model.DispatchRefused || deniedDecision[0].Actuated {
		t.Fatalf("restricted identity result = %+v", deniedDecision[0])
	}
	if observedRestricted.evictionCalls != 1 || !observedRestricted.evictionForbidden {
		t.Fatalf("restricted identity Eviction calls=%d forbidden=%v", observedRestricted.evictionCalls, observedRestricted.evictionForbidden)
	}
	if m012Counter(t, "phorvex_actuation_attempts_total", deniedAttemptLabels) != deniedAttemptsBefore+1 ||
		m012Counter(t, "phorvex_actuation_failures_total", deniedFailureLabels) != deniedFailuresBefore+1 ||
		m012Counter(t, "phorvex_actuations_total", deniedAcceptedLabels) != deniedAcceptedBefore {
		t.Fatal("real API Forbidden did not produce exactly one failed attempt with no accepted credit")
	}
	var retained corev1.Pod
	if err := admin.Get(ctx, client.ObjectKeyFromObject(target), &retained); err != nil || retained.UID != target.UID {
		t.Fatalf("authorization-denied target changed: uid=%s err=%v", retained.UID, err)
	}

	allowedTenant := "m012-real-api-allowed"
	allowedPolicy := model.Policy{Tenant: allowedTenant, PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, MaxGracePeriodSeconds: cap, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	allowedNative := actuator.NewNativeActuator(admin)
	allowedNative.SetBoundaryReader(admin)
	allowedManager := &Manager{Local: &inprocess.Services{Actuator: allowedNative}, BoundaryReader: admin, Intents: exposure.NewIntents(), Log: logr.Discard()}
	allowedAttemptLabels := map[string]string{"tenant": allowedTenant, "action": string(model.ActionRotate), "outcome": string(metricspkg.AttemptAccepted)}
	allowedAcceptedLabels := map[string]string{"tenant": allowedTenant, "action": string(model.ActionRotate)}
	allowedAttemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", allowedAttemptLabels)
	allowedAcceptedBefore := m012Counter(t, "phorvex_actuations_total", allowedAcceptedLabels)
	allowedDecision := decision()
	if got := allowedManager.actuate(ctx, entry, allowedPolicy, allowedDecision, views); got != 1 || !allowedDecision[0].Actuated {
		t.Fatalf("allowed identity result got=%d decision=%+v", got, allowedDecision[0])
	}
	if m012Counter(t, "phorvex_actuation_attempts_total", allowedAttemptLabels) != allowedAttemptsBefore+1 ||
		m012Counter(t, "phorvex_actuations_total", allowedAcceptedLabels) != allowedAcceptedBefore+1 {
		t.Fatal("allowed API dispatch did not produce one accepted attempt and one accepted emission")
	}
	retained = corev1.Pod{}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(target), &retained); err == nil {
		if retained.DeletionTimestamp.IsZero() {
			t.Fatal("allowed native rotate did not submit target deletion")
		}
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("reading allowed native rotate target: %v", err)
	}
}
