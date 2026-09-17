package runner

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	metricspkg "github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type m012AuthorizationClient struct {
	client.Client
	deleteCalls     int
	deleteForbidden bool
}

func (c *m012AuthorizationClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	c.deleteCalls++
	err := c.Client.Delete(ctx, obj, opts...)
	c.deleteForbidden = apierrors.IsForbidden(err)
	return err
}

// TestM012RealAPIAuthorizationDenialCountsOneAttempt proves that an API-server
// authorization denial is an actual backend attempt, while a manager identity
// with the same read authority and Pod delete authority reaches the positive
// native path. The restricted identity can read only the exact Namespace, Pod,
// and owner used by the dispatch; it receives no Pod mutation permission.
func TestM012RealAPIAuthorizationDenialCountsOneAttempt(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	useExistingCluster := false
	env := &envtest.Environment{UseExistingCluster: &useExistingCluster}
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
		namespace = "m012-authz"
		ownerName = "owner"
		podName   = "target"
		saName    = "read-only-runner"
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

	roleName := "m012-read-exact-dispatch-inputs"
	create(&rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: roleName},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{namespace}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{podName}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"replicationcontrollers"}, ResourceNames: []string{ownerName}, Verbs: []string{"get"}},
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

	entry := &policyEntry{namespace: namespace, spec: v1alpha1.PhorvexPolicySpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}},
	}}
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: namespace, Name: podName, UID: string(target.UID), Ready: true,
		DesiredReplicas: 1, ReadyReplicas: 1,
	}}
	views := map[string]*model.WorkloadView{namespace + "/" + podName: view}
	decision := func() []model.Decision {
		return []model.Decision{{Namespace: namespace, Pod: podName, Action: model.ActionRotate, Selected: true, Feasible: true}}
	}

	deniedTenant := "m012-real-api-denied"
	deniedPolicy := model.Policy{Tenant: deniedTenant, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	observedRestricted := &m012AuthorizationClient{Client: restricted}
	deniedNative := actuator.NewNativeActuator(observedRestricted)
	deniedNative.SetBoundaryReader(restricted)
	deniedManager := &Manager{Actuator: deniedNative, BoundaryReader: restricted, Intents: exposure.NewIntents(), Log: logr.Discard()}
	deniedAttemptLabels := map[string]string{"tenant": deniedTenant, "action": string(model.ActionRotate), "outcome": string(metricspkg.AttemptError)}
	deniedFailureLabels := map[string]string{"tenant": deniedTenant, "action": string(model.ActionRotate), "reason": string(metricspkg.AttemptError)}
	deniedAcceptedLabels := map[string]string{"tenant": deniedTenant, "action": string(model.ActionRotate)}
	deniedAttemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", deniedAttemptLabels)
	deniedFailuresBefore := m012Counter(t, "phorvex_actuation_failures_total", deniedFailureLabels)
	deniedAcceptedBefore := m012Counter(t, "phorvex_actuations_total", deniedAcceptedLabels)
	deniedDecision := decision()
	if got := deniedManager.actuate(ctx, entry, deniedPolicy, deniedDecision, views); got != 0 {
		t.Fatalf("restricted identity actuations = %d", got)
	}
	if deniedDecision[0].DispatchOutcome != model.DispatchError || deniedDecision[0].Actuated {
		t.Fatalf("restricted identity result = %+v", deniedDecision[0])
	}
	if observedRestricted.deleteCalls != 1 || !observedRestricted.deleteForbidden {
		t.Fatalf("restricted identity Delete calls=%d forbidden=%v", observedRestricted.deleteCalls, observedRestricted.deleteForbidden)
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
	allowedPolicy := model.Policy{Tenant: allowedTenant, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	allowedNative := actuator.NewNativeActuator(admin)
	allowedNative.SetBoundaryReader(admin)
	allowedManager := &Manager{Actuator: allowedNative, BoundaryReader: admin, Intents: exposure.NewIntents(), Log: logr.Discard()}
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
