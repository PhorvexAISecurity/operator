package console

import (
	"context"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	idNS      = "console-identity-test"
	idRun     = "console-id-fixture"
	idPodName = "console-id-fixture-5f9c7"
	idPodUID  = "pod-uid-0001"
	idSAUID   = "sa-uid-old-0001"
	idPolUID  = "policy-uid-0001"
)

type identityClusterObjects struct {
	ns     *corev1.Namespace
	pod    *corev1.Pod
	sa     *corev1.ServiceAccount
	rs     *appsv1.ReplicaSet
	dep    *appsv1.Deployment
	policy *v1alpha1.PhorvexPolicy
	marker *corev1.ConfigMap // when set, pre-existing (dirty) marker in the kube store
}

func newIdentityClusterObjects() *identityClusterObjects {
	controller := true
	saCreated := metav1.NewTime(time.Now().UTC().Add(-10 * time.Minute))
	podCreated := metav1.NewTime(time.Now().UTC().Add(-5 * time.Minute))
	rep := int32(1)
	expiry := identityfixture.TokenExpirationSeconds
	return &identityClusterObjects{
		ns: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: idNS, UID: "ns-uid-0001",
			Labels: map[string]string{identityfixture.Label: identityfixture.NamespaceOwnedLabelValue}}},
		sa: &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: idRun, Namespace: idNS, UID: idSAUID,
			CreationTimestamp: saCreated, Labels: map[string]string{identityfixture.Label: idRun}}},
		dep: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: idRun, Namespace: idNS, UID: "dep-uid-0001"},
			Spec: appsv1.DeploymentSpec{Replicas: &rep,
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: idRun}}}},
		rs: &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: idRun + "-5f9c7", Namespace: idNS, UID: "rs-uid-0001",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: idRun, UID: "dep-uid-0001", Controller: &controller}}}},
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: idPodName, Namespace: idNS, UID: idPodUID,
			CreationTimestamp: podCreated, Labels: map[string]string{identityfixture.Label: idRun},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: idRun + "-5f9c7", UID: "rs-uid-0001", Controller: &controller}}},
			Spec: corev1.PodSpec{ServiceAccountName: idRun,
				Containers: []corev1.Container{{Name: "workload", Image: identityfixture.Image, Command: identityfixture.Command,
					VolumeMounts: []corev1.VolumeMount{{Name: "api", MountPath: identityfixture.Mount, ReadOnly: true}}}},
				Volumes: []corev1.Volume{{Name: "api", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Path: "token", ExpirationSeconds: &expiry}}}}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
				Name: "workload", Ready: true, Started: idBoolPtr(true), RestartCount: 0,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
		policy: &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: idRun, Namespace: idNS, UID: idPolUID, Generation: 3},
			Status: v1alpha1.PhorvexPolicyStatus{ObservedGeneration: 3},
			Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{identityfixture.Label: idRun}},
				Triggers: v1alpha1.TriggersSpec{EventDriven: true, ReactiveOnly: true},
				Actions:  v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionIdentityRotate)}}}},
	}
}

func idBoolPtr(b bool) *bool { return &b }

func (o *identityClusterObjects) profile() identityfixture.Profile {
	return identityfixture.Profile{JournalNamespace: "phorvex-journal", Namespace: idNS, NamespaceUID: "ns-uid-0001",
		PolicyName: idRun, PolicyUID: idPolUID, PolicyGeneration: 0, Cluster: "phorvex-dev-eks", Region: "us-east-2"}
}

func (o *identityClusterObjects) cluster(t *testing.T) *kubernetesIdentityCatalogCluster {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	base := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(o.ns, o.pod, o.sa, o.rs, o.dep, o.policy).Build()
	reader := interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}
			list.SetResourceVersion("1000")
			return nil
		},
	})
	kubeObjs := []runtime.Object{o.pod.DeepCopy(), o.sa.DeepCopy()}
	if o.marker != nil {
		kubeObjs = append(kubeObjs, o.marker)
	}
	kube := kubernetesfake.NewSimpleClientset(kubeObjs...)
	// Mint a bounded credential and authenticate it as the pinned ServiceAccount.
	kube.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			return false, nil, nil
		}
		tr := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenRequest).DeepCopy()
		tr.Status.Token = "minted-bounded-fixture-token"
		return true, tr, nil
	})
	kube.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview).DeepCopy()
		review.Status.Authenticated = true
		review.Status.User.Username = "system:serviceaccount:" + idNS + ":" + idRun
		return true, review, nil
	})
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	return &kubernetesIdentityCatalogCluster{profile: o.profile(), kube: kube, dynamic: dyn, client: reader}
}

func TestIdentityClusterPrepareBindsLiveGenerationAndMintsFreshCredential(t *testing.T) {
	o := newIdentityClusterObjects()
	fixture, err := o.cluster(t).Prepare(context.Background())
	if err != nil {
		t.Fatalf("prepare rejected a valid long-lived fixture: %v", err)
	}
	// The profile pins generation 0; the run must bind the live, reconciled generation.
	if fixture.PolicyGeneration != 3 {
		t.Fatalf("prepare did not bind the live policy generation: %+v", fixture)
	}
	if fixture.PodUID != idPodUID || fixture.ServiceAccountUID != idSAUID || fixture.ServiceAccountName != idRun {
		t.Fatalf("prepare bound the wrong identity: %+v", fixture)
	}
	if fixture.Credential == "" || fixture.Username != "system:serviceaccount:"+idNS+":"+idRun {
		t.Fatalf("prepare did not mint/authenticate a fresh credential: %+v", fixture)
	}
	if !fixture.ReactiveOnly {
		t.Fatalf("prepare lost the policy reactive-only trigger mode: %+v", fixture)
	}
}

func TestIdentityClusterPrepareIdempotent(t *testing.T) {
	o := newIdentityClusterObjects()
	cluster := o.cluster(t)
	first, err := cluster.Prepare(context.Background())
	if err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	second, err := cluster.Prepare(context.Background())
	if err != nil {
		t.Fatalf("second prepare was not idempotent: %v", err)
	}
	if first.PodUID != second.PodUID || first.ServiceAccountUID != second.ServiceAccountUID ||
		first.PolicyGeneration != second.PolicyGeneration {
		t.Fatalf("prepare bound different state across runs: %+v vs %+v", first, second)
	}
	if second.Credential == "" {
		t.Fatalf("repeat prepare did not mint a fresh credential: %+v", second)
	}
}

func TestIdentityClusterPrepareRejects(t *testing.T) {
	cases := map[string]func(*identityClusterObjects){
		"restarted-pod":       func(o *identityClusterObjects) { o.pod.Status.ContainerStatuses[0].RestartCount = 101 },
		"unreconciled-policy": func(o *identityClusterObjects) { o.policy.Generation = 4; o.policy.Status.ObservedGeneration = 3 },
		"wrong-policy-uid":    func(o *identityClusterObjects) { o.policy.UID = "other-policy-uid" },
		"dry-run-policy":      func(o *identityClusterObjects) { o.policy.Spec.Mode = v1alpha1.ModeDryRun },
		"not-event-driven":    func(o *identityClusterObjects) { o.policy.Spec.Triggers.EventDriven = false },
		"stale-marker": func(o *identityClusterObjects) {
			o.marker = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: idRun, Namespace: idNS}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := newIdentityClusterObjects()
			mutate(o)
			if _, err := o.cluster(t).Prepare(context.Background()); err == nil {
				t.Fatalf("%s state was accepted by prepare", name)
			}
		})
	}
}

func TestIdentityClusterPhysicalRotationOracleRequiresCredentialRejectionAndPodRetention(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		credentialAuthenticatedAfter bool
		podUID                       string
		wantValidated                bool
	}{
		{name: "rotated-service-account", podUID: idPodUID, wantValidated: true},
		{name: "old-credential-still-authenticates", credentialAuthenticatedAfter: true, podUID: idPodUID},
		{name: "pod-was-replaced", podUID: "replacement-pod-uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			o := newIdentityClusterObjects()
			o.pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
			cluster := o.cluster(t)
			fixture, err := cluster.Prepare(ctx)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}

			rotatedSA := o.sa.DeepCopy()
			rotatedSA.UID = "sa-uid-new-0002"
			if _, err = cluster.kube.CoreV1().ServiceAccounts(idNS).Update(ctx, rotatedSA, metav1.UpdateOptions{}); err != nil {
				t.Fatalf("rotate ServiceAccount: %v", err)
			}
			pod := o.pod.DeepCopy()
			pod.UID = types.UID(tc.podUID)
			if _, err = cluster.kube.CoreV1().Pods(idNS).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
				t.Fatalf("update Pod: %v", err)
			}
			replayed := false
			cluster.kube.(*kubernetesfake.Clientset).PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview).DeepCopy()
				if review.Spec.Token != fixture.Credential {
					t.Fatal("physical observation did not replay the prepared credential")
				}
				replayed = true
				review.Status.Authenticated = tc.credentialAuthenticatedAfter
				return true, review, nil
			})

			result, err := cluster.Physical(ctx, fixture)
			if err != nil {
				t.Fatalf("physical observation: %v", err)
			}
			if result.Oracle != "service-account-rotation-v1" {
				t.Errorf("physical oracle = %q, want service-account-rotation-v1", result.Oracle)
			}
			if !replayed || !result.CredentialAuthenticatedBefore || result.CredentialAuthenticatedAfter != tc.credentialAuthenticatedAfter {
				t.Errorf("physical observation lost credential replay evidence: %+v", result)
			}
			if result.OldServiceAccountUID != idSAUID || result.NewServiceAccountUID != string(rotatedSA.UID) || result.PodUID != idPodUID {
				t.Errorf("physical observation lost bound identity evidence: %+v", result)
			}
			if result.PodRetained != (tc.podUID == idPodUID) || result.Validated != tc.wantValidated {
				t.Errorf("physical observation accepted the wrong rotation outcome: %+v", result)
			}
		})
	}
}
