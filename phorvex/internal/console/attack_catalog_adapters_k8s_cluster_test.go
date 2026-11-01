package console

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	k8sCatalogueTestActuatorIdentity  = "system:serviceaccount:phorvex-staging:staging-actuator"
	k8sCatalogueTestCleanupIdentity   = "system:serviceaccount:phorvex-staging:staging-attacks-cleanup"
	k8sCatalogueTestOperatorNamespace = "phorvex-staging"
)

type realK8sCatalogueTestFixture struct {
	cluster *kubernetesK8sCatalogueCluster
	kube    *kubernetesfake.Clientset
	dynamic *dynamicfake.FakeDynamicClient
	entry   attackcatalog.Entry
	profile k8sCatalogueProfile
}

func newRealK8sCatalogueTestFixture(t *testing.T, family string) realK8sCatalogueTestFixture {
	t.Helper()
	entry := k8sCatalogueTestEntry(t, k8sCatalogueTestRepresentatives[family])
	profile, err := k8sCatalogueProfileForFamily(family)
	if err != nil {
		t.Fatal(err)
	}
	controller := true
	ready := true
	replicas := int32(3)
	old := metav1.NewTime(time.Now().UTC().Add(-10 * time.Minute))
	depUID, rsUID := types.UID("deployment-uid"), types.UID("replicaset-uid")
	objects := []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: profile.Namespace, UID: "namespace-uid"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: profile.Deployment, Namespace: profile.Namespace, UID: depUID, Generation: 3},
			Spec: appsv1.DeploymentSpec{Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "demo-api"}}},
			Status: appsv1.DeploymentStatus{ObservedGeneration: 3, AvailableReplicas: 3, ReadyReplicas: 3}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "demo-api-rs", Namespace: profile.Namespace, UID: rsUID,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: profile.Deployment, UID: depUID, Controller: &controller}}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: profile.Service, Namespace: profile.Namespace, UID: "service-uid"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app.kubernetes.io/name": "demo-api"}}},
	}
	podNames := []string{"demo-api-old", "demo-api-sibling-a", "demo-api-sibling-b"}
	podUIDs := []types.UID{"pod-old-uid", "pod-sibling-a", "pod-sibling-b"}
	for i := range podNames {
		started := metav1.NewTime(old.Add(time.Duration(i) * time.Second))
		objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podNames[i], Namespace: profile.Namespace,
			UID: podUIDs[i], Labels: map[string]string{"app.kubernetes.io/name": "demo-api"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "demo-api-rs", UID: rsUID, Controller: &controller}}},
			Status: corev1.PodStatus{StartTime: &started, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}})
	}
	endpoints := make([]discoveryv1.Endpoint, 0, len(podUIDs))
	for i := range podUIDs {
		endpoints = append(endpoints, discoveryv1.Endpoint{Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: profile.Namespace, Name: podNames[i], UID: podUIDs[i]}})
	}
	objects = append(objects, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "demo-api-slice", Namespace: profile.Namespace,
		UID: "endpoint-slice-uid", Labels: map[string]string{discoveryv1.LabelServiceName: profile.Service},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: profile.Service, UID: "service-uid", Controller: &controller}}},
		Endpoints: endpoints})
	kube := kubernetesfake.NewSimpleClientset(objects...)
	kube.Fake.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
		review.Status.Allowed = true
		return true, review, nil
	})
	// The actuation/cleanup verbs are proven against the defender principals via
	// SubjectAccessReview; the preflight issues these as the attacks SA.
	kube.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		review.Status.Allowed = true
		return true, review, nil
	})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, discoveryv1.AddToScheme, networkingv1.AddToScheme, v1alpha1.AddToScheme} {
		if err = add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	actions := make([]v1alpha1.ActionType, 0, len(profile.EnabledActions))
	for _, action := range profile.EnabledActions {
		actions = append(actions, v1alpha1.ActionType(action))
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: profile.PolicyName, Namespace: profile.Namespace,
		UID: "policy-uid", Generation: 7}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "demo-api"}},
		SLO:      v1alpha1.SLOSpec{MinAvailableReplicas: profile.MinAvailable},
		Triggers: v1alpha1.TriggersSpec{EventDriven: true, ReactiveOnly: true}, Actions: v1alpha1.ActionsSpec{Enabled: actions}}}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	cluster := &kubernetesK8sCatalogueCluster{profile: profile, kube: kube, eventKube: kube, dynamic: dynamicClient,
		eventDynamic: dynamicClient, cleanupKube: kube, reader: ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		actuatorIdentity: k8sCatalogueTestActuatorIdentity, cleanupIdentity: k8sCatalogueTestCleanupIdentity,
		operatorNamespace: k8sCatalogueTestOperatorNamespace}
	return realK8sCatalogueTestFixture{cluster: cluster, kube: kube, dynamic: dynamicClient, entry: entry, profile: profile}
}

func (f realK8sCatalogueTestFixture) preflight(t *testing.T) k8sCatalogueFixture {
	t.Helper()
	fixture, err := f.cluster.Preflight(context.Background(), f.entry, f.profile)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f realK8sCatalogueTestFixture) installFamilyEffect(t *testing.T, fixture k8sCatalogueFixture) {
	t.Helper()
	ctx := context.Background()
	if f.profile.Family == k8sCatalogueFamilyQuarantine {
		pod, err := f.kube.CoreV1().Pods(f.profile.Namespace).Get(ctx, fixture.Target.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pod.Labels["phorvex.ai/quarantined"] = fixture.Target.UID
		pod.OwnerReferences = nil
		if _, err = f.kube.CoreV1().Pods(f.profile.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: fixture.NetworkPolicyName, Namespace: fixture.Namespace,
			UID: "network-policy-uid", Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/quarantine-of": fixture.Target.Name},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: fixture.Target.Name, UID: types.UID(fixture.Target.UID)}}},
			Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/quarantined": fixture.Target.UID}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}}
		if _, err = f.kube.NetworkingV1().NetworkPolicies(f.profile.Namespace).Create(ctx, np, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	} else if err := f.kube.CoreV1().Pods(f.profile.Namespace).Delete(ctx, fixture.Target.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	controller := true
	started := metav1.NewTime(time.Now().UTC())
	replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "demo-api-replacement", Namespace: f.profile.Namespace,
		UID: "pod-replacement", Labels: map[string]string{"app.kubernetes.io/name": "demo-api"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "demo-api-rs", UID: "replicaset-uid", Controller: &controller}}},
		Status: corev1.PodStatus{StartTime: &started, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	if _, err := f.kube.CoreV1().Pods(f.profile.Namespace).Create(ctx, replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	slice, err := f.kube.DiscoveryV1().EndpointSlices(f.profile.Namespace).Get(ctx, "demo-api-slice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ready := true
	updated := make([]discoveryv1.Endpoint, 0, 3)
	for _, endpoint := range slice.Endpoints {
		if string(endpoint.TargetRef.UID) != fixture.Target.UID {
			updated = append(updated, endpoint)
		}
	}
	updated = append(updated, discoveryv1.Endpoint{Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: f.profile.Namespace, Name: replacement.Name, UID: replacement.UID}})
	slice.Endpoints = updated
	if _, err = f.kube.DiscoveryV1().EndpointSlices(f.profile.Namespace).Update(ctx, slice, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestK8sCatalogueRealPreflightIsReadOnlyAndProfileBound(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			f := newRealK8sCatalogueTestFixture(t, family)
			fixture := f.preflight(t)
			if fixture.CatalogueID != f.entry.ID || fixture.ProfileKey != f.profile.Key || fixture.Target.UID != "pod-old-uid" || !fixture.ReactiveOnly {
				t.Fatalf("preflight did not pin the reviewed fixture: %+v", fixture)
			}
			for _, action := range f.kube.Actions() {
				// Authorization reviews are non-mutating authz probes (SelfSubjectAccessReview for
				// the attacks SA's own reads, SubjectAccessReview for the actuator/cleanup identities).
				if action.GetVerb() == "create" && (action.GetResource().Resource == "selfsubjectaccessreviews" || action.GetResource().Resource == "subjectaccessreviews") {
					continue
				}
				if action.GetVerb() == "create" || action.GetVerb() == "update" || action.GetVerb() == "patch" || action.GetVerb() == "delete" || action.GetVerb() == "delete-collection" {
					t.Fatalf("preflight mutated Kubernetes state: %s %s", action.GetVerb(), action.GetResource().Resource)
				}
			}
		})
	}
}

func TestK8sCatalogueRealPreflightRejectsNonemptyCapacityWithoutMutation(t *testing.T) {
	f := newRealK8sCatalogueTestFixture(t, k8sCatalogueFamilyQuarantine)
	ledger := k8sSharedCapacityLedger{Version: 1, Records: map[string]k8sSharedCapacityRecord{
		"stale": {OperationID: "stale", PolicyUID: "old-policy", TargetName: "old-pod", TargetUID: "old-uid",
			Action: string(model.ActionQuarantine), Phase: "uncertain"},
	}}
	raw, _ := json.Marshal(ledger)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "phorvex-shared-capacity", Namespace: k8sCatalogueTestOperatorNamespace,
		UID: "shared-ledger-uid", ResourceVersion: "1", Labels: map[string]string{"phorvex.ai/shared-capacity": "v1"}},
		Data: map[string]string{"ledger": string(raw)}}
	if _, err := f.kube.CoreV1().ConfigMaps(k8sCatalogueTestOperatorNamespace).Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	actionsBefore := len(f.kube.Actions())
	if _, err := f.cluster.Preflight(context.Background(), f.entry, f.profile); err == nil {
		t.Fatal("nonempty shared-capacity state passed quarantine preflight")
	}
	for _, action := range f.kube.Actions()[actionsBefore:] {
		if action.GetVerb() == "create" && (action.GetResource().Resource == "selfsubjectaccessreviews" || action.GetResource().Resource == "subjectaccessreviews") {
			continue
		}
		if action.GetVerb() == "create" || action.GetVerb() == "update" || action.GetVerb() == "patch" || action.GetVerb() == "delete" {
			t.Fatalf("failed preflight mutated Kubernetes state: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
	got, err := f.kube.CoreV1().ConfigMaps(k8sCatalogueTestOperatorNamespace).Get(context.Background(), cm.Name, metav1.GetOptions{})
	if err != nil || got.Data["ledger"] != cm.Data["ledger"] {
		t.Fatalf("failed preflight rewrote capacity ledger: got=%+v err=%v", got, err)
	}
}

func TestK8sCatalogueRealPhysicalOraclesAndRetrySafeCleanup(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			f := newRealK8sCatalogueTestFixture(t, family)
			fixture := f.preflight(t)
			f.installFamilyEffect(t, fixture)
			signal := k8sCatalogueSignal{Name: "catalog-k8s-real", UID: "event-uid", Creator: f.profile.DetectorIdentity, CreatedAt: time.Now().UTC()}
			physical, err := f.cluster.Physical(context.Background(), f.entry, f.profile, fixture, signal)
			if err != nil || !physical.Validated || physical.Oracle != f.profile.Oracle {
				t.Fatalf("real family oracle failed: result=%+v err=%v", physical, err)
			}
			for attempt := 1; attempt <= 2; attempt++ {
				cleanup := f.cluster.Cleanup(context.Background(), f.entry, f.profile, fixture, k8sCatalogueSignal{}, "", "k8s-test-run")
				if !cleanup.Verified || !cleanup.EventDeleted || !cleanup.MarkerDeleted {
					t.Fatalf("cleanup attempt %d was not exact and retry-safe: %+v", attempt, cleanup)
				}
			}
		})
	}
}

func TestK8sCatalogueRealPhysicalOraclesRejectMissingEffect(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			f := newRealK8sCatalogueTestFixture(t, family)
			fixture := f.preflight(t)
			physical, err := f.cluster.Physical(context.Background(), f.entry, f.profile, fixture,
				k8sCatalogueSignal{Name: "catalog-k8s-real", UID: "event-uid", Creator: f.profile.DetectorIdentity, CreatedAt: time.Now().UTC()})
			if err != nil {
				t.Fatal(err)
			}
			if physical.Validated {
				t.Fatalf("missing %s physical effect passed its oracle: %+v", family, physical)
			}
		})
	}
}

func TestK8sCatalogueRealSignalAdmissionAndExactDeletion(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			f := newRealK8sCatalogueTestFixture(t, family)
			fixture := f.preflight(t)
			f.dynamic.PrependReactor("create", "securityevents", func(action k8stesting.Action) (bool, runtime.Object, error) {
				object := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
				object.SetUID("admitted-event-uid")
				object.SetCreationTimestamp(metav1.NewTime(time.Now().UTC()))
				annotations := object.GetAnnotations()
				annotations[eventtrust.CreatorIdentityAnnotation] = f.profile.DetectorIdentity
				object.SetAnnotations(annotations)
				return false, nil, nil
			})
			signal, err := f.cluster.CreateSignal(context.Background(), f.entry, f.profile, fixture, "k8s-real-signal-run")
			if err != nil || signal.UID != "admitted-event-uid" || signal.Creator != f.profile.DetectorIdentity || signal.CreatedAt.IsZero() {
				t.Fatalf("exact SecurityEvent admission failed: signal=%+v err=%v", signal, err)
			}
			object, err := f.dynamic.Resource(k8sCatalogueSecurityEventGVR).Get(context.Background(), signal.Name, metav1.GetOptions{})
			if err != nil || object.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != fixture.Target.UID ||
				object.GetAnnotations()[attackCatalogCorrelationAnnotation] != "k8s-real-signal-run" {
				t.Fatalf("admitted event lost exact target/run binding: object=%+v err=%v", object, err)
			}
			if got := object.GetLabels()["phorvex.ai/catalogue-id"]; got != catalogueIDLabelValue(f.entry.ID) {
				t.Fatalf("catalogue-id label = %q, want sanitised %q for id %q", got, catalogueIDLabelValue(f.entry.ID), f.entry.ID)
			}
			if got := object.GetAnnotations()[catalogueIDAnnotationKey]; got != f.entry.ID {
				t.Fatalf("catalogue-id annotation = %q, want raw id %q", got, f.entry.ID)
			}
			if family == k8sCatalogueFamilyQuarantine && object.GetAnnotations()["phorvex.ai/protected-outcomes-v1"] == "" {
				t.Fatal("quarantine signal has no reviewed protected-outcome assertion")
			}
			cleanup := f.cluster.Cleanup(context.Background(), f.entry, f.profile, fixture, signal, "", "k8s-real-signal-run")
			if !cleanup.Verified || !cleanup.EventDeleted {
				t.Fatalf("exact admitted event cleanup failed: %+v", cleanup)
			}
			if _, err = f.dynamic.Resource(k8sCatalogueSecurityEventGVR).Get(context.Background(), signal.Name, metav1.GetOptions{}); err == nil {
				t.Fatal("exact admitted SecurityEvent remained after cleanup")
			}
		})
	}
}

func TestK8sCatalogueRealCleanupRefusesForeignArtifact(t *testing.T) {
	f := newRealK8sCatalogueTestFixture(t, k8sCatalogueFamilyQuarantine)
	fixture := f.preflight(t)
	foreign := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: fixture.NetworkPolicyName, Namespace: fixture.Namespace,
		UID: "foreign-network-policy", Labels: map[string]string{"app.kubernetes.io/managed-by": "someone-else"}}}
	if _, err := f.kube.NetworkingV1().NetworkPolicies(f.profile.Namespace).Create(context.Background(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	cleanup := f.cluster.Cleanup(context.Background(), f.entry, f.profile, fixture, k8sCatalogueSignal{}, "", "k8s-test-run")
	if cleanup.Verified || cleanup.MarkerDeleted {
		t.Fatalf("foreign artifact was accepted as exact cleanup: %+v", cleanup)
	}
	remaining, err := f.kube.NetworkingV1().NetworkPolicies(f.profile.Namespace).Get(context.Background(), fixture.NetworkPolicyName, metav1.GetOptions{})
	if err != nil || remaining.UID != foreign.UID {
		t.Fatalf("cleanup deleted or replaced a foreign artifact: remaining=%+v err=%v", remaining, err)
	}
}

func TestK8sCatalogueExactCapacityCleanupPreservesOtherRecords(t *testing.T) {
	f := newRealK8sCatalogueTestFixture(t, k8sCatalogueFamilyQuarantine)
	fixture := f.preflight(t)
	f.kube.Fake.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		cm := action.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		version, _ := strconv.Atoi(cm.ResourceVersion)
		cm.ResourceVersion = strconv.Itoa(version + 1)
		return false, nil, nil
	})
	podObject := "Pod/" + fixture.Namespace + "/" + fixture.Target.Name
	npObject := "NetworkPolicy/" + fixture.Namespace + "/" + fixture.NetworkPolicyName
	quarantineLedger := k8sQuarantineCapacityLedger{Version: 1, Namespace: fixture.Namespace, NamespaceUID: fixture.NamespaceUID,
		Records: map[string]k8sQuarantineCapacityRecord{
			fixture.Target.UID: {OperationID: k8sQuarantineCapacityOperationID(fixture), Phase: "native-effect",
				Namespace: fixture.Namespace, NamespaceUID: fixture.NamespaceUID, Pod: fixture.Target.Name, PodUID: fixture.Target.UID,
				PolicyName: fixture.PolicyName, PolicyUID: fixture.PolicyUID, Backend: "native", EventName: "event",
				EventUID: "event-uid", Objects: []string{podObject, npObject}, Detail: "bound"},
			"other-pod": {OperationID: "other-operation", Phase: "native-effect", Namespace: fixture.Namespace,
				NamespaceUID: fixture.NamespaceUID, Pod: "other", PodUID: "other-pod", PolicyName: fixture.PolicyName,
				PolicyUID: fixture.PolicyUID, Backend: "native", EventName: "other-event", EventUID: "other-event-uid", Detail: "keep-me"},
		}}
	scope := model.ResourceScope{Kind: model.ResourceUnavailableReadyReplica, Namespace: fixture.Namespace,
		ServiceName: f.profile.Service, ServiceUID: fixture.ServiceUID, ControllerUID: fixture.DeploymentUID}
	sharedLedger := k8sSharedCapacityLedger{Version: 1, Records: map[string]k8sSharedCapacityRecord{
		"decision-id": {OperationID: "decision-id", PolicyUID: fixture.PolicyUID, TargetName: fixture.Target.Name,
			TargetUID: fixture.Target.UID, Action: string(model.ActionQuarantine), Phase: "uncertain",
			Admissions: []k8sSharedCapacityAdmission{{Scope: scope, Units: 1, Floor: 2, ReadyBefore: 3}}},
		"other-decision": {OperationID: "other-decision", PolicyUID: "other-policy", TargetName: "other",
			TargetUID: "other-pod", Action: string(model.ActionRotate), Phase: "reserved",
			Admissions: []k8sSharedCapacityAdmission{{Scope: scope, Units: 1, Floor: 2, ReadyBefore: 3}}},
	}}
	quarantineRaw, _ := json.Marshal(quarantineLedger)
	sharedRaw, _ := json.Marshal(sharedLedger)
	objects := []*corev1.ConfigMap{
		{ObjectMeta: metav1.ObjectMeta{Name: k8sQuarantineCapacityLedgerName(fixture.NamespaceUID), Namespace: k8sCatalogueTestOperatorNamespace,
			UID: "quarantine-ledger-uid", ResourceVersion: "1", Labels: map[string]string{"phorvex.ai/quarantine-capacity": "v1"}},
			Data: map[string]string{"ledger": string(quarantineRaw)}},
		{ObjectMeta: metav1.ObjectMeta{Name: "phorvex-shared-capacity", Namespace: k8sCatalogueTestOperatorNamespace,
			UID: "shared-ledger-uid", ResourceVersion: "1", Labels: map[string]string{"phorvex.ai/shared-capacity": "v1"}},
			Data: map[string]string{"ledger": string(sharedRaw)}},
	}
	for _, object := range objects {
		if _, err := f.kube.CoreV1().ConfigMaps(k8sCatalogueTestOperatorNamespace).Create(context.Background(), object, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if !f.cluster.cleanupK8sQuarantineCapacity(context.Background(), fixture, "decision-id") {
		t.Fatal("exact capacity records were not removed")
	}
	quarantineCM, err := f.kube.CoreV1().ConfigMaps(k8sCatalogueTestOperatorNamespace).Get(context.Background(), objects[0].Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sharedCM, err := f.kube.CoreV1().ConfigMaps(k8sCatalogueTestOperatorNamespace).Get(context.Background(), objects[1].Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var gotQuarantine k8sQuarantineCapacityLedger
	var gotShared k8sSharedCapacityLedger
	if json.Unmarshal([]byte(quarantineCM.Data["ledger"]), &gotQuarantine) != nil ||
		json.Unmarshal([]byte(sharedCM.Data["ledger"]), &gotShared) != nil {
		t.Fatal("updated capacity ledger is not decodable")
	}
	if _, exists := gotQuarantine.Records[fixture.Target.UID]; exists || gotQuarantine.Records["other-pod"].Detail != "keep-me" ||
		gotQuarantine.Records["other-pod"].EventUID != "other-event-uid" {
		t.Fatalf("quarantine cleanup removed or truncated another record: %+v", gotQuarantine)
	}
	if _, exists := gotShared.Records["decision-id"]; exists || len(gotShared.Records["other-decision"].Admissions) != 1 ||
		gotShared.Records["other-decision"].Admissions[0].Scope.Key() != scope.Key() {
		t.Fatalf("shared cleanup removed or truncated another record: %+v", gotShared)
	}
}

// capturedReview is one recorded authorization probe issued by the preflight.
type capturedReview struct {
	self                                        bool
	user, verb, group, resource, sub, namespace string
	name                                        string
}

// recordK8sCatalogueReviews replaces the fixture's allow-all authz reactors with
// recording ones (still allow-all) so a test can assert WHICH identity each verb was
// proven against. allow lets a test deny a specific principal/verb to prove gating.
func recordK8sCatalogueReviews(f realK8sCatalogueTestFixture, out *[]capturedReview, allow func(capturedReview) bool) {
	f.kube.Fake.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		r := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
		ra := r.Spec.ResourceAttributes
		c := capturedReview{self: true, verb: ra.Verb, group: ra.Group, resource: ra.Resource, sub: ra.Subresource, namespace: ra.Namespace, name: ra.Name}
		*out = append(*out, c)
		r.Status.Allowed = allow == nil || allow(c)
		return true, r, nil
	})
	f.kube.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		r := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		ra := r.Spec.ResourceAttributes
		c := capturedReview{user: r.Spec.User, verb: ra.Verb, group: ra.Group, resource: ra.Resource, sub: ra.Subresource, namespace: ra.Namespace, name: ra.Name}
		*out = append(*out, c)
		r.Status.Allowed = allow == nil || allow(c)
		return true, r, nil
	})
}

func isK8sCatalogueActuationVerb(c capturedReview) bool {
	switch {
	case c.resource == "pods" && c.sub == "eviction" && c.verb == "create":
		return true
	case c.resource == "pods" && (c.verb == "delete" || c.verb == "update" || c.verb == "patch"):
		return true
	case c.resource == "networkpolicies" && (c.verb == "create" || c.verb == "delete" || c.verb == "update" || c.verb == "patch"):
		return true
	case c.resource == "configmaps" && (c.verb == "update" || c.verb == "patch"):
		return true
	}
	return false
}

// TestK8sCataloguePreflightProvesActuationAgainstDefenderNotAttacks is the trust-boundary
// regression: the red-team attacks SA must NEVER be self-checked for (and so never needs) an
// actuation/remediation verb. Every actuation verb is proven with a SubjectAccessReview naming
// the defender actuator (remediation) or the dedicated delete-only cleanup identity (undo).
func TestK8sCataloguePreflightProvesActuationAgainstDefenderNotAttacks(t *testing.T) {
	for _, family := range []string{k8sCatalogueFamilyQuarantine, k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop} {
		t.Run(family, func(t *testing.T) {
			f := newRealK8sCatalogueTestFixture(t, family)
			var reviews []capturedReview
			recordK8sCatalogueReviews(f, &reviews, nil)
			if _, err := f.cluster.Preflight(context.Background(), f.entry, f.profile); err != nil {
				t.Fatalf("preflight failed with the defender identities configured: %v", err)
			}
			// The attacks SA is never even asked whether it can actuate.
			for _, r := range reviews {
				if r.self && isK8sCatalogueActuationVerb(r) {
					t.Fatalf("attacks SA self-checked an actuation verb (must be proven against a defender identity): %+v", r)
				}
				if !r.self && isK8sCatalogueActuationVerb(r) && r.user != k8sCatalogueTestActuatorIdentity && r.user != k8sCatalogueTestCleanupIdentity {
					t.Fatalf("actuation verb proven against an unexpected principal %q: %+v", r.user, r)
				}
			}
			proven := func(user, verb, group, resource, sub, namespace, name string) bool {
				for _, r := range reviews {
					if !r.self && r.user == user && r.verb == verb && r.group == group && r.resource == resource && r.sub == sub && r.namespace == namespace && r.name == name {
						return true
					}
				}
				return false
			}
			if family == k8sCatalogueFamilyQuarantine {
				quarantineLedger := k8sQuarantineCapacityLedgerName("namespace-uid")
				for _, name := range []string{"phorvex-shared-capacity", quarantineLedger} {
					seen := false
					for _, r := range reviews {
						seen = seen || (r.self && r.verb == "get" && r.resource == "configmaps" && r.namespace == k8sCatalogueTestOperatorNamespace && r.name == name)
					}
					if !seen {
						t.Fatalf("quarantine ledger read was not resourceName-bound: %s", name)
					}
				}
				want := []capturedReview{
					{user: k8sCatalogueTestActuatorIdentity, verb: "update", resource: "pods", namespace: f.profile.Namespace},
					{user: k8sCatalogueTestActuatorIdentity, verb: "create", group: "networking.k8s.io", resource: "networkpolicies", namespace: f.profile.Namespace},
					{user: k8sCatalogueTestActuatorIdentity, verb: "update", resource: "configmaps", namespace: k8sCatalogueTestOperatorNamespace},
					{user: k8sCatalogueTestCleanupIdentity, verb: "delete", resource: "pods", namespace: f.profile.Namespace},
					{user: k8sCatalogueTestCleanupIdentity, verb: "delete", group: "networking.k8s.io", resource: "networkpolicies", namespace: f.profile.Namespace},
					{user: k8sCatalogueTestCleanupIdentity, verb: "update", resource: "configmaps", namespace: k8sCatalogueTestOperatorNamespace, name: "phorvex-shared-capacity"},
					{user: k8sCatalogueTestCleanupIdentity, verb: "update", resource: "configmaps", namespace: k8sCatalogueTestOperatorNamespace, name: quarantineLedger},
				}
				for _, w := range want {
					if !proven(w.user, w.verb, w.group, w.resource, w.sub, w.namespace, w.name) {
						t.Fatalf("quarantine actuation/cleanup verb not proven against its identity: %+v", w)
					}
				}
			} else if !proven(k8sCatalogueTestActuatorIdentity, "create", "", "pods", "eviction", f.profile.Namespace, "") {
				t.Fatalf("%s rotate eviction not proven against the actuator identity", family)
			}
		})
	}
}

// TestK8sCataloguePreflightDecoupledFromAttacksActuationGrants proves the attacks SA can be
// fully DENIED every actuation verb and the preflight still passes: it is gated only on the
// attacks SA's reads/event lifecycle plus the defender-identity SubjectAccessReviews.
func TestK8sCataloguePreflightDecoupledFromAttacksActuationGrants(t *testing.T) {
	f := newRealK8sCatalogueTestFixture(t, k8sCatalogueFamilyQuarantine)
	var reviews []capturedReview
	recordK8sCatalogueReviews(f, &reviews, func(c capturedReview) bool {
		// Deny the attacks SA (self) any actuation verb; it must not need them.
		return !(c.self && isK8sCatalogueActuationVerb(c))
	})
	if _, err := f.cluster.Preflight(context.Background(), f.entry, f.profile); err != nil {
		t.Fatalf("preflight must not depend on the attacks SA holding actuation verbs: %v", err)
	}
}

// TestK8sCataloguePreflightFailsWhenDefenderLacksActuation proves the actuation verbs are
// genuinely gated on the defender identities: deny the actuator and the preflight fails closed.
func TestK8sCataloguePreflightFailsWhenDefenderLacksActuation(t *testing.T) {
	f := newRealK8sCatalogueTestFixture(t, k8sCatalogueFamilyQuarantine)
	var reviews []capturedReview
	recordK8sCatalogueReviews(f, &reviews, func(c capturedReview) bool {
		return !(c.user == k8sCatalogueTestActuatorIdentity && c.resource == "networkpolicies")
	})
	if _, err := f.cluster.Preflight(context.Background(), f.entry, f.profile); err == nil {
		t.Fatal("quarantine preflight passed while the actuator could not create the deny-all NetworkPolicy")
	}
}

// TestK8sCatalogueQuarantineCleanupRequiresCleanupIdentity proves the undo of actuator-created
// artifacts never silently runs as the attacks SA: with no cleanup identity wired, cleanup of
// the quarantined Pod / deny-all NetworkPolicy / capacity records is not performed or verified.
func TestK8sCatalogueQuarantineCleanupRequiresCleanupIdentity(t *testing.T) {
	f := newRealK8sCatalogueTestFixture(t, k8sCatalogueFamilyQuarantine)
	fixture := f.preflight(t)
	f.installFamilyEffect(t, fixture)
	f.cluster.cleanupKube = nil // no delete-only cleanup identity available
	result := f.cluster.Cleanup(context.Background(), f.entry, f.profile, fixture,
		k8sCatalogueSignal{Name: "catalog-k8s-real", UID: "event-uid", Creator: f.profile.DetectorIdentity, CreatedAt: time.Now().UTC()}, "", "k8s-test-run")
	if result.Verified || result.MarkerDeleted {
		t.Fatalf("quarantine cleanup must not remediate actuator artifacts without the cleanup identity: %+v", result)
	}
	pod, err := f.kube.CoreV1().Pods(fixture.Namespace).Get(context.Background(), fixture.Target.Name, metav1.GetOptions{})
	if err != nil || string(pod.UID) != fixture.Target.UID {
		t.Fatalf("quarantined Pod was deleted without the cleanup identity: err=%v", err)
	}
}
