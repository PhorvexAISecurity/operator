package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNATSResponseCleanupPhaseJournalRejectsAmbiguousCreate(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	out := t.TempDir()
	row := func(phase string, uid types.UID) []byte {
		raw, err := json.Marshal(natsResponseCleanupPhase{Schema: natsResponseSchema, RunID: "run-7", Nonce: nonce,
			NamespaceUID: "namespace-uid", Phase: phase, Resource: "services", Name: natsResponseName(nonce),
			UID: uid, At: time.Now().UTC().Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	path := filepath.Join(out, "nats-response-phases.jsonl")
	if err := os.WriteFile(path, row("CREATE_INTENT", ""), 0600); err != nil {
		t.Fatal(err)
	}
	states, err := natsResponseCleanupPhases(out, "run-7", nonce, "namespace-uid")
	if err != nil {
		t.Fatal(err)
	}
	if err := natsResponseCreateAuthority(states, "services", ""); err == nil {
		t.Fatal("ambiguous Service CREATE was misclassified as absent")
	}
	if err := os.WriteFile(path, append(row("CREATE_INTENT", ""), row("CREATED", "owned-uid")...), 0600); err != nil {
		t.Fatal(err)
	}
	states, err = natsResponseCleanupPhases(out, "run-7", nonce, "namespace-uid")
	if err != nil || natsResponseCreateAuthority(states, "services", "owned-uid") != nil {
		t.Fatalf("acknowledged UID refused: %v", err)
	}
	if natsResponseCreateAuthority(states, "services", "replacement") == nil {
		t.Fatal("replacement UID admitted")
	}
	partial := row("CREATED", "owned-uid")
	if err := os.WriteFile(path, append(row("CREATE_INTENT", ""), partial[:len(partial)-1]...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := natsResponseCleanupPhases(out, "run-7", nonce, "namespace-uid"); err == nil {
		t.Fatal("partial terminal row admitted")
	}
}

func TestNATSResponseCleanupPhaseJournalRejectsSymlink(t *testing.T) {
	out := t.TempDir()
	target := filepath.Join(out, "target")
	if err := os.WriteFile(target, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(out, "nats-response-phases.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := natsResponseCleanupPhases(out, "run-7", "0123456789abcdef01234567", "namespace-uid"); err == nil {
		t.Fatal("linked journal admitted")
	}
}

func TestNATSResponseExactDeleteUsesUIDAndRVOnce(t *testing.T) {
	current, rv := types.UID("owned-uid"), "version-7"
	removes := 0
	get := func(context.Context) (types.UID, string, error) {
		if current == "" {
			return "", "", apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "owned")
		}
		return current, rv, nil
	}
	remove := func(_ context.Context, uid types.UID, version string) error {
		removes++
		if uid != current || version != rv {
			t.Fatalf("unbound delete %s/%s", uid, version)
		}
		current = ""
		return nil
	}
	if err := natsResponseExactDelete(context.Background(), "pods", "owned", "wrong-uid", get, remove); err == nil || removes != 0 {
		t.Fatalf("replacement was deleted or admitted: calls=%d err=%v", removes, err)
	}
	if err := natsResponseExactDelete(context.Background(), "pods", "owned", "owned-uid", get, remove); err != nil || removes != 1 {
		t.Fatalf("exact cleanup failed: calls=%d err=%v", removes, err)
	}
	if err := natsResponseExactDelete(context.Background(), "pods", "owned", "owned-uid", get, remove); err != nil || removes != 1 {
		t.Fatalf("absence retried a delete: calls=%d err=%v", removes, err)
	}
}

func TestNATSResponseExactDeleteAmbiguousRequestIsNotRetried(t *testing.T) {
	calls := 0
	err := natsResponseExactDelete(context.Background(), "pods", "owned", "owned-uid",
		func(context.Context) (types.UID, string, error) { return "owned-uid", "version-7", nil },
		func(context.Context, types.UID, string) error {
			calls++
			return errors.New("transport outcome unknown")
		})
	if err == nil || calls != 1 {
		t.Fatalf("ambiguous delete replayed: calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = natsResponseExactDelete(ctx, "pods", "owned", "owned-uid",
		func(context.Context) (types.UID, string, error) { return "owned-uid", "version-7", nil },
		func(context.Context, types.UID, string) error { return nil })
	if err == nil {
		t.Fatal("unobserved absence after canceled context accepted")
	}
}

func TestNATSResponseCleanupEvidenceRejectsDuplicateAndLinkedFiles(t *testing.T) {
	out := t.TempDir()
	const name = "nats-response-decision-evidence.json"
	path := filepath.Join(out, name)
	if err := os.WriteFile(path, []byte(`{"objectEffect":{"amtdUID":"first","amtdUID":"second"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := natsResponseCleanupReadPrivate(out, name, 32<<10)
	if err != nil {
		t.Fatal(err)
	}
	if err := natsResponseCleanupNoDuplicates(raw); err == nil {
		t.Fatal("duplicate nested UID admitted")
	}
	if err := os.Link(path, filepath.Join(out, "second-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := natsResponseCleanupReadPrivate(out, name, 32<<10); err == nil {
		t.Fatal("hardlinked decision evidence admitted")
	}
}

func TestNATSResponseCleanupUsesCanonicalPhoenixPolicyName(t *testing.T) {
	name := amtdv1beta1.QuarantineNetworkPolicyName(natsResponseFixtureNamespace, "nats-response-0123456789abcdef01234567-abcde")
	if len(name) > 63 || name == natsResponseFixtureNamespace+"-nats-response-0123456789abcdef01234567-abcde-policy" {
		t.Fatalf("long-Pod Phoenix policy name was not canonical: %q", name)
	}
}

func TestNATSResponseCleanupQuarantinedSourceAuthorityIsExact(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	trueValue := true
	f := natsResponseFixture{Client: natsResponsePodIdentity{Name: "source", UID: "source-uid"}, ReplicaSetUID: "rs-uid"}
	e := &natsResponseEffectID{AMTDName: "owned-amtd", AMTDUID: "amtd-uid", PhoenixNetworkPolicyName: "owned-np"}
	source := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: f.Client.Name, UID: f.Client.UID,
		Labels: map[string]string{natsResponseOwnerLabel: nonce, natsResponseRoleLabel: "source", "amtd.r6security.com/network-policy": e.PhoenixNetworkPolicyName},
		Annotations: map[string]string{core.OwnedLabelKey: core.OwnedLabelValue, core.ScenarioLabelKey: natsResponseScenario,
			core.TrialLabelKey: "0", natsResponseComponentLabel: "consumer"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "amtd.r6security.com/v1beta1", Kind: "AdaptiveMovingTargetDefense", Name: e.AMTDName, UID: e.AMTDUID, Controller: &trueValue}}}}
	if !natsResponseCleanupPodOwned(source, f, "owned-rs", e, nonce) {
		t.Fatal("exact Phoenix-reparented source refused")
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"wrong uid":      func(p *corev1.Pod) { p.UID = "replacement" },
		"missing marker": func(p *corev1.Pod) { delete(p.Labels, "amtd.r6security.com/network-policy") },
		"wrong owner":    func(p *corev1.Pod) { p.OwnerReferences[0].UID = "other-amtd" },
		"lost provenance": func(p *corev1.Pod) {
			delete(p.Annotations, core.ScenarioLabelKey)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := source.DeepCopy()
			mutate(candidate)
			if natsResponseCleanupPodOwned(candidate, f, "owned-rs", e, nonce) {
				t.Fatal("changed source authority admitted")
			}
		})
	}
	peer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "peer", UID: "peer-uid", Labels: natsResponseLabels(nonce),
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "owned-rs", UID: "rs-uid", Controller: &trueValue}}}}
	if !natsResponseCleanupPodOwned(peer, f, "owned-rs", e, nonce) {
		t.Fatal("exact original peer refused")
	}
	peer.Labels = source.Labels
	peer.OwnerReferences = source.OwnerReferences
	if natsResponseCleanupPodOwned(peer, f, "owned-rs", e, nonce) {
		t.Fatal("Phoenix-owned peer adopted as fixture child")
	}
}

type responseCleanupRecordingCtrl struct {
	ctrlclient.Client
	deleted []string
}

func (r *responseCleanupRecordingCtrl) Delete(ctx context.Context, obj ctrlclient.Object, options ...ctrlclient.DeleteOption) error {
	var opts ctrlclient.DeleteOptions
	for _, option := range options {
		option.ApplyToDelete(&opts)
	}
	_, clusterScoped := obj.(*amtdv1beta1.SecurityEvent)
	if obj.GetName() == "" || (!clusterScoped && obj.GetNamespace() == "") || opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID == "" || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion == "" {
		return errors.New("CRD delete lacks exact name, namespace, UID or resourceVersion")
	}
	r.deleted = append(r.deleted, fmt.Sprintf("%T/%s", obj, obj.GetName()))
	return r.Client.Delete(ctx, obj, options...)
}

// This uses both fake clients across the entire no-op cleanup path, including
// the actual policy Delete call. Helper-only tests missed an empty delete name.
func TestNATSResponseCleanupFullNoopFixtureUsesExactDeletes(t *testing.T) {
	testNATSResponseCleanupFullFixture(t, false)
}

func TestNATSResponseCleanupFullQuarantinedSourceUsesExactDeletes(t *testing.T) {
	testNATSResponseCleanupFullFixture(t, true)
}

func testNATSResponseCleanupFullFixture(t *testing.T, selected bool) {
	const nonce = "0123456789abcdef01234567"
	const ns = natsResponseFixtureNamespace
	const runID = "run-7"
	name := natsResponseName(nonce)
	env := responseManifestEnv()
	env.Config.OutDir = t.TempDir()
	env.Config.NATSExposureFixture.RunID = runID
	env.Guard = natsResponseAllowGuard{}
	yes := true
	labels := natsResponseLabels(nonce)
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: "ns-uid", Labels: map[string]string{"phorvex.ai/nats-exposure-fixture": "true"}}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: "cm-uid", ResourceVersion: "1", Labels: labels}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: "svc-uid", ResourceVersion: "1", Labels: labels}}
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: "pdb-uid", ResourceVersion: "1", Labels: labels}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: "dep-uid", ResourceVersion: "1", Labels: labels}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: name + "-rs", Namespace: ns, UID: "rs-uid", ResourceVersion: "1", Labels: labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: name, UID: dep.UID, Controller: &yes}}}}
	peerLabels := natsResponseLabels(nonce)
	peerLabels[natsResponseComponentLabel] = "consumer"
	sourceLabels := natsResponseLabels(nonce)
	sourceLabels[natsResponseComponentLabel] = "consumer"
	sourceLabels[natsResponseRoleLabel] = "source"
	owners := []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}
	source := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-a", Namespace: ns, UID: "source-uid", ResourceVersion: "1", Labels: sourceLabels, OwnerReferences: owners}}
	peer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-b", Namespace: ns, UID: "peer-uid", ResourceVersion: "1", Labels: peerLabels, OwnerReferences: owners}}
	var effect *natsResponseEffectID
	var objects []runtime.Object
	objects = append(objects, namespace, cm, svc, pdb, dep, rs, source, peer)
	if selected {
		effect = &natsResponseEffectID{GeneratedEventName: "phoenix-generated", GeneratedEventUID: "generated-uid", OperationID: "0123456789abcdef0123456789abcdef01234567",
			AMTDName: "phorvex-" + ns + "-" + nonce, AMTDUID: "amtd-uid", PhoenixNetworkPolicyName: amtdv1beta1.QuarantineNetworkPolicyName(ns, source.Name),
			PhoenixNetworkPolicyUID: "np-uid", SourcePodUID: source.UID, PeerPodUID: peer.UID}
		source.Labels = map[string]string{natsResponseOwnerLabel: nonce, natsResponseRoleLabel: "source", "amtd.r6security.com/network-policy": effect.PhoenixNetworkPolicyName}
		source.Annotations = map[string]string{core.OwnedLabelKey: core.OwnedLabelValue, core.ScenarioLabelKey: natsResponseScenario,
			core.TrialLabelKey: "0", natsResponseComponentLabel: "consumer"}
		source.OwnerReferences = []metav1.OwnerReference{{APIVersion: "amtd.r6security.com/v1beta1", Kind: "AdaptiveMovingTargetDefense", Name: effect.AMTDName, UID: effect.AMTDUID, Controller: &yes}}
		objects = append(objects, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: effect.PhoenixNetworkPolicyName, Namespace: ns, UID: effect.PhoenixNetworkPolicyUID,
			ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{{APIVersion: "amtd.r6security.com/v1beta1", Kind: "AdaptiveMovingTargetDefense", Name: effect.AMTDName, UID: effect.AMTDUID, Controller: &yes}}},
			Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"amtd.r6security.com/network-policy": effect.PhoenixNetworkPolicyName}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}})
	}
	kube := kubefake.NewSimpleClientset(objects...)
	env.Kube = kube
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	policy := natsResponsePolicy(env, name)
	policy.SetUID("policy-uid")
	policy.SetResourceVersion("1")
	policy.SetGeneration(1)
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{ObjectMeta: metav1.ObjectMeta{Name: "phorvex-" + ns + "-" + nonce, Namespace: ns, UID: "amtd-uid", ResourceVersion: "1",
		Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": nonce},
		Annotations: map[string]string{"phorvex.ai/identity-version": "v1", "phorvex.ai/namespace-raw": ns, "phorvex.ai/tenant-raw": nonce,
			"phorvex.ai/policy-name": name, "phorvex.ai/policy-uid": "policy-uid", "phorvex.ai/policy-generation": "1"}},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{PodSelector: map[string]string{natsResponseOwnerLabel: nonce, natsResponseRoleLabel: "source"}, MatcherMode: amtdv1beta1.MatcherModeExact,
			Strategy: []amtdv1beta1.ResponseStrategy{
				{Rule: amtdv1beta1.Rule{Type: "phorvex.rotate", ThreatLevel: "high", Source: "PhorvexController"}, Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}}},
				{Rule: amtdv1beta1.Rule{Type: "phorvex.quarantine", ThreatLevel: "high", Source: "PhorvexController"}, Action: amtdv1beta1.AMTDAction{Quarantine: &amtdv1beta1.QuarantineAction{}}}}}}
	scheme := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	scheme.AddKnownTypeWithName(natsResponsePolicyGVK, &unstructured.Unstructured{})
	var ctrlObjects []ctrlclient.Object
	ctrlObjects = append(ctrlObjects, policy, amtd)
	if selected {
		ctrlObjects = append(ctrlObjects, &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: effect.GeneratedEventName, UID: effect.GeneratedEventUID, ResourceVersion: "1",
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": nonce, "phorvex.ai/action": "quarantine"},
			Annotations: map[string]string{"phorvex.ai/quarantine-target-uid": string(source.UID), "phorvex.ai/quarantine-namespace-uid": "ns-uid", "phorvex.ai/quarantine-operation": effect.OperationID}},
			Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{ns + "/" + source.Name}, Rule: amtdv1beta1.Rule{Type: "phorvex.quarantine", Source: "PhorvexController", ThreatLevel: "high"}}})
	}
	control := &responseCleanupRecordingCtrl{Client: ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(ctrlObjects...).Build()}
	env.Ctrl = control
	fixture := natsResponseFixture{Name: name, NamespaceUID: "ns-uid", ConfigMapUID: cm.UID, ServiceUID: svc.UID, PDBUID: pdb.UID, DeploymentUID: dep.UID,
		ReplicaSetUID: rs.UID, PolicyUID: policy.GetUID(), PolicyGen: 1, Client: natsResponsePodIdentity{Name: source.Name, UID: source.UID}, Peer: natsResponsePodIdentity{Name: peer.Name, UID: peer.UID}}
	for _, item := range []struct {
		resource string
		uid      types.UID
	}{{"configmaps", cm.UID}, {"services", svc.UID}, {"poddisruptionbudgets", pdb.UID}, {"phorvexpolicies", policy.GetUID()}, {"deployments", dep.UID}} {
		if err := natsResponsePhase(env, "CREATE_INTENT", item.resource, name, ""); err != nil {
			t.Fatal(err)
		}
		if err := env.RecordCreatedUID(item.resource, name, item.uid); err != nil {
			t.Fatal(err)
		}
		if err := natsResponsePhase(env, "CREATED", item.resource, name, item.uid); err != nil {
			t.Fatal(err)
		}
	}
	selectedAction := "noop"
	if selected {
		selectedAction = "quarantine"
	}
	whyRaw, err := json.Marshal(natsResponseCleanupWhy{Schema: "nats-client-response-decision-evidence-v1", RunID: runID, NamespaceUID: "ns-uid", ClientPodUID: source.UID, PolicyUID: policy.GetUID(), EventName: "injected-owned", EventUID: "event-uid", SelectedAction: selectedAction, ObjectEffect: effect})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.Config.OutDir, "nats-response-decision-evidence.json"), whyRaw, 0600); err != nil {
		t.Fatal(err)
	}
	decision := &natsResponseSignalDecision{RunID: runID, Nonce: nonce, NamespaceUID: "ns-uid", ClientPodUID: source.UID, PeerPodUID: peer.UID, PolicyUID: policy.GetUID(), EventName: "injected-owned", EventUID: "event-uid", DecisionEvidenceSHA256: natsSHA(whyRaw), SelectedAction: selectedAction, EventCleanupStatus: "CONFIRMED_ABSENT"}
	var receipts [2]natsexposure.Receipt
	subjects := natsResponseSubjects(nonce)
	for i, phase := range [2]string{"M0", "M1"} {
		receipts[i] = natsexposure.Receipt{Stream: "CAT_" + nonce + "_" + phase, Subject: subjects[i], Consumer: "CAT_" + nonce + "_" + phase + "_C", Nonce: nonce, Cleanup: "CONFIRMED_ABSENT", StreamCreatedUTC: time.Now().UTC().Format(time.RFC3339Nano)}
		if err := natsResponseProtocolRecord(env, phase, receipts[i]); err != nil {
			t.Fatal(err)
		}
	}
	checks, err := natsResponseCleanup(context.Background(), env, fixture, decision, receipts)
	if err != nil || !checks.allConfirmed() {
		t.Fatalf("full fixture cleanup failed (selected=%t): checks=%+v err=%v", selected, checks, err)
	}
	wantCtrlDeletes := 2
	if selected {
		wantCtrlDeletes++
	}
	if len(control.deleted) != wantCtrlDeletes {
		t.Fatalf("expected exact controller deletes: %v", control.deleted)
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() != "delete" {
			continue
		}
		deleted, ok := action.(kubetesting.DeleteAction)
		if !ok || deleted.GetDeleteOptions().Preconditions == nil || deleted.GetDeleteOptions().Preconditions.UID == nil || deleted.GetDeleteOptions().Preconditions.ResourceVersion == nil {
			t.Fatalf("Kubernetes delete lacks UID/RV: %#v", action)
		}
	}
	if _, err := kube.CoreV1().Namespaces().Get(context.Background(), ns, metav1.GetOptions{}); err != nil {
		t.Fatalf("shared Namespace removed: %v", err)
	}
	if _, err := kube.CoreV1().ConfigMaps(ns).Get(context.Background(), name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("owned fixture remains: %v", err)
	}
}
