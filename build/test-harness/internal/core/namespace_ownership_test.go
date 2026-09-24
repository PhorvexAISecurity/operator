package core

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

func TestEnsureNamespaceCapturesCreatedUID(t *testing.T) {
	kube := fake.NewSimpleClientset()
	kube.PrependReactor("create", "namespaces", func(action ktest.Action) (bool, runtime.Object, error) {
		ns := action.(ktest.CreateAction).GetObject().(*corev1.Namespace)
		ns.UID = types.UID("created-uid")
		return false, nil, nil
	})
	env := &Env{
		Kube: kube, Config: config.TargetConfig{Namespace: "sandbox"},
		Log: &nopLogger{}, Guard: refusingGuard{allow: "sandbox"},
	}
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatalf("EnsureNamespace: %v", err)
	}
	if env.namespaceUID != types.UID("created-uid") {
		t.Fatalf("captured UID = %q, want created-uid", env.namespaceUID)
	}
}

func TestPodBoundTokenRequiresExistingVoiceNamespace(t *testing.T) {
	kube := fake.NewSimpleClientset()
	env := &Env{Kube: kube, Config: config.TargetConfig{Namespace: "voice", PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{}}, Log: &nopLogger{}, Guard: refusingGuard{allow: "voice"}}
	if err := env.EnsureNamespace(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing to create") {
		t.Fatalf("missing Voice namespace was not refused: %v", err)
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() != "get" {
			t.Fatalf("Pod token fixture mutated missing Voice namespace: %#v", action)
		}
	}
}

func TestEnsureNamespaceRefusesConcurrentAlreadyExists(t *testing.T) {
	kube := fake.NewSimpleClientset()
	kube.PrependReactor("create", "namespaces", func(ktest.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "namespaces"}, "sandbox")
	})
	env := &Env{Kube: kube, Config: config.TargetConfig{Namespace: "sandbox"}, Log: &nopLogger{}, Guard: refusingGuard{allow: "sandbox"}}
	err := env.EnsureNamespace(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
		t.Fatalf("concurrent namespace was accepted: %v", err)
	}
	if env.namespaceUID != "" {
		t.Fatalf("concurrent namespace captured UID %q", env.namespaceUID)
	}
}

func TestEnsureNamespaceRequiresExpectedUIDBeforeScenarioMutation(t *testing.T) {
	uid := "11111111-2222-4333-8444-555555555555"
	env := &Env{
		Kube:   fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: types.UID(uid)}}),
		Config: config.TargetConfig{Namespace: "sandbox", ExpectedNamespaceUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"},
		Log:    &nopLogger{}, Guard: refusingGuard{allow: "sandbox"},
	}
	if err := env.EnsureNamespace(context.Background()); err == nil || !strings.Contains(err.Error(), "expectedNamespaceUID") {
		t.Fatalf("mismatched externally created namespace was accepted: %v", err)
	}
	for _, action := range env.Kube.(*fake.Clientset).Actions() {
		if action.GetVerb() != "get" {
			t.Fatalf("mismatch caused mutation: %#v", action)
		}
	}
	if env.namespaceUID != "" {
		t.Fatalf("mismatch captured namespace UID %q", env.namespaceUID)
	}
}

func TestEnsureNamespaceRefusesMissingExpectedUIDWithoutCreate(t *testing.T) {
	kube := fake.NewSimpleClientset()
	env := &Env{
		Kube:   kube,
		Config: config.TargetConfig{Namespace: "sandbox", ExpectedNamespaceUID: "11111111-2222-4333-8444-555555555555"},
		Log:    &nopLogger{}, Guard: refusingGuard{allow: "sandbox"},
	}
	err := env.EnsureNamespace(context.Background())
	if err == nil || !strings.Contains(err.Error(), "expectedNamespaceUID") || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing pinned namespace was not refused: %v", err)
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() != "get" {
			t.Fatalf("missing pinned namespace caused mutation: %#v", action)
		}
	}
}

func TestEnsureNamespaceAcceptsExpectedUIDAndUnsetCompatibility(t *testing.T) {
	uid := "11111111-2222-4333-8444-555555555555"
	for _, expected := range []string{uid, ""} {
		env := &Env{
			Kube:   fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: types.UID(uid)}}),
			Config: config.TargetConfig{Namespace: "sandbox", ExpectedNamespaceUID: expected},
			Log:    &nopLogger{}, Guard: refusingGuard{allow: "sandbox"},
		}
		if err := env.EnsureNamespace(context.Background()); err != nil {
			t.Fatalf("expected UID %q refused: %v", expected, err)
		}
		if env.namespaceUID != types.UID(uid) {
			t.Fatalf("expected UID %q captured %q", expected, env.namespaceUID)
		}
	}
}

func TestEnsureNamespaceDoesNotAdoptReplacement(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	kube := env.Kube.(*fake.Clientset)
	replaceNamespace(t, kube, "sandbox", "replacement-uid")
	err := env.EnsureNamespace(context.Background())
	if err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("same-name replacement was adopted: %v", err)
	}
	if env.namespaceUID != types.UID("namespace-sandbox") {
		t.Fatalf("captured UID changed to %q", env.namespaceUID)
	}
}

func TestEnsureNamespaceDoesNotRecreateDisappearedOriginal(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	kube := env.Kube.(*fake.Clientset)
	if err := kube.Tracker().Delete(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, "", "sandbox"); err != nil {
		t.Fatal(err)
	}
	err := env.EnsureNamespace(context.Background())
	if err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("missing original was recreated: %v", err)
	}
	for _, action := range kube.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "namespaces" {
			t.Fatalf("EnsureNamespace issued CREATE after original UID disappeared")
		}
	}
}

func TestCleanupOriginalAbsentIssuesNoDestructiveRequest(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	kube := env.Kube.(*fake.Clientset)
	if err := kube.Tracker().Delete(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, "", "sandbox"); err != nil {
		t.Fatal(err)
	}
	if err := env.CleanupOwned(context.Background(), true); err != nil {
		t.Fatalf("absent original should be a clean no-op: %v", err)
	}
	assertNoDestructiveActions(t, kube.Actions())
}

func TestCleanupRefusesReplacementBeforeAnyChildRequest(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	kube := env.Kube.(*fake.Clientset)
	replaceNamespace(t, kube, "sandbox", "replacement-uid")
	if err := kube.Tracker().Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "replacement-owned", Namespace: "sandbox", UID: "replacement-pod-uid",
		Labels: map[string]string{OwnedLabelKey: OwnedLabelValue},
	}}); err != nil {
		t.Fatal(err)
	}
	err := env.CleanupOwned(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("cleanup did not refuse replacement namespace: %v", err)
	}
	assertNoDestructiveActions(t, kube.Actions())
}

func TestCleanupRefusesReplacementCreatedDuringChildEnumeration(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	kube := env.Kube.(*fake.Clientset)
	replaced := false
	kube.PrependReactor("list", "pods", func(ktest.Action) (bool, runtime.Object, error) {
		if !replaced {
			replaced = true
			replaceNamespace(t, kube, "sandbox", "replacement-uid")
			if err := kube.Tracker().Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "replacement-owned", Namespace: "sandbox", UID: "replacement-pod-uid",
				Labels: map[string]string{OwnedLabelKey: OwnedLabelValue},
			}}); err != nil {
				t.Fatal(err)
			}
		}
		return false, nil, nil
	})
	err := env.CleanupOwned(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("cleanup did not refuse replacement observed after list: %v", err)
	}
	assertNoDestructiveActions(t, kube.Actions())
	if _, err := kube.CoreV1().Pods("sandbox").Get(context.Background(), "replacement-owned", metav1.GetOptions{}); err != nil {
		t.Fatalf("replacement child was touched: %v", err)
	}
}

func TestCleanupUsesExactChildAndNamespaceUIDPreconditions(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	kube := env.Kube.(*fake.Clientset)
	if err := kube.Tracker().Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "owned", Namespace: "sandbox", UID: "pod-uid",
		Labels: map[string]string{OwnedLabelKey: OwnedLabelValue},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := env.CleanupOwned(context.Background(), true); err != nil {
		t.Fatalf("CleanupOwned: %v", err)
	}
	want := map[string]types.UID{"pods/owned": "pod-uid", "namespaces/sandbox": "namespace-sandbox"}
	for _, action := range kube.Actions() {
		if action.GetVerb() != "delete" {
			continue
		}
		del := action.(ktest.DeleteAction)
		key := action.GetResource().Resource + "/" + del.GetName()
		uid := del.GetDeleteOptions().Preconditions
		if expected, ok := want[key]; ok {
			if uid == nil || uid.UID == nil || *uid.UID != expected {
				t.Errorf("%s precondition = %+v, want UID %q", key, uid, expected)
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing exact deletes: %v", want)
	}
}

func replaceNamespace(t *testing.T, kube *fake.Clientset, name string, uid types.UID) {
	t.Helper()
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	if err := kube.Tracker().Delete(gvr, "", name); err != nil {
		t.Fatal(err)
	}
	if err := kube.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid}}); err != nil {
		t.Fatal(err)
	}
}

func assertNoDestructiveActions(t *testing.T, actions []ktest.Action) {
	t.Helper()
	for _, action := range actions {
		if action.GetVerb() == "delete" || action.GetVerb() == "delete-collection" {
			t.Fatalf("unexpected destructive request: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
}
