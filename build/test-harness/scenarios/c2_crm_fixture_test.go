package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type crmAllowGuard struct{}

func (crmAllowGuard) AssertMutationAllowed(string) error { return nil }

func TestCRMFixtureExactSourceAndDependencyLock(t *testing.T) {
	app, probe, err := crmFixtureFiles()
	if err != nil || len(app) != 5438 || len(probe) == 0 {
		t.Fatalf("exact CRM fixture sources unavailable: app=%d probe=%d err=%v", len(app), len(probe), err)
	}
	lock, err := crmLoadDependencyLock()
	if err != nil || lock.Packages["pymongo"] != "4.17.0" || lock.Packages["fastapi"] != "0.115.14" {
		t.Fatalf("CRM installed dependency closure differs: %v", err)
	}
}

func TestCRMScopedIdentityAndImageDigestBeforeEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	raw := []byte("apiVersion: v1\nkind: Config\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sha := fmt.Sprintf("%x", sha256.Sum256(raw))
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.SelfSubjectReview{Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:crm-fixture:fixture-sa"}}}, nil
	})
	if err := crmVerifyScopedIdentity(context.Background(), client, path, "crm-fixture", "fixture-sa", sha); err != nil {
		t.Fatalf("scoped identity refused: %v", err)
	}
	if err := crmVerifyScopedIdentity(context.Background(), client, path, "crm-fixture", "other-sa", sha); err == nil {
		t.Fatal("wrong service account accepted")
	}
	if err := crmVerifyScopedIdentity(context.Background(), client, path, "crm-fixture", "fixture-sa", strings.Repeat("0", 64)); err == nil {
		t.Fatal("changed kubeconfig accepted")
	}
	if !crmRuntimeImageMatches("example.invalid/crm@sha256:"+strings.Repeat("a", 64), "containerd://sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("matching runtime image rejected")
	}
	if crmRuntimeImageMatches("example.invalid/crm@sha256:"+strings.Repeat("a", 64), "containerd://sha256:"+strings.Repeat("b", 64)) {
		t.Fatal("mismatched runtime image accepted")
	}
}

func TestCRMTeardownPreservesForeignOwnedObjectAndNamespace(t *testing.T) {
	const ns = "crm-fixture"
	const uid = "11111111-1111-4111-8111-111111111111"
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: types.UID(uid), Labels: map[string]string{"phorvex.ai/crm-capability-fixture": "true"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "c2-crm-refund-1234567890abcdef", Namespace: ns, UID: types.UID("pod-uid"), Labels: map[string]string{core.OwnedLabelKey: core.OwnedLabelValue}}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "c2-crm-refund-1234567890abcdef-code", Namespace: ns, UID: types.UID("cm-uid"), Labels: map[string]string{core.OwnedLabelKey: core.OwnedLabelValue}}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foreign-owned", Namespace: ns, UID: types.UID("foreign"), Labels: map[string]string{core.OwnedLabelKey: core.OwnedLabelValue}}},
	)
	env := &core.Env{Kube: client, Guard: crmAllowGuard{}, Config: config.TargetConfig{Namespace: ns, ExpectedNamespaceUID: uid, OutDir: t.TempDir(), ScenarioFilter: []string{"c2-crm-refund-capability"}, CRMCapabilityFixture: &config.CRMCapabilityFixtureConfig{RunID: "1234567890abcdef", NamespaceUID: uid}}}
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := &crmCapabilityScenario{kind: "refund", run: "1234567890abcdef", name: "c2-crm-refund-1234567890abcdef", configMapName: "c2-crm-refund-1234567890abcdef-code", podUID: types.UID("pod-uid"), configMapUID: types.UID("cm-uid")}
	if err := env.RecordCreatedUID("pods", s.name, s.podUID); err != nil {
		t.Fatal(err)
	}
	if err := env.RecordCreatedUID("configmaps", s.configMapName, s.configMapUID); err != nil {
		t.Fatal(err)
	}
	if err := s.recordUIDEvent(env, "created", "pods", s.name, s.podUID); err != nil {
		t.Fatal(err)
	}
	if err := s.recordUIDEvent(env, "created", "configmaps", s.configMapName, s.configMapUID); err != nil {
		t.Fatal(err)
	}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := env.CleanupOwned(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().ConfigMaps(ns).Get(context.Background(), "foreign-owned", metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign owned object deleted: %v", err)
	}
	if _, err := client.CoreV1().Namespaces().Get(context.Background(), ns, metav1.GetOptions{}); err != nil {
		t.Fatalf("fixture namespace deleted: %v", err)
	}
	ledger, err := os.ReadFile(filepath.Join(env.Config.OutDir, "crm-created.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ledger), `"event":"created"`) || !strings.Contains(string(ledger), `"event":"retired"`) {
		t.Fatal("verified UID retirement not persisted")
	}
}

func TestCRMFixtureManifestRejectsTagsAndDependencyDrift(t *testing.T) {
	manifest := crmFixtureManifest{Schema: crmFixtureSchema,
		CRMImage:        "example.invalid/crm@sha256:" + strings.Repeat("a", 64),
		MongoImage:      "example.invalid/mongo@sha256:" + strings.Repeat("b", 64),
		BaseImageDigest: crmInstalledBaseImage, SourceSHA256: crmInstalledSourceSHA,
		DependencyLockSHA256: crmDependencyLockSHA, WheelhouseManifestSHA256: strings.Repeat("c", 64), Dependencies: crmExpectedDependencies}
	path := filepath.Join(t.TempDir(), "fixture.json")
	write := func() {
		t.Helper()
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, _, err := crmLoadManifest(path); err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
	manifest.CRMImage = "example.invalid/crm:latest"
	write()
	if _, _, err := crmLoadManifest(path); err == nil {
		t.Fatal("mutable fixture image was accepted")
	}
	manifest.CRMImage = "example.invalid/crm@sha256:" + strings.Repeat("a", 64)
	manifest.DependencyLockSHA256 = strings.Repeat("0", 64)
	write()
	if _, _, err := crmLoadManifest(path); err == nil {
		t.Fatal("dependency lock drift was accepted")
	}
}

func TestCRMCapabilityControlsAbstainWithoutPreparedImage(t *testing.T) {
	t.Setenv(crmFixtureManifestEnv, "")
	for _, sc := range []core.Scenario{&c2CRMRefundCapability{}, &c2CRMResetCapability{}} {
		name := sc.Metadata().Name
		if err := sc.Setup(context.Background(), &core.Env{}); err != nil {
			t.Fatalf("%s unavailable setup failed: %v", name, err)
		}
		got, err := sc.Execute(context.Background(), &core.Env{})
		if err != nil || !got.Skipped || got.SkipReason == "" || !sc.Metadata().BenignControl || sc.Metadata().EffectiveRealism() != core.RealismExecutable {
			t.Fatalf("%s missing-image outcome invalid: result=%+v err=%v", name, got, err)
		}
		if err := sc.Teardown(context.Background(), &core.Env{}); err != nil {
			t.Fatalf("%s unavailable teardown failed: %v", name, err)
		}
	}
}
