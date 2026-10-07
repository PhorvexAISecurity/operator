package v1alpha1_test

import (
	"context"
	"fmt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"os"
	"testing"

	phorvexv1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestPost25EconomicsExplicitYAMLEmptyAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API-server binaries")
	}
	local := false
	env := &envtest.Environment{
		CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true,
		UseExistingCluster: &local,
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

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := phorvexv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "post25-economics"}}); err != nil {
		t.Fatal(err)
	}

	const manifest = `apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata:
  name: explicit-empty
  namespace: post25-economics
spec:
  tenant: post25-economics
  selector: {}
  objective:
    disruptionAversion: ""
  budget:
    tickInterval: 20s
    antiOverRotationWindow: 5m
    proactiveFloor: 1h
  slo: {}
  assetValue: {}
  triggers: {}
  actions: {}
`
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	if err := yaml.Unmarshal([]byte(manifest), &obj.Object); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, obj); err != nil {
		t.Fatalf("API server rejected explicit YAML empty disruptionAversion: %v", err)
	}
	stored := &unstructured.Unstructured{}
	stored.SetAPIVersion("phorvex.ai/v1alpha1")
	stored.SetKind("PhorvexPolicy")
	if err := c.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
		t.Fatal(err)
	}
	value, found, err := unstructured.NestedString(stored.Object, "spec", "objective", "disruptionAversion")
	if err != nil || !found || value != "" {
		t.Fatalf("stored explicit empty = %q found=%t err=%v", value, found, err)
	}
	encoded, err := yaml.Marshal(stored.Object)
	if err != nil {
		t.Fatal(err)
	}
	var typed phorvexv1alpha1.PhorvexPolicy
	if err := yaml.Unmarshal(encoded, &typed); err != nil {
		t.Fatal(err)
	}
	if value, configured, err := typed.Spec.EffectiveDisruptionAversion(); err != nil || configured || value != 0 {
		t.Fatalf("explicit empty did not resolve to legacy semantics: value=%g configured=%t err=%v", value, configured, err)
	}

	// The same isolated API server verifies the P2 presence/conflict contract.
	for i, tc := range []struct {
		name      string
		objective map[string]any
		valid     bool
	}{
		{"zero", map[string]any{"costPreferences": map[string]any{"norm": "0", "flow": "0"}}, true},
		{"different", map[string]any{"costPreferences": map[string]any{"norm": "0.2", "flow": "10"}}, true},
		{"empty-beta", map[string]any{"disruptionAversion": "", "costPreferences": map[string]any{"norm": "1", "flow": "2"}}, true},
		{"missing-norm", map[string]any{"costPreferences": map[string]any{"flow": "0"}}, false},
		{"missing-flow", map[string]any{"costPreferences": map[string]any{"norm": "0"}}, false},
		{"empty", map[string]any{"costPreferences": map[string]any{}}, false},
		{"negative", map[string]any{"costPreferences": map[string]any{"norm": "-1", "flow": "0"}}, false},
		{"out-of-range", map[string]any{"costPreferences": map[string]any{"norm": "0", "flow": "10.01"}}, false},
		{"nonfinite", map[string]any{"costPreferences": map[string]any{"norm": "NaN", "flow": "0"}}, false},
		{"conflict", map[string]any{"disruptionAversion": "0", "costPreferences": map[string]any{"norm": "0", "flow": "0"}}, false},
	} {
		t.Run("cost-preferences-"+tc.name, func(t *testing.T) {
			candidate := obj.DeepCopy()
			candidate.SetName(fmt.Sprintf("preferences-%d", i))
			candidate.SetResourceVersion("")
			candidate.SetUID("")
			if err := unstructured.SetNestedMap(candidate.Object, tc.objective, "spec", "objective"); err != nil {
				t.Fatal(err)
			}
			err := c.Create(ctx, candidate)
			if tc.valid && err != nil {
				t.Fatalf("valid preferences rejected: %v", err)
			}
			if !tc.valid && !apierrors.IsInvalid(err) {
				t.Fatalf("invalid preferences require admission error, got %v", err)
			}
		})
	}
}
