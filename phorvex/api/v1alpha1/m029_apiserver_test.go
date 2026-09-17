package v1alpha1_test

import (
	"context"
	"os"
	"testing"
	"time"

	phorvexv1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestM029EventAgeHorizonAPIPresenceDefaultingAndAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API-server binaries")
	}
	local := false
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../config/crd/bases"},
		ErrorIfCRDPathMissing: true,
		UseExistingCluster:    &local,
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
	const namespace = "m029-horizon"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}

	validSpec := func() phorvexv1alpha1.PhorvexPolicySpec {
		return phorvexv1alpha1.PhorvexPolicySpec{
			Selector: metav1.LabelSelector{},
			Budget: phorvexv1alpha1.BudgetSpec{
				TickInterval:           metav1.Duration{Duration: 20 * time.Second},
				AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
				ProactiveFloor:         metav1.Duration{Duration: 10 * time.Minute},
			},
		}
	}
	createTyped := func(name string, horizon *metav1.Duration) (*phorvexv1alpha1.PhorvexPolicy, error) {
		spec := validSpec()
		spec.Triggers.EventAgeHorizon = horizon
		obj := &phorvexv1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: spec}
		err := c.Create(ctx, obj)
		return obj, err
	}

	omitted, err := createTyped("typed-omitted", nil)
	if err != nil {
		t.Fatal(err)
	}
	omittedRead := &phorvexv1alpha1.PhorvexPolicy{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(omitted), omittedRead); err != nil {
		t.Fatal(err)
	}
	omitted = omittedRead
	if omitted.Spec.Triggers.EventAgeHorizon == nil || omitted.Spec.Triggers.EventAgeHorizon.Duration != time.Hour {
		t.Fatalf("typed omission did not persist the independent one-hour default: %+v", omitted.Spec.Triggers.EventAgeHorizon)
	}
	if omitted.Spec.EffectiveProactiveFloor() != 10*time.Minute || omitted.Spec.EffectiveEventAgeHorizon() != time.Hour {
		t.Fatalf("default remained coupled to proactive floor: floor=%v horizon=%v", omitted.Spec.EffectiveProactiveFloor(), omitted.Spec.EffectiveEventAgeHorizon())
	}

	positive, err := createTyped("typed-positive", &metav1.Duration{Duration: 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	positiveRead := &phorvexv1alpha1.PhorvexPolicy{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(positive), positiveRead); err != nil {
		t.Fatal(err)
	}
	positive = positiveRead
	if positive.Spec.Triggers.EventAgeHorizon == nil || positive.Spec.Triggers.EventAgeHorizon.Duration != 2*time.Hour {
		t.Fatalf("positive horizon did not round-trip: %+v", positive.Spec.Triggers.EventAgeHorizon)
	}
	if _, err := createTyped("typed-zero", &metav1.Duration{}); err == nil || !apierrors.IsInvalid(err) {
		t.Fatalf("typed explicit zero error=%v, want Invalid", err)
	}

	gvk := schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicy"}
	makeRaw := func(name string, horizon any, include bool) *unstructured.Unstructured {
		triggers := map[string]any{}
		if include {
			triggers["eventAgeHorizon"] = horizon
		}
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "phorvex.ai/v1alpha1",
			"kind":       "PhorvexPolicy",
			"metadata":   map[string]any{"name": name, "namespace": namespace},
			"spec": map[string]any{
				"selector": map[string]any{}, "objective": map[string]any{},
				"budget": map[string]any{
					"tickInterval": "20s", "antiOverRotationWindow": "5m", "proactiveFloor": "2h",
				},
				"slo": map[string]any{}, "assetValue": map[string]any{},
				"triggers": triggers, "actions": map[string]any{},
			},
		}}
		obj.SetGroupVersionKind(gvk)
		return obj
	}

	rawOmitted := makeRaw("raw-omitted", nil, false)
	if err := c.Create(ctx, rawOmitted); err != nil {
		t.Fatal(err)
	}
	rawRead := &unstructured.Unstructured{}
	rawRead.SetGroupVersionKind(gvk)
	if err := c.Get(ctx, client.ObjectKeyFromObject(rawOmitted), rawRead); err != nil {
		t.Fatal(err)
	}
	rawOmitted = rawRead
	if got, found, err := unstructured.NestedString(rawOmitted.Object, "spec", "triggers", "eventAgeHorizon"); err != nil || !found || got != "1h" {
		t.Fatalf("unstructured omission default=%q found=%t err=%v", got, found, err)
	}

	missingTriggers := makeRaw("missing-triggers", nil, false)
	unstructured.RemoveNestedField(missingTriggers.Object, "spec", "triggers")
	if err := c.Create(ctx, missingTriggers); err == nil || !apierrors.IsInvalid(err) {
		t.Fatalf("missing required triggers block error=%v, want Invalid", err)
	}

	for i, value := range []any{"0s", "-1s", "not-a-duration", "2562047h47m16.854775808s"} {
		obj := makeRaw("raw-invalid-"+string(rune('a'+i)), value, true)
		if err := c.Create(ctx, obj); err == nil || !apierrors.IsInvalid(err) {
			t.Fatalf("horizon %q error=%v, want Invalid", value, err)
		}
	}
}
