package v1alpha1_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

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

func TestM022MaxMovesPerTickAPIDefaultingAndAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	}()

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
	const namespace = "m022-presence"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}

	gvk := schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicy"}
	policy := func(name string, budget map[string]any) *unstructured.Unstructured {
		spec := map[string]any{
			"tenant":     "m022-presence",
			"selector":   map[string]any{},
			"objective":  map[string]any{},
			"slo":        map[string]any{},
			"assetValue": map[string]any{},
			"triggers":   map[string]any{},
			"actions":    map[string]any{},
		}
		if budget != nil {
			spec["budget"] = budget
		}
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "phorvex.ai/v1alpha1",
			"kind":       "PhorvexPolicy",
			"metadata": map[string]any{
				"name": name, "namespace": namespace,
			},
			"spec": spec,
		}}
		obj.SetGroupVersionKind(gvk)
		return obj
	}

	tests := []struct {
		name       string
		budget     map[string]any
		wantField  bool
		want       int64
		wantReject bool
	}{
		{name: "omitted-budget", wantReject: true},
		{name: "omitted-field", budget: map[string]any{}, wantField: true, want: 3},
		{name: "explicit-zero", budget: map[string]any{"maxMovesPerTick": int64(0)}, wantField: true, want: 0},
		{name: "positive", budget: map[string]any{"maxMovesPerTick": int64(1)}, wantField: true, want: 1},
		{name: "negative", budget: map[string]any{"maxMovesPerTick": int64(-1)}, wantReject: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := policy(tt.name, tt.budget)
			err := c.Create(ctx, obj)
			if tt.wantReject {
				if err == nil || !apierrors.IsInvalid(err) {
					t.Fatalf("create error = %v, want Invalid", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, found, err := unstructured.NestedInt64(obj.Object, "spec", "budget", "maxMovesPerTick")
			if err != nil {
				t.Fatal(err)
			}
			if found != tt.wantField || (found && got != tt.want) {
				t.Fatalf("stored maxMovesPerTick = %d (found %t), want %d (found %t)", got, found, tt.want, tt.wantField)
			}
			encoded, err := json.Marshal(obj.Object)
			if err != nil {
				t.Fatal(err)
			}
			var typed phorvexv1alpha1.PhorvexPolicy
			if err := json.Unmarshal(encoded, &typed); err != nil {
				t.Fatal(err)
			}
			if got := typed.Spec.EffectiveMaxMovesPerTick(); got != int(tt.want) {
				t.Fatalf("effective maxMovesPerTick = %d, want %d", got, tt.want)
			}
		})
	}
}
