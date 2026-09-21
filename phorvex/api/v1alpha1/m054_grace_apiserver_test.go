package v1alpha1_test

import (
	"context"
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

func TestM054MaxGracePeriodAPIDefaultAndAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, phorvexv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const namespace = "m054-grace"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	gkv := schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicy"}
	policy := func(name string, grace any, include bool) *unstructured.Unstructured {
		budget := map[string]any{}
		if include {
			budget["maxGracePeriodSeconds"] = grace
		}
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy",
			"metadata": map[string]any{"name": name, "namespace": namespace},
			"spec": map[string]any{
				"tenant": name, "selector": map[string]any{"matchLabels": map[string]any{"app": name}},
				"mode": "active", "objective": map[string]any{}, "budget": budget,
				"slo": map[string]any{}, "assetValue": map[string]any{}, "triggers": map[string]any{},
				"actions": map[string]any{"enabled": []any{"rotate"}},
			},
		}}
		obj.SetGroupVersionKind(gkv)
		return obj
	}
	tests := []struct {
		name       string
		value      any
		include    bool
		want       int64
		wantReject bool
	}{
		{name: "omitted-default", want: 30},
		{name: "lower-bound", value: int64(1), include: true, want: 1},
		{name: "upper-bound", value: int64(300), include: true, want: 300},
		{name: "zero", value: int64(0), include: true, wantReject: true},
		{name: "negative", value: int64(-1), include: true, wantReject: true},
		{name: "oversized", value: int64(301), include: true, wantReject: true},
		{name: "malformed", value: "30", include: true, wantReject: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := policy(tt.name, tt.value, tt.include)
			err := c.Create(ctx, obj)
			if tt.wantReject {
				if err == nil || !apierrors.IsInvalid(err) {
					t.Fatalf("create error=%v, want Invalid", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, found, err := unstructured.NestedInt64(obj.Object, "spec", "budget", "maxGracePeriodSeconds")
			if err != nil || !found || got != tt.want {
				t.Fatalf("stored maxGracePeriodSeconds=%d found=%t err=%v want=%d", got, found, err, tt.want)
			}
		})
	}
}
