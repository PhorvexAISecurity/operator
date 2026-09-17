package capability

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

func m093CapabilityConfig(t *testing.T) *actuator.ServingSecurityConfig {
	t.Helper()
	binding := actuator.ServingSecurityBinding{Namespace: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: "model-sa", ProfileID: "profile", SecretName: "credential", BearerKey: "bearer", CAKey: "ca.crt", ServerName: "model-admin.example"}
	payload, _ := json.Marshal(struct {
		Version  int                               `json:"version"`
		Bindings []actuator.ServingSecurityBinding `json:"bindings"`
	}{1, []actuator.ServingSecurityBinding{binding}})
	path := filepath.Join(t.TempDir(), "serving-security.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := actuator.LoadServingSecurityFile(path, actuator.ServingSecuritySecureRequired, "operator")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestM093CapabilityUsesOnlyObservedIdentityAndImmutableConfig(t *testing.T) {
	reads := 0
	base := fake.NewClientBuilder().Build()
	api := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		reads++
		return c.Get(ctx, key, obj, opts...)
	}})
	native := actuator.NewNativeActuator(api)
	native.Reader = api
	native.SetServingSecurity(m093CapabilityConfig(t))
	target := actuator.Target{Namespace: "tenant", Pod: "model-0", UID: "pod-uid", PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: "model-sa"}
	if ok, why := native.SupportsAction(t.Context(), model.ActionKVReset, target); !ok || why != "" {
		t.Fatalf("exact configured capability=%v why=%q", ok, why)
	}
	if reads != 0 {
		t.Fatalf("counterfactual capability spent %d API reads", reads)
	}
	target.ServiceAccount = "other"
	if ok, why := native.SupportsAction(t.Context(), model.ActionKVReset, target); ok || !strings.Contains(why, "exact trusted workload binding") {
		t.Fatalf("profile mismatch capability=%v why=%q", ok, why)
	}
	if ok, why := native.SupportsAction(t.Context(), model.ActionRouteRotate, actuator.Target{}); !ok || why != "" {
		t.Fatalf("Kubernetes-only route inherited serving credential requirement: ok=%v why=%q", ok, why)
	}
	if reads != 0 {
		t.Fatalf("capability mismatch spent %d API reads", reads)
	}
}
