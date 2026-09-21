package actuator

import (
	"context"
	"os"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Uses the existing structural schema, not a fake client, to detect pruning.
func TestM032CoverageAPIServerReadback(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires envtest API server assets")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../../build/phoenix-extended/config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := e.Stop(); err != nil {
			t.Error(err)
		}
	}()
	c, err := client.New(cfg, client.Options{Scheme: newScheme(t)})
	if err != nil {
		t.Fatal(err)
	}
	value := 12.3456789012345
	result, err := NewPhoenixActuator(c).Actuate(context.Background(), Request{Namespace: "default", Pod: "fixture", TargetUID: "pod-uid", TargetNamespaceUID: "namespace-uid", OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: model.ActionQuarantine, CoverageValue: &value})
	if err != nil {
		t.Fatal(err)
	}
	var stored amtd.SecurityEvent
	if err = c.Get(context.Background(), client.ObjectKey{Name: result.EventName}, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Spec.Metrics["coverageValue"] != "12.3456789012345" || stored.Spec.AnomalyScore != nil {
		t.Fatalf("stored spec: %+v", stored.Spec)
	}
}
