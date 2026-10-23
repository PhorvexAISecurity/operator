package inprocess

import (
	"testing"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/decision"
)

func TestNewComposesTheDefaultServicesOnTheResolvedBackend(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	s, err := New(c, logr.Discard(), actuator.BackendResolution{Backend: actuatorapi.BackendNative})
	if err != nil {
		t.Fatal(err)
	}
	if s.Optimizer == nil || s.Optimizer.Name() != decision.NewCoverageEngine().Name() {
		t.Fatalf("default engine = %v", s.Optimizer)
	}
	if s.Actuator == nil || s.Actuator.Name() != string(actuatorapi.BackendNative) {
		t.Fatalf("backend = %v", s.Actuator)
	}
	if act := s.Actuation(c, "operator", nil); act == nil || act.Backend() != actuatorapi.BackendNative {
		t.Fatalf("actuation = %v", act)
	}
	if s.Brain() == nil || s.Sensor(c, c, c, "") == nil {
		t.Fatal("the brain and the sensor must be composed")
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("the registered recon profiles are invalid: %v", err)
	}
}

func TestAnUnknownBackendIsRefused(t *testing.T) {
	if _, err := New(fake.NewClientBuilder().Build(), logr.Discard(), actuator.BackendResolution{Backend: "kubectl"}); err == nil {
		t.Fatal("composed services on a backend nobody named")
	}
}

// Without a backend nothing acts: the runner reads a nil interface, never a typed nil.
func TestServicesWithoutABackendDoNotAct(t *testing.T) {
	if act := (&Services{}).Actuation(nil, "", nil); act != nil {
		t.Fatalf("actuation = %#v", act)
	}
}
