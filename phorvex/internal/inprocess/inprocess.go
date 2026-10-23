// Package inprocess composes the services a manager runs in its own process when no
// endpoint names them (ADR-0001): the decision engine, the cluster sensor and the
// actuation backend, each behind its contract. cmd builds it, as do the tests that
// run a manager in process. The runner reaches these services only through
// runner.LocalServices, so the dispatcher's own code imports no other service's.
//
// No service package imports this one (internal/archtest): it belongs to the
// composition, not to a domain.
package inprocess

import (
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/actuatorsvc"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainsvc"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorsvc"
)

// Services are the in-process brain, sensor and actuator, and their parts.
type Services struct {
	// Optimizer is the decision engine; MathLab, when set, records its snapshots.
	Optimizer decision.Optimizer
	MathLab   *mathlab.Recorder
	// MetricsSource and PCIeClasses are the sensor's telemetry source and PCIe
	// capacity class table.
	MetricsSource ingest.MetricsSource
	PCIeClasses   ingest.PCIeClassTable
	// Actuator is the actuation backend, nil when none is wired, and
	// QuarantineCapacity its retained-quarantine ledger.
	Actuator           actuator.Actuator
	QuarantineCapacity *actuator.QuarantineCapacity
}

// New builds the default in-process services on an already-resolved backend: the P1
// coverage engine, the registry's default metrics source and the backend's actuator.
func New(c client.Client, log logr.Logger, res actuator.BackendResolution) (*Services, error) {
	act, err := buildActuator(c, log, res)
	if err != nil {
		return nil, err
	}
	src, _ := ingest.SourceRegistry.Default()
	// P-PHYSICS (UCW): make the discovered-physics recon-EMR profile the engine default
	// (byte-identical to standard-recon at nil-data; lifts only under measured dispersion).
	recon.Registry.SetDefault("ucw-recon")
	return &Services{
		Optimizer:     decision.NewCoverageEngine(), // P1 default brain
		MetricsSource: src,
		Actuator:      act, // P-ACTUATOR: the ONE resolved backend (dispatch + support share it)
	}, nil
}

// Validate checks the in-process brain's startup invariants: the exact-optimality
// claim depends on block-disjoint cover keys, so every registered recon profile is
// validated once, before the sub-second tick path starts.
func (s *Services) Validate() error {
	if err := recon.ValidateRegistryCoverKeys(); err != nil {
		return fmt.Errorf("recon cover-key startup invariant failed: %w", err)
	}
	return nil
}

// Brain is the decision engine behind the brain contract.
func (s *Services) Brain() brainapi.Brain {
	return brainsvc.NewLocal(s.Optimizer, s.MathLab)
}

// Sensor observes the cluster through c and the readers, behind the sensor contract.
func (s *Services) Sensor(c client.Client, ownership, boundary client.Reader, promURL string) sensorapi.Sensor {
	return &sensorsvc.Local{Client: c, OwnershipReader: ownership, BoundaryReader: boundary,
		PromURL: promURL, PCIeClasses: s.PCIeClasses, Metrics: s.MetricsSource}
}

// Actuation is the backend behind the actuator contract, nil when none is wired.
func (s *Services) Actuation(boundary client.Reader, operatorNamespace string, access *authz.Checker) actuatorapi.Actuator {
	if s.Actuator == nil {
		return nil
	}
	return &actuatorsvc.Local{Actuator: s.Actuator, Capacity: s.QuarantineCapacity, Reader: boundary,
		OperatorNamespace: operatorNamespace, Access: access}
}

// backendPurpose is the operator-facing one-liner logged for the resolved backend, so
// EVERY valid branch — including the default — is observable. Before M-21 only the two
// explicit non-default branches logged anything, so the single most common configuration
// (the Phoenix default) resolved in silence and a typo resolved the same silent way.
func backendPurpose(b actuator.Backend) string {
	switch b {
	case actuatorapi.BackendNative:
		return "Phorvex's own hands; direct client-go enactment, no Phoenix CRDs"
	case actuatorapi.BackendHybrid:
		return "native for policy-bounded rotate and AI-native moves; Phoenix for quarantine"
	default:
		return "drives UNMODIFIED Phoenix via SecurityEvent/AMTD CRs"
	}
}

// buildActuator constructs the hands for an ALREADY-RESOLVED backend and logs the
// effective choice with its source, so every valid branch — including the default — is
// observable. [M-21]
//
// It takes the resolution rather than reading the environment so that a process resolves
// PHORVEX_ACTUATOR exactly ONCE, at its entrypoint, before any code path can act. Reading
// it again here would reintroduce the possibility of two answers in one process.
func buildActuator(c client.Client, log logr.Logger, res actuator.BackendResolution) (actuator.Actuator, error) {
	act, err := actuator.New(res.Backend, c)
	if err != nil {
		return nil, err
	}
	// The entrypoint reports the CONFIGURATION (what was asked for and by whom); this
	// reports the CONSTRUCTION (what was actually wired, and what it does). Distinct facts,
	// so a caller that never passes through cmd/main.go still observes the effective hands.
	log.WithName("runner").Info("actuator constructed",
		"actuator", string(res.Backend),
		"source", res.Origin(),
		"purpose", backendPurpose(res.Backend))
	return act, nil
}
