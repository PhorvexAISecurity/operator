// Package decisionconfig applies the process-wide settings decisions depend on and
// describes them for the brain service handshake (ADR-0001). The brain applies
// them before it serves; the manager applies the same flags during its startup
// and presents the description, so a dispatcher and its brain decide under one
// configuration or not at all.
package decisionconfig

import (
	"fmt"
	"strings"

	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/physics"
	"github.com/phorvex/phorvex/internal/recon"
)

// ReconProfile is the recon model production decides with: discovered physics,
// byte-identical to the standard profile when nothing is measured.
const ReconProfile = "ucw-recon"

// Apply installs the flow-residual activation, the GPU warm-up envelope and the
// recon profile, and selects the decision engine.
func Apply(engine string, gpuEnvelopeMax float64, flowResidualClasses string) (decision.Optimizer, error) {
	physics.ConfigureFlowActivation(strings.Split(flowResidualClasses, ","))
	if err := cost.ConfigureGPUEnvelopeMax(gpuEnvelopeMax); err != nil {
		return nil, fmt.Errorf("invalid GPU warm-up calibration: %w", err)
	}
	if !recon.Registry.SetDefault(ReconProfile) {
		return nil, fmt.Errorf("recon profile %q is not registered", ReconProfile)
	}
	optimizer, err := decision.SelectOptimizer(engine)
	if err != nil {
		return nil, err
	}
	return optimizer, nil
}

// Describe returns the decision configuration for the handshake: the engine, the
// recon profile, the configured flags and the production parameter manifest.
func Describe(optimizer decision.Optimizer, gpuEnvelopeMax float64, flowResidualClasses string) (brainapi.DecisionConfig, error) {
	manifest, err := decision.ProductionParameterManifest().CanonicalHash()
	if err != nil {
		return brainapi.DecisionConfig{}, fmt.Errorf("decision parameter manifest: %w", err)
	}
	return brainapi.DecisionConfig{
		Engine:                  optimizer.Name(),
		ReconProfile:            ReconProfile,
		GPUEnvelopeMax:          gpuEnvelopeMax,
		FlowResidualClasses:     strings.Split(flowResidualClasses, ","),
		ParameterManifestSHA256: manifest,
	}, nil
}
