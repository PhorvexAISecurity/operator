package runner

import (
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

// wireCapabilityGates installs one tick's gate pair directly on an engine, as the brain does
// for the duration of a Decide call, for tests that drive the engine without the runner.
func wireCapabilityGates(ce *decision.CoverageEngine, capWit capability.Witness, authzNil bool, hasQualified func(*model.WorkloadView) bool) {
	gate := capabilityGate(capWit, authzNil, hasQualified)
	ce.Capability, ce.ShadowCapability = gate.Capability, gate.ShadowCapability
}
