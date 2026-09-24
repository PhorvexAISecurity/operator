package scenarios

import (
	"context"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c2CRMResetCapability{}) }

// c2CRMResetCapability is a benign, source-real control. A and B are owned
// synthetic fixture records, not identities recognized by the CRM application.
type c2CRMResetCapability struct{ crmCapabilityScenario }

func (s *c2CRMResetCapability) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name: "c2-crm-reset-capability", Category: core.CategoryModernUnsupported,
		Source:        "installed CRM app.py sha256:" + crmInstalledSourceSHA,
		R6ResponseTag: core.R6CannotRespond, BenignControl: true, Realism: core.RealismExecutable,
		Mechanism:          "immutable dependency-closed image runs unmodified installed CRM app.py against a dedicated disposable Mongo; actual HTTP password-reset handler receives owned synthetic A and cross-record B requests",
		OracleDescription:  "Mongo returns exact created reset ObjectIDs for A and B; legitimate A read/reset works and A/B account and order hashes remain unchanged",
		CleanupDescription: "delete only create-response-UID-bound fixture Pod and ConfigMap; Pod deletion destroys its Mongo EmptyDir",
		ClaimLimits:        "functional authorization-capability control only; CRM has no caller identity or ownership contract; no authentication bypass, customer impact, remote reachability or Phorvex detection efficacy is inferred",
		R6Justification:    "No business-aware detector was established; this benign control is excluded from attack/defense rate claims.",
	}
}

func (s *c2CRMResetCapability) Setup(ctx context.Context, env *core.Env) error {
	return s.crmCapabilityScenario.setup(ctx, env, "reset")
}

var _ core.Scenario = (*c2CRMResetCapability)(nil)
