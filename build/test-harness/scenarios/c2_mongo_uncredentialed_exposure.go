package scenarios

import (
	"context"
	"errors"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// The registered descriptor makes the case discoverable. The actual one-use
// producer is a dedicated named-suite path, never the generic matrix.
type c2MongoUncredentialedExposure struct{}

func init() { core.RegisterScenario(&c2MongoUncredentialedExposure{}) }

func (*c2MongoUncredentialedExposure) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name: "c2-mongo-uncredentialed-service-exposure", Category: core.CategoryModernUnsupported,
		Source:        "Installed Mongo Service; one nonce-owned synthetic document and separate uncredentialed client",
		R6ResponseTag: core.R6CannotRespond, BenignControl: true, Realism: core.RealismExecutable,
		Mechanism:          "one exact-ID Service read from a no-token/no-credential Pod, compared with direct legitimate reads",
		OracleDescription:  "exact original mongosh reply and document hash, stable source and same-window manager audit",
		CleanupDescription: "one UUID-bound collection and UID-bound client Pod; no namespace or shared policy deletion",
		ClaimLimits:        "configuration exposure only; no tenant-auth bypass, detector, actuator, defense efficacy or customer-data claim",
		R6Justification:    "no signal or response is requested by this configuration baseline",
	}
}

func (*c2MongoUncredentialedExposure) Setup(context.Context, *core.Env) error {
	return errors.New("Mongo exposure requires the server-owned dedicated named suite")
}
func (*c2MongoUncredentialedExposure) Execute(context.Context, *core.Env) (core.AttackResult, error) {
	return core.AttackResult{}, errors.New("Mongo exposure generic matrix path refused")
}
func (*c2MongoUncredentialedExposure) SuccessOracle(context.Context, *core.Env) (core.OracleResult, error) {
	return core.OracleResult{}, errors.New("Mongo exposure generic matrix oracle refused")
}
func (*c2MongoUncredentialedExposure) Teardown(context.Context, *core.Env) error { return nil }
