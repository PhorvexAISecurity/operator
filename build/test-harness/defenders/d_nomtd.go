package defenders

import (
	"context"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterDefender(&noMTD{}) }

// noMTD is the NoMTD POSITIVE control baseline. Setup/Start/Stop/Teardown are
// no-ops; no rotation, no emitter, no actuator. Every scenario's attack MUST
// achieve its oracle under this arm — it anchors the 100% undefended baseline
// that every DisruptionVsOracle number is measured against.
type noMTD struct{}

func (n *noMTD) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:                      "d-nomtd",
		Description:               "NoMTD positive control: no rotation, no emitter, no actuator. Anchors the 100% undefended baseline; every attack must achieve its oracle here.",
		IsNegativeControlBaseline: true, // this is the undefended anchor arm
	}
}

func (n *noMTD) Setup(ctx context.Context, env *core.Env) error    { return nil }
func (n *noMTD) Start(ctx context.Context, env *core.Env) error    { return nil }
func (n *noMTD) Stop(ctx context.Context, env *core.Env) error     { return nil }
func (n *noMTD) Teardown(ctx context.Context, env *core.Env) error { return nil }

// DefensiveActions: a no-MTD arm takes zero defensive actions, ever.
func (n *noMTD) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	return 0, nil, nil
}
