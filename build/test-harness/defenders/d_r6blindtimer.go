package defenders

import (
	"context"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterDefender(&blindTimer{}) }

// BlindRotationInterval is the DOCUMENTED, realistic-relative fixed rotation period
// for the blind timer arm. It is a SCALED-FOR-TEST value (real production periodic
// rotation is minutes-to-hours; the PRD cites ~hourly) chosen so the RELATIVE ordering
// is honest and not rigged: PX's risk-driven proactive floor (~6s) < a fast attacker's
// objective (~9s) < this blind interval (15s). A fixed cadence that rotates EVERYTHING
// slowly thus arrives too late on a fast attack and yields a high (≈interval) dwell on
// persistence, while PX rotates the HIGH-RISK pod early. The attacker speeds in the
// scenarios are scaled with this interval — the comparison measures timing STRUCTURE,
// not absolute seconds.
const BlindRotationInterval = 15 * time.Second

// blindTimer models R6's reactive design approximated as a BLIND fixed-interval
// rotation with NO telemetry/emitter (a pure TimeBasedTrigger). It caps dwell at
// the interval but cannot target on demand, so it disrupts scenarios only
// OPPORTUNISTICALLY — by landing a rotation during the attack window.
type blindTimer struct {
	eng timerEngine
}

func (b *blindTimer) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:                        "d-r6blindtimer",
		Description:                 "Blind fixed-interval rotation with no telemetry (TimeBasedTrigger approximation). Caps dwell at the interval; disrupts only opportunistically.",
		MeanRotationIntervalSeconds: BlindRotationInterval.Seconds(),
	}
}

func (b *blindTimer) Setup(ctx context.Context, env *core.Env) error {
	// Fixed (deterministic) cadence: every BlindRotationInterval.
	b.eng.nextDelay = func() time.Duration { return BlindRotationInterval }
	return nil
}

func (b *blindTimer) Start(ctx context.Context, env *core.Env) error {
	env.Log.Logf("d-r6blindtimer: arming blind rotation every %s (no emitter)", BlindRotationInterval)
	b.eng.startEngine(ctx, env)
	return nil
}

func (b *blindTimer) Stop(ctx context.Context, env *core.Env) error {
	b.eng.stopEngine()
	return nil
}

func (b *blindTimer) Teardown(ctx context.Context, env *core.Env) error {
	b.eng.stopEngine()
	return nil
}

func (b *blindTimer) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	a := b.eng.actions()
	return len(a), a, nil
}
