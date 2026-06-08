package defenders

import (
	"context"
	"math"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterDefender(&randomEqual{}) }

// randomEqual is RandomAtEqualRate: the SAME mean rotation rate as the blind
// timer / FullPhoenix, but with randomized (memoryless / exponential) inter-
// rotation gaps. It is the FAIR equal-cost comparison arm — it isolates the value
// of telemetry-driven timing vs blind randomness at matched cost, and it is the
// arm the ADAPTIVE attacker tries hardest to learn (and should FAIL to, since the
// gaps carry no exploitable structure).
type randomEqual struct {
	eng timerEngine
}

func (r *randomEqual) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:                        "d-randomequal",
		Description:                 "RandomAtEqualRate: same mean rate as the blind timer but memoryless (exponential) gaps. The fair equal-cost arm; defeats the adaptive attacker's rhythm-learning.",
		MeanRotationIntervalSeconds: BlindRotationInterval.Seconds(),
	}
}

func (r *randomEqual) Setup(ctx context.Context, env *core.Env) error {
	mean := BlindRotationInterval.Seconds()
	// Memoryless gaps: exponential with the SAME mean as the blind arm, drawn from
	// the DETERMINISTIC per-trial RNG so the run is reproducible. Bounded to a
	// sane [1s, 3*mean] window so smoke trials still observe rotations.
	r.eng.nextDelay = func() time.Duration {
		u := env.Rand.Float64()
		if u <= 0 {
			u = 1e-9
		}
		gap := -mean * math.Log(u) // inverse-CDF of Exp(1/mean)
		if gap < 1 {
			gap = 1
		}
		if gap > 3*mean {
			gap = 3 * mean
		}
		return time.Duration(gap * float64(time.Second))
	}
	return nil
}

func (r *randomEqual) Start(ctx context.Context, env *core.Env) error {
	env.Log.Logf("d-randomequal: arming memoryless rotation (mean %s, exponential gaps)", BlindRotationInterval)
	r.eng.startEngine(ctx, env)
	return nil
}

func (r *randomEqual) Stop(ctx context.Context, env *core.Env) error {
	r.eng.stopEngine()
	return nil
}

func (r *randomEqual) Teardown(ctx context.Context, env *core.Env) error {
	r.eng.stopEngine()
	return nil
}

func (r *randomEqual) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	a := r.eng.actions()
	return len(a), a, nil
}
