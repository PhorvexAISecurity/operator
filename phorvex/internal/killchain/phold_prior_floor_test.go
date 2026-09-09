package killchain

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// phold_prior_floor_test.go — PHORVEXSEC-189 / M-143 (form A, capped noisy-OR).
//
// Old form: p = clamp01(t_exp/T), pHold = betaMean + p*(1-betaMean). At p = 1 (every pod
// older than the floor) pHold = 1 for EVERY betaMean: the Beta posterior, the tenant prior
// and the feedback had zero effect. New form: p = cap*min(1, t_exp/T) with 0 < cap < 1, so
// d pHold / d betaMean = 1-p >= 1-cap > 0 at every exposure age.

const (
	testExposureScaleSec = 15 * 60.0 // T_exp = 15 min (the deployed proactive floor)
	testCap              = 0.5       // INSUFFICIENT EVIDENCE — provisional, fit in T3-D
)

// pholdModel returns a killchain model whose Beta posterior mean for tenant "t" is
// betaMean (steered from the (1,4) default through Observe, which only ever adds mass to
// one side, so the mean is exact up to float rounding) and whose just-moved damping is
// switched off (RecoverScale -> ~0 so damping = 1 for any t > 0). The test then reads the
// capped noisy-OR alone. ConfidenceK = 0 keeps betaMean the plain posterior mean.
// pholdOwner is the M-140 owner key for this fixture's policy. Assess reads the belief
// prior under pol.Owner(), so priming the bare tenant name would seed a different key and
// leave the fixture reading the shipped default instead of the intended betaMean.
var pholdOwner = model.OwnerKey(model.OwnerKindName, "t")

func pholdModel(t *testing.T, betaMean float64) *Model {
	t.Helper()
	m := NewModel()
	m.RecoverScale = 1e-9
	m.ConfidenceK = 0
	const a0, b0 = 1.0, 4.0 // NewConjugateMemory defaults
	switch {
	case betaMean >= 1:
		m.Memory.Observe(pholdOwner, 1e12)
	case betaMean <= 0:
		m.Memory.Observe(pholdOwner, -1e12)
	case betaMean > a0/(a0+b0):
		m.Memory.Observe(pholdOwner, betaMean*b0/(1-betaMean)-a0) // raise alpha
	default:
		m.Memory.Observe(pholdOwner, -((1-betaMean)*a0/betaMean - b0)) // raise beta
	}
	if got := m.Memory.PriorMean(pholdOwner); math.Abs(got-betaMean) > 1e-6 {
		t.Fatalf("test harness: prior mean = %.9f, want %.3f", got, betaMean)
	}
	return m
}

func pholdPolicy(cap float64) model.Policy {
	return model.Policy{Tenant: "t", ProactiveFloor: 15 * time.Minute, ExposurePressureCap: cap}
}

func pholdAt(t *testing.T, betaMean, exposureSec float64) Assessment {
	t.Helper()
	m := pholdModel(t, betaMean)
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	return m.Assess(v, pholdPolicy(testCap), exposureSec, testExposureScaleSec)
}

// (a) t_exp = 60 m: betaMean 0.1 vs 0.9 must differ by >= 0.4*(1-cap). Old code: both 1.00.
func TestPHoldPosteriorSurvivesSaturatedClock(t *testing.T) {
	lo := pholdAt(t, 0.1, 60*60).PHold
	hi := pholdAt(t, 0.9, 60*60).PHold
	if want := 0.4 * (1 - testCap); hi-lo < want-1e-9 {
		t.Fatalf("at t_exp=60m pHold(beta=0.9)-pHold(beta=0.1) = %.4f-%.4f = %.4f, want >= %.4f (old code: both 1.00, the posterior was annihilated)", hi, lo, hi-lo, want)
	}
}

// (b) t_exp = 0 -> pHold = betaMean (the post-rotation value is unchanged). Damping is off
// in this model, so the raw term is what is compared.
func TestPHoldAtZeroExposureIsBetaMean(t *testing.T) {
	for _, b := range []float64{0.1, 0.5, 0.9} {
		a := pholdAt(t, b, 0)
		if math.Abs(a.PHoldInputs.Raw-b) > 1e-9 {
			t.Fatalf("t_exp=0: raw pHold = %.6f, want betaMean %.2f", a.PHoldInputs.Raw, b)
		}
		if a.PHoldInputs.Pressure != 0 {
			t.Fatalf("t_exp=0: pressure = %v, want 0", a.PHoldInputs.Pressure)
		}
	}
}

// (c) monotone non-decreasing in t_exp and strictly increasing in betaMean, at every point.
func TestPHoldMonotoneInExposureAndBetaMean(t *testing.T) {
	ages := []float64{0, 60, 7.5 * 60, 14 * 60, 15 * 60, 30 * 60, 60 * 60, 24 * 3600}
	betas := []float64{0, 0.05, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99}
	for _, b := range betas {
		prev := -1.0
		for _, age := range ages {
			p := pholdAt(t, b, age).PHoldInputs.Raw
			if p < prev-1e-12 {
				t.Fatalf("beta=%.2f: pHold decreased with exposure at t=%.0fs (%.6f < %.6f)", b, age, p, prev)
			}
			prev = p
		}
	}
	for _, age := range ages {
		prev := -1.0
		for _, b := range betas {
			p := pholdAt(t, b, age).PHoldInputs.Raw
			if p <= prev {
				t.Fatalf("t=%.0fs: pHold not strictly increasing in betaMean at beta=%.2f (%.6f <= %.6f)", age, b, p, prev)
			}
			prev = p
		}
	}
}

// (d) betaMean < 1 => pHold < 1 for any exposure, including far beyond the scale.
func TestPHoldNeverPinsToOneBelowBetaOne(t *testing.T) {
	for _, b := range []float64{0, 0.5, 0.9, 0.99, 0.999} {
		for _, age := range []float64{15 * 60, 60 * 60, 7 * 24 * 3600, 1e9} {
			a := pholdAt(t, b, age)
			if a.PHold >= 1 || a.PHoldInputs.Raw >= 1 {
				t.Fatalf("beta=%.3f t=%.0fs: pHold=%.6f raw=%.6f, want < 1 (old code pinned every pod older than the floor to 1.00)", b, age, a.PHold, a.PHoldInputs.Raw)
			}
			if want := b + testCap*(1-b); math.Abs(a.PHoldInputs.Raw-want) > 1e-9 {
				t.Fatalf("beta=%.3f t=%.0fs: plateau raw=%.6f, want beta+cap*(1-beta)=%.6f", b, age, a.PHoldInputs.Raw, want)
			}
		}
	}
	if a := pholdAt(t, 1, 60*60); math.Abs(a.PHoldInputs.Raw-1) > 1e-9 {
		t.Fatalf("beta=1 must still give pHold=1, got %.6f", a.PHoldInputs.Raw)
	}
}

// (e) the ruling's predicted vector (p_max = 0.5, T_exp = 15 m) matches to 1e-6.
func TestPHoldMatchesMathRulingVector(t *testing.T) {
	want := map[float64][3]float64{ // t_exp minutes -> pHold for beta 0.1 / 0.5 / 0.9
		0:   {0.100, 0.500, 0.900},
		7.5: {0.325, 0.625, 0.925},
		15:  {0.550, 0.750, 0.950},
		60:  {0.550, 0.750, 0.950},
	}
	wantP := map[float64]float64{0: 0, 7.5: 0.25, 15: 0.5, 60: 0.5}
	for minutes, row := range want {
		for i, b := range []float64{0.1, 0.5, 0.9} {
			a := pholdAt(t, b, minutes*60)
			if math.Abs(a.PHoldInputs.Raw-row[i]) > 1e-6 {
				t.Fatalf("t=%.1fm beta=%.1f: pHold=%.6f, ruling says %.3f", minutes, b, a.PHoldInputs.Raw, row[i])
			}
			if math.Abs(a.PHoldInputs.Pressure-wantP[minutes]) > 1e-6 {
				t.Fatalf("t=%.1fm: p=%.6f, ruling says %.3f", minutes, a.PHoldInputs.Pressure, wantP[minutes])
			}
			if a.PHoldInputs.Cap != testCap || a.PHoldInputs.ScaleSec != testExposureScaleSec || math.Abs(a.PHoldInputs.BetaMean-b) > 1e-6 {
				t.Fatalf("recorded inputs = %+v, want cap %.2f scale %.0f beta %.2f", a.PHoldInputs, testCap, testExposureScaleSec, b)
			}
		}
	}
}

// An unset or out-of-range policy cap falls back to the tagged provisional default rather
// than to the old annihilating form.
func TestPHoldCapBackstopIsProvisionalDefault(t *testing.T) {
	m := pholdModel(t, 0.5)
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	for _, cap := range []float64{0, -1, 1, 1.5} {
		pol := pholdPolicy(cap)
		a := m.Assess(v, pol, 60*60, testExposureScaleSec)
		if a.PHoldInputs.Cap != DefaultExposurePressureCap || math.Abs(a.PHoldInputs.Raw-0.75) > 1e-9 {
			t.Fatalf("cap=%v: inputs=%+v, want provisional default %.2f and raw 0.75", cap, a.PHoldInputs, DefaultExposurePressureCap)
		}
	}
}
