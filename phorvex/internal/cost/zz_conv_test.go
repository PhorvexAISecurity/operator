package cost

import (
	"fmt"
	"testing"
)

// Does the rate limit prevent convergence after a LARGE, GENUINE cost shift? The covariance P still
// shrinks with the full gain K while theta only moves by the clamped step, so the estimator can grow
// confident about a value it never reached.
func TestDiagLargeShiftConvergence(t *testing.T) {
	var f [featureDim]float64
	f[0], f[1] = 1, 1 // bias + cold
	for _, target := range []float64{0.05, 0.5, 1.0, 1.9} {
		r := NewRLS()
		start := r.Predict(f)
		var at10, at50, at200, at1000 float64
		for i := 1; i <= 1000; i++ {
			r.Update(f, target)
			switch i {
			case 10:
				at10 = r.Predict(f)
			case 50:
				at50 = r.Predict(f)
			case 200:
				at200 = r.Predict(f)
			case 1000:
				at1000 = r.Predict(f)
			}
		}
		fmt.Printf("  true=%.2f  start=%.4f -> n=10:%.4f  n=50:%.4f  n=200:%.4f  n=1000:%.4f  |err|=%.5f\n",
			target, start, at10, at50, at200, at1000, at1000-target)
	}
}
