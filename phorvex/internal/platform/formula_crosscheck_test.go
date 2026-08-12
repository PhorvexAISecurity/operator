package platform

import (
	"math"
	"testing"
)

// TestScaleReportFormulasMatchProduction pins the Go values used to cross-check the
// PHORVEXSEC-130 live scale report. The previous diagnostic only printed these values,
// so it passed even if the implementation drifted away from the report.
func TestScaleReportFormulasMatchProduction(t *testing.T) {
	rarityCases := []struct {
		count, total int
		want         float64
	}{
		{1, 100, 2.0000000000},
		{2, 100, 1.8494850022},
		{4, 100, 1.6989700043},
		{8, 100, 1.5484550065},
		{21, 100, 1.3388903526},
		{100, 100, 1.0000000000},
		{1, 1, 1.0000000000},
		{2, 2, 1.0000000000},
	}
	for _, tc := range rarityCases {
		if got := rarity(tc.count, tc.total); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("rarity(%d,%d) = %.10f, want %.10f; PHORVEXSEC-130's scale measurements need re-computing",
				tc.count, tc.total, got, tc.want)
		}
	}

	coResidencyCases := []struct {
		tenants int
		want    float64
	}{{1, 1.0}, {2, 1.25}, {5, 2.0}, {7, 2.0}, {8, 2.0}, {9, 2.0}}
	for _, tc := range coResidencyCases {
		got := 1 + clamp01(float64(tc.tenants-1)/CoResidencyCap)
		if math.Abs(got-tc.want) > 1e-12 {
			t.Errorf("co-residency(%d tenants) = %.10f, want %.10f", tc.tenants, got, tc.want)
		}
	}
}
