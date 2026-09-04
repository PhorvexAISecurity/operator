package recon

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// epss_form_test.go — PHORVEXSEC-194 / M-104 (ruling Q1 = (a) value layer, Q2 form, Q4 bound).
//
// Old anchor (platform): 1 + clamp01(0.5·e + 0.5·c/10) — a MEASURED e = 0 with CVSS 5 still
// lifted the weight by 25%, and (0.5, 5) gave 1.50. Ruled: m = 1 + e·(c/10); e = 0 → exactly 1.

// (a) the ruling's vector to 1e-9. Fails on the old form: (0.5,5) → 1.50 and (0,5) → 1.25 there.
func TestEPSSMultiplierMatchesRulingVector(t *testing.T) {
	for _, tc := range []struct {
		e, c    float64
		present bool
		want    float64
		wantOK  bool
	}{
		{0, 5, true, 1.00, true},
		{0, 10, true, 1.00, true},
		{0.5, 5, true, 1.25, true},
		{1, 10, true, 2.00, true},
		{0.97, 9.8, true, 1.9506, true},
		{0.5, 5, false, 1.00, false},
	} {
		m, ok, _ := EPSSMultiplier(tc.e, tc.c, tc.present)
		if math.Abs(m-tc.want) > 1e-9 || ok != tc.wantOK {
			t.Fatalf("EPSSMultiplier(%v,%v,present=%v) = %.9f ok=%v, ruling says %.4f ok=%v", tc.e, tc.c, tc.present, m, ok, tc.want, tc.wantOK)
		}
	}
}

// (b) property over the valid rectangle: range [1,2], monotone non-decreasing in e and in c.
func TestEPSSMultiplierBoundedAndMonotone(t *testing.T) {
	for ei := 0; ei <= 20; ei++ {
		for ci := 0; ci <= 20; ci++ {
			e, c := float64(ei)/20, float64(ci)/2
			m, ok, _ := EPSSMultiplier(e, c, true)
			if !ok || m < 1 || m > 2 {
				t.Fatalf("(%v,%v) → %v ok=%v outside [1,2]", e, c, m, ok)
			}
			if ei > 0 {
				prev, _, _ := EPSSMultiplier(float64(ei-1)/20, c, true)
				if m < prev {
					t.Fatalf("not monotone in e at (%v,%v): %v < %v", e, c, m, prev)
				}
			}
			if ci > 0 {
				prev, _, _ := EPSSMultiplier(e, float64(ci-1)/2, true)
				if m < prev {
					t.Fatalf("not monotone in c at (%v,%v): %v < %v", e, c, m, prev)
				}
			}
		}
	}
}

// (c) zero is evidence, absence is not; absent / non-finite / out-of-domain are neutral,
// present=false, with a distinguishable reason.
func TestEPSSMultiplierAbsenceSemantics(t *testing.T) {
	if m, ok, reason := EPSSMultiplier(0, 7.5, true); m != 1 || !ok || reason != "" {
		t.Fatalf("measured e=0: m=%v ok=%v reason=%q, want 1/true/\"\"", m, ok, reason)
	}
	for _, tc := range []struct {
		name    string
		e, c    float64
		present bool
		reason  string
	}{
		{"absent", 0.9, 9, false, EPSSReasonAbsent},
		{"e NaN", math.NaN(), 5, true, EPSSReasonNonFinite},
		{"c +Inf", 0.5, math.Inf(1), true, EPSSReasonNonFinite},
		{"e > 1", 1.5, 5, true, EPSSReasonInvalidDomain},
		{"e < 0", -0.1, 5, true, EPSSReasonInvalidDomain},
		{"c > 10", 0.5, 11, true, EPSSReasonInvalidDomain},
		{"c < 0", 0.5, -1, true, EPSSReasonInvalidDomain},
	} {
		m, ok, reason := EPSSMultiplier(tc.e, tc.c, tc.present)
		if m != 1 || ok || reason != tc.reason {
			t.Fatalf("%s: m=%v ok=%v reason=%q, want 1/false/%q (never a stale or invented value)", tc.name, m, ok, reason, tc.reason)
		}
	}
}

// (d) one layer: EPSS/CVSS are consumed on the recon value axis only. Belief, hazard, stage,
// cost, lambda and feasibility must not reference them; the multiplier formula exists once.
func TestEPSSEntersExactlyOneLayer(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..")
	forbidden := []string{"killchain", "belief", "ctxprov", "cost", "feasibility", "exposure", "actionset", "decision"}
	for _, pkg := range forbidden {
		entries, err := os.ReadDir(filepath.Join(root, pkg))
		if err != nil {
			t.Fatalf("read %s: %v", pkg, err)
		}
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join(root, pkg, ent.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(src), "\n") {
				code := line
				if i := strings.Index(code, "//"); i >= 0 {
					code = code[:i]
				}
				if pkg == "decision" && (strings.Contains(code, "EPSSScore") || strings.Contains(code, "EPSSReason") || strings.Contains(code, "EPSSPresent") || strings.Contains(code, "Physics.EPSSMultiplier")) {
					continue // the trace RECORDS the pair; it does not consume it
				}
				if strings.Contains(code, "EPSSMultiplier(") || strings.Contains(code, "Physics.EPSSMultiplier") || strings.Contains(code, ".CVSS") {
					t.Fatalf("%s/%s consumes EPSS/CVSS: %q — EPSS enters exactly one layer (recon value axis)", pkg, ent.Name(), strings.TrimSpace(line))
				}
			}
		}
	}
	// The formula exists once, here.
	count := 0
	for _, pkg := range []string{"recon", "platform"} {
		entries, _ := os.ReadDir(filepath.Join(root, pkg))
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
				continue
			}
			src, _ := os.ReadFile(filepath.Join(root, pkg, ent.Name()))
			count += strings.Count(string(src), "e*(c/10)") + strings.Count(string(src), "0.5*e.EPSS")
		}
	}
	if count != 1 {
		t.Fatalf("EPSS multiplier formula sites = %d, want exactly 1 (the old 0.5/0.5 anchor must be gone)", count)
	}
}
