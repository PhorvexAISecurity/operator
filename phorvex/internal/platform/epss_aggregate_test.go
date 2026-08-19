/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package platform

import (
	"fmt"
	"math"
	"testing"
)

func vulns(epss ...float64) []Vuln {
	out := make([]Vuln, 0, len(epss))
	for i, e := range epss {
		// CVSS deliberately anti-correlated with EPSS, so any test that accidentally mixed the
		// two CVEs would produce a visibly wrong pair rather than a plausible one.
		out = append(out, Vuln{CVE: fmt.Sprintf("CVE-2026-%04d", i), EPSS: e, CVSS: 10 - 9*e})
	}
	return out
}

// The pair must belong to ONE REAL CVE. The multiplier weights EPSS and CVSS equally, so
// splicing the top EPSS from one CVE onto the top CVSS from another would put a vulnerability
// that does not exist directly into the score.
func TestSelectedPairBelongsToOneRealCVE(t *testing.T) {
	in := vulns(0.9, 0.02, 0.5, 0.01)
	got, ok := AggregateVulns(in)
	if !ok {
		t.Fatal("no selection from a non-empty list")
	}
	for _, v := range in {
		if v.CVE == got.CVE {
			if v.EPSS != got.EPSS || v.CVSS != got.CVSS {
				t.Fatalf("selected %s as (%v,%v) but that CVE is (%v,%v) — the pair was spliced",
					got.CVE, got.EPSS, got.CVSS, v.EPSS, v.CVSS)
			}
			return
		}
	}
	t.Fatalf("selected %q, which is not in the input", got.CVE)
}

// On a short CVE list nearest-rank P99 IS the maximum, because ceil(0.99*n) == n for n <= 99.
// (At exactly n=100 the product is 99.0 and ceil leaves it there, so 100 is the first size at
// which P99 steps off the maximum — the boundary is 99, not 100.)
// This is the property that makes P99 safe: it only departs from max once the list is long
// enough that max has started measuring image size instead of exploitability.
func TestP99EqualsMaxOnShortLists(t *testing.T) {
	for _, n := range []int{1, 2, 5, 25, 50, 99} {
		in := make([]Vuln, 0, n)
		for i := 0; i < n; i++ {
			in = append(in, Vuln{CVE: fmt.Sprintf("CVE-%04d", i), EPSS: float64(i) / float64(n), CVSS: 5})
		}
		got, ok := AggregateVulns(in)
		if !ok {
			t.Fatalf("n=%d: no selection", n)
		}
		want := in[n-1].EPSS // the maximum
		if got.EPSS != want {
			t.Errorf("n=%d: P99 selected EPSS %v, want the maximum %v", n, got.EPSS, want)
		}
	}
}

// Above ~100 CVEs P99 trims the extreme tail. That is the whole point: a long list almost
// always contains one high-EPSS outlier, so the maximum ends up reporting how big the image is.
func TestP99TrimsTheTailOnLongLists(t *testing.T) {
	in := make([]Vuln, 0, 200)
	for i := 0; i < 199; i++ {
		in = append(in, Vuln{CVE: fmt.Sprintf("CVE-%04d", i), EPSS: 0.01, CVSS: 5})
	}
	in = append(in, Vuln{CVE: "CVE-9999", EPSS: 0.99, CVSS: 5}) // the lone outlier

	got, _ := AggregateVulns(in)
	if got.CVE == "CVE-9999" {
		t.Fatal("P99 picked the single extreme outlier out of 200 CVEs; that is max behaviour and reintroduces the size artefact")
	}
	if got.EPSS != 0.01 {
		t.Fatalf("selected EPSS %v, want 0.01 — the body of the distribution, not its tail", got.EPSS)
	}
}

// A clean image must not be recorded as a real zero. Zero would score
// 1 + clamp01(0 + 0) = 1.0, which is numerically the same as honest-absent but semantically a
// claim: "we scanned and found nothing exploitable". Leaving it out of the cache keeps the
// distinction between "no vulnerabilities" and "no data".
func TestCleanImageIsAbsentNotZero(t *testing.T) {
	if _, ok := AggregateVulns(nil); ok {
		t.Error("an empty vulnerability list produced a selection")
	}
	if _, _, ok := AggregateToEntry([]Vuln{}); ok {
		t.Error("a clean image produced a cache entry; it must be omitted so lookups degrade to honest-absent")
	}
}

// Ties must break deterministically or two replicas can disagree about the same image.
func TestTiesBreakDeterministically(t *testing.T) {
	in := []Vuln{
		{CVE: "CVE-2026-0003", EPSS: 0.5, CVSS: 9},
		{CVE: "CVE-2026-0001", EPSS: 0.5, CVSS: 3},
		{CVE: "CVE-2026-0002", EPSS: 0.5, CVSS: 6},
	}
	first, _ := AggregateVulns(in)
	for i := 0; i < 20; i++ {
		got, _ := AggregateVulns([]Vuln{in[2], in[0], in[1]})
		if got.CVE != first.CVE {
			t.Fatalf("input order changed the selection: %s vs %s", got.CVE, first.CVE)
		}
	}
}

func TestAggregateDoesNotMutateInput(t *testing.T) {
	in := vulns(0.9, 0.02, 0.5)
	before := append([]Vuln(nil), in...)
	_, _ = AggregateVulns(in)
	for i := range in {
		if in[i] != before[i] {
			t.Fatalf("input was reordered at %d: %v vs %v", i, in[i], before[i])
		}
	}
}

// The two rules that were measured and eliminated, encoded so nobody re-proposes them from
// first principles. Both are defensible on paper and both produce a dead term.
func TestEliminatedRulesWouldProduceADeadTerm(t *testing.T) {
	// noisy-OR over 200 modest CVEs: probabilistically the "right" aggregation, and it pins.
	const n = 200
	prod := 1.0
	for i := 0; i < n; i++ {
		prod *= 1 - 0.03
	}
	if noisyOR := 1 - prod; noisyOR < 0.99 {
		t.Fatalf("noisy-OR over %d CVEs at EPSS 0.03 = %.4f; the elimination rationale assumed it saturates", n, noisyOR)
	}

	// mean over a realistic list: dominated by the 60% of CVEs scoring under 0.01.
	in := make([]Vuln, 0, n)
	sum := 0.0
	for i := 0; i < n; i++ {
		e := 0.005
		if i >= 180 {
			e = 0.4 // a severe tail
		}
		in = append(in, Vuln{CVE: fmt.Sprintf("CVE-%04d", i), EPSS: e, CVSS: 5})
		sum += e
	}
	if mean := sum / float64(n); mean > 0.05 {
		t.Fatalf("mean = %.4f; the elimination rationale assumed it stays near the noise floor", mean)
	}

	// P99 on that same list still reports the severe tail, which is the point.
	got, _ := AggregateVulns(in)
	if math.Abs(got.EPSS-0.4) > 1e-9 {
		t.Fatalf("P99 selected %v on a list with a severe tail, want 0.4 — it must not average the tail away", got.EPSS)
	}
}
