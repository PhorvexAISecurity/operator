/*
 * Phorvex — P-VCLUSTER O1: the single-tenant byte-identity gate (the gate-preserving obligation).
 * Captures the full single-tenant Decision stream on a fixed fleet over several ticks; after the
 * per-tenant refactor it MUST reproduce the golden bit-for-bit (default-to-old-scalar). Regenerate the
 * golden only intentionally with O1_UPDATE=1.
 */

package decision

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// o1Capture runs the engine single-tenant over a fixed fleet for several ticks (so λ + memory evolve)
// at a FIXED clock, and serializes every decision field that the brain produces — a deterministic
// fingerprint of the single-tenant decision path.
func o1Capture() string {
	e := NewCoverageEngine()
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	pol := covPolicy(2)
	views := shippedFleet()
	var b strings.Builder
	for tick := 0; tick < 6; tick++ {
		decs := e.Decide(views, pol)
		for _, d := range decs {
			fmt.Fprintf(&b, "t%d %s/%s act=%s sel=%v pd=%.6f lam=%.6f net=%.6f cw=%.6f risk=%.6f phold=%.6f stage=%s rate=%.6f\n",
				tick, d.Namespace, d.Pod, d.Action, d.Selected, d.PerDollar, d.Lambda, d.Net,
				d.CoveredWeight, d.Risk, d.PHold, d.Stage, d.ProactiveRate)
		}
	}
	return b.String()
}

func TestO1SingleTenantByteIdentical(t *testing.T) {
	got := o1Capture()
	path := filepath.Join("testdata", "o1_golden.txt")
	if os.Getenv("O1_UPDATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("O1 golden written (%d bytes) — captures the PRE-refactor single-tenant decision path", len(got))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read O1 golden: %v (generate once on the pre-refactor code with O1_UPDATE=1)", err)
	}
	if got != string(want) {
		t.Errorf("O1 VIOLATED — the single-tenant decision path changed (the per-tenant refactor was NOT byte-identical):\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
	}
}

// compile-time use of model to keep the import honest if the struct shape shifts.
var _ = model.Decision{}
