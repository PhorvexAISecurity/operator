package console

// corpus_parity_test.go — the console reader must reach the SAME verdict as the
// harness for the same bytes (V3-M161, lead review R2 finding 1).
//
// The corpus is real harness output plus single-field counterexamples derived
// from it; the expectations are the shared contract's. Routing through the
// shared rules is not enough on its own — a reader can still get the wrong
// answer by failing to DECODE a field those rules depend on, which is precisely
// how this reader once certified rows the producer refuses. So the row goes
// through THIS package's own struct and THIS package's own predicates.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phorvex/metricvalidity"
)

func TestConsoleReaderMatchesTheSharedContract(t *testing.T) {
	problems := metricvalidity.CheckCorpusParity(func(row []byte) (metricvalidity.ExpectedVerdict, error) {
		var m metricRow
		if err := json.Unmarshal(row, &m); err != nil {
			return metricvalidity.ExpectedVerdict{}, err
		}
		return metricvalidity.VerdictOf(m.verdict()), nil
	})
	for _, p := range problems {
		t.Errorf("console reader disagrees with the shared contract: %s", p)
	}
}

// The predicates the panels actually call must follow the same verdict, and the
// published trial aggregate must contain exactly the certifiable rows.
func TestConsolePublishedAggregateMatchesTheSharedContract(t *testing.T) {
	for _, c := range metricvalidity.Corpus() {
		t.Run(c.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metrics.jsonl")
			if err := os.WriteFile(path, append([]byte(c.Row), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			rows, ok := readMetrics(path)
			if !ok || len(rows) != 1 {
				t.Fatalf("%s: the row must stay READABLE (disclosed, not dropped on read)", c.Name)
			}
			m := rows[0]
			if m.scorable() != c.Expect.Scorable {
				t.Errorf("scorable() = %v, contract says %v", m.scorable(), c.Expect.Scorable)
			}
			if m.legacy() != c.Expect.Legacy {
				t.Errorf("legacy() = %v, contract says %v", m.legacy(), c.Expect.Legacy)
			}
			if m.costUsable() != c.Expect.CostUsable {
				t.Errorf("costUsable() = %v, contract says %v", m.costUsable(), c.Expect.CostUsable)
			}
			if m.negControlUsable() != c.Expect.NegControlUsable {
				t.Errorf("negControlUsable() = %v, contract says %v", m.negControlUsable(), c.Expect.NegControlUsable)
			}
			// Only a certifiable row may reach a published panel.
			kept := fixedTrials(rows, m.Scenario, m.Defender)
			want := 0
			if c.Expect.Scorable {
				want = 1
			}
			if len(kept) != want {
				t.Fatalf("%s (%s): published trial aggregate has %d row(s), want %d",
					c.Name, c.Why, len(kept), want)
			}
		})
	}
}
