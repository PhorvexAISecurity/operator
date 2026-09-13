package main

// corpus_parity_test.go — p3report must reach the SAME verdict as the harness
// for the same bytes (V3-M161, lead review R2 finding 1). See the console's
// copy for why routing through the shared rules is not sufficient on its own.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phorvex/metricvalidity"
)

func TestP3ReportReaderMatchesTheSharedContract(t *testing.T) {
	problems := metricvalidity.CheckCorpusParity(func(row []byte) (metricvalidity.ExpectedVerdict, error) {
		var m Metric
		if err := json.Unmarshal(row, &m); err != nil {
			return metricvalidity.ExpectedVerdict{}, err
		}
		return metricvalidity.VerdictOf(m.verdict()), nil
	})
	for _, p := range problems {
		t.Errorf("p3report reader disagrees with the shared contract: %s", p)
	}
}

// Only a certifiable row may enter a published mean.
func TestP3ReportAggregateAdmitsOnlyCertifiedRows(t *testing.T) {
	for _, c := range metricvalidity.Corpus() {
		t.Run(c.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metrics.jsonl")
			if err := os.WriteFile(path, append([]byte(c.Row), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			rows, err := readMetrics(path)
			if err != nil || len(rows) != 1 {
				t.Fatalf("%s: the row must stay READABLE: err=%v rows=%d", c.Name, err, len(rows))
			}
			m := rows[0]
			if m.scorable() != c.Expect.Scorable || m.legacy() != c.Expect.Legacy ||
				m.costUsable() != c.Expect.CostUsable {
				t.Fatalf("%s: reader predicates disagree with the contract (%s)", c.Name, c.Expect)
			}
			by, _, _ := aggregate(rows)
			a := by[m.Scenario][m.Defender]
			got := 0
			if a != nil {
				got = len(a.disruption)
			}
			want := 0
			if c.Expect.Scorable {
				want = 1
			}
			if got != want {
				t.Fatalf("%s (%s): %d row(s) entered the disruption mean, want %d", c.Name, c.Why, got, want)
			}
			if a != nil && !c.Expect.CostUsable && len(a.actions) != 0 {
				t.Fatalf("%s: an unusable cost entered the cost mean: %v", c.Name, a.actions)
			}
		})
	}
}
