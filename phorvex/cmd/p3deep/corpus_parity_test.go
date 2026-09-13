package main

// corpus_parity_test.go — p3deep must reach the SAME verdict as the harness for
// the same bytes (V3-M161, lead review R2 finding 1). See the console's copy for
// why routing through the shared rules is not sufficient on its own.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/metricvalidity"
)

func TestP3DeepReaderMatchesTheSharedContract(t *testing.T) {
	problems := metricvalidity.CheckCorpusParity(func(row []byte) (metricvalidity.ExpectedVerdict, error) {
		var m Metric
		if err := json.Unmarshal(row, &m); err != nil {
			return metricvalidity.ExpectedVerdict{}, err
		}
		return metricvalidity.VerdictOf(m.verdict()), nil
	})
	for _, p := range problems {
		t.Errorf("p3deep reader disagrees with the shared contract: %s", p)
	}
}

// Only a certifiable row may reach a published table.
func TestP3DeepAdmitsOnlyCertifiedRows(t *testing.T) {
	for _, c := range metricvalidity.Corpus() {
		t.Run(c.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metrics.jsonl")
			if err := os.WriteFile(path, append([]byte(c.Row), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			rows, err := read(path)
			if err != nil || len(rows) != 1 {
				t.Fatalf("%s: the row must stay READABLE: err=%v rows=%d", c.Name, err, len(rows))
			}
			m := rows[0]
			if m.scorable() != c.Expect.Scorable || m.legacy() != c.Expect.Legacy ||
				m.costUsable() != c.Expect.CostUsable {
				t.Fatalf("%s: reader predicates disagree with the contract (%s)", c.Name, c.Expect)
			}
			md := render(rows, path)
			// An uncertified row is disclosed, and never silently absorbed.
			switch {
			case c.Expect.Legacy && !strings.Contains(md, "1 LEGACY/UNVERIFIED row(s)"):
				t.Fatalf("%s: legacy row not counted:\n%s", c.Name, md)
			case !c.Expect.Scorable && !c.Expect.Legacy && !strings.Contains(md, "1 attack row(s) REFUSED"):
				t.Fatalf("%s (%s): refusal not disclosed:\n%s", c.Name, c.Why, md)
			case c.Expect.Scorable && !strings.Contains(md, "0 attack row(s) REFUSED"):
				t.Fatalf("%s: a certified row was reported as refused:\n%s", c.Name, md)
			}
		})
	}
}
