package metricvalidity

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// corpus.go carries a SHARED PARITY CORPUS: a set of real metric rows, produced
// by the actual harness, together with the verdict every consumer must reach for
// each one.
//
// The shared Evaluate above already removes the possibility of two consumers
// implementing different RULES. The corpus closes the remaining gap: a consumer
// can still get the wrong answer by failing to DECODE a field the rules depend
// on — which is exactly how a reader once certified rows the producer refused,
// having quietly dropped the baseline evidence from its local struct.
//
// So every reader runs the same rows through its own decode path and its own
// predicates, and compares against these expectations. The corpus is embedded in
// the module both sides already import, so there is one copy and no path
// juggling across module boundaries.
//
// The rows are GENERATED, not hand-written: see the regeneration test in the
// harness (internal/report), which drives Runner.Run -> MetricWriter -> the real
// reader and then derives single-field counterexamples from the row it produced.
// Hand-crafted permissive fixtures would defeat the purpose.

//go:embed corpus.json
var corpusJSON []byte

// ExpectedVerdict is the verdict every consumer must reach for one corpus row.
type ExpectedVerdict struct {
	Legacy           bool `json:"legacy"`
	Unverified       bool `json:"unverified"`
	Scorable         bool `json:"scorable"`
	CostUsable       bool `json:"costUsable"`
	OracleUsable     bool `json:"oracleUsable"`
	NegControlUsable bool `json:"negControlUsable"`
}

// String renders the verdict compactly for test failure messages.
func (e ExpectedVerdict) String() string {
	return fmt.Sprintf("legacy=%v unverified=%v scorable=%v costUsable=%v oracleUsable=%v negControlUsable=%v",
		e.Legacy, e.Unverified, e.Scorable, e.CostUsable, e.OracleUsable, e.NegControlUsable)
}

// CorpusCase is one row of the parity corpus.
type CorpusCase struct {
	// Name identifies the case (e.g. "positive-control", "baseline-contradiction").
	Name string `json:"name"`
	// Why explains what the case exists to catch.
	Why string `json:"why"`
	// Row is the metric row exactly as it appears in a metrics.jsonl file: one
	// compact line, so a test can write it straight into such a file. Each
	// reader decodes it with its OWN struct, which is the point.
	Row string `json:"row"`
	// Expect is the verdict every consumer must reach.
	Expect ExpectedVerdict `json:"expect"`
}

// VerdictOf collapses a Verdict into the comparable expectation.
func VerdictOf(v Verdict) ExpectedVerdict {
	return ExpectedVerdict{
		Legacy: v.Legacy, Unverified: v.Unverified, Scorable: v.Scorable,
		CostUsable: v.CostUsable, OracleUsable: v.OracleUsable, NegControlUsable: v.NegControlUsable,
	}
}

// Corpus returns the shared parity corpus. It panics only if the embedded file
// is malformed, which would be a build-time mistake.
func Corpus() []CorpusCase {
	var out []CorpusCase
	if err := json.Unmarshal(corpusJSON, &out); err != nil {
		panic("metricvalidity: embedded parity corpus is malformed: " + err.Error())
	}
	return out
}

// CheckCorpusParity runs one reader's decode-and-decide path over every corpus
// row and returns a description of each disagreement, empty when the reader
// agrees with the contract throughout.
//
// `verdict` must do what the reader really does in production: decode the row
// with the reader's OWN struct and apply the reader's OWN predicates. That is
// what catches a reader which routes through the shared rules but forgets to
// decode a field those rules depend on.
func CheckCorpusParity(verdict func(row []byte) (ExpectedVerdict, error)) []string {
	var problems []string
	for _, c := range Corpus() {
		got, err := verdict([]byte(c.Row))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: reader failed to decode the row: %v", c.Name, err))
			continue
		}
		if got != c.Expect {
			problems = append(problems, fmt.Sprintf("%s (%s):\n    contract: %s\n    reader:   %s",
				c.Name, c.Why, c.Expect, got))
		}
	}
	return problems
}
