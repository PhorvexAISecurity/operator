/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package cost

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// TestPhaseVocabularyCompleteness is the WorkloadPhase analog of
// actuator.TestCRDActionVocabularyCompleteness: it binds the phase source of truth
// (model.AllWorkloadPhases), the WorkloadPhase const block, the single cost-encoding
// spec (phaseFlowEncoding), and the RLS prior (priorTheta) so none can drift. A new
// phase constant added without an encoding row, or an encoding number silently changed,
// fails the build here — the silent-absorption hole T1-D closes.
func TestPhaseVocabularyCompleteness(t *testing.T) {
	// (a) const block <-> slice: every WorkloadPhase constant is in AllWorkloadPhases and vice versa.
	constValues := workloadPhaseConstants(t)
	sliceValues := make([]string, 0, len(model.AllWorkloadPhases))
	for _, p := range model.AllWorkloadPhases {
		sliceValues = append(sliceValues, string(p))
	}
	assertSamePhaseSet(t, "const block vs AllWorkloadPhases", stringSet(t, "const block", constValues),
		stringSet(t, "AllWorkloadPhases", sliceValues))

	// (b) slice <-> table: exactly one encoding row per phase, no extras.
	if len(phaseFlowEncoding) != len(model.AllWorkloadPhases) {
		t.Fatalf("phaseFlowEncoding has %d rows, AllWorkloadPhases has %d — a phase is unencoded or the table has an extra",
			len(phaseFlowEncoding), len(model.AllWorkloadPhases))
	}
	for _, p := range model.AllWorkloadPhases {
		if _, ok := phaseFlowEncoding[p]; !ok {
			t.Fatalf("phase %q has no phaseFlowEncoding row (silent-absorption hole)", p)
		}
	}

	// (c) feature-bit sanity + prior derivation consistency.
	seen := map[int]model.WorkloadPhase{}
	theta := priorTheta()
	for _, p := range model.AllWorkloadPhases {
		enc := phaseFlowEncoding[p]
		if enc.featureBit == 0 {
			t.Fatalf("phase %q uses featureBit 0 — that is the bias slot, never a phase bit", p)
		}
		if enc.featureBit < -1 {
			t.Fatalf("phase %q featureBit %d < -1 — only -1 (no bit) or a valid index is allowed", p, enc.featureBit)
		}
		if enc.featureBit >= featureDim {
			t.Fatalf("phase %q featureBit %d >= featureDim %d", p, enc.featureBit, featureDim)
		}
		if enc.featureBit >= 0 {
			if other, dup := seen[enc.featureBit]; dup {
				t.Fatalf("featureBit %d shared by %q and %q", enc.featureBit, other, p)
			}
			seen[enc.featureBit] = p
			if !approxEq(theta[enc.featureBit], enc.priorWeight) {
				t.Fatalf("priorTheta()[%d]=%v != phaseFlowEncoding[%q].priorWeight=%v (prior/table drift)",
					enc.featureBit, theta[enc.featureBit], p, enc.priorWeight)
			}
		}
	}
}

// TestPhaseEncodingGoldenBand pins the pre-registered §Band (03-decision / 01-proposal):
// per-phase flowCost, Features, and priorTheta must equal these LITERALS byte-for-byte.
// The literals are independent of phaseFlowEncoding on purpose — this is the behavior
// contract, so a table edit that changes any output is caught here, not rationalized.
func TestPhaseEncodingGoldenBand(t *testing.T) {
	rotate := model.Move{Action: model.ActionRotate}
	cases := []struct {
		phase    model.WorkloadPhase
		flow     float64    // clamp01c(0.55*switchPrior) on an empty (no-gpu, reqRate-absent) view
		features [6]float64 // Features one-hot
	}{
		{model.PhaseColdStarting, 0.55, [6]float64{1, 1, 0, 0, 0, 0}},
		{model.PhaseWarm, 0.385, [6]float64{1, 0, 1, 0, 0, 0}},
		{model.PhaseIdle, 0.0825, [6]float64{1, 0, 0, 1, 0, 0}},
		{model.PhaseDraining, 0.11, [6]float64{1, 0, 0, 0, 0, 0}},
		{model.PhaseUnknown, 0.275, [6]float64{1, 0, 0, 0, 0, 0}},
	}
	for _, c := range cases {
		view := &model.WorkloadView{Phase: c.phase}
		if got := flowCost(view, rotate); !approxEq(got, c.flow) {
			t.Errorf("flowCost(%q) = %v, want %v", c.phase, got, c.flow)
		}
		got := Features(view)
		for i := range c.features {
			if !approxEq(got[i], c.features[i]) {
				t.Errorf("Features(%q)[%d] = %v, want %v", c.phase, i, got[i], c.features[i])
			}
		}
	}

	// The explicit unrecognized-string fallback (finding #6): a phase outside the
	// vocabulary must encode EXACTLY as Unknown — not free-to-rotate, not bias-bit-set.
	bogus := &model.WorkloadView{Phase: model.WorkloadPhase("bogus")}
	if got, want := flowCost(bogus, rotate), 0.275; !approxEq(got, want) {
		t.Errorf("flowCost(bogus) = %v, want %v (== Unknown)", got, want)
	}
	if got := Features(bogus); !approxEq(got[0], 1) || got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Errorf("Features(bogus) = %v, want bias-only {1,0,0,0,..} (== Unknown)", got)
	}

	if got, want := priorTheta(), [6]float64{0.15, 0.85, 0.55, 0.0, 0.45, 0.20}; got != want {
		t.Errorf("priorTheta() = %v, want %v", got, want)
	}
}

func approxEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// workloadPhaseConstants AST-parses the string values of every `WorkloadPhase` const in
// model/types.go (mirrors actuator/crd_vocabulary_test.go::actionTypeConstants).
func workloadPhaseConstants(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "model", "types.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var values []string
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, rawSpec := range group.Specs {
			spec, ok := rawSpec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			typeName, ok := spec.Type.(*ast.Ident)
			if !ok || typeName.Name != "WorkloadPhase" {
				continue
			}
			if len(spec.Names) != 1 || len(spec.Values) != 1 {
				t.Fatalf("%s: WorkloadPhase constants must have one explicit name and string value", path)
			}
			literal, ok := spec.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatalf("%s: WorkloadPhase constant %s must have an explicit string value", path, spec.Names[0].Name)
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("%s: unquote %s: %v", path, spec.Names[0].Name, err)
			}
			values = append(values, value)
		}
	}
	return values
}

func stringSet(t *testing.T, source string, values []string) map[string]struct{} {
	t.Helper()
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, dup := set[value]; dup {
			t.Fatalf("%s: duplicate phase %q", source, value)
		}
		set[value] = struct{}{}
	}
	return set
}

func assertSamePhaseSet(t *testing.T, source string, got, want map[string]struct{}) {
	t.Helper()
	var missing, extra []string
	for value := range want {
		if _, ok := got[value]; !ok {
			missing = append(missing, value)
		}
	}
	for value := range got {
		if _, ok := want[value]; !ok {
			extra = append(extra, value)
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("%s phase-vocabulary drift: missing=%v extra=%v", source, missing, extra)
	}
}
