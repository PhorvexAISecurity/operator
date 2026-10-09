package actionset

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestEveryGeneratedExclusionNamesItsGate is a structural guard: a new exclusion site
// added to Generate without a Gate would silently fall out of Math Lab gate attribution.
func TestEveryGeneratedExclusionNamesItsGate(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "generator.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{"GateReconAbsent": true}
	for _, g := range []string{"GatePolicyBinding", "GateUnsupportedAction", "GateQuarantineCapacity", "GateCapability",
		"GateSharedResources", "GateFeasibility", "GateCostNaN", "GateCHiCeiling"} {
		known[g] = true
	}
	literals := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "Exclusion" {
			return true
		}
		literals++
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Gate" {
				if value, ok := kv.Value.(*ast.Ident); ok && known[value.Name] {
					return true
				}
				t.Errorf("%s: Exclusion gate is not a known Gate constant", fset.Position(lit.Pos()))
				return true
			}
		}
		t.Errorf("%s: Exclusion literal has no Gate", fset.Position(lit.Pos()))
		return true
	})
	if literals < 19 {
		t.Fatalf("found only %d Exclusion literals; the guard is not reading generator.go", literals)
	}
	if len(CandidateGateOrder) != 8 {
		t.Fatalf("candidate gate order has %d gates", len(CandidateGateOrder))
	}
}
