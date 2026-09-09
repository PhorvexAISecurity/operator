package feasibility

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// Read declarations independently of both registries: adding a Var constant without
// deciding whether it is live or declared-only must fail this test.
func TestM030EveryDeclaredVariableClassified(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "../model/types.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	vocab := map[string]string{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			v := spec.(*ast.ValueSpec)
			for i, name := range v.Names {
				if !strings.HasPrefix(name.Name, "Var") {
					continue
				}
				if i >= len(v.Values) {
					t.Fatalf("%s needs an explicit value", name)
				}
				lit, ok := v.Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("%s needs a literal", name)
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if _, exists := vocab[value]; exists {
					t.Fatalf("duplicate variable %s", value)
				}
				vocab[value] = v.Doc.Text()
			}
		}
	}
	if len(vocab) == 0 {
		t.Fatal("no variable declarations inspected")
	}
	live := liveVarSet()
	declared := map[string]bool{}
	consumed := map[string]bool{}
	for _, v := range model.DeclaredExposureVariables {
		if declared[v] {
			t.Fatalf("duplicate declared-only variable %s", v)
		}
		declared[v] = true
	}
	if len(live) != len(model.LiveExposureVariables) {
		t.Fatal("duplicate live variable")
	}
	for _, a := range model.MutatingActions {
		consumed[ExposureVarFor(a)] = true
	}
	for v, comment := range vocab {
		if live[v] {
			if declared[v] || !consumed[v] {
				t.Errorf("%s live but declared-only or unconsumed", v)
			}
		} else if !declared[v] || !strings.Contains(comment, "declared-only: no clock, no consumer") || consumed[v] {
			t.Errorf("%s neither clocked-and-consumed nor explicitly declared-only", v)
		}
	}
	for _, list := range [][]string{model.LiveExposureVariables, model.DeclaredExposureVariables} {
		for _, v := range list {
			if _, ok := vocab[v]; !ok {
				t.Errorf("registry variable %s not declared", v)
			}
		}
	}
}
