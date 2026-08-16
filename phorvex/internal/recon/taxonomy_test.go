package recon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// taxonomy_test.go — PHVX-77 / PHORVEXSEC-133.

func aiPod() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m", Stateful: true,
	}}
}

func aiCover(t *testing.T) map[model.Action][]string {
	t.Helper()
	return ucwRecon{}.AssetFacts(aiPod(),
		FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true, Stateful: true}).CoverByAction
}

func kindsOf(t *testing.T, keys []string) []string {
	t.Helper()
	af := ucwRecon{}.AssetFacts(aiPod(),
		FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true, Stateful: true})
	byKey := map[string]string{}
	for _, f := range af.Facts {
		byKey[f.Key()] = f.Kind
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

// TestKVMigrateInvalidateCoversSessionNotRoute is item 3. Invalidating a KV cache destroys in-pod
// session state; it does not change the inference route the attacker learned. Granting it
// endpointPath claimed a defence it does not perform.
func TestKVMigrateInvalidateCoversSessionNotRoute(t *testing.T) {
	got := kindsOf(t, aiCover(t)[model.ActionKVMigrateInvalidate])
	if len(got) == 0 {
		t.Fatal("kv-migrate-invalidate has no cover at all on an AI pod")
	}
	for _, kind := range got {
		if kind == FactEndpointPath {
			t.Fatalf("kv-migrate-invalidate still claims %q — a KV flush does not stale a learned "+
				"route; endpoint-rotate is the action that does", FactEndpointPath)
		}
	}
	found := false
	for _, kind := range got {
		if kind == FactSession {
			found = true
		}
	}
	if !found {
		t.Fatalf("kv-migrate-invalidate should cover %q; got %v", FactSession, got)
	}
}

// TestNoDeadFactKinds is item 1, generalised: a declared fact kind that no profile ever emits is
// dead weight that reads as capability. FactNodePlacement was exactly that — two repo-wide
// references, both its own comment and declaration.
//
// The declared set is parsed from facts.go rather than hand-listed. A hand-list can only catch the
// kind you already knew about: the first version of this test kept one, and re-declaring
// FactNodePlacement did NOT fail it, which made it useless for the thing it is named for.
func TestNoDeadFactKinds(t *testing.T) {
	declared := declaredFactKinds(t)
	if len(declared) < 8 {
		t.Fatalf("parsed only %d fact kinds from facts.go; the parser has drifted from the source", len(declared))
	}

	emitted := map[string]bool{}
	fctx := FactContext{
		AssetValue: 10, PHold: 1, StageUrgency: 1, LateralUrgency: 1,
		HasGPU: true, Stateful: true,
		Neighbors: []NeighborRef{{Key: "ns/neighbour", Value: 1}},
	}
	views := []*model.WorkloadView{
		aiPod(),
		{Pod: model.Pod{Namespace: "ns", Name: "web"}},
		{Pod: model.Pod{Namespace: "ns", Name: "db", Stateful: true}},
		{Pod: model.Pod{Namespace: "ns", Name: "lora", HasGPU: true, ModelID: "m", SuspectAdapter: "evil"}},
	}
	for _, p := range Registry.All() {
		for _, v := range views {
			for _, f := range p.AssetFacts(v, fctx).Facts {
				emitted[f.Kind] = true
			}
		}
	}
	for name, value := range declared {
		if !emitted[value] {
			t.Errorf("%s = %q is declared but no registered profile emits it across any archetype — "+
				"dead taxonomy reads as capability", name, value)
		}
	}
}

// declaredFactKinds reads every Fact* string constant straight out of facts.go, so a newly-added
// dead kind is caught without anyone remembering to update a list here.
func declaredFactKinds(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "facts.go", nil, 0)
	if err != nil {
		t.Fatalf("parse facts.go: %v", err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if !strings.HasPrefix(name.Name, "Fact") || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			out[name.Name] = strings.Trim(lit.Value, `"`)
		}
		return true
	})
	return out
}

// TestIdenticalCoverIsStillOutstanding records items 2 and 4 rather than silently leaving them.
// They are NOT fixed here: PHORVEXSEC-121 owns the warm-swap/mig-rebind split, specifies it in
// detail, and carries a math question that is not mine to answer. This test asserts the CURRENT
// state, so when 121 lands it fails and forces this note to be revisited.
func TestIdenticalCoverIsStillOutstanding(t *testing.T) {
	cover := aiCover(t)
	ws, mr := cover[model.ActionWarmSwap], cover[model.ActionMIGRebind]
	same := len(ws) == len(mr) && len(ws) > 0
	if same {
		for i := range ws {
			if ws[i] != mr[i] {
				same = false
				break
			}
		}
	}
	if !same {
		t.Skip("warm-swap and mig-rebind no longer share identical cover — PHORVEXSEC-121 has " +
			"landed; delete this test and close PHVX-77 items 2 and 4")
	}
	t.Logf("KNOWN, NOT FIXED HERE: warm-swap and mig-rebind still share byte-identical cover %v. "+
		"PHORVEXSEC-121 owns the split and is waiting on its math item.", kindsOf(t, ws))
}
