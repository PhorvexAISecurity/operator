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
		Namespace: "ns", Name: "llm", Node: "node-a", HasGPU: true, ModelID: "m", Stateful: true,
		RouteService: "infer", GuardrailVariants: 2,
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
				"route; endpointPath must remain audit-only", FactEndpointPath)
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

func TestTierTwoAndThreeCarryNoCover(t *testing.T) {
	af := ucwRecon{}.AssetFacts(aiPod(), FactContext{
		AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true, Stateful: true,
	})
	covered := map[string]bool{}
	for _, keys := range af.CoverByAction {
		for _, key := range keys {
			covered[key] = true
		}
	}
	expected := map[string]FactScope{
		FactNodeFoothold:            ScopeNode,
		FactModelIdentity:           ScopeModel,
		FactGuardrailVariant:        ScopeService,
		FactCredential:              ScopePod,
		FactRetrievalState:          ScopePod,
		FactArtifactProvenance:      ScopePod,
		FactControlPlanePersistence: ScopePod,
	}
	seen := map[string]bool{}
	for _, fact := range af.Facts {
		scope, tracked := expected[fact.Kind]
		if !tracked {
			continue
		}
		seen[fact.Kind] = true
		if fact.Scope != scope {
			t.Errorf("%s scope = %q, want %q", fact.Kind, fact.Scope, scope)
		}
		if covered[fact.Key()] {
			t.Errorf("audit-only fact %s leaked into an action cover as %q", fact.Kind, fact.Key())
		}
	}
	for kind := range expected {
		if !seen[kind] {
			t.Errorf("audit taxonomy fact %s was not emitted by the rich workload fixture", kind)
		}
	}
}

func TestEveryEmittedFactDeclaresScope(t *testing.T) {
	for _, profile := range Registry.All() {
		for _, archetype := range coverArchetypes() {
			for _, fact := range profile.AssetFacts(archetype.view, archetype.fctx).Facts {
				if fact.Scope == "" {
					t.Errorf("%s/%s emitted unscoped fact %s", profile.Name(), archetype.name, fact.Kind)
				}
			}
		}
	}
}

func TestNoOrphanedCover(t *testing.T) {
	for _, profile := range Registry.All() {
		for _, archetype := range coverArchetypes() {
			af := profile.AssetFacts(archetype.view, archetype.fctx)
			facts := map[string]bool{}
			for _, fact := range af.Facts {
				facts[fact.Key()] = true
			}
			for action, keys := range af.CoverByAction {
				for _, key := range keys {
					if !facts[key] {
						t.Errorf("%s/%s action %s claims orphaned cover key %q",
							profile.Name(), archetype.name, action, key)
					}
				}
			}
		}
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
