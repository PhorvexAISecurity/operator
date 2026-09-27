/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/phorvex/phorvex/internal/model"
)

const requiredActionVocabularySize = 19

// TestCRDActionVocabularyCompleteness prevents the API marker, generated CRDs,
// ActionType constants, and the optimizer's canonical action vocabulary from
// agreeing on an accidentally stripped subset.
func TestCRDActionVocabularyCompleteness(t *testing.T) {
	expected := actionSet(t, "model vocabulary", modelActionVocabulary())
	if got := len(expected); got != requiredActionVocabularySize {
		t.Fatalf("model.MutatingActions union {noop, disable}: got %d values, want %d", got, requiredActionVocabularySize)
	}

	apiConstants := actionSet(t, "ActionType const block", actionTypeConstants(t))
	assertSameActionSet(t, "ActionType const block", apiConstants, expected)

	for _, path := range []string{
		filepath.Join("..", "..", "config", "crd", "bases", "phorvex.ai_phorvexpolicies.yaml"),
		filepath.Join("..", "..", "charts", "phorvex", "crds", "phorvex.ai_phorvexpolicies.yaml"),
	} {
		got := actionSet(t, path, crdActionEnum(t, path))
		assertSameActionSet(t, path, got, expected)
	}
}

func modelActionVocabulary() []string {
	values := make([]string, 0, len(model.MutatingActions)+2)
	for _, action := range model.MutatingActions {
		values = append(values, string(action))
	}
	return append(values, string(model.ActionNoop), string(model.ActionDisable))
}

func actionTypeConstants(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "api", "v1alpha1", "phorvexpolicy_types.go")
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
			if !ok || typeName.Name != "ActionType" {
				continue
			}
			if len(spec.Names) != 1 || len(spec.Values) != 1 {
				t.Fatalf("%s: ActionType constants must have one explicit name and string value", path)
			}
			literal, ok := spec.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatalf("%s: ActionType constant %s must have an explicit string value", path, spec.Names[0].Name)
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("%s: unquote ActionType constant %s: %v", path, spec.Names[0].Name, err)
			}
			values = append(values, value)
		}
	}
	return values
}

func crdActionEnum(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	jsonDocument, err := utilyaml.ToJSON(raw)
	if err != nil {
		t.Fatalf("convert %s to JSON: %v", path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(jsonDocument, &document); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	versions, found, err := unstructured.NestedSlice(document, "spec", "versions")
	if err != nil || !found {
		t.Fatalf("read %s spec.versions: found=%v err=%v", path, found, err)
	}
	for _, rawVersion := range versions {
		version, ok := rawVersion.(map[string]any)
		if !ok || version["name"] != "v1alpha1" {
			continue
		}
		rawEnum, found, err := unstructured.NestedSlice(version,
			"schema", "openAPIV3Schema", "properties", "spec", "properties",
			"actions", "properties", "enabled", "items", "enum")
		if err != nil || !found {
			t.Fatalf("read %s ActionType enum: found=%v err=%v", path, found, err)
		}
		values := make([]string, 0, len(rawEnum))
		for _, rawValue := range rawEnum {
			value, ok := rawValue.(string)
			if !ok {
				t.Fatalf("%s: non-string ActionType enum value %#v", path, rawValue)
			}
			values = append(values, value)
		}
		return values
	}
	t.Fatalf("%s: v1alpha1 schema not found", path)
	return nil
}

func actionSet(t *testing.T, source string, values []string) map[string]struct{} {
	t.Helper()
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := set[value]; duplicate {
			t.Fatalf("%s: duplicate action %q", source, value)
		}
		set[value] = struct{}{}
	}
	return set
}

func assertSameActionSet(t *testing.T, source string, got, want map[string]struct{}) {
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
		t.Fatalf("%s vocabulary drift: missing=%v extra=%v", source, missing, extra)
	}
}
