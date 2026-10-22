package policyscope

import (
	"flag"
	"slices"
	"testing"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

func TestListNormalizesAndValidates(t *testing.T) {
	var s Scope
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	s.Register(fs)
	if err := fs.Parse([]string{"--policy-namespaces= staging-b,staging-a,,staging-b"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil || !slices.Equal(got, []string{"staging-a", "staging-b"}) {
		t.Fatalf("List = %v, %v", got, err)
	}
	if got, err := (Scope{}).List(); err != nil || got != nil {
		t.Fatalf("an empty scope = %v, %v; want every namespace (nil)", got, err)
	}
	for _, bad := range []string{"Staging", "a/b", "-x", "x_y"} {
		if _, err := (Scope{Namespaces: bad}).List(); err == nil {
			t.Errorf("namespace %q accepted", bad)
		}
	}
}

func TestCacheScopesOnlyPolicies(t *testing.T) {
	if opts := Cache(nil); opts.ByObject != nil || opts.DefaultNamespaces != nil {
		t.Fatalf("an unscoped cache = %+v", opts)
	}
	opts := Cache([]string{"staging"})
	if opts.DefaultNamespaces != nil || len(opts.ByObject) != 1 {
		t.Fatalf("only PhorvexPolicy may be scoped: %+v", opts)
	}
	for object, byObject := range opts.ByObject {
		if _, ok := object.(*v1alpha1.PhorvexPolicy); !ok {
			t.Fatalf("scoped %T", object)
		}
		if len(byObject.Namespaces) != 1 {
			t.Fatalf("namespaces = %v", byObject.Namespaces)
		}
		if _, ok := byObject.Namespaces["staging"]; !ok {
			t.Fatalf("namespaces = %v", byObject.Namespaces)
		}
	}
}
