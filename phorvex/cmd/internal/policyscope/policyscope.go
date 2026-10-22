// Package policyscope limits the PhorvexPolicies a deployment acts on to listed
// namespaces. Empty, the default, is every namespace, as before. A second
// deployment on a cluster that already runs Phorvex, such as a staging
// environment in its own namespace, lists its own namespaces, so it never
// reconciles, ticks or authorizes the other deployment's policies. The manager,
// the sensor and the actuator register the flag, and their handshakes compare it.
package policyscope

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

// Scope is the configured policy scope.
type Scope struct {
	Namespaces string
}

// Register defines the flag on fs.
func (s *Scope) Register(fs *flag.FlagSet) {
	fs.StringVar(&s.Namespaces, "policy-namespaces", "", "Comma-separated namespaces whose PhorvexPolicies this deployment reconciles, ticks and authorizes. Empty (default) = every namespace. A second deployment on the same cluster must list only its own; it must match across the manager, the sensor and the actuator, or their handshakes refuse.")
}

// List returns the scope's namespaces, sorted and without duplicates; nil means
// every namespace.
func (s Scope) List() ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, ns := range strings.Split(s.Namespaces, ",") {
		if ns = strings.TrimSpace(ns); ns == "" || seen[ns] {
			continue
		}
		if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
			return nil, fmt.Errorf("--policy-namespaces: %q is not a namespace name: %s", ns, strings.Join(errs, "; "))
		}
		seen[ns] = true
		out = append(out, ns)
	}
	sort.Strings(out)
	return out, nil
}

// Cache returns the manager cache options that limit PhorvexPolicy, and so the
// policy controller and every cached policy read, to namespaces; nil namespaces
// leave the cache unscoped.
func Cache(namespaces []string) cache.Options {
	if len(namespaces) == 0 {
		return cache.Options{}
	}
	scoped := map[string]cache.Config{}
	for _, ns := range namespaces {
		scoped[ns] = cache.Config{}
	}
	return cache.Options{ByObject: map[client.Object]cache.ByObject{&v1alpha1.PhorvexPolicy{}: {Namespaces: scoped}}}
}
