/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package registry is the tiny, type-safe plugin registry that makes every Phorvex
// modular surface (PhysicsProfile, FeasibilityConstraint, CostModel,
// BeliefEstimator, ContextProvider) extensible by ADDING ONE FILE with an init()
// that calls Register — and ZERO change to any core file. The decision engine reads
// providers back through Default()/Get()/All(), never by importing a concrete impl.
package registry

import (
	"sort"
	"sync"
)

// Named is anything carrying a stable string name (every Phorvex plugin does).
type Named interface {
	Name() string
}

// Registry is a concurrency-safe name->impl map with a designated default (the
// first registered impl, overridable). One Registry exists per interface kind.
type Registry[T Named] struct {
	mu          sync.RWMutex
	items       map[string]T
	order       []string
	defaultName string
}

// New constructs an empty Registry.
func New[T Named]() *Registry[T] {
	return &Registry[T]{items: make(map[string]T)}
}

// Register adds an impl under its Name(). The first registration becomes the
// default. Re-registering the same name overwrites (last wins) so a custom impl can
// shadow a built-in by registering after it. Registration is intended for init().
func (r *Registry[T]) Register(item T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := item.Name()
	if _, exists := r.items[name]; !exists {
		r.order = append(r.order, name)
	}
	r.items[name] = item
	if r.defaultName == "" {
		r.defaultName = name
	}
}

// Get returns the impl registered under name.
func (r *Registry[T]) Get(name string) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.items[name]
	return v, ok
}

// Default returns the default impl (the first registered, unless SetDefault moved
// it).
func (r *Registry[T]) Default() (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.items[r.defaultName]
	return v, ok
}

// SetDefault designates name as the default if it is registered.
func (r *Registry[T]) SetDefault(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[name]; !ok {
		return false
	}
	r.defaultName = name
	return true
}

// DefaultName reports the current default's name ("" if the registry is empty).
func (r *Registry[T]) DefaultName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultName
}

// Names returns the registered names in registration order.
func (r *Registry[T]) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// All returns every registered impl, ordered by name for deterministic iteration
// (used where every constraint must run, e.g. the feasibility gate).
func (r *Registry[T]) All() []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.items))
	for n := range r.items {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]T, 0, len(names))
	for _, n := range names {
		out = append(out, r.items[n])
	}
	return out
}
