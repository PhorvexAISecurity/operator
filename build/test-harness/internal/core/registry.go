package core

import (
	"fmt"
	"sort"
	"sync"
)

// The registries are package-level maps populated ONLY by func init() in each
// plugin file. The runner enumerates them. There is NO central switch/list to
// edit when adding a plugin — that is the whole extensibility contract.
var (
	registryMu        sync.RWMutex
	scenarioRegistry  = map[string]Scenario{}
	defenderRegistry  = map[string]Defender{}
)

// RegisterScenario registers a scenario plugin. Called from a scenario file's
// func init(). Panics on a duplicate name so a copy-paste collision fails loudly
// at startup rather than silently shadowing.
func RegisterScenario(s Scenario) {
	registryMu.Lock()
	defer registryMu.Unlock()
	name := s.Metadata().Name
	if name == "" {
		panic("core.RegisterScenario: scenario has empty Name")
	}
	if _, dup := scenarioRegistry[name]; dup {
		panic(fmt.Sprintf("core.RegisterScenario: duplicate scenario %q", name))
	}
	scenarioRegistry[name] = s
}

// RegisterDefender registers a defender plugin. Called from a defender file's
// func init(). Panics on a duplicate name.
func RegisterDefender(d Defender) {
	registryMu.Lock()
	defer registryMu.Unlock()
	name := d.Metadata().Name
	if name == "" {
		panic("core.RegisterDefender: defender has empty Name")
	}
	if _, dup := defenderRegistry[name]; dup {
		panic(fmt.Sprintf("core.RegisterDefender: duplicate defender %q", name))
	}
	defenderRegistry[name] = d
}

// Scenarios returns all registered scenarios sorted by name (deterministic order
// for reproducible runs).
func Scenarios() []Scenario {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Scenario, 0, len(scenarioRegistry))
	for _, s := range scenarioRegistry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Metadata().Name < out[j].Metadata().Name
	})
	return out
}

// Defenders returns all registered defenders sorted by name (deterministic).
func Defenders() []Defender {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Defender, 0, len(defenderRegistry))
	for _, d := range defenderRegistry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Metadata().Name < out[j].Metadata().Name
	})
	return out
}

// LookupScenario returns a scenario by name.
func LookupScenario(name string) (Scenario, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := scenarioRegistry[name]
	return s, ok
}

// LookupDefender returns a defender by name.
func LookupDefender(name string) (Defender, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	d, ok := defenderRegistry[name]
	return d, ok
}

// resetRegistriesForTest clears the registries. Test-only helper (no _test build
// tag so tests in other packages cannot reach it, but tests in this package can).
func resetRegistriesForTest() {
	registryMu.Lock()
	defer registryMu.Unlock()
	scenarioRegistry = map[string]Scenario{}
	defenderRegistry = map[string]Defender{}
}
