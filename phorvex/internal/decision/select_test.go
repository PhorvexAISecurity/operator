package decision

import (
	"strings"
	"testing"
)

// select_test.go — PHORVEXSEC-195 / M-107: the retired brain is rejected at the boundary.

func TestSelectOptimizerRejectsTheRetiredEngine(t *testing.T) {
	for _, name := range []string{"p0", "p0-greedy"} {
		opt, err := SelectOptimizer(name)
		if err == nil || opt != nil {
			t.Fatalf("engine %q was accepted (%v): a removed brain must not be silently ignored or aliased to p1", name, opt)
		}
		if !strings.Contains(err.Error(), "M-107") || !strings.Contains(err.Error(), name) {
			t.Fatalf("engine %q error must name the value and the reason, got %q", name, err)
		}
	}
}

func TestSelectOptimizerReturnsTheCoverageBrain(t *testing.T) {
	for _, name := range []string{"", EngineP1} {
		opt, err := SelectOptimizer(name)
		if err != nil {
			t.Fatalf("engine %q: %v", name, err)
		}
		if opt == nil || opt.Name() != NewCoverageEngine().Name() {
			t.Fatalf("engine %q resolved to %v, want the coverage brain", name, opt)
		}
	}
}

func TestSelectOptimizerRejectsAnUnknownName(t *testing.T) {
	if _, err := SelectOptimizer("p2"); err == nil || !strings.Contains(err.Error(), "unknown engine") {
		t.Fatalf("an unknown engine must be refused by name, got %v", err)
	}
}
