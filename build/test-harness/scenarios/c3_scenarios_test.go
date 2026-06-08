package scenarios

import (
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// These table tests pin the CATEGORY-3 (modern, R6-unsupported, Phorvex
// differentiator) scenarios: each must self-register, carry complete metadata,
// declare the HONEST R6 verdict from the locked plan, the plan's exact ATT&CK IDs,
// and run UNCHANGED on the single CPU-only kind node (no capability requirements).
// They are the durable contract for the Phorvex-differentiator scenarios; a future
// edit that quietly inflates R6 coverage or drops a technique id fails here.

// c3Want is the locked-plan expectation for one Category-3 scenario.
type c3Want struct {
	r6Tag      core.R6Tag
	attackIDs  []string
	sourceHint string // a substring the Source must contain (provenance anchor)
}

// c3Expected is the locked plan's Category-3 set: name -> expectation.
var c3Expected = map[string]c3Want{
	"c3-supplychain": {
		r6Tag:      core.R6CannotRespond,
		attackIDs:  []string{"T1525", "T1204.003", "T1610", "T1612"},
		sourceHint: "c3-supplychain",
	},
	"c3-cicd": {
		r6Tag:      core.R6CannotRespond,
		attackIDs:  []string{"T1053.007", "T1610", "T1525", "T1204.003"},
		sourceHint: "c3-cicd",
	},
	"c3-sidecar-inject": {
		r6Tag:      core.R6CannotRespond,
		attackIDs:  []string{"T1610", "T1543.005", "T1525", "T1611"},
		sourceHint: "c3-sidecar-inject",
	},
	"c3-admission-bypass": {
		r6Tag:      core.R6CannotRespond,
		attackIDs:  []string{"T1610", "T1611", "T1068", "T1078.001"},
		sourceHint: "c3-admission-bypass",
	},
	"c3-cryptomining": {
		// Honest: R6 can evict ONLY via a Prometheus emitter + Scored strategy; in
		// default Exact mode the anomalyScore clause is inert -> Partial, not Covers.
		r6Tag:      core.R6Partial,
		attackIDs:  []string{"T1496.001", "T1610", "T1059.013"},
		sourceHint: "c3-cryptomining",
	},
	"c3-imds-theft": {
		r6Tag:      core.R6CannotRespond,
		attackIDs:  []string{"T1552.005", "T1528", "T1552.007", "T1078.004"},
		sourceHint: "c3-imds-theft",
	},
	"c3-secrets-sprawl": {
		r6Tag:      core.R6CannotRespond,
		attackIDs:  []string{"T1552.001", "T1552.007", "T1528", "T1078"},
		sourceHint: "c3-secrets-sprawl",
	},
}

// TestCategory3Registered asserts every Category-3 scenario this task implements
// self-registered and is bucketed as ModernUnsupported. Adding a scenario is one
// new file + one register call, ZERO core changes — so the runner enumerating the
// registry MUST surface each by name with the right category.
func TestCategory3Registered(t *testing.T) {
	reg := allScenarios()
	for name := range c3Expected {
		s, ok := reg[name]
		if !ok {
			t.Errorf("Category-3 scenario %q is not registered", name)
			continue
		}
		if got := s.Metadata().Category; got != core.CategoryModernUnsupported {
			t.Errorf("%s: Category = %q, want %q", name, got, core.CategoryModernUnsupported)
		}
	}
}

// TestCategory3R6TagsAreHonest pins each Category-3 R6 verdict to the locked plan.
// Six are R6CannotRespond (genuine Phorvex differentiators: no admission / image
// provenance / CI-CD / IMDS / secrets-mount actuator in api/v1beta1) and crypto-
// mining is R6Partial (emitter+Scored-mode dependent). This guards against a future
// edit quietly upgrading a differentiator to a coverage claim.
func TestCategory3R6TagsAreHonest(t *testing.T) {
	reg := allScenarios()
	for name, want := range c3Expected {
		s, ok := reg[name]
		if !ok {
			t.Errorf("scenario %q not registered", name)
			continue
		}
		md := s.Metadata()
		if md.R6ResponseTag != want.r6Tag {
			t.Errorf("%s: R6ResponseTag = %q, want %q (honest verdict drifted)", name, md.R6ResponseTag, want.r6Tag)
		}
		if strings.TrimSpace(md.R6Justification) == "" {
			t.Errorf("%s: R6Justification must be non-empty (code-grounded prose)", name)
		}
	}
}

// TestCategory3AttackIDsMatchPlan asserts each Category-3 scenario carries EXACTLY
// the locked-plan ATT&CK for Containers technique IDs (order-independent). A
// dropped/extra technique would corrupt the MITRE coverage matrix in the report.
func TestCategory3AttackIDsMatchPlan(t *testing.T) {
	reg := allScenarios()
	for name, want := range c3Expected {
		s, ok := reg[name]
		if !ok {
			t.Errorf("scenario %q not registered", name)
			continue
		}
		got := s.Metadata().AttackTechniqueIDs
		if !sameStringSet(got, want.attackIDs) {
			t.Errorf("%s: AttackTechniqueIDs = %v, want %v", name, got, want.attackIDs)
		}
		for _, id := range got {
			if !attackIDRe.MatchString(id) {
				t.Errorf("%s: ATT&CK id %q is not well-formed", name, id)
			}
		}
	}
}

// TestCategory3MetadataComplete asserts every Category-3 scenario's metadata is
// complete: non-empty name == registry key, a documented Source anchoring it to the
// task scenario set, a valid category and R6 tag, and at least one ATT&CK id.
func TestCategory3MetadataComplete(t *testing.T) {
	reg := allScenarios()
	for name, want := range c3Expected {
		s, ok := reg[name]
		if !ok {
			t.Errorf("scenario %q not registered", name)
			continue
		}
		md := s.Metadata()
		t.Run(name, func(t *testing.T) {
			if md.Name != name {
				t.Errorf("registry key %q != Metadata().Name %q", name, md.Name)
			}
			if !validCategories[md.Category] {
				t.Errorf("Category %q is not a known category", md.Category)
			}
			if !validR6Tags[md.R6ResponseTag] {
				t.Errorf("R6ResponseTag %q is not a known R6 tag", md.R6ResponseTag)
			}
			if strings.TrimSpace(md.Source) == "" {
				t.Errorf("Source must not be empty (provenance)")
			}
			if !strings.Contains(md.Source, want.sourceHint) {
				t.Errorf("Source %q should anchor to %q", md.Source, want.sourceHint)
			}
			if len(md.AttackTechniqueIDs) == 0 {
				t.Errorf("AttackTechniqueIDs must not be empty")
			}
		})
	}
}

// TestCategory3NeedNoSpecialCapabilities asserts the Category-3 scenarios carry NO
// CapabilityRequirements, so they run UNCHANGED on the single CPU-only kind node
// (and on EKS/CoreWeave/vcluster). The crypto-mining scenario in particular is a
// CPU-bounded stand-in precisely so it does NOT require a GPU on this cluster.
func TestCategory3NeedNoSpecialCapabilities(t *testing.T) {
	reg := allScenarios()
	for name := range c3Expected {
		s, ok := reg[name]
		if !ok {
			t.Errorf("scenario %q not registered", name)
			continue
		}
		if reqs := s.Metadata().CapabilityRequirements; len(reqs) != 0 {
			t.Errorf("%s: CapabilityRequirements = %v, want none (CPU-only stand-ins run anywhere)", name, reqs)
		}
	}
}

// TestCategory3DifferentiatorCount asserts the headline Phorvex story: at least the
// six clearly-unsupported Category-3 attacks are honestly tagged R6CannotRespond
// (Phoenix's reactive pod-rotation actuator cannot touch their oracle). This is the
// number the report leans on, so it is pinned.
func TestCategory3DifferentiatorCount(t *testing.T) {
	reg := allScenarios()
	cannot := 0
	for name := range c3Expected {
		if s, ok := reg[name]; ok && s.Metadata().R6ResponseTag == core.R6CannotRespond {
			cannot++
		}
	}
	if cannot < 6 {
		t.Errorf("expected >=6 Category-3 R6CannotRespond differentiators, got %d", cannot)
	}
}

// sameStringSet reports whether a and b contain the same elements (order- and
// duplicate-independent), used to compare ATT&CK id sets.
func sameStringSet(a, b []string) bool {
	am := map[string]bool{}
	for _, x := range a {
		am[x] = true
	}
	bm := map[string]bool{}
	for _, x := range b {
		bm[x] = true
	}
	if len(am) != len(bm) {
		return false
	}
	for k := range am {
		if !bm[k] {
			return false
		}
	}
	return true
}
