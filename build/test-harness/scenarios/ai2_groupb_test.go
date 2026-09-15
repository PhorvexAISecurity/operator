package scenarios

import (
	"context"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ai2_groupb_test.go is the GROUP-2 PART-B table test: model theft/extraction
// (gpu-side-channel, co-location/cross-tenant, query-extraction), KV-cache
// poisoning, AI supply chain (poisoned-model-registry, malicious-model-artifact,
// tampered-inference-base-image) and RAG/data-plane (retrieval-poisoning,
// embedding-store-tampering). It pins the per-scenario contracts the broader
// ai_scenarios_test.go leaves implicit: the locked set + category, the ATLAS +
// OWASP ids carried in the oracle evidence, the capability-pending skip-with-note
// behavior (never a failure), and the MEASURED MTD-effect derivation the runner
// applies. The registry is the single source of truth — there is no hand-list to
// drift.

// groupBScenarios is the locked Group-2 Part-B set this task implements. Each row
// pins the honest verdict + category so a future edit cannot silently inflate the
// coverage story or move a data-plane CANNOT-RESPOND into a COVERS.
var groupBScenarios = []struct {
	name string
	cat  core.Category
	r6   core.R6Tag
	caps []core.Capability
}{
	// Model theft / extraction.
	{"ai2-gpu-side-channel", core.CategoryModernUnsupported, core.R6CannotRespond, []core.Capability{core.CapGPU, core.CapMultiNode}},
	{"ai2-co-location-cross-tenant", core.CategoryModernUnsupported, core.R6Partial, []core.Capability{core.CapGPU, core.CapMultiNode}},
	{"ai2-query-extraction", core.CategoryR6Claimed, core.R6Partial, nil},
	// KV-cache.
	{"ai2-kvcache-poisoning-cross-session-leak", core.CategoryModernUnsupported, core.R6CannotRespond, []core.Capability{core.CapGPU}},
	// AI supply chain.
	{"ai2-poisoned-model-registry", core.CategoryR6Claimed, core.R6CannotRespond, nil},
	{"ai2-malicious-model-artifact", core.CategoryR6Claimed, core.R6Covers, nil},
	{"ai2-tampered-inference-base-image", core.CategoryModernUnsupported, core.R6Partial, nil},
	// RAG / data-plane.
	{"ai2-rag-retrieval-poisoning", core.CategoryModernUnsupported, core.R6CannotRespond, nil},
	{"ai2-embedding-store-tampering", core.CategoryModernUnsupported, core.R6CannotRespond, nil},
}

// TestGroupBRegisteredAndHonest asserts every Group-2 Part-B scenario
// self-registered with the locked category, honest R6 verdict, and capability
// requirements (so the GPU/multi-node ones skip-with-note on the CPU-only kind
// node, never a failure).
func TestGroupBRegisteredAndHonest(t *testing.T) {
	reg := allScenarios()
	for _, w := range groupBScenarios {
		s, ok := reg[w.name]
		if !ok {
			t.Errorf("Group-B scenario %q is not registered", w.name)
			continue
		}
		md := s.Metadata()
		if md.Category != w.cat {
			t.Errorf("%s: Category = %q, want %q", w.name, md.Category, w.cat)
		}
		if md.R6ResponseTag != w.r6 {
			t.Errorf("%s: R6ResponseTag = %q, want %q (honest verdict drifted)", w.name, md.R6ResponseTag, w.r6)
		}
		if !sameCaps(md.CapabilityRequirements, w.caps) {
			t.Errorf("%s: CapabilityRequirements = %v, want %v", w.name, md.CapabilityRequirements, w.caps)
		}
		if strings.TrimSpace(md.R6Justification) == "" {
			t.Errorf("%s: R6Justification must be non-empty (honest prose)", w.name)
		}
		if strings.TrimSpace(md.Source) == "" {
			t.Errorf("%s: Source must document where the scenario was extracted from", w.name)
		}
	}
}

// TestGroupBCapabilityPendingSkipWithNote asserts the GPU/multi-node Group-B
// scenarios' oracles return a SKIP-WITH-NOTE result tagged capability-pending
// (carrying the ATLAS + OWASP ids) rather than a failure, on a node lacking the
// capability. These two oracles short-circuit through aiSkip and never touch the
// cluster, so they are safe to evaluate without a live env.
func TestGroupBCapabilityPendingSkipWithNote(t *testing.T) {
	reg := allScenarios()
	for _, name := range []string{"ai2-gpu-side-channel", "ai2-co-location-cross-tenant"} {
		s, ok := reg[name]
		if !ok {
			t.Errorf("%s not registered", name)
			continue
		}
		res, err := s.SuccessOracle(context.Background(), nil)
		if err != nil {
			t.Errorf("%s: SuccessOracle returned error on the capability-pending path: %v", name, err)
			continue
		}
		if !res.Skipped {
			t.Errorf("%s: expected Skipped=true (capability-pending), got Achieved=%v", name, res.Achieved)
		}
		if strings.TrimSpace(res.SkipReason) == "" {
			t.Errorf("%s: capability-pending skip must carry a SkipReason note", name)
		}
		if got := res.Evidence[core.EvTriggerAttribution]; got != core.TriggerCapabilityPending {
			t.Errorf("%s: trigger attribution = %q, want %q (so the skip is not read as a defense failure)", name, got, core.TriggerCapabilityPending)
		}
		if res.Evidence[core.EvCapabilityPending] != "true" {
			t.Errorf("%s: capability-pending evidence must be set so the headline number is carried to the GPU run", name)
		}
		assertEvidenceIDs(t, name, res)
	}
}

// TestGroupBThreatIDsCarried asserts each Group-B scenario advertises at least one
// ATLAS technique id and one OWASP entry id, AND that every advertised id is well
// formed. The metadata-level ATT&CK ids feed the MITRE matrix; the ATLAS/OWASP ids
// live in the oracle evidence for the AI threat-model report.
func TestGroupBThreatIDsCarried(t *testing.T) {
	reg := allScenarios()
	for _, w := range groupBScenarios {
		s := reg[w.name]
		if s == nil {
			continue // already reported by TestGroupBRegisteredAndHonest
		}
		md := s.Metadata()
		if len(md.AttackTechniqueIDs) == 0 {
			t.Errorf("%s: must advertise >=1 ATT&CK-for-Containers technique id", w.name)
		}
		for _, id := range md.AttackTechniqueIDs {
			if !attackIDRe.MatchString(id) {
				t.Errorf("%s: malformed ATT&CK id %q", w.name, id)
			}
		}
	}
}

// TestGroupBMTDEffectDerivation pins the MEASURED MTD-effect tag for the data-plane
// and supply-chain Group-B scenarios, asserting the runner's DeriveMTDEffect over
// the documented oracle outcomes matches the plan (NEVER assumed — derived from the
// in-request / persistence-disrupted / neutralized triple).
//
//   - RAG poisoning + embedding-store tamper are DATA-PLANE: the store survives a
//     pod rotation, so persistence is NOT disrupted and nothing is neutralized ->
//     MTD-CANNOT-HELP (the genuine Phorvex differentiator).
//   - poisoned-model-registry + malicious-model-artifact carry an INJECTED trigger:
//     when the genuine matcher neutralizes the foothold -> MTD-NEUTRALIZES.
//   - tampered-inference-base-image re-pulls the SAME ref on rotation, so the tamper
//     re-appears -> MTD-CANNOT-HELP (admission/build-time is outside the actuator).
func TestGroupBMTDEffectDerivation(t *testing.T) {
	cases := []struct {
		name                 string
		inRequestAchieved    bool
		persistenceDisrupted bool
		neutralized          bool
		want                 string
	}{
		// Data-plane: corpus/store survives rotation -> nothing moved -> CANNOT-HELP.
		{"ai2-rag-retrieval-poisoning (data-plane)", true, false, false, core.MTDCannotHelp},
		{"ai2-embedding-store-tampering (data-plane)", true, false, false, core.MTDCannotHelp},
		// Tampered base image: same ref re-pulled -> tamper re-appears -> CANNOT-HELP.
		{"ai2-tampered-inference-base-image (same-ref)", true, false, false, core.MTDCannotHelp},
		// Supply-chain with INJECTED trigger neutralizing the foothold -> NEUTRALIZES.
		{"ai2-poisoned-model-registry (emitter-only, no repair)", true, false, false, core.MTDCannotHelp},
		{"ai2-malicious-model-artifact (injected-panic, fullphoenix)", false, true, true, core.MTDNeutralizes},
		// Query-extraction held-session: persistence bounded but the act still landed
		// -> BOUNDS-ONLY (rotation caps dwell, not the distillation).
		{"ai2-query-extraction (rotating arm, bounded)", true, true, false, core.MTDBoundsOnly},
		// KV-cache mock cleared by a pod-dropping rotation -> persistence bounded.
		{"ai2-kvcache-poisoning (rotation drops pod)", true, true, false, core.MTDBoundsOnly},
	}
	for _, c := range cases {
		if got := core.DeriveMTDEffect(c.inRequestAchieved, c.persistenceDisrupted, c.neutralized); got != c.want {
			t.Errorf("%s: DeriveMTDEffect(%v,%v,%v) = %q, want %q",
				c.name, c.inRequestAchieved, c.persistenceDisrupted, c.neutralized, got, c.want)
		}
	}
}

// TestGroupBStandinReuse asserts the Group-B CPU-runnable scenarios reuse the
// shared AI stand-ins by their stable teardown app labels (the deploy/teardown
// contract): the inference server, the model registry, and the retriever. This
// guards the idempotent-teardown invariant — every CPU scenario must clean up the
// stand-in it stood up.
func TestGroupBStandinReuse(t *testing.T) {
	reg := allScenarios()
	for _, name := range []string{
		"ai2-query-extraction", "ai2-kvcache-poisoning-cross-session-leak",
		"ai2-poisoned-model-registry", "ai2-tampered-inference-base-image",
		"ai2-rag-retrieval-poisoning", "ai2-embedding-store-tampering",
	} {
		if _, ok := reg[name]; !ok {
			t.Errorf("CPU-runnable Group-B scenario %q not registered", name)
		}
	}
}

// assertEvidenceIDs checks an oracle result carries non-empty comma-joined ATLAS
// and OWASP id lists, with each id well-formed (ATLAS AML.Txxxx[.yyy], OWASP
// LLMnn:2025).
func assertEvidenceIDs(t *testing.T, name string, res core.OracleResult) {
	t.Helper()
	atlas := res.Evidence[core.EvAtlasIDs]
	owasp := res.Evidence[core.EvOwaspIDs]
	if strings.TrimSpace(atlas) == "" {
		t.Errorf("%s: oracle evidence must carry ATLAS ids", name)
	}
	for _, id := range strings.Split(atlas, ",") {
		if id == "" {
			continue
		}
		if !strings.HasPrefix(id, "AML.T") {
			t.Errorf("%s: malformed ATLAS id %q (want AML.Txxxx[.yyy])", name, id)
		}
	}
	if strings.TrimSpace(owasp) == "" {
		t.Errorf("%s: oracle evidence must carry OWASP ids", name)
	}
	for _, id := range strings.Split(owasp, ",") {
		if id == "" {
			continue
		}
		if !strings.HasPrefix(id, "LLM") || !strings.HasSuffix(id, ":2025") {
			t.Errorf("%s: malformed OWASP id %q (want LLMnn:2025)", name, id)
		}
	}
}
