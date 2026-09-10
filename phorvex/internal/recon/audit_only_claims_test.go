package recon

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// audit_only_claims_test.go — PHVX-76.
//
// Three statements shipped in this package were false: two said the AI recon facts are
// "AUDIT-ONLY … not in CoverByAction" while the same files grant them cover, and one asserted the
// greedy keeps a 1-1/e guarantee on an objective that is not monotone under a constraint that is
// not a cardinality constraint.
//
// Correcting the words is the easy half. A comment cannot be compiled, so it can drift again the
// moment cover is granted or withdrawn — which is exactly how these three got stale. These tests
// bind the claims to the behaviour: if the code and the comment disagree, CI says so.

// factsWithCover returns every fact kind that appears in some action's cover set, for a workload
// shaped to exercise the AI path.
func factsWithCover(t *testing.T) map[string]bool {
	t.Helper()
	fctx := FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1, LateralUrgency: 1, HasGPU: true}
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m", SuspectAdapter: "evil",
		MIGDevice: "MIG-audit-fixture",
	}}
	af := ucwRecon{}.AssetFacts(view, fctx)

	covered := map[string]bool{}
	for _, keys := range af.CoverByAction {
		for _, k := range keys {
			// key shape is "<scope>|<asset>|<kind>|..." — take the kind.
			if parts := strings.Split(k, "|"); len(parts) >= 3 {
				covered[parts[2]] = true
			}
		}
	}
	return covered
}

// TestNoFactIsDocumentedAuditOnlyWhileCarryingCover is the guard. Any fact kind whose doc comment
// claims AUDIT-ONLY must genuinely carry no cover.
func TestNoFactIsDocumentedAuditOnlyWhileCarryingCover(t *testing.T) {
	src, err := os.ReadFile("facts.go")
	if err != nil {
		t.Fatal(err)
	}
	covered := factsWithCover(t)

	// Match:  // FactX = ... AUDIT-ONLY ...   \n   FactX = "kind"
	decl := regexp.MustCompile(`(?s)//\s*(Fact\w+)\s*=(.{0,400}?)\n\s*Fact\w+\s*=\s*"([^"]+)"`)
	for _, m := range decl.FindAllStringSubmatch(string(src), -1) {
		doc, kind := m[2], m[3]
		if !strings.Contains(strings.ToUpper(doc), "AUDIT-ONLY") {
			continue
		}
		// "was audit-only" / "NOT audit-only" are corrections, not claims.
		low := strings.ToLower(doc)
		if strings.Contains(low, "not audit-only") || strings.Contains(low, "no longer audit-only") ||
			strings.Contains(low, "were audit-only") {
			continue
		}
		if covered[kind] {
			t.Errorf("fact %q is documented AUDIT-ONLY but IS granted cover by ucw.go — the comment "+
				"lies to whoever reasons about selectable cover (this is exactly PHVX-76)", kind)
		}
	}
}

// TestAIFactCoverClaimsMatchCapabilities pins both directions after PHVX-26a narrowed the GPU
// model. MIG contention carries conditional cover. Endpoint paths, modelFingerprint
// and GPU co-location stay audit-only pending their respective effect evidence.
func TestAIFactCoverClaimsMatchCapabilities(t *testing.T) {
	covered := factsWithCover(t)
	for _, kind := range []string{FactGPUContentionChannel} {
		if !covered[kind] {
			t.Errorf("fact %q should carry cover for this capable fixture; update the code and its "+
				"claim together", kind)
		}
	}
	if covered[FactEndpointPath] {
		t.Error("endpointPath must stay cover-free without locator invalidation proof")
	}
	if covered[FactGPUColocation] {
		t.Errorf("fact %q must stay cover-free until an actuator guarantees relocation", FactGPUColocation)
	}
	if covered[FactModelFingerprint] {
		t.Errorf("fact %q must stay cover-free without loaded-identity/effect evidence", FactModelFingerprint)
	}
}

// TestNoSourceClaimsTheOneMinusOneOverEBound guards the optimality assertion. The objective is
// Σw(cover) − λ·C(S): submodular but NOT monotone, under a truncated partition matroid rather than
// a cardinality constraint. The monotone/cardinality 1−1/e guarantee therefore does not apply, and
// asserting it in shipped source is a claim a customer or reviewer can check and disprove.
func TestNoSourceClaimsTheOneMinusOneOverEBound(t *testing.T) {
	// Scan every shipped module-level document, not a hand-maintained sample. The earlier
	// explicit list let stale claims survive in P-VCLUSTER and older physics documents.
	files := []string{
		"ucw.go",
		"profile.go",
		"facts.go",
		"../../../dashboard-web/components/subsystems/panels.tsx",
		"../../../dashboard-web/components/steps/bench.tsx",
	}
	docs, err := filepath.Glob("../../*.md")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, docs...)
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			l := strings.ToLower(line)
			if !strings.Contains(l, "1-1/e") && !strings.Contains(l, "1−1/e") {
				continue
			}
			// A DISCLAIMER is fine; an ASSERTION is not. The disclaiming words often land on the
			// neighbouring line because the sentence wraps, so judge a small window, not one line.
			lo, hi := i-2, i+3
			if lo < 0 {
				lo = 0
			}
			if hi > len(lines) {
				hi = len(lines)
			}
			ctx := strings.ToLower(strings.Join(lines[lo:hi], " "))
			disclaimed := false
			for _, neg := range []string{"does not apply", "do not apply", "not monotone",
				"guarantee does not", "was asserted falsely", "not a cardinality",
				"no generic", "not a generic"} {
				if strings.Contains(ctx, neg) {
					disclaimed = true
					break
				}
			}
			if disclaimed {
				continue
			}
			t.Errorf("%s:%d asserts a 1-1/e bound: %q\n  the objective is non-monotone (−λ·C) under a "+
				"partition matroid; no replacement approximation constant should be claimed without a "+
				"proof tied to the implemented selection rule", f, i+1, strings.TrimSpace(line))
		}
	}
}

// TestNoShippedDocumentUsesTheRetiredSideChannelClaim catches the other PHVX-76
// failure class. FactSideChannel was renamed and split: GPU contention has conditional
// MIG cover, while GPU co-location remains audit-only. Keeping the old umbrella name in
// a document recreates the false claim that either both are covered or neither is.
func TestNoShippedDocumentUsesTheRetiredSideChannelClaim(t *testing.T) {
	docs, err := filepath.Glob("../../*.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range docs {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "Fact"+"SideChannel") {
			t.Errorf("%s still uses the retired umbrella fact; name GPUContentionChannel or GPUColocation explicitly", f)
		}
	}
}
