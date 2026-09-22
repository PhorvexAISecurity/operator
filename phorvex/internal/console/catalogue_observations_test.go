package console

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCatalogueCurrentAndLegacyHarness(t *testing.T) {
	for _, row := range []string{
		"  - ai1-inference-manipulation [R6Claimed] R6=R6Partial realism=unassessed benign=false declared=[T1557 T1565.002] exercised=[] caps=[GPU] limits=\"no claim\"",
		"  - ai1-inference-manipulation [R6Claimed] R6=R6Partial techniques=[T1557 T1565.002] caps=[GPU]",
	} {
		got := parseCatalog([]byte("Registered scenarios:\n"+row+"\nRegistered defenders:\n - none baseline=true rate=0s\n"), map[string]bool{"ai1-inference-manipulation": true})
		if len(got) != 1 || got[0].Name != "ai1-inference-manipulation" || len(got[0].Techniques) != 2 || got[0].Techniques[1] != "T1565.002" || len(got[0].Caps) != 1 || !got[0].HasRun {
			t.Fatalf("catalogue=%+v", got)
		}
	}
	if got := parseCatalog([]byte(" - new [R6Claimed] R6=R6Partial unexpected-format\n"), nil); got != nil {
		t.Fatalf("unknown format exposed incomplete catalogue: %+v", got)
	}
}

func TestLiveObservationsAreOptInTenantBoundAndPaged(t *testing.T) {
	attackMu.Lock()
	saved := attackList
	attackList = []*attackRecord{
		{ID: "real", Namespace: "acme"},
		{ID: "effect", Namespace: "acme", EvidenceKind: "vllm-in-place-effect", OutcomeClass: "behavioral-oracle-unsupported"},
		{ID: "response", Namespace: "acme", EvidenceKind: "vllm-unsupported-stimulus"},
		{ID: "experiment", Namespace: "acme", EvidenceKind: "synthetic-detector-signal"},
		{ID: "unknown", Namespace: "acme", EvidenceKind: "unknown"},
		{ID: "secret", Namespace: "secret", EvidenceKind: "vllm-in-place-effect"},
	}
	attackMu.Unlock()
	t.Cleanup(func() { attackMu.Lock(); attackList = saved; attackMu.Unlock() })
	p := testOperatorPrincipal("acme")
	if got := realAttackSnapshots(p); len(got) != 1 || got[0].ID != "real" {
		t.Fatalf("default report changed: %+v", got)
	}
	got := realAttackSnapshots(p, true)
	if len(got) != 3 || got[0].ID != "response" || got[1].Outcome != "" {
		t.Fatalf("observations leaked/overclaimed: %+v", got)
	}
	req := httptest.NewRequest("GET", "/api/attack-results?limit=1", nil)
	pg, err := collectionPagingFromRequest(req, "/api/attack-results", p, map[string]string{"includeObservations": "true"})
	if err != nil {
		t.Fatal(err)
	}
	rows, page, err := pagedRealAttackSnapshots("/api/attack-results", p, pg, "", "effect", true)
	if err != nil || len(rows) != 1 || rows[0].ID != "effect" || page.Total != 1 {
		t.Fatalf("exact observation missing: rows=%+v page=%+v err=%v", rows, page, err)
	}
	req = httptest.NewRequest("GET", "/api/attack-results?limit=1", nil)
	pg, _ = collectionPagingFromRequest(req, "/api/attack-results", p, map[string]string{"includeObservations": "true"})
	_, page, err = pagedRealAttackSnapshots("/api/attack-results", p, pg, "", "", true)
	if err != nil || page.NextCursor == "" {
		t.Fatalf("cursor: %+v %v", page, err)
	}
	req = httptest.NewRequest("GET", "/api/attack-results?limit=1&cursor="+page.NextCursor, nil)
	if _, err = collectionPagingFromRequest(req, "/api/attack-results", p, nil); err == nil {
		t.Fatal("observation cursor crossed into default report")
	}
}

func TestCompletionRefusalDoesNotInventGuardrailEvidence(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"error":{"type":"guardrail_blocked"}}`, "blocked by the guardrail"},
		{`{"error":{"type":"forbidden"}}`, "returned HTTP 403"},
	} {
		exec := func(string) (string, error) {
			return fmt.Sprintf("__PHORVEX_HTTP_BEGIN__\n%s\n__PHORVEX_HTTP_STATUS__403\n", tc.body), nil
		}
		err := runVLLMCompletion(exec, false, map[string]any{"prompt": "bounded"})
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "not started") {
			t.Fatalf("refusal=%v", err)
		}
	}
}
