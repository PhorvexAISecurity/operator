/*
 * Phorvex — P-VCLUSTER Pass 2: LIVE HTTP flow for the apply-fix write-path (submit → two-key → applied),
 * exercised through the real router. Proves the endpoints are wired + the safety lifecycle holds at the
 * HTTP boundary (this is the flow the dashboard's apply-fix button drives — "verify by clicking").
 */

package console

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestApplyFixEndpoints_LiveTwoKeyFlow(t *testing.T) {
	applied := false
	var gotPol model.Policy
	af := NewApplyFixManager(safeBase, func(_, _ string, c model.Policy) error { applied = true; gotPol = c; return nil }, nil)
	s := NewServer(Config{})
	s.EnableVCluster(nil, NewTenantQuota(DefaultQuota()), af) // dev identity (no OIDC) for local click-through
	h := s.Handler()

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// 1) SUBMIT a safe, in-bounds delta as alice@acme → 200 pending (allowlist + gate pass).
	if w := post("/api/apply-fix/submit?user=alice&tenant=acme", `{"id":"r1","delta":{"normSparsity":1.5},"reason":"tune"}`); w.Code != 200 {
		t.Fatalf("submit must be 200 pending; got %d %s", w.Code, w.Body.String())
	}

	// 2) a MALICIOUS delta (MaxMovesPerTick=0) → 422 (allowlist reject), never staged.
	if w := post("/api/apply-fix/submit?user=alice&tenant=acme", `{"id":"r2","delta":{"maxMovesPerTick":0}}`); w.Code != 422 {
		t.Errorf("malicious delta must be 422 (allowlist); got %d %s", w.Code, w.Body.String())
	}

	// 3) APPROVE r1 as the SAME user → 422 two-key violation (no apply).
	if w := post("/api/apply-fix/approve?user=alice", `{"id":"r1"}`); w.Code != 422 {
		t.Errorf("same-user approve must be 422 (two-key); got %d %s", w.Code, w.Body.String())
	}
	if applied {
		t.Fatal("a same-user approval must NOT apply")
	}

	// 4) APPROVE r1 as a DISTINCT user → 200 applied (per-namespace SA + audit).
	if w := post("/api/apply-fix/approve?user=bob", `{"id":"r1"}`); w.Code != 200 {
		t.Fatalf("distinct approve must be 200 applied; got %d %s", w.Code, w.Body.String())
	}
	if !applied || gotPol.NormSparsity != 1.5 {
		t.Errorf("the gate-passed, two-key-approved delta must apply (NormSparsity=1.5); applied=%v pol=%+v", applied, gotPol)
	}
}
