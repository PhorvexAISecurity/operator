/*
 * Phorvex — P-VCLUSTER Pass 2: the UI read endpoints (gate-preview / pending / audit) through the real
 * router. Proves the dashboard's "will it pass the gate?" preview, the two-key queue, and the audit trail
 * are wired to the proven backend.
 */

package console

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestApplyFixEndpoints_PreviewPendingAudit(t *testing.T) {
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { return nil }, nil)
	s := NewServer(Config{})
	s.EnableVCluster(nil, NewTenantQuota(DefaultQuota()), af)
	h := s.Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	getq := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// GATE-PREVIEW: a safe delta passes, a malicious one fails — WITHOUT staging anything.
	var pv struct{ Pass bool `json:"pass"`; Reason string `json:"reason"` }
	w := post("/api/apply-fix/gate-preview?user=alice&tenant=acme", `{"delta":{"normSparsity":1.5}}`)
	_ = json.Unmarshal(w.Body.Bytes(), &pv)
	if w.Code != 200 || !pv.Pass {
		t.Fatalf("preview(safe) must pass: %d %s", w.Code, w.Body.String())
	}
	w = post("/api/apply-fix/gate-preview?user=alice&tenant=acme", `{"delta":{"maxMovesPerTick":0}}`)
	_ = json.Unmarshal(w.Body.Bytes(), &pv)
	if w.Code != 200 || pv.Pass || pv.Reason == "" {
		t.Errorf("preview(malicious) must FAIL with a reason: %d %s", w.Code, w.Body.String())
	}
	// nothing was staged by preview.
	if w := getq("/api/apply-fix/pending?user=alice&tenant=acme"); !strings.Contains(w.Body.String(), `"pending":[]`) {
		t.Errorf("preview must not stage anything: %s", w.Body.String())
	}

	// SUBMIT → it appears in the PENDING queue with the applierMode label.
	if w := post("/api/apply-fix/submit?user=alice&tenant=acme", `{"id":"q1","delta":{"normSparsity":1.5},"reason":"tune"}`); w.Code != 200 {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	pw := getq("/api/apply-fix/pending?user=alice&tenant=acme")
	if !strings.Contains(pw.Body.String(), `"q1"`) || !strings.Contains(pw.Body.String(), `record-only`) {
		t.Errorf("pending must list q1 + the record-only applierMode: %s", pw.Body.String())
	}

	// APPROVE (distinct) → AUDIT shows submitted + applied.
	if w := post("/api/apply-fix/approve?user=bob", `{"id":"q1"}`); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	aw := getq("/api/apply-fix/audit?user=alice&tenant=acme")
	if !strings.Contains(aw.Body.String(), "apply-fix.submitted") || !strings.Contains(aw.Body.String(), "apply-fix.applied") {
		t.Errorf("audit must show submitted + applied: %s", aw.Body.String())
	}
}
