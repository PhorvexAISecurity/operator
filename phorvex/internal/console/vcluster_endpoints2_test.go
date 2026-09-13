/*
 * Phorvex — the apply-fix UI read endpoints (gate-preview / pending / audit) through the real
 * router with real signed identities (M-136). The tenant is resolved from the caller's grant,
 * so the previews and queues a caller sees are its own.
 */

package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestApplyFixEndpoints_PreviewPendingAudit(t *testing.T) {
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { return nil }, nil)
	f := newAuthFixture(t, Config{},
		operatorGrant("alice", []string{"acme"}, []string{defaultTargetID}),
		operatorGrant("bob", []string{"acme"}, []string{defaultTargetID}),
	)
	f.srv.EnableVCluster(NewTenantQuota(DefaultQuota()), af)

	post := func(path, body, subject string) string {
		w := f.do(f.albReqAs(t, http.MethodPost, path, body, subject))
		if w.Code != 200 {
			t.Fatalf("%s as %s: %d %s", path, subject, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	get := func(path, subject string) string {
		w := f.do(f.albReqAs(t, http.MethodGet, path, "", subject))
		if w.Code != 200 {
			t.Fatalf("%s as %s: %d %s", path, subject, w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	// GATE-PREVIEW: a safe delta passes, a malicious one fails — WITHOUT staging anything.
	var pv struct {
		Pass   bool   `json:"pass"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal([]byte(post("/api/apply-fix/gate-preview", `{"delta":{"normSparsity":1.5}}`, "alice")), &pv)
	if !pv.Pass {
		t.Fatalf("preview(safe) must pass: %+v", pv)
	}
	_ = json.Unmarshal([]byte(post("/api/apply-fix/gate-preview", `{"delta":{"maxMovesPerTick":0}}`, "alice")), &pv)
	if pv.Pass || pv.Reason == "" {
		t.Errorf("preview(malicious) must FAIL with a reason: %+v", pv)
	}
	// nothing was staged by preview.
	if body := get("/api/apply-fix/pending", "alice"); !strings.Contains(body, `"pending":[]`) {
		t.Errorf("preview must not stage anything: %s", body)
	}

	// SUBMIT → it appears in the PENDING queue with the applierMode label.
	post("/api/apply-fix/submit", `{"id":"q1","delta":{"normSparsity":1.5},"reason":"tune"}`, "alice")
	pending := get("/api/apply-fix/pending", "alice")
	if !strings.Contains(pending, `"q1"`) || !strings.Contains(pending, `record-only`) {
		t.Errorf("pending must list q1 + the record-only applierMode: %s", pending)
	}

	// APPROVE (distinct verified subject) → AUDIT shows submitted + applied, attributed to the
	// verified identities rather than a query parameter.
	post("/api/apply-fix/approve", `{"id":"q1"}`, "bob")
	audit := get("/api/apply-fix/audit", "alice")
	if !strings.Contains(audit, "apply-fix.submitted") || !strings.Contains(audit, "apply-fix.applied") {
		t.Errorf("audit must show submitted + applied: %s", audit)
	}
	if !strings.Contains(audit, testALBIssuer+"#alice") {
		t.Errorf("the audit trail must attribute the VERIFIED submitter, not a request field: %s", audit)
	}
}

// A caller granted several tenants must name the one it acts on: the write path never guesses.
func TestApplyFixRequiresAnUnambiguousTenant(t *testing.T) {
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { return nil }, nil)
	f := newAuthFixture(t, Config{},
		operatorGrant("multi", []string{"acme", "globex"}, []string{defaultTargetID}),
		operatorGrant("wide", []string{wildcardScope}, []string{wildcardScope}),
	)
	f.srv.EnableVCluster(NewTenantQuota(DefaultQuota()), af)

	for _, subject := range []string{"multi", "wide"} {
		w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/submit", `{"id":"a","delta":{"normSparsity":1.5}}`, subject))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: got %d, want 403 (ambiguous tenant must be named, never guessed)\n%s", subject, w.Code, w.Body.String())
		}
	}
	// Naming a granted tenant works; naming one outside the grant does not.
	if w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/submit?tenant=acme", `{"id":"a","delta":{"normSparsity":1.5}}`, "multi")); w.Code != 200 {
		t.Fatalf("named granted tenant: got %d %s", w.Code, w.Body.String())
	}
	if w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/submit?tenant=evilcorp", `{"id":"b","delta":{"normSparsity":1.5}}`, "multi")); w.Code != http.StatusForbidden {
		t.Fatalf("named ungranted tenant: got %d, want 403", w.Code)
	}
}
