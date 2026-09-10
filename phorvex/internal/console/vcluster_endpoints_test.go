/*
 * Phorvex — the apply-fix write-path (submit → two-key → applied) through the REAL router with
 * REAL signed identities (M-136).
 *
 * The previous version of this test drove the flow with `?user=alice&tenant=acme` — the
 * demo-trust fallback. That fallback is gone, so the flow is exercised the way it now works: two
 * distinct verified subjects, each granted the operator role on the acme tenant, and the tenant
 * taken from the grant rather than the URL.
 */

package console

import (
	"net/http"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestApplyFixEndpoints_LiveTwoKeyFlow(t *testing.T) {
	applied := false
	var gotPol model.Policy
	af := NewApplyFixManager(safeBase, func(_, _ string, c model.Policy) error { applied = true; gotPol = c; return nil }, nil)
	f := newAuthFixture(t, Config{},
		operatorGrant("alice", []string{"acme"}, []string{defaultTargetID}),
		operatorGrant("bob", []string{"acme"}, []string{defaultTargetID}),
	)
	f.srv.EnableVCluster(NewTenantQuota(DefaultQuota()), af)

	submit := func(body, subject string) int {
		w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/submit", body, subject))
		t.Logf("submit(%s) -> %d %s", subject, w.Code, strings.TrimSpace(w.Body.String()))
		return w.Code
	}
	approve := func(body, subject string) int {
		w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/approve", body, subject))
		t.Logf("approve(%s) -> %d %s", subject, w.Code, strings.TrimSpace(w.Body.String()))
		return w.Code
	}

	// 1) SUBMIT a safe, in-bounds delta as alice → 200 pending. The tenant comes from alice's
	//    grant; there is no ?tenant= to assert.
	if code := submit(`{"id":"r1","delta":{"normSparsity":1.5},"reason":"tune"}`, "alice"); code != 200 {
		t.Fatalf("submit must be 200 pending; got %d", code)
	}

	// 2) a MALICIOUS delta (MaxMovesPerTick=0) → 422 (allowlist reject), never staged.
	if code := submit(`{"id":"r2","delta":{"maxMovesPerTick":0}}`, "alice"); code != 422 {
		t.Errorf("malicious delta must be 422 (allowlist); got %d", code)
	}

	// 3) APPROVE r1 as the SAME verified subject → 422 two-key violation (no apply).
	if code := approve(`{"id":"r1"}`, "alice"); code != 422 {
		t.Errorf("same-subject approve must be 422 (two-key); got %d", code)
	}
	if applied {
		t.Fatal("a same-subject approval must NOT apply")
	}

	// 4) APPROVE r1 as a DISTINCT verified subject → 200 applied.
	if code := approve(`{"id":"r1"}`, "bob"); code != 200 {
		t.Fatalf("distinct approve must be 200 applied; got %d", code)
	}
	if !applied || gotPol.NormSparsity != 1.5 {
		t.Errorf("the gate-passed, two-key-approved delta must apply (NormSparsity=1.5); applied=%v pol=%+v", applied, gotPol)
	}
}

// The write path is closed to an unauthenticated caller and to an authenticated read-only one.
func TestApplyFixEndpoints_ClosedWithoutOperatorGrant(t *testing.T) {
	staged := 0
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { staged++; return nil }, nil)
	f := newAuthFixture(t, Config{},
		investorGrant("inv", []string{"acme"}, []string{defaultTargetID}),
	)
	f.srv.EnableVCluster(NewTenantQuota(DefaultQuota()), af)

	// no credential at all
	req := f.albReq(t, http.MethodPost, "/api/apply-fix/submit", `{"id":"x","delta":{"normSparsity":1.5}}`)
	req.Header.Del(ALBDataHeader)
	if w := f.do(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated submit: got %d, want 401", w.Code)
	}
	// investor: authenticated, read-only
	if w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/submit", `{"id":"x","delta":{"normSparsity":1.5}}`, "inv")); w.Code != http.StatusForbidden {
		t.Fatalf("investor submit: got %d, want 403 (investor is read-only)", w.Code)
	}
	if staged != 0 {
		t.Fatalf("a rejected request reached the applier %d time(s); it must reach it zero times", staged)
	}
}
