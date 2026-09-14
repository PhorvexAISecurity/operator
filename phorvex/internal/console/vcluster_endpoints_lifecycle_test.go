/*
 * Phorvex — M-166: the apply-fix approval contract through the REAL router with REAL signed
 * identities: generation-bound approval, tenant scope on approve, one apply per generation under
 * concurrency, honest non-applied outcomes, and the exact JSON the dashboard consumes.
 */

package console

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// approveResponse is the wire contract of POST /api/apply-fix/approve as the dashboard reads it.
type approveResponse struct {
	Status     string `json:"status"`
	ID         string `json:"id"`
	Tenant     string `json:"tenant"`
	Generation string `json:"generation"`
	State      string `json:"state"`
	Approver   string `json:"approver"`
	Retry      bool   `json:"retry"`
	Error      string `json:"error"`
}

func approveAs(t *testing.T, f *authFixture, subject, query, body string) (int, approveResponse, string) {
	t.Helper()
	w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/approve"+query, body, subject))
	var out approveResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	t.Logf("approve(%s%s %s) -> %d %s", subject, query, body, w.Code, strings.TrimSpace(w.Body.String()))
	return w.Code, out, w.Body.String()
}

func submitAs(t *testing.T, f *authFixture, subject, query, body string) (int, map[string]any) {
	t.Helper()
	w := f.do(f.albReqAs(t, http.MethodPost, "/api/apply-fix/submit"+query, body, subject))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	t.Logf("submit(%s%s %s) -> %d %s", subject, query, body, w.Code, strings.TrimSpace(w.Body.String()))
	return w.Code, out
}

func auditEvents(t *testing.T, f *authFixture, subject string) map[string]int {
	t.Helper()
	w := f.do(f.albReqAs(t, http.MethodGet, "/api/apply-fix/audit", "", subject))
	var doc struct {
		Audit []AuditEntry `json:"audit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range doc.Audit {
		counts[e.Event]++
	}
	return counts
}

func acmeFixture(t *testing.T, af *ApplyFixManager, extra ...SubjectGrant) *authFixture {
	t.Helper()
	grants := append([]SubjectGrant{
		operatorGrant("alice", []string{"acme"}, []string{defaultTargetID}),
		operatorGrant("bob", []string{"acme"}, []string{defaultTargetID}),
	}, extra...)
	f := newAuthFixture(t, Config{}, grants...)
	f.srv.EnableVCluster(NewTenantQuota(DefaultQuota()), af)
	return f
}

// An approval must name the exact generation: missing => 400, wrong => 409 stale-generation, right =>
// 200 applied with the full outcome; an identical retry is 200 applied with retry=true and no second
// callback; a different approver afterwards is 409 conflict.
func TestApplyFixEndpoints_ApprovalBoundToGeneration(t *testing.T) {
	var calls int32
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }, nil)
	f := acmeFixture(t, af, operatorGrant("carol", []string{"acme"}, []string{defaultTargetID}))

	code, sub := submitAs(t, f, "alice", "", `{"id":"r1","delta":{"normSparsity":1.5},"reason":"tune"}`)
	if code != 200 || sub["status"] != "pending-approval" || sub["generation"] == "" || sub["tenant"] != "acme" || sub["existing"] != false {
		t.Fatalf("submit contract: %d %v", code, sub)
	}
	gen := pendingGeneration(t, f, "bob", "r1")
	if gen != sub["generation"] {
		t.Fatalf("pending generation %q must equal the submit response %v", gen, sub["generation"])
	}
	if code, _, _ := approveAs(t, f, "bob", "", `{"id":"r1"}`); code != 400 {
		t.Errorf("approval without generation: want 400, got %d", code)
	}
	if code, out, _ := approveAs(t, f, "bob", "", `{"id":"r1","generation":"`+gen+`x"}`); code != 409 || out.Status != "stale-generation" {
		t.Errorf("wrong generation: want 409 stale-generation, got %d %+v", code, out)
	}
	if code, out, _ := approveAs(t, f, "bob", "", `{"id":"missing","generation":"`+gen+`"}`); code != 404 || out.Status != "not-found" {
		t.Errorf("unknown id: want 404 not-found, got %d %+v", code, out)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("refused approvals reached the applier %d time(s)", calls)
	}
	code, out, _ := approveAs(t, f, "bob", "", `{"id":"r1","generation":"`+gen+`"}`)
	if code != 200 || out.Status != "applied" || out.State != "applied" || out.Retry || out.Generation != gen || out.Tenant != "acme" || out.Approver != testALBIssuer+"#bob" || out.Error != "" {
		t.Fatalf("applied contract: %d %+v", code, out)
	}
	code, out, _ = approveAs(t, f, "bob", "", `{"id":"r1","generation":"`+gen+`"}`)
	if code != 200 || out.Status != "applied" || !out.Retry {
		t.Errorf("identical retry: want 200 applied retry=true, got %d %+v", code, out)
	}
	code, out, _ = approveAs(t, f, "carol", "", `{"id":"r1","generation":"`+gen+`"}`)
	if code != 409 || out.Status != "conflict" || out.State != "applied" || out.Approver != testALBIssuer+"#bob" {
		t.Errorf("other approver after apply: want 409 conflict naming the applier, got %d %+v", code, out)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("applier calls=%d; want 1", calls)
	}
	if ev := auditEvents(t, f, "alice"); ev["apply-fix.applied"] != 1 {
		t.Errorf("audit applied=%d; want 1", ev["apply-fix.applied"])
	}
}

// The approve tenant is resolved through the grant like a submit: a multi/wildcard grant must name
// it, a body or query tenant outside the grant is 403, and a granted-elsewhere principal cannot reach
// another tenant's record through the shared id or its generation.
func TestApplyFixEndpoints_ApproveTenantScope(t *testing.T) {
	var mu sync.Mutex
	var appliedTenants []string
	af := NewApplyFixManager(safeBase, func(tenant, _ string, _ model.Policy) error {
		mu.Lock()
		appliedTenants = append(appliedTenants, tenant)
		mu.Unlock()
		return nil
	}, nil)
	f := acmeFixture(t, af,
		operatorGrant("dave", []string{"globex"}, []string{defaultTargetID}),
		operatorGrant("eve", []string{"globex"}, []string{defaultTargetID}),
		operatorGrant("multi", []string{"acme", "globex"}, []string{defaultTargetID}),
		operatorGrant("wide", []string{wildcardScope}, []string{wildcardScope}),
	)
	submitAs(t, f, "alice", "", `{"id":"shared","delta":{"normSparsity":1.5}}`)
	submitAs(t, f, "dave", "", `{"id":"shared","delta":{"normSparsity":2.5}}`)
	acmeGen, globexGen := pendingGeneration(t, f, "bob", "shared"), pendingGeneration(t, f, "eve", "shared")
	if acmeGen == globexGen {
		t.Fatal("two tenants' records must carry distinct generations")
	}

	// bob (acme only) with globex's generation: the id exists in acme, the generation does not match.
	if code, out, _ := approveAs(t, f, "bob", "", `{"id":"shared","generation":"`+globexGen+`"}`); code != 409 || out.Status != "stale-generation" {
		t.Errorf("acme-only approver with globex's generation: want 409 stale-generation, got %d %+v", code, out)
	}
	// A forged body tenant cannot widen bob's scope.
	if code, _, _ := approveAs(t, f, "bob", "", `{"id":"shared","tenant":"globex","generation":"`+globexGen+`"}`); code != 403 {
		t.Errorf("body tenant outside the grant: want 403, got %d", code)
	}
	if code, _, _ := approveAs(t, f, "bob", "?tenant=globex", `{"id":"shared","generation":"`+globexGen+`"}`); code != 403 {
		t.Errorf("query tenant outside the grant: want 403, got %d", code)
	}
	// Multi-tenant and wildcard grants must NAME the tenant; the id/generation never infers it.
	for _, subject := range []string{"multi", "wide"} {
		if code, _, _ := approveAs(t, f, subject, "", `{"id":"shared","generation":"`+globexGen+`"}`); code != 403 {
			t.Errorf("%s without ?tenant=: want 403, got %d", subject, code)
		}
	}
	mu.Lock()
	if len(appliedTenants) != 0 {
		t.Fatalf("scope refusals reached the applier: %v", appliedTenants)
	}
	mu.Unlock()
	// Naming the tenant works for the multi grant — on THAT tenant's record and generation only.
	if code, out, _ := approveAs(t, f, "multi", "?tenant=globex", `{"id":"shared","generation":"`+acmeGen+`"}`); code != 409 || out.Status != "stale-generation" {
		t.Errorf("multi on globex with acme's generation: want 409 stale-generation, got %d %+v", code, out)
	}
	if code, out, _ := approveAs(t, f, "multi", "?tenant=globex", `{"id":"shared","generation":"`+globexGen+`"}`); code != 200 || out.Status != "applied" || out.Tenant != "globex" {
		t.Errorf("multi on globex with globex's generation: want 200 applied, got %d %+v", code, out)
	}
	if code, out, _ := approveAs(t, f, "bob", "", `{"id":"shared","generation":"`+acmeGen+`"}`); code != 200 || out.Tenant != "acme" {
		t.Errorf("acme's record is untouched and applies for its own approver: %d %+v", code, out)
	}
	mu.Lock()
	got := append([]string(nil), appliedTenants...)
	mu.Unlock()
	sort.Strings(got)
	if strings.Join(got, ",") != "acme,globex" {
		t.Errorf("applied tenants %v; want exactly acme and globex once each", got)
	}
}

// Two distinct valid approvers race through HTTP: one 200 applied, one 409 in-progress that returns
// while the first is still inside the callback, one callback, one applied audit record.
func TestApplyFixEndpoints_ConcurrentApproversApplyOnce(t *testing.T) {
	ap := newBarrierApplier(2)
	af := NewApplyFixManager(safeBase, ap.apply, nil)
	f := acmeFixture(t, af, operatorGrant("carol", []string{"acme"}, []string{defaultTargetID}))
	submitAs(t, f, "alice", "", `{"id":"r1","delta":{"normSparsity":1.5}}`)
	gen := pendingGeneration(t, f, "bob", "r1")

	type reply struct {
		code int
		out  approveResponse
	}
	replies := make(chan reply, 2)
	for _, who := range []string{"bob", "carol"} {
		go func(who string) {
			code, out, _ := approveAs(t, f, who, "", `{"id":"r1","generation":"`+gen+`"}`)
			replies <- reply{code, out}
		}(who)
	}
	<-ap.entered
	var loser reply
	select {
	case loser = <-replies:
	case <-ap.entered:
		t.Fatal("the second approver entered the applier while the first held the claim")
	}
	if loser.code != 409 || loser.out.Status != "in-progress" || loser.out.State != "applying" {
		t.Errorf("competing approver: want 409 in-progress/applying, got %d %+v", loser.code, loser.out)
	}
	// While the claim is held the listing shows it, so the UI can say who is applying.
	w := f.do(f.albReqAs(t, http.MethodGet, "/api/apply-fix/pending", "", "alice"))
	if !strings.Contains(w.Body.String(), `"state":"applying"`) || !strings.Contains(w.Body.String(), `"approver":"`) {
		t.Errorf("pending must show the in-flight claim: %s", w.Body.String())
	}
	close(ap.release)
	winner := <-replies
	if winner.code != 200 || winner.out.Status != "applied" {
		t.Errorf("winner: want 200 applied, got %d %+v", winner.code, winner.out)
	}
	if ap.count() != 1 {
		t.Errorf("applier calls=%d; want 1", ap.count())
	}
	if ev := auditEvents(t, f, "alice"); ev["apply-fix.applied"] != 1 {
		t.Errorf("audit applied=%d; want 1", ev["apply-fix.applied"])
	}
}

// No applier wired (whatever the mode label says): 501 applier-unavailable, state pending, the
// request still listed, applierWired=false in the listing, and no applied audit record.
func TestApplyFixEndpoints_NilApplierIsExplicitlyNotApplied(t *testing.T) {
	for _, mode := range []string{"record-only", "live"} {
		af := NewApplyFixManager(safeBase, nil, nil)
		af.ApplierMode = mode
		f := acmeFixture(t, af)
		submitAs(t, f, "alice", "", `{"id":"n1","delta":{"normSparsity":1.5}}`)
		gen := pendingGeneration(t, f, "bob", "n1")
		code, out, _ := approveAs(t, f, "bob", "", `{"id":"n1","generation":"`+gen+`"}`)
		if code != 501 || out.Status != "applier-unavailable" || out.State != "pending" || out.Error == "" {
			t.Errorf("mode %s: want 501 applier-unavailable/pending with an error, got %d %+v", mode, code, out)
		}
		w := f.do(f.albReqAs(t, http.MethodGet, "/api/apply-fix/pending", "", "alice"))
		if !strings.Contains(w.Body.String(), `"applierWired":false`) || !strings.Contains(w.Body.String(), `"id":"n1"`) || !strings.Contains(w.Body.String(), `"applierMode":"`+mode+`"`) {
			t.Errorf("mode %s: listing must keep the request pending and report applierWired=false: %s", mode, w.Body.String())
		}
		if ev := auditEvents(t, f, "alice"); ev["apply-fix.applied"] != 0 || ev["apply-fix.apply.unavailable"] != 1 {
			t.Errorf("mode %s: audit applied=%d unavailable=%d; want 0/1", mode, ev["apply-fix.applied"], ev["apply-fix.apply.unavailable"])
		}
	}
}

// An applier error is a terminal 500 failed with the sanitized detail; the retry returns the same
// retained outcome; another approver gets 409 conflict; the applier ran once.
func TestApplyFixEndpoints_ApplyErrorIsTerminalAndReplaySafe(t *testing.T) {
	var calls int32
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error {
		atomic.AddInt32(&calls, 1)
		return &gateErr{} // "synthetic gate failure" text stands in for a transport error
	}, nil)
	f := acmeFixture(t, af, operatorGrant("carol", []string{"acme"}, []string{defaultTargetID}))
	submitAs(t, f, "alice", "", `{"id":"e1","delta":{"normSparsity":1.5}}`)
	gen := pendingGeneration(t, f, "bob", "e1")
	code, out, _ := approveAs(t, f, "bob", "", `{"id":"e1","generation":"`+gen+`"}`)
	if code != 500 || out.Status != "failed" || out.State != "failed" || !strings.Contains(out.Error, "synthetic gate failure") {
		t.Fatalf("want 500 failed with detail, got %d %+v", code, out)
	}
	code2, out2, _ := approveAs(t, f, "bob", "", `{"id":"e1","generation":"`+gen+`"}`)
	if code2 != 500 || out2.Status != "failed" || !out2.Retry || out2.Error != out.Error {
		t.Errorf("retry: want the same retained failure with retry=true, got %d %+v", code2, out2)
	}
	if code, out, _ := approveAs(t, f, "carol", "", `{"id":"e1","generation":"`+gen+`"}`); code != 409 || out.Status != "conflict" || out.State != "failed" {
		t.Errorf("other approver: want 409 conflict/failed, got %d %+v", code, out)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("a failed generation was retried through HTTP: calls=%d", calls)
	}
	w := f.do(f.albReqAs(t, http.MethodGet, "/api/apply-fix/pending", "", "alice"))
	if strings.Contains(w.Body.String(), `"id":"e1"`) {
		t.Errorf("a failed generation must not be listed as open: %s", w.Body.String())
	}
}

// Same-subject approval (two-key) is 422 refused, a gate refusal at approval is 422 rejected, and a
// stale base is 409 stale — none of them applied.
func TestApplyFixEndpoints_RefusalStatuses(t *testing.T) {
	var mu sync.Mutex
	base := safeBase("")
	var calls int32
	af := NewApplyFixManager(func(string) model.Policy { mu.Lock(); defer mu.Unlock(); return base },
		func(_, _ string, _ model.Policy) error { atomic.AddInt32(&calls, 1); return nil }, nil)
	f := acmeFixture(t, af)
	submitAs(t, f, "alice", "", `{"id":"k1","delta":{"normSparsity":1.5}}`)
	submitAs(t, f, "alice", "", `{"id":"k2","delta":{"normSparsity":1.5}}`)
	submitAs(t, f, "alice", "", `{"id":"k3","delta":{"normSparsity":1.5}}`)
	g1, g2, g3 := pendingGeneration(t, f, "bob", "k1"), pendingGeneration(t, f, "bob", "k2"), pendingGeneration(t, f, "bob", "k3")

	if code, out, _ := approveAs(t, f, "alice", "", `{"id":"k1","generation":"`+g1+`"}`); code != 422 || out.Status != "refused" || out.State != "pending" {
		t.Errorf("two-key: want 422 refused/pending, got %d %+v", code, out)
	}
	af.Gate = func(model.Policy) error { return errGateBreak }
	if code, out, _ := approveAs(t, f, "bob", "", `{"id":"k2","generation":"`+g2+`"}`); code != 422 || out.Status != "rejected" || out.State != "rejected" {
		t.Errorf("gate at approval: want 422 rejected, got %d %+v", code, out)
	}
	af.Gate = PolicySafetyGate
	mu.Lock()
	base.FlowDisruption = 2
	mu.Unlock()
	if code, out, _ := approveAs(t, f, "bob", "", `{"id":"k3","generation":"`+g3+`"}`); code != 409 || out.Status != "stale" || out.State != "stale" {
		t.Errorf("stale base: want 409 stale, got %d %+v", code, out)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("refusals reached the applier %d time(s)", calls)
	}
	if ev := auditEvents(t, f, "alice"); ev["apply-fix.applied"] != 0 {
		t.Errorf("audit applied=%d; want 0", ev["apply-fix.applied"])
	}
}

// Submit is idempotent for identical content (200, existing=true, same generation) and a conflict
// (409) for different content under the same tenant/id.
func TestApplyFixEndpoints_SubmitIdempotentOrConflict(t *testing.T) {
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { return nil }, nil)
	f := acmeFixture(t, af)
	_, first := submitAs(t, f, "alice", "", `{"id":"s1","delta":{"normSparsity":1.5},"reason":"tune"}`)
	code, again := submitAs(t, f, "alice", "", `{"id":"s1","delta":{"normSparsity":1.5},"reason":"tune"}`)
	if code != 200 || again["existing"] != true || again["generation"] != first["generation"] {
		t.Errorf("identical resubmit: want 200 existing with the same generation, got %d %v", code, again)
	}
	if code, out := submitAs(t, f, "alice", "", `{"id":"s1","delta":{"normSparsity":1.6},"reason":"tune"}`); code != 409 || out["error"] == "" {
		t.Errorf("different content: want 409 with error, got %d %v", code, out)
	}
	if code, _ := submitAs(t, f, "bob", "", `{"id":"s1","delta":{"normSparsity":1.5},"reason":"tune"}`); code != 409 {
		t.Errorf("different requester under the same id: want 409, got %d", code)
	}
	af.MaxRecords = 1
	if code, out := submitAs(t, f, "alice", "", `{"id":"s2","delta":{"normSparsity":1.5}}`); code != 503 || !strings.Contains(out["error"].(string), "capacity") {
		t.Errorf("at capacity: want 503 capacity, got %d %v", code, out)
	}
}

// The pending listing is the exact shape the dashboard's ApproveQueue reads: each entry carries the
// generation and state it needs to approve, and the top level tells it whether an approval can apply.
func TestApplyFixEndpoints_PendingSerializationContract(t *testing.T) {
	af := NewApplyFixManager(safeBase, func(_, _ string, _ model.Policy) error { return nil }, nil)
	f := acmeFixture(t, af)
	submitAs(t, f, "alice", "", `{"id":"p1","delta":{"normSparsity":1.5},"reason":"tune"}`)
	w := f.do(f.albReqAs(t, http.MethodGet, "/api/apply-fix/pending", "", "alice"))
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	top := keysOf(doc)
	if strings.Join(top, ",") != "applierMode,applierWired,pending" {
		t.Errorf("top-level keys %v; want applierMode,applierWired,pending", top)
	}
	var entries []map[string]any
	if err := json.Unmarshal(doc["pending"], &entries); err != nil || len(entries) != 1 {
		t.Fatalf("pending entries: %v %v", err, entries)
	}
	keys := keysOf(entries[0])
	if strings.Join(keys, ",") != "deltaHash,generation,id,namespace,reason,requester,state,tenant" {
		t.Errorf("entry keys %v", keys)
	}
	e := entries[0]
	if e["state"] != "pending" || e["generation"] == "" || e["tenant"] != "acme" || e["namespace"] != "acme" || e["requester"] != testALBIssuer+"#alice" || e["reason"] != "tune" {
		t.Errorf("entry values: %v", e)
	}
	if string(doc["applierWired"]) != "true" || string(doc["applierMode"]) != `"record-only"` {
		t.Errorf("applierWired=%s applierMode=%s", doc["applierWired"], doc["applierMode"])
	}
}

func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
