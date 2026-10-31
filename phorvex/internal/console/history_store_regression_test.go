package console

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/audit"
)

func testHistoryStore(t *testing.T, cfg Config) *Server {
	t.Helper()
	h, err := openHistoryStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Stop the periodic worker; deterministic imports below use precisely the same implementation.
	h.cancel()
	<-h.done
	s := &Server{cfg: cfg, history: h}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close history store: %v", err)
		}
	})
	return s
}
func testDurableRecord(i int) audit.Record {
	r := historyRecord(i, false)
	r.Action = "rotate"
	r.Selected = true
	return r
}
func importHistoryNow(s *Server) { s.history.ingestOnce(context.Background()) }

func TestConsoleDurableRestartRotationDeletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeHistory(t, path, testDurableRecord(1), testDurableRecord(2), testDurableRecord(3))
	cfg := Config{StateDir: dir, AuditPath: path}
	s := testHistoryStore(t, cfg)
	importHistoryNow(s)
	q := url.Values{"lens": {"operator"}, "limit": {"2"}}
	first, _ := getHistory(t, s, q, 200)
	if len(first.Events) != 2 || eventPod(t, first.Events[0]) != "pod-0003" || first.NextCursor == "" {
		t.Fatalf("first=%+v", first)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeHistory(t, path, testDurableRecord(4))
	importHistoryNow(s)
	q.Set("cursor", first.NextCursor)
	older, _ := getHistory(t, s, q, 200)
	if len(older.Events) != 1 || eventPod(t, older.Events[0]) != "pod-0001" {
		t.Fatalf("append moved old page: %+v", older)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = testHistoryStore(t, cfg)
	importHistoryNow(s)
	q.Del("cursor")
	q.Set("limit", "50")
	all, _ := getHistory(t, s, q, 200)
	if len(all.Events) != 4 {
		t.Fatalf("restart lost/duplicated rows: %d", len(all.Events))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".1"); err != nil {
		t.Fatal(err)
	}
	importHistoryNow(s)
	retained, _ := getHistory(t, s, q, 200)
	if len(retained.Events) != 4 || !retained.Partial {
		t.Fatalf("deleted source not retained/marked partial: %+v", retained)
	}
}

func TestConsoleDurableTenantNoopProjection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	other := testDurableRecord(9)
	other.Tenant = "secret"
	other.Reason = "private reason"
	writeHistory(t, path, testDurableRecord(1), historyRecord(2, false), other)
	s := testHistoryStore(t, Config{StateDir: dir, AuditPath: path})
	importHistoryNow(s)
	q := url.Values{"lens": {"operator"}, "limit": {"50"}}
	p, _ := getHistoryAs(t, s, testOperatorPrincipal("acme"), q, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0001" {
		t.Fatalf("scope/default noop: %+v", p)
	}
	q.Set("includeNoop", "true")
	p, _ = getHistoryAs(t, s, testOperatorPrincipal("acme"), q, 200)
	if len(p.Events) != 2 {
		t.Fatalf("explicit noop missing: %+v", p)
	}
	q.Set("includeNoop", "false")
	p, _ = getHistoryAs(t, s, testOperatorPrincipal("acme"), q, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0001" {
		t.Fatalf("explicit noop exclusion failed: %+v", p)
	}
	q.Del("includeNoop")
	q.Set("action", "noop")
	p, _ = getHistoryAs(t, s, testOperatorPrincipal("acme"), q, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0002" {
		t.Fatalf("explicit noop action failed: %+v", p)
	}
	q.Del("action")
	q.Set("includeNoop", "true")
	q.Set("tenant", "secret")
	getHistoryAs(t, s, testOperatorPrincipal("acme"), q, 403)
	q.Set("tenant", "acme")
	q.Set("lens", "owner")
	p, body := getHistoryAs(t, s, testOwnerPrincipal("acme"), q, 200)
	if len(p.Events) != 1 || strings.Contains(body, "private reason") || strings.Contains(body, "perDollar") {
		t.Fatalf("owner projection: %s", body)
	}
	q.Set("cursor", "not-a-valid-cursor")
	getHistoryAs(t, s, testOwnerPrincipal("acme"), q, 400)
}

func TestConsoleDurableBatchAndPartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for i := 0; i < 300; i++ {
		writeHistory(t, path, testDurableRecord(i))
	}
	last, _ := json.Marshal(testDurableRecord(300))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(last); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	s := testHistoryStore(t, Config{StateDir: dir, AuditPath: path})
	importHistoryNow(s)
	if s.history.statusFor("default").ready {
		t.Fatal("batch limit failed to report pending import")
	}
	importHistoryNow(s)
	p, _ := getHistory(t, s, url.Values{"q": {"pod-0300"}}, 200)
	if len(p.Events) != 0 {
		t.Fatal("unterminated record became visible")
	}
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	importHistoryNow(s)
	p, _ = getHistory(t, s, url.Values{"q": {"pod-0300"}}, 200)
	if len(p.Events) != 1 || !s.history.statusFor("default").ready {
		t.Fatalf("completed line missing: %+v", p)
	}
}

func TestConsoleDurableMalformedAndRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeHistory(t, path, testDurableRecord(1))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("not-json\n"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	writeHistory(t, path, testDurableRecord(2))
	s := testHistoryStore(t, Config{StateDir: dir, AuditPath: path})
	importHistoryNow(s)
	p, _ := getHistory(t, s, url.Values{}, 200)
	if len(p.Events) != 2 || !p.Partial || !strings.Contains(p.Notice, "gap") {
		t.Fatalf("malformed source handling: %+v", p)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	writeHistory(t, path, testDurableRecord(3))
	importHistoryNow(s)
	importHistoryNow(s)
	p, _ = getHistory(t, s, url.Values{}, 200)
	if len(p.Events) != 3 {
		t.Fatalf("rewrite lost old/new history: %+v", p)
	}
}

func TestConsoleCollectionCursorScopeAndTamper(t *testing.T) {
	p := testOperatorPrincipal("acme")
	req := httptest.NewRequest("GET", "/api/test?limit=2", nil)
	pg, err := collectionPagingFromRequest(req, "/api/test", p, map[string]string{"q": "x"})
	if err != nil {
		t.Fatal(err)
	}
	cur := pg.establish("/api/test", 5, "a")
	_, _, page, err := collectionPageFor(cur, 5)
	if err != nil {
		t.Fatal(err)
	}
	check := func(raw string, principal *Principal, fail bool) {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/test?limit=2&cursor="+url.QueryEscape(raw), nil)
		_, err := collectionPagingFromRequest(r, "/api/test", principal, map[string]string{"q": "x"})
		if (err != nil) != fail {
			t.Fatalf("cursor fail=%v error=%v", fail, err)
		}
	}
	check(page.NextCursor, p, false)
	check(page.NextCursor, testOperatorPrincipal("other"), true)
	decoded, err := base64.RawURLEncoding.DecodeString(page.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	var modified map[string]any
	if err = json.Unmarshal(decoded, &modified); err != nil {
		t.Fatal(err)
	}
	modified["o"] = 999
	raw, err := json.Marshal(modified)
	if err != nil {
		t.Fatal(err)
	}
	check(base64.RawURLEncoding.EncodeToString(raw), p, true)
}

func TestConsoleAttackPaginationSnapshot(t *testing.T) {
	attackMu.Lock()
	saved := attackList
	attackList = []*attackRecord{{ID: "1", Namespace: "acme"}, {ID: "2", Namespace: "secret"}, {ID: "3", Namespace: "acme"}}
	attackMu.Unlock()
	t.Cleanup(func() { attackMu.Lock(); attackList = saved; attackMu.Unlock() })
	p := testOperatorPrincipal("acme")
	req := httptest.NewRequest("GET", "/api/attacks?limit=1", nil)
	pg, err := collectionPagingFromRequest(req, "/api/attacks", p, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, page, err := pagedRealAttackSnapshots("/api/attacks", p, pg, "", "")
	if err != nil || len(rows) != 1 || rows[0].ID != "3" || page.Total != 2 {
		t.Fatalf("first: %v %+v %+v", err, rows, page)
	}
	attackMu.Lock()
	attackList = append(attackList, &attackRecord{ID: "4", Namespace: "acme"})
	attackMu.Unlock()
	req = httptest.NewRequest("GET", "/api/attacks?limit=1&cursor="+url.QueryEscape(page.NextCursor), nil)
	pg, err = collectionPagingFromRequest(req, "/api/attacks", p, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, page, err = pagedRealAttackSnapshots("/api/attacks", p, pg, "", "")
	if err != nil || len(rows) != 1 || rows[0].ID != "1" || page.Total != 2 {
		t.Fatalf("append shifted snapshot: %v %+v %+v", err, rows, page)
	}
}

func TestConsoleAttackEvidenceCloneIsolation(t *testing.T) {
	original := &attackRecord{DecisionEvidence: &decisionEvidence{Reason: "before"}}
	copied := cloneAttackRecord(original)
	if copied.DecisionEvidence == original.DecisionEvidence || copied.DecisionEvidence.Reason != "before" {
		t.Fatalf("decision evidence was not independently copied: original=%p copied=%p value=%+v", original.DecisionEvidence, copied.DecisionEvidence, copied.DecisionEvidence)
	}
	copied.DecisionEvidence.Reason = "after"
	if original.DecisionEvidence.Reason != "before" {
		t.Fatal("cloneAttackRecord shares mutable DecisionEvidence pointer")
	}
	if cloneAttackRecord(&attackRecord{}).DecisionEvidence != nil {
		t.Fatal("cloneAttackRecord changed nil DecisionEvidence")
	}
}

func TestConsoleRunPaginationAuthorizationAndAppend(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	rm := NewRunManager(cfg)
	rm.runs = map[string]*RunStatus{
		"run-1": {ID: "run-1", Target: "dev", ScopeTarget: "dev", ScopeTenant: "acme", State: "done"},
		"run-2": {ID: "run-2", Target: "dev", ScopeTarget: "dev", ScopeTenant: "secret", State: "done"},
		"run-3": {ID: "run-3", Target: "dev", ScopeTarget: "dev", ScopeTenant: "acme", State: "done"},
	}
	s := &Server{cfg: cfg, runs: rm}
	get := func(cursor string) ([]RunStatus, collectionPage) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/runs/list?context=dev&limit=1&cursor="+url.QueryEscape(cursor), nil)
		s.runsList(w, withTestPrincipal(r, testOperatorPrincipal("acme")))
		if w.Code != 200 {
			t.Fatalf("runs status=%d %s", w.Code, w.Body.String())
		}
		var response struct {
			Runs []RunStatus    `json:"runs"`
			Page collectionPage `json:"page"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Runs, response.Page
	}
	rows, page := get("")
	if len(rows) != 1 || rows[0].ID != "run-3" || page.Total != 2 {
		t.Fatalf("runs first=%+v page=%+v", rows, page)
	}
	rm.runs["run-4"] = &RunStatus{ID: "run-4", Target: "dev", ScopeTarget: "dev", ScopeTenant: "acme"}
	rows, page = get(page.NextCursor)
	if len(rows) != 1 || rows[0].ID != "run-1" || page.Total != 2 {
		t.Fatalf("runs snapshot shifted: %+v %+v", rows, page)
	}
}

func TestConsoleRunPaginationMatchesLocalClusterAliases(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	rm := NewRunManager(cfg)
	rm.runs = map[string]*RunStatus{
		"cat-14": {ID: "cat-14", Config: "AML.T0086", Target: defaultTargetID, ScopeTarget: defaultTargetID, ScopeTenant: "acme", State: "done"},
	}
	s := &Server{cfg: cfg, runs: rm}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/runs/list?context="+inClusterTargetID+"&q=cat-14&limit=20", nil)
	s.runsList(w, withTestPrincipal(r, testOperatorPrincipal("acme")))
	if w.Code != http.StatusOK {
		t.Fatalf("runs status=%d %s", w.Code, w.Body.String())
	}
	var response struct {
		Runs []RunStatus    `json:"runs"`
		Page collectionPage `json:"page"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Runs) != 1 || response.Runs[0].ID != "cat-14" || response.Page.Total != 1 {
		t.Fatalf("local alias hid the retained run: runs=%+v page=%+v", response.Runs, response.Page)
	}
}

func TestConsoleArmsEmptyAndMalformed(t *testing.T) {
	s := &Server{cfg: Config{StateDir: t.TempDir()}}
	request := func(want int) armsResponse {
		t.Helper()
		w := httptest.NewRecorder()
		s.availabilityArms(w, withTestPrincipal(httptest.NewRequest("GET", "/api/availability-arms?limit=2", nil), testOperatorPrincipal("acme")))
		if w.Code != want {
			t.Fatalf("arms status=%d want=%d body=%s", w.Code, want, w.Body.String())
		}
		var result armsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	r := request(200)
	if r.Page == nil || r.Page.Total != 0 || r.Available {
		t.Fatalf("empty arms=%+v", r)
	}
	if err := os.WriteFile(armsPath(s.cfg), []byte("bad-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request(503)
}
