package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func historyRecord(i int, large bool) audit.Record {
	r := audit.ToRecord(model.Decision{Tenant: "acme", Namespace: "apps", Pod: fmt.Sprintf("pod-%04d", i), Action: model.ActionNoop})
	r.Kind = "phorvex.decision"
	r.Time = time.Unix(100, 0).UTC()
	if large {
		r.DecisionTrace = &model.DecisionTraceV2{SchemaVersion: model.DecisionTraceSchemaV3, ActionStatus: []model.DecisionActionStatusV3{{Action: "rotate", Status: model.ActionStatusNotEnabled, Reason: strings.Repeat("observed input; ", 7000)}}}
	}
	return r
}
func writeHistory(t *testing.T, path string, recs ...audit.Record) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	for _, r := range recs {
		if e := json.NewEncoder(f).Encode(r); e != nil {
			t.Fatal(e)
		}
	}
}
func getHistory(t *testing.T, s *Server, q url.Values, want int) (historyPage, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/live/history?"+q.Encode(), nil))
	if w.Code != want {
		t.Fatalf("history status %d want %d: %s", w.Code, want, w.Body.String())
	}
	var p historyPage
	if want == 200 {
		if e := json.Unmarshal(w.Body.Bytes(), &p); e != nil {
			t.Fatal(e)
		}
	}
	return p, w.Body.String()
}
func eventPod(t *testing.T, item historyItem) string {
	t.Helper()
	return item.Event.(map[string]any)["pod"].(string)
}

func TestHistoryRetainedActuationAfterLargeNoops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer, e := audit.NewRotatingWriter(path, 12<<20, 8)
	if e != nil {
		t.Fatal(e)
	}
	enc := json.NewEncoder(writer)
	for i := 0; i < 430; i++ {
		r := historyRecord(i, true)
		if i == 1 {
			r.Action = "rotate"
			r.Selected = true
			r.Actuated = true
		}
		if e := enc.Encode(r); e != nil {
			t.Fatal(e)
		}
	}
	if e := writer.Close(); e != nil {
		t.Fatal(e)
	}
	s := NewServer(Config{AuditPath: path})
	q := url.Values{"lens": {"operator"}, "actuated": {"true"}}
	var found []historyItem
	partials := 0
	for n := 0; n < 12; n++ {
		p, body := getHistory(t, s, q, 200)
		found = append(found, p.Events...)
		if p.Partial {
			partials++
			if p.NextCursor == "" {
				t.Fatal("budget result must continue")
			}
		}
		if strings.Contains(body, "decisionTrace") && strings.Contains(body, "observed input") {
			t.Fatal("summary leaked trace")
		}
		if p.ScannedBytes > historyScanBytes+liveRecordBytes+65536 {
			t.Fatalf("unbounded scan: %d", p.ScannedBytes)
		}
		if p.NextCursor == "" {
			break
		}
		q.Set("cursor", p.NextCursor)
	}
	if len(found) != 1 || eventPod(t, found[0]) != "pod-0001" || partials == 0 {
		t.Fatalf("deep actuation not recovered: %#v partials=%d", found, partials)
	}
}

func TestHistoryCursorStableAcrossAppendAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 12; i++ {
		writeHistory(t, path, historyRecord(i, false))
	}
	s := NewServer(Config{AuditPath: path})
	q := url.Values{"lens": {"operator"}, "limit": {"3"}}
	first, _ := getHistory(t, s, q, 200)
	if len(first.Events) != 3 {
		t.Fatal(first)
	}
	seen := map[string]bool{}
	for _, r := range first.Events {
		seen[r.ID] = true
	}
	writeHistory(t, path, historyRecord(12, false))
	if e := os.Rename(path, path+".1"); e != nil {
		t.Fatal(e)
	}
	writeHistory(t, path, historyRecord(13, false))
	q.Set("cursor", first.NextCursor)
	var pods []string
	for n := 0; n < 8; n++ {
		p, _ := getHistory(t, s, q, 200)
		for _, r := range p.Events {
			if seen[r.ID] {
				t.Fatal("duplicate cursor record")
			}
			seen[r.ID] = true
			pods = append(pods, eventPod(t, r))
		}
		if p.NextCursor == "" {
			break
		}
		q.Set("cursor", p.NextCursor)
	}
	if len(pods) != 9 || pods[0] != "pod-0008" || pods[8] != "pod-0000" {
		t.Fatalf("moved older pages: %v", pods)
	}
	latest, _ := getHistory(t, s, url.Values{"lens": {"operator"}, "limit": {"3"}}, 200)
	if eventPod(t, latest.Events[0]) != "pod-0013" || eventPod(t, latest.Events[1]) != "pod-0012" {
		t.Fatalf("latest lost rotation records: %#v", latest)
	}
}

func TestHistoryScopesPredicatesAndInvalidCursors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	r0 := historyRecord(0, false)
	r0.Selected = true
	r0.Action = "rotate"
	r0.Lambda = 12
	r0.PerDollar = 33
	r0.Reason = "private IP"
	r1 := historyRecord(1, false)
	r1.Actuated = true
	r1.DryRun = true
	r1.Action = "quarantine" // anomalous true actuation must not be hidden
	r2 := historyRecord(2, false)
	r2.Selected = true
	r2.Tenant = "other"
	r3 := historyRecord(3, false)
	r3.DryRun = true
	r3.Selected = true
	writeHistory(t, path, r0, r1, r2, r3)
	vc := historyRecord(90, false)
	vc.Actuated = true
	writeHistory(t, filepath.Join(filepath.Dir(path), "phorvex-live-vcluster.jsonl"), vc)
	s := NewServer(Config{AuditPath: path})
	for _, lens := range []string{"owner", "", "unknown"} {
		p, _ := getHistory(t, s, url.Values{"lens": {lens}}, 200)
		if len(p.Events) != 0 {
			t.Fatal("unscoped owner leak")
		}
		p, body := getHistory(t, s, url.Values{"lens": {lens}, "tenant": {"acme"}}, 200)
		if len(p.Events) != 3 {
			t.Fatalf("owner eligibility: %s", body)
		}
		if strings.Contains(body, "private IP") || strings.Contains(body, "perDollar") || strings.Contains(body, "lambda") || strings.Contains(body, "other") {
			t.Fatal("owner IP/tenant leak")
		}
	}
	p, _ := getHistory(t, s, url.Values{"lens": {"operator"}, "actuated": {"true"}}, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0001" {
		t.Fatal("actuated filter changed truth")
	}
	p, _ = getHistory(t, s, url.Values{"lens": {"operator"}, "actuated": {"false"}, "action": {"rotate"}, "q": {"APPS/POD-0000"}, "from": {"1970-01-01T00:01:40Z"}, "to": {"1970-01-01T00:01:40Z"}}, 200)
	if len(p.Events) != 1 {
		t.Fatal("action/text/inclusive time filter")
	}
	p, _ = getHistory(t, s, url.Values{"lens": {"operator"}, "context": {"vc-test"}}, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0090" {
		t.Fatal("provider scope")
	}
	first, _ := getHistory(t, s, url.Values{"lens": {"operator"}, "limit": {"1"}}, 200)
	for k, v := range map[string]string{"lens": "owner", "tenant": "acme", "context": "vc-test", "q": "other", "action": "rotate", "actuated": "true"} {
		q := url.Values{"lens": {"operator"}, "cursor": {first.NextCursor}}
		q.Set(k, v)
		getHistory(t, s, q, 400)
	}
	for k, v := range map[string]string{"cursor": "../../etc/passwd", "limit": "51", "actuated": "yes", "from": "yesterday"} {
		q := url.Values{"lens": {"operator"}}
		q.Set(k, v)
		getHistory(t, s, q, 400)
	}
	if e := os.Truncate(path, 0); e != nil {
		t.Fatal(e)
	}
	getHistory(t, s, url.Values{"lens": {"operator"}, "cursor": {first.NextCursor}}, 409)
}

func TestHistoryMalformedOversizedAndPartialLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeHistory(t, path, historyRecord(0, false))
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(append(bytes.Repeat([]byte("x"), historyScanBytes+5000), '\n')); e != nil {
		t.Fatal(e)
	}
	f.WriteString("not-json\n")
	f.Close()
	writeHistory(t, path, historyRecord(1, false))
	b, _ := json.Marshal(historyRecord(2, false))
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write(b[:len(b)/2])
	f.Close()
	s := NewServer(Config{AuditPath: path})
	q := url.Values{"lens": {"operator"}}
	p, _ := getHistory(t, s, q, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0001" || !p.Partial || p.NextCursor == "" {
		t.Fatalf("bad first bounded page: %#v", p)
	}
	q.Set("cursor", p.NextCursor)
	p, _ = getHistory(t, s, q, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0000" {
		t.Fatalf("oversized continuation lost older record: %#v", p)
	}
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write(append(b[len(b)/2:], '\n'))
	f.Close()
	p, _ = getHistory(t, s, url.Values{"lens": {"operator"}, "limit": {"1"}}, 200)
	if eventPod(t, p.Events[0]) != "pod-0002" {
		t.Fatal("completed record lost")
	}
}

func TestLiveReplayLargeRecordsAndSplitTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 100; i++ {
		writeHistory(t, path, historyRecord(i, true))
	}
	var got []audit.Record
	offset := tailReplay(path, 80, func(r audit.Record) { got = append(got, r) })
	if len(got) != 80 || got[0].Pod != "pod-0020" || got[79].Pod != "pod-0099" || got[0].DecisionTrace == nil {
		t.Fatalf("large full replay failed: %d", len(got))
	}
	b, _ := json.Marshal(historyRecord(100, false))
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write(b[:len(b)/2])
	f.Close()
	count := 0
	offset = streamNew(path, offset, func(audit.Record) { count++ })
	if count != 0 {
		t.Fatal("partial emitted")
	}
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write(append(b[len(b)/2:], '\n'))
	f.Close()
	streamNew(path, offset, func(audit.Record) { count++ })
	if count != 1 {
		t.Fatalf("split line emitted %d times", count)
	}
}

type historyFlushRecorder struct {
	*httptest.ResponseRecorder
	onFlush func()
}

func (w *historyFlushRecorder) Flush() {
	w.ResponseRecorder.Flush()
	if w.onFlush != nil {
		w.onFlush()
	}
}

func TestLiveReplaySurvivesReplacementDuringFlush(t *testing.T) {
	for _, truncate := range []bool{false, true} {
		t.Run(fmt.Sprintf("truncate_%v", truncate), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			writer, e := audit.NewRotatingWriter(path, 1400, 4)
			if e != nil {
				t.Fatal(e)
			}
			defer writer.Close()
			old := historyRecord(0, false)
			old.Pod = "before"
			old.Reason = strings.Repeat("old ", 100)
			if e := json.NewEncoder(writer).Encode(old); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			recorder := &historyFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
			replaced := false
			recorder.onFlush = func() {
				body := recorder.Body.String()
				if strings.Contains(body, `"pod":"after"`) {
					cancel()
					return
				}
				if replaced || !strings.Contains(body, `"pod":"before"`) {
					return
				}
				replaced = true
				next := historyRecord(1, false)
				next.Pod = "after"
				next.Reason = strings.Repeat("new ", 3000)
				next.Actuated = true
				if truncate {
					if e := os.Truncate(path, 0); e != nil {
						t.Fatal(e)
					}
					writeHistory(t, path, next)
				} else {
					if e := json.NewEncoder(writer).Encode(next); e != nil {
						t.Fatal(e)
					}
				}
			}
			NewServer(Config{AuditPath: path}).live(recorder, httptest.NewRequest("GET", "/api/live?lens=operator", nil).WithContext(ctx))
			if !strings.Contains(recorder.Body.String(), `"pod":"after"`) {
				t.Fatalf("replacement event lost: %s", recorder.Body.String())
			}
		})
	}
}

func TestHistoryRejectsSpecialFilesAndExpiredRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeHistory(t, path, historyRecord(0, false), historyRecord(1, false))
	if e := syscall.Mkfifo(path+".2", 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(path, path+".3"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path+".not-a-segment", []byte("unrelated"), 0600); e != nil {
		t.Fatal(e)
	}
	s := NewServer(Config{AuditPath: path})
	q := url.Values{"lens": {"operator"}, "limit": {"1"}}
	p, _ := getHistory(t, s, q, 200)
	if len(p.Events) != 1 {
		t.Fatal("regular audit not readable")
	}
	if f, e := openAuditFile(path + ".2"); e == nil {
		f.Close()
		t.Fatal("FIFO accepted")
	}
	if f, e := openAuditFile(path + ".3"); e == nil {
		f.Close()
		t.Fatal("symlink accepted")
	}
	getHistory(t, s, url.Values{"lens": {"operator"}, "cursor": {strings.Repeat("x", 3000)}}, 400)
	if e := os.Rename(path, path+".old"); e != nil {
		t.Fatal(e)
	}
	writeHistory(t, path, historyRecord(3, false))
	q.Set("cursor", p.NextCursor)
	getHistory(t, s, q, 409)
	p, _ = getHistory(t, s, url.Values{"lens": {"operator"}, "actuated": {"false"}}, 200)
	if len(p.Events) != 1 {
		t.Fatal("explicit false predicate")
	}
	missing := NewServer(Config{AuditPath: filepath.Join(t.TempDir(), "missing.jsonl")})
	p, _ = getHistory(t, missing, url.Values{"lens": {"operator"}}, 200)
	if len(p.Events) != 0 || p.NextCursor != "" {
		t.Fatal("missing file fabricated history")
	}
}

func TestHistoryBlankLinesRespectScanBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeHistory(t, path, historyRecord(0, false))
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := f.Write(bytes.Repeat([]byte{'\n'}, 2*historyScanBytes+128)); e != nil {
		t.Fatal(e)
	}
	f.Close()
	s := NewServer(Config{AuditPath: path})
	q := url.Values{"lens": {"operator"}}
	for i := 0; i < 2; i++ {
		p, _ := getHistory(t, s, q, 200)
		if p.ScannedBytes > historyScanBytes || !p.Partial || p.NextCursor == "" || len(p.Events) != 0 {
			t.Fatalf("blank-line budget bypass: %#v", p)
		}
		q.Set("cursor", p.NextCursor)
	}
	p, _ := getHistory(t, s, q, 200)
	if len(p.Events) != 1 || eventPod(t, p.Events[0]) != "pod-0000" {
		t.Fatal("blank-line continuation lost older record")
	}
}

func TestHistoryConcurrentRotationRejectsMixedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer, e := audit.NewRotatingWriter(path, 1, 4)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	enc := json.NewEncoder(writer)
	for i := 0; i < 2; i++ {
		if e := enc.Encode(historyRecord(i, false)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := os.Stat(path + ".1"); e != nil {
		t.Fatal(e)
	}
	opens := 0
	rotated := false
	openFile := func(p string) (*os.File, error) {
		f, e := openAuditFile(p)
		opens++
		// Two generation opens establish the manifest. Rotate after the first
		// scan handle opens: the next numeric path now names that same generation.
		if opens == 3 {
			if e := enc.Encode(historyRecord(2, false)); e != nil {
				t.Fatal(e)
			}
			rotated = true
		}
		return f, e
	}
	w := httptest.NewRecorder()
	s := NewServer(Config{AuditPath: path})
	s.liveHistoryWithOpener(w, httptest.NewRequest("GET", "/api/live/history?lens=operator", nil), openFile)
	if !rotated || w.Code != 409 {
		t.Fatalf("mixed manifest accepted: rotated=%v status=%d %s", rotated, w.Code, w.Body.String())
	}
	p, _ := getHistory(t, s, url.Values{"lens": {"operator"}}, 200)
	if len(p.Events) != 3 {
		t.Fatalf("stable retry lost retained records: %#v", p)
	}
}
