package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func drainCursorFixture(t *testing.T) (*drainAuditCursor, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	row, _ := vllmWatchRows(t, time.Now().UTC())
	if err := os.WriteFile(path, append(drainJSON(row), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	cfg := audittransport.ServerConfig{AuditPath: path, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 3}
	ts := httptest.NewUnstartedServer(cfg.Handler())
	ts.TLS = cfg.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	p := drainTestProfile()
	s := NewServer(Config{AuditSource: client, AuditSourceIdentity: p.AuditSourceIdentity})
	c, err := s.newDrainAuditCursor(context.Background(), dir, p)
	if err != nil {
		t.Fatal(err)
	}
	return c, path
}
func drainAppend(t *testing.T, path string, b []byte) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		t.Fatal(e)
	}
}
func TestDrainCursorActualAppendRotationAndMissingBackup(t *testing.T) {
	c, path := drainCursorFixture(t)
	ctx := context.Background()
	row, _ := vllmWatchRows(t, time.Now().UTC())
	row.DecisionTrace.AssetUID = c.targetUID
	row.DecisionTrace.PolicyUID = c.policyUID
	raw := append(drainJSON(row), '\n')
	cut := len(raw) / 2
	drainAppend(t, path, raw[:cut])
	if e := c.update(ctx); e != nil {
		t.Fatal(e)
	}
	if len(c.records) != 1 || len(c.pending) == 0 {
		t.Fatal("partial row accepted or lost")
	}
	drainAppend(t, path, raw[cut:])
	if e := c.update(ctx); e != nil {
		t.Fatal(e)
	}
	if len(c.records) != 2 || !bytes.Equal(c.originals[1], raw[:len(raw)-1]) {
		t.Fatal("original selection lost")
	}
	old := c.segment.Generation
	if e := os.Rename(path, path+".1"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, append(drainJSON(audit.Record{Kind: "phorvex.decision", Time: time.Now().UTC()}), '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if e := c.update(ctx); e != nil {
		t.Fatal(e)
	}
	if len(c.records) != 2 || c.segment.Generation == old || !bytes.Equal(c.originals[1], raw[:len(raw)-1]) {
		t.Fatal("rotation lost/duplicated original evidence")
	}
	// Preserve the current generation as backup-3 with backup-2 absent.
	if e := os.Rename(path, path+".3"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, append(drainJSON(audit.Record{Kind: "phorvex.decision", Time: time.Now().UTC()}), '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if e := c.update(ctx); e == nil || drainAuditRetry(e) {
		t.Fatalf("missing backup crossed: %v", e)
	}
}
func TestDrainCursorFailureDoesNotAdvance(t *testing.T) {
	for _, name := range []string{"malformed", "budget", "transient", "lost"} {
		t.Run(name, func(t *testing.T) {
			c, path := drainCursorFixture(t)
			offset := c.offset
			switch name {
			case "malformed":
				drainAppend(t, path, []byte("{invalid}\n"))
			case "budget":
				c.fetched = drainAuditLimit
				drainAppend(t, path, []byte("{}\n"))
			case "transient", "lost":
				if e := os.Rename(path, path+".hidden"); e != nil {
					t.Fatal(e)
				}
				if name == "lost" {
					if e := os.WriteFile(path, []byte("{}\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			e := c.update(context.Background())
			if e == nil || c.offset != offset || len(c.records) != 1 {
				t.Fatalf("failed read advanced: %v", e)
			}
			if name == "transient" {
				if !drainAuditRetry(e) {
					t.Fatal("transient not retryable")
				}
				if e := os.Rename(path+".hidden", path); e != nil {
					t.Fatal(e)
				}
				if e := c.updateWithRetry(context.Background()); e != nil {
					t.Fatal(e)
				}
			} else if drainAuditRetry(e) {
				t.Fatal("integrity failure retryable")
			}
		})
	}
}
func TestDrainCooldownTraceScopeAndGuard(t *testing.T) {
	now := time.Now().UTC()
	p := drainTestProfile()
	base := audit.Record{Kind: "phorvex.decision", Time: now, DecisionTrace: &model.DecisionTraceV2{AssetUID: p.PodUID, PolicyUID: p.PolicyUID, PolicyName: p.PolicyName, PolicyNamespace: "vllm", AssetNamespace: "vllm"}}
	// Use wire JSON so this exercises the actual trace decoder and typed inputs.
	var value map[string]any
	json.Unmarshal(drainJSON(base), &value)
	trace := value["decisionTrace"].(map[string]any)
	trace["inputs"] = map[string]any{"antiOverRotationWindowSeconds": 90}
	trace["actionStatus"] = []map[string]any{{"action": "request-drain", "status": "infeasible", "reason": "request-drain capability: no new operation currently advertised"}}
	for _, name := range []string{"idle", "anti", "failure", "stale", "target", "window", "missing"} {
		t.Run(name, func(t *testing.T) {
			var row audit.Record
			if e := json.Unmarshal(drainJSON(value), &row); e != nil {
				t.Fatal(e)
			}
			switch name {
			case "anti":
				row.DecisionTrace.ActionStatus[0].Reason = "anti-over-rotation: drainEpoch unchanged for 40s < 90s"
			case "failure":
				row.DecisionTrace.ActionStatus[0].ExclusionKind = "action-failure-cooldown"
			case "stale":
				row.Time = now.Add(-time.Minute)
			case "target":
				row.DecisionTrace.AssetUID = "wrong"
			case "window":
				row.DecisionTrace.Inputs.AntiOverRotateSec = 1
			case "missing":
				row.DecisionTrace.ActionStatus = nil
			}
			_, e := drainCooldownRecord([]audit.Record{row}, p, now, 90*time.Second, 10*time.Second)
			if (e == nil) != (name == "idle") {
				t.Fatalf("scope/guard %s: %v", name, e)
			}
			if name == "anti" || name == "failure" {
				if !strings.Contains(drainLiveSafeIssue(e), "cooldown active; wait before retry") {
					t.Fatal("opaque cooldown")
				}
			}
		})
	}
}
func TestDrainRealProducerLongResponseAndCap(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Fatal(e)
	}
	for _, count := range []int{600, 2050} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			nonce := strings.Repeat("a", 32)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var v map[string]any
				json.Unmarshal(b, &v)
				if v["max_tokens"] != float64(1024) || v["stream"] != true {
					t.Error("request budget changed")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				for i := 0; i < count; i++ {
					fmt.Fprintf(w, "data: {\"id\":\"cmpl-%s\"}\n\n", nonce)
				}
				fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer ts.Close()
			u, _ := url.Parse(ts.URL)
			script := strings.Replace(drainStreamPython, `"vllm.vllm.svc.cluster.local",8000`, fmt.Sprintf("%q,%s", u.Hostname(), u.Port()), 1)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "-B", "-c", script)
			cmd.Stdin = bytes.NewReader(drainJSON(map[string]string{"body": base64Body(drainRequestBody("fixture", 1024, true)), "nonce": nonce}))
			raw, e := cmd.Output()
			if e != nil {
				t.Fatal(e)
			}
			lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
			if len(lines) != 2 {
				t.Fatalf("projection rows %d", len(lines))
			}
			var final drainStreamRow
			if e := json.Unmarshal(lines[1], &final); e != nil {
				t.Fatal(e)
			}
			if count == 600 && (final.Frames != 600 || !final.Done || final.CapReached) {
				t.Fatalf("premature truncation: %+v", final)
			}
			if count == 2050 && (final.Frames != 2048 || final.Done || !final.CapReached || drainAbortCompatible(final)) {
				t.Fatalf("cap credited: %+v", final)
			}
			if count == 2050 {
				run := &drainStreamRun{done: make(chan error, 1), final: make(chan drainStreamRow, 1)}
				run.done <- nil
				final.Original = lines[1]
				run.final <- final
				r := &attackRecord{DrainLiveProbe: &drainLiveProbeResult{}}
				if _, e := drainNoOverlapIfCompleted(t.TempDir(), r, run); e == nil || r.DrainLiveProbe.Status != "" {
					t.Fatal("capped completion credited")
				}
			}
		})
	}
}

func TestDrainCursorValidatesFleetRowsWithoutRetainingFleet(t *testing.T) {
	c, path := drainCursorFixture(t)
	other, _ := vllmWatchRows(t, time.Now().UTC())
	other.DecisionTrace.AssetUID = "unrelated-fleet-target"
	var raw []byte
	for len(raw) < 2*audittransport.ChunkBytes {
		raw = append(raw, append(drainJSON(other), '\n')...)
	}
	drainAppend(t, path, raw)
	if err := c.update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.records) != 1 || len(c.originals) != 1 || len(c.spans) < 3 {
		t.Fatal("fleet retained in memory or chunk proof missing")
	}
	for _, span := range c.spans {
		b, err := os.ReadFile(filepath.Join(c.out, span["file"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > audittransport.ChunkBytes || availabilityHash(b) != span["originalSHA256"] {
			t.Fatal("chunk evidence unbounded or changed")
		}
	}
	drainAppend(t, path, []byte("{invalid-fleet-row}\n"))
	if err := c.update(context.Background()); err == nil {
		t.Fatal("non-target malformed complete row skipped")
	}
}
