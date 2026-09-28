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

// A tail beginning five bytes before a 1MiB boundary has no delimiter in its
// first authenticated suffix. Valid large rows continue into the next chunk.
func TestDrainCursorInitialTinySuffixCrossesAlignedChunk(t *testing.T) {
	c, path := drainCursorFixture(t)
	makeRow := func(size int) []byte {
		row := audit.Record{Kind: "phorvex.decision", Time: time.Now().UTC(), Reason: ""}
		row.Reason = strings.Repeat("r", size-len(drainJSON(row))-1)
		return append(drainJSON(row), '\n')
	}
	desired := 17*audittransport.ChunkBytes - 5
	raw := append(makeRow(500000), makeRow(700000)...)
	for desired-len(raw) > audittransport.ChunkBytes {
		raw = append(raw, makeRow(600000)...)
	}
	raw = append(raw, makeRow(desired-len(raw))...)
	if bytes.IndexByte(raw[audittransport.ChunkBytes-5:audittransport.ChunkBytes], '\n') >= 0 {
		t.Fatal("fixture lacks tiny partial suffix")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p := drainTestProfile()
	s := NewServer(Config{AuditSource: c.source, AuditSourceIdentity: c.identity})
	got, err := s.newDrainAuditCursor(context.Background(), t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	if got.skipLeading || len(got.records) != 1 || got.offset != int64(desired) || got.skippedLeadingBytes <= 5 {
		t.Fatal("initial partial row lost or complete coverage missing")
	}
	var captured []byte
	for _, span := range got.spans {
		b, err := os.ReadFile(filepath.Join(got.out, span["file"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		captured = append(captured, b...)
	}
	if !bytes.Equal(captured, raw[audittransport.ChunkBytes-5:]) {
		t.Fatal("initial raw bytes skipped from source proof")
	}
}

func TestDrainCursorLeadingSkipPersistsAcrossTransientAndRejectsLaterMalformed(t *testing.T) {
	c, path := drainCursorFixture(t)
	row := audit.Record{Kind: "phorvex.decision", Time: time.Now().UTC(), Reason: strings.Repeat("r", 800000)}
	raw := append(drainJSON(row), '\n')
	raw = append(raw, raw...)
	raw = append(raw, []byte("{invalid-complete-row}\n")...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := c.source.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.segment = manifest.Segments[0]
	c.offset = audittransport.ChunkBytes - 5
	c.records = nil
	c.originals = nil
	c.spans = nil
	c.sequence = 0
	c.out = t.TempDir()
	c.pending = nil
	first := c.segment
	first.Size = audittransport.ChunkBytes
	if err = c.consume(context.Background(), first, true); err != nil {
		t.Fatal(err)
	}
	if !c.skipLeading || c.skippedLeadingBytes != 5 || c.offset != audittransport.ChunkBytes {
		t.Fatal("partial first suffix not committed")
	}
	if err = os.Rename(path, path+".hidden"); err != nil {
		t.Fatal(err)
	}
	if err = c.update(context.Background()); !drainAuditRetry(err) || !c.skipLeading {
		t.Fatalf("transient lost skip state: %v", err)
	}
	if err = os.Rename(path+".hidden", path); err != nil {
		t.Fatal(err)
	}
	if err = c.update(context.Background()); err == nil || drainAuditRetry(err) {
		t.Fatalf("later malformed row skipped: %v", err)
	}
	if c.offset != audittransport.ChunkBytes || !c.skipLeading {
		t.Fatal("failed later row committed incomplete state")
	}
}

func TestDrainCursorOversizedLeadingSuffixAndRotationRemainClosed(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(fmt.Sprint(rotate), func(t *testing.T) {
			c, path := drainCursorFixture(t)
			raw := bytes.Repeat([]byte{'r'}, 2*audittransport.ChunkBytes+100)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			m, err := c.source.Manifest(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			c.segment = m.Segments[0]
			c.offset = audittransport.ChunkBytes - 5
			c.records = nil
			c.originals = nil
			c.spans = nil
			c.sequence = 0
			c.out = t.TempDir()
			c.pending = nil
			first := c.segment
			first.Size = audittransport.ChunkBytes
			if err = c.consume(context.Background(), first, true); err != nil {
				t.Fatal(err)
			}
			if rotate {
				if err := os.Truncate(path, int64(audittransport.ChunkBytes)); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".1"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(drainJSON(audit.Record{Kind: "phorvex.decision", Time: time.Now().UTC()}), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = c.update(context.Background())
			if err == nil || (rotate && !drainAuditRetry(err)) || (!rotate && drainAuditRetry(err)) || !c.skipLeading {
				t.Fatalf("unbounded leading suffix/rotation accepted: %v", err)
			}
		})
	}
}
