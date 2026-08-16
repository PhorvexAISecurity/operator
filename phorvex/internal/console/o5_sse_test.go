/*
 * Phorvex — P-VCLUSTER O5: the owner IP-wall must hold on the REAL SSE stream bytes (not just the
 * ToOwnerEvent projection in isolation). Drives the live() handler end-to-end and asserts the bytes
 * actually written to the wire carry NONE of the redacted IP field names.
 */

package console

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestO5_OwnerSSEStreamBytesRedacted(t *testing.T) {
	// A decision laden with IP-internal fields (recon math, λ, per-$, attribution).
	d := model.Decision{
		Tenant: "acme", Namespace: "ns", Pod: "p1", Action: model.ActionRotate,
		Selected: true, CoverageValue: 3.74, Cost: 0.57, Net: 3.18, PerDollar: 13.23, Lambda: 0.6,
		CoveredWeight: 3.74, CoveredFacts: 4, AssetValue: 100, BlastRadius: 0.5, Exposure: 9000,
		PHold: 0.9, Stage: "recon", StageHazard: 0.2, ProactiveRate: 12.6,
		ThreatPosture: 0.8, Reason: "submodular greedy picked this",
	}
	rec := audit.ToRecord(d)
	rec.Kind = "phorvex.decision"
	rec.Selected = true
	rec.Actuated = true
	b, _ := json.Marshal(rec)

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewServer(Config{AuditPath: path})
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/live?lens=owner&tenant=acme", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	go func() { time.Sleep(250 * time.Millisecond); cancel() }()
	s.live(w, req) // blocks until ctx cancelled; emits the record on the first streamNew

	body := w.Body.String()
	if !strings.Contains(body, "data:") {
		t.Fatalf("O5: the owner SSE stream emitted no decision data (cannot assert redaction):\n%s", body)
	}
	// the REAL streamed bytes must carry the owner projection and NONE of the redacted IP tokens.
	if tok, ok := mustNoIP(body); !ok {
		t.Errorf("O5 LEAK: the owner SSE stream leaked IP token %q in the REAL wire bytes:\n%s", tok, body)
	}
	// sanity: a raw Record (what a regression would emit) WOULD contain the tokens — proving the test bites.
	rawBytes, _ := json.Marshal(rec)
	if _, ok := mustNoIP("data: " + string(rawBytes)); ok {
		t.Error("O5 test is not biting: a raw Record stream should have tripped mustNoIP (the redaction list may be stale)")
	}
}
