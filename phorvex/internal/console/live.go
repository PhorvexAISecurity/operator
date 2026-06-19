/*
 * Phorvex Console (P-DASHBOARD-2) — LIVE OPERATIONS (Wave 2): SSE over the decision audit.
 *
 * GET /api/live (text/event-stream) replays the existing decision-audit JSONL and then
 * tails it for new records, emitting one SSE event per audit.Record. PER-LENS PROJECTION at
 * the stream boundary: Investor/Operator receive the full Record; Customer-Owner receives
 * ONLY ToOwnerEvent(rec) — the IP-wall whitelist extends to the stream, so EMR/lambda/per-$/
 * attribution can never reach the owner stream. Honest: live data is whatever the operator
 * has written to --audit-json; if none, the stream is idle (no fabrication).
 */

package console

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
)

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]string{"error": "streaming unsupported"})
		return
	}
	lens := lensOf(r) // default-deny: a missing/unknown lens streams the REDACTED owner projection
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	path := s.cfg.AuditPath
	if path == "" {
		path = s.newestAudit()
	}
	ownerTenant := r.URL.Query().Get("tenant") // [P4c F4] owner stream is tenant-scoped
	emit := func(rec audit.Record) {
		if rec.Kind != "phorvex.decision" {
			return
		}
		var payload any
		if lens == "owner" {
			if !rec.Selected && !rec.Actuated {
				return // owners see actions, not every candidate
			}
			// [P4c D7/F4 cross-tenant FIX] FAIL-CLOSED: the owner SSE streams ONLY the caller's
			// tenant; an absent/empty ?tenant= streams NOTHING (was: every tenant's actions).
			if ownerTenant == "" || rec.Tenant != ownerTenant {
				return
			}
			payload = ToOwnerEvent(rec) // <- the ONLY owner projection (never a raw Record)
		} else {
			payload = rec // investor/operator get the full internals
		}
		b, _ := json.Marshal(payload)
		_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
		flusher.Flush()
	}

	// initial heartbeat so the client connects even with no audit yet.
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	var offset int64
	ctx := r.Context()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		offset = streamNew(path, offset, emit)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// liveClear truncates the live decision-audit JSONL (operator-only). The SSE replays this
// file on connect, so emptying it clears the decision history; a still-running operator
// simply starts appending fresh records again. Honest: this deletes real audit data, so it
// is a deliberate operator action, never automatic.
func (s *Server) liveClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	path := s.cfg.AuditPath
	if path == "" {
		path = s.newestAudit()
	}
	if path == "" {
		writeJSON(w, 200, map[string]any{"cleared": false, "note": "no audit file configured"})
		return
	}
	if err := os.Truncate(path, 0); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not clear audit: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"cleared": true})
}

// streamNew reads any records appended past offset and returns the new offset.
func streamNew(path string, offset int64, emit func(audit.Record)) int64 {
	if path == "" {
		return offset
	}
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	var read int64
	for sc.Scan() {
		line := sc.Bytes()
		read += int64(len(line)) + 1
		var rec audit.Record
		if json.Unmarshal(line, &rec) == nil {
			emit(rec)
		}
	}
	return offset + read
}
