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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
)

// isVClusterContext reports whether a kubeconfig context names a vCluster (vs the EKS host). The ONE
// place provider routing is decided, shared by the audit/cost/uptime scoping.
func isVClusterContext(ctxName string) bool {
	lc := strings.ToLower(ctxName)
	return strings.Contains(lc, "vcluster") || strings.Contains(lc, "vc-")
}

// auditPathForContext returns the decision-audit file for a kubeconfig context, so Live Ops can be
// SCOPED per provider. Each provider's operator writes its OWN audit file: a vCluster context reads
// phorvex-live-vcluster.jsonl (alongside the default), everything else (EKS) reads the default
// AuditPath. An empty/unknown context falls back to the default — never a mixed cross-provider view.
func (c Config) auditPathForContext(ctxName string) string {
	if c.AuditSource != nil {
		if isVClusterContext(ctxName) {
			return "audit://vcluster-live"
		}
		return "audit://live"
	}
	base := c.AuditPath
	if base == "" {
		return base
	}
	if isVClusterContext(ctxName) {
		return filepath.Join(filepath.Dir(base), "phorvex-live-vcluster.jsonl")
	}
	return base
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	if !liveCanFlush(w) {
		writeJSON(w, 500, map[string]string{"error": "streaming unsupported"})
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	writeBudget := s.liveWriteBudget
	if writeBudget <= 0 {
		writeBudget = liveWriteTimeout
	}
	send := func(sendCtx context.Context, body []byte) bool {
		if sendCtx.Err() != nil {
			cancel()
			return false
		}
		return liveSSEWrite(sendCtx, w, body, cancel, writeBudget)
	}
	// The projection comes from the GRANT, narrowed by any lens the request asked for. It is not
	// a header the caller chooses: an operator lens on an owner-only grant stays owner.
	p := principalOf(r)
	lens := lensOfRequest(r)
	// [M-136] Tenant scoping for the stream. An owner lens must name one of ITS granted tenants;
	// an investor/operator lens streams only the tenants its grant covers, so an omitted or
	// mismatched ?tenant= yields nothing rather than every tenant's decisions.
	askedTenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	if askedTenant != "" && !p.AllowsTenant(askedTenant) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "tenant " + askedTenant + " is outside this identity's tenant scope"})
		return
	}
	if lens == string(RoleOwner) && askedTenant == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "select a tenant to stream owner events"})
		return
	}
	if lens != string(RoleOwner) && !p.CanRead() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": accessDenialMessage(accessRead)})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// SCOPED per provider: ?context=<kubeconfig-context> selects which operator's audit to stream
	// (EKS vs vCluster), so the dashboard shows ONLY the selected provider's decisions.
	path := s.liveAuditPath(r)
	ownerTenant := askedTenant // [P4c F4] owner stream is tenant-scoped
	// inScope is the cross-tenant control for EVERY lens, not just owner.
	inScope := func(rec audit.Record) bool {
		if askedTenant != "" {
			return rec.Tenant == askedTenant
		}
		return p.TenantWildcard() || p.AllowsTenant(rec.Tenant)
	}
	// ?namespace=<ns> narrows the investor/operator stream to one namespace. It is a volume
	// control, not an access control: it only drops records inScope already lets the caller
	// read, and it never widens anything. The E2E post-attack capture uses it — on a cluster
	// with a dozen tenants the unfiltered stream runs at hundreds of KB/s (each decision
	// carries its full trace) and exhausts the pipeline's byte cap before the observation
	// window ends, while the checks only read the target namespace. The owner lens ignores it:
	// its tenant scope stays fail-closed and is never widened or replaced.
	namespace := r.URL.Query().Get("namespace")
	inNamespace := func(rec audit.Record) bool {
		return lens == "owner" || namespace == "" || rec.Namespace == namespace
	}
	visible := func(rec audit.Record) bool {
		if rec.Kind != "phorvex.decision" || !inScope(rec) || !inNamespace(rec) {
			return false
		}
		return lens != "owner" || (ownerTenant != "" && rec.Tenant == ownerTenant && (rec.Selected || rec.Actuated))
	}
	noticeScoped := func(writeCtx context.Context, message string) {
		b, _ := json.Marshal(map[string]string{"message": message})
		send(writeCtx, []byte("event: notice\ndata: "+string(b)+"\n\n"))
	}
	emitScoped := func(writeCtx context.Context, rec audit.Record) {
		if rec.Kind != "phorvex.decision" {
			return
		}
		// The same tenant control applies on the tailing path, not just the replay path.
		if !inScope(rec) {
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
			if !inNamespace(rec) {
				return
			}
			payload = rec // investor/operator get the full internals
		}
		b, _ := json.Marshal(payload)
		send(writeCtx, []byte("data: "+string(b)+"\n\n"))
	}

	notice := func(message string) { noticeScoped(ctx, message) }
	emit := func(rec audit.Record) { emitScoped(ctx, rec) }

	// initial heartbeat so the client connects even with no audit yet.
	if !send(ctx, []byte(": connected\n\n")) {
		return
	}

	// TAIL-ONLY initial replay: after the operator has run for hours the audit can hold tens of
	// thousands of records — replaying ALL of them on connect floods the page ("fast train").
	// Instead we replay only the last ?tail=N decisions (default 80), then tail live. tail=0 or
	// tail=all replays everything (opt-in).
	tail := 80
	if v := r.URL.Query().Get("tail"); v != "" {
		if v == "all" || v == "0" {
			tail = 0
		} else if n, err := strconv.Atoi(v); err == nil && n > 0 {
			tail = n
		}
	}
	if tail > 1000 {
		tail = 1000
		notice("Replay is limited to 1000 records; use /api/live/history for older decisions.")
	}
	if s.cfg.AuditSource != nil {
		s.remoteLive(r, path, tail, visible, emitScoped, noticeScoped)
		return
	}
	var previous os.FileInfo
	var offset int64
	var anchor string
	skipping := false
	if f, e := openAuditFile(path); e == nil {
		previous, _ = f.Stat()
		if tail <= 0 {
			offset, anchor = streamAuditFile(f, 0, &skipping, emit, notice)
		} else {
			offset, anchor = replayAuditFile(f, tail, visible, emit, notice)
		}
		f.Close()
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		if f, e := openAuditFile(path); e == nil {
			st, _ := f.Stat()
			current, e := auditAnchor(f, offset)
			if previous != nil && (st == nil || !os.SameFile(previous, st) || e != nil || current != anchor) {
				offset = 0
				skipping = false
				previous = st
				notice("Audit replaced or truncated; following the current file. Retained history is available at /api/live/history.")
			}
			// Identity, offset reads and anchor all belong to this SAME handle.
			// A writer may rename the path during emit/Flush without blessing a
			// different generation's prefix as already consumed.
			offset, anchor = streamAuditFile(f, offset, &skipping, emit, notice)
			previous = st
			f.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) remoteLive(r *http.Request, path string, tail int, visible func(audit.Record) bool, emitScoped func(context.Context, audit.Record), noticeScoped func(context.Context, string)) {
	ctx := r.Context()
	source := s.cfg.AuditSource
	id := strings.TrimPrefix(path, "audit://")
	find := func(m audittransport.Manifest, id string) (audittransport.Segment, bool) {
		for _, seg := range m.Segments {
			if seg.ID == id {
				return seg, true
			}
		}
		return audittransport.Segment{}, false
	}
	var live audittransport.Segment
	var offset int64
	var anchor string
	skipping := false
	if err := s.withLiveAuditRead(ctx, func(readCtx context.Context) error {
		emit := func(rec audit.Record) { emitScoped(readCtx, rec) }
		notice := func(message string) { noticeScoped(readCtx, message) }
		m, e := source.Manifest(readCtx)
		if e != nil {
			notice("Live audit source unavailable: " + e.Error())
			return errors.New("live audit replay unavailable")
		}
		var ok bool
		live, ok = find(m, id)
		if !ok {
			notice("Configured provider audit source unavailable.")
			return errors.New("live audit replay unavailable")
		}
		f := source.Open(readCtx, live)
		if tail <= 0 {
			offset, anchor = streamAuditFile(f, 0, &skipping, emit, notice)
		} else {
			offset, anchor = replayAuditFile(f, tail, visible, emit, notice)
		}
		if e = f.Verify(); e != nil {
			notice("Live audit replay changed; reconnect to recover history.")
			return errors.New("live audit replay unavailable")
		}
		return nil
	}); err != nil {
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := s.withLiveAuditRead(ctx, func(readCtx context.Context) error {
			emit := func(rec audit.Record) { emitScoped(readCtx, rec) }
			notice := func(message string) { noticeScoped(readCtx, message) }
			m, e := source.Manifest(readCtx)
			if e != nil {
				notice("Live audit source unavailable; reconnect after recovery.")
				return errors.New("live audit poll unavailable")
			}
			newLive, found := find(m, id)
			if !found {
				notice("Configured provider audit source unavailable.")
				return errors.New("live audit poll unavailable")
			}
			if newLive.Generation != live.Generation {
				// Finish any records committed just before rotation from the retained
				// copy, then start the new live file at zero. A missing old segment is
				// a visible retention gap, never an empty verified replay.
				old, retained := audittransport.Segment{}, false
				for _, seg := range m.Segments {
					if seg.Generation == live.Generation && strings.HasPrefix(seg.ID, strings.TrimSuffix(id, "live")+"backup-") {
						old = seg
						retained = true
						break
					}
				}
				if !retained {
					notice("Audit generation lost before reconnect; refresh retained history.")
					return errors.New("live audit poll unavailable")
				}
				if old.ID != strings.TrimSuffix(id, "live")+"backup-1" {
					notice("More than one audit rotation occurred between live polls; refresh paged retained history to recover intervening decisions.")
					return errors.New("live audit poll unavailable")
				}
				oldReader := source.Open(readCtx, old)
				if offset > old.Size {
					notice("Audit generation truncated during rotation.")
					return errors.New("live audit poll unavailable")
				}
				offset, _ = streamAuditFile(oldReader, offset, &skipping, emit, notice)
				if e = oldReader.Verify(); e != nil {
					notice("Retained audit generation changed during rotation.")
					return errors.New("live audit poll unavailable")
				}
				live = newLive
				offset = 0
				anchor = ""
				skipping = false
			} else if newLive.Size < offset {
				notice("Audit truncated; reconnect and refresh history.")
				return errors.New("live audit poll unavailable")
			} else {
				live = newLive
			}
			reader := source.Open(readCtx, live)
			if offset > 0 {
				current, ae := auditAnchor(reader, offset)
				if ae != nil || current != anchor {
					notice("Audit append boundary changed; reconnect and refresh history.")
					return errors.New("live audit poll unavailable")
				}
			}
			offset, anchor = streamAuditFile(reader, offset, &skipping, emit, notice)
			if e = reader.Verify(); e != nil {
				notice("Live audit generation changed during read; reconnect.")
				return errors.New("live audit poll unavailable")
			}
			return nil
		}); err != nil {
			return
		}
	}
}

// tailReplay emits only the last n phorvex.decision records from the audit and returns the byte
// offset at end-of-file so the caller can tail from there. It reads ONLY the tail chunk of the
// file (not the whole thing) — on a multi-hundred-MB audit this is the difference between an
// instant page load and a multi-second flood. n<=0 replays everything (opt-in, slow path).
func tailReplay(path string, n int, emit func(audit.Record)) int64 {
	return replayAudit(path, n, func(rec audit.Record) bool { return rec.Kind == "phorvex.decision" }, emit, func(string) {})
}

func replayAudit(path string, n int, visible func(audit.Record) bool, emit func(audit.Record), notice func(string)) int64 {
	if path == "" {
		return 0
	}
	f, err := openAuditFile(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	offset, _ := replayAuditFile(f, n, visible, emit, notice)
	return offset
}

func replayAuditFile(f auditHandle, n int, visible func(audit.Record) bool, emit func(audit.Record), notice func(string)) (int64, string) {
	st, err := f.Stat()
	if err != nil {
		return 0, ""
	}
	size := st.Size()
	if n <= 0 {
		skipping := false
		return streamAuditFile(f, 0, &skipping, emit, notice)
	}
	rd := reverseAuditReader{f: f, pos: size}
	// Only newline-committed records are replayed. Leave an incomplete final
	// record for the forward tailer once the producer finishes its write.
	complete := size
	for complete > 0 {
		b, e := rd.byteBefore()
		if e != nil {
			notice("Audit replay read failed.")
			return 0, ""
		}
		if b == '\n' {
			complete = rd.pos + 1
			break
		}
		complete = rd.pos
		if rd.read >= historyScanBytes {
			notice("Incomplete audit suffix exceeds scan budget; history is partial.")
			return 0, ""
		}
	}
	rd.pos = complete
	var recs []audit.Record
	for rd.pos > 0 && len(recs) < n && rd.read < 32<<20 {
		ln, _, large, e := rd.next(32 << 20)
		if e != nil {
			notice("Audit replay changed while reading.")
			break
		}
		if large {
			notice("Audit record exceeds 1 MiB and was omitted from replay.")
		}
		var rec audit.Record
		if json.Unmarshal(ln, &rec) == nil && visible(rec) {
			recs = append(recs, rec)
		}
	}
	if rd.pos > 0 && len(recs) < n {
		notice("Replay scan budget reached; use /api/live/history to continue older records.")
	}
	// Capture the bytes before Flush can race an in-place truncation/rewrite.
	anchor, _ := auditAnchor(f, complete)
	for i := len(recs) - 1; i >= 0; i-- {
		emit(recs[i])
	}
	return complete, anchor
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
	if s.cfg.AuditSource != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "audit clear is unavailable in remote read-only mode; use the manager's retention procedure"})
		return
	}
	path := s.cfg.auditPathForContext(r.URL.Query().Get("context"))
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
	skipping := false
	return streamAudit(path, offset, &skipping, emit, func(string) {})
}

func streamAudit(path string, offset int64, skipping *bool, emit func(audit.Record), notice func(string)) int64 {
	if path == "" {
		return offset
	}
	f, err := openAuditFile(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	n, _ := streamAuditFile(f, offset, skipping, emit, notice)
	return n
}

func streamAuditFile(f auditHandle, offset int64, skipping *bool, emit func(audit.Record), notice func(string)) (int64, string) {
	if st, e := f.Stat(); e == nil && st.Size() < offset {
		offset = 0
		*skipping = false
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return offset, ""
	}
	rd := bufio.NewReaderSize(io.LimitReader(f, historyScanBytes), 65536)
	committed := offset
	committedAnchor, _ := auditAnchor(f, committed)
	var read int64
	var line []byte
	for {
		part, e := rd.ReadSlice('\n')
		read += int64(len(part))
		if !*skipping {
			if len(line)+len(part) > liveRecordBytes {
				*skipping = true
				line = nil
				notice("Audit record exceeds 1 MiB and was omitted from the stream.")
			} else {
				line = append(line, part...)
			}
		}
		if e == nil {
			committed = offset + read
			committedAnchor, _ = auditAnchor(f, committed)
			if !*skipping {
				var rec audit.Record
				if json.Unmarshal(line, &rec) == nil {
					emit(rec)
					if current, e := auditAnchor(f, committed); e != nil || current != committedAnchor {
						return committed, committedAnchor
					}
				}
			}
			line = nil
			*skipping = false
		} else if e != bufio.ErrBufferFull {
			if *skipping {
				committed = offset + read
				committedAnchor, _ = auditAnchor(f, committed)
			}
			if e != io.EOF {
				notice("Audit stream read failed.")
			}
			if read >= historyScanBytes {
				notice("Stream scan budget reached; continuing on the next tick.")
			}
			return committed, committedAnchor
		}
	}
}
