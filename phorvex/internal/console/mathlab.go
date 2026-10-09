package console

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/mathlab"
)

// Math Lab snapshot proxy. The console is the only mTLS client of the operator's audit
// listener, so it relays the read-only snapshot index and immutable snapshot bytes to an
// authorized reader. Nothing is cached or written: the console's history store never sees
// a snapshot, and every request is scoped to one granted namespace.

func (s *Server) mathLabSnapshots(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuditSource == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit source is not configured"})
		return
	}
	q := r.URL.Query()
	query := audittransport.MathLabSnapshotQuery{Namespace: q.Get("namespace"), Policy: q.Get("policy"), PolicyUID: q.Get("policyUID")}
	for name, dst := range map[string]*time.Time{"since": &query.Since, "until": &query.Until} {
		if raw := q.Get(name); raw != "" {
			t, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid " + name})
				return
			}
			*dst = t
		}
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 5000 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be in [1,5000]"})
			return
		}
		query.Limit = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	raw, err := s.cfg.AuditSource.MathLabSnapshots(ctx, query)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "math-lab snapshot index unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (s *Server) mathLabSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuditSource == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit source is not configured"})
		return
	}
	namespace, digest := r.URL.Query().Get("namespace"), r.URL.Query().Get("digest")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	raw, err := s.cfg.AuditSource.MathLabSnapshot(ctx, digest)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "math-lab snapshot unavailable"})
		return
	}
	// The digest alone is not an authorization: the snapshot must belong to the namespace the
	// caller was granted, or it is reported as absent.
	header, err := mathlab.ReadHeader(bytes.NewReader(raw))
	if err != nil || header.Namespace != namespace {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "math-lab snapshot unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Snapshot-Digest", digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	_, _ = w.Write(raw)
}
