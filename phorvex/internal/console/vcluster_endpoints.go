/*
 * Phorvex — P-VCLUSTER Pass 2 endpoints: the safe apply-fix write-path (submit/approve) behind verified
 * identity (OIDC) + per-tenant quota. Demo-trust dev fallback when OIDC is not configured.
 */

package console

import (
	"encoding/json"
	"net/http"
)

// verifiedIdentity resolves the authenticated principal. With OIDC configured it is AUTHORITATIVE — a
// forged ?tenant= is ignored (O6 closed). Absent OIDC, demo-trust dev fallback (NOT for production):
// ?user=/?tenant= self-asserted, usable only for local click-through of the two-key flow.
func (s *Server) verifiedIdentity(r *http.Request) (*VerifiedIdentity, error) {
	if s.oidc != nil {
		tok, err := bearerToken(r)
		if err != nil {
			return nil, err
		}
		return s.oidc.Verify(tok) // tenant + lens + subject come from VERIFIED claims
	}
	return &VerifiedIdentity{
		Subject: r.URL.Query().Get("user"),
		Tenant:  r.URL.Query().Get("tenant"),
		Lens:    lensOf(r),
	}, nil
}

func (s *Server) applyFixSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	id, err := s.verifiedIdentity(r)
	if err != nil || id.Tenant == "" || id.Subject == "" {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated (OIDC verification failed or no verified tenant/subject)"})
		return
	}
	if s.quota != nil && !s.quota.Allow(id.Tenant) {
		writeJSON(w, 429, map[string]string{"error": "tenant rate-limited (per-tenant quota exhausted)"})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 501, map[string]string{"error": "apply-fix write-path not enabled"})
		return
	}
	var body struct {
		ID     string        `json:"id"`
		Delta  ApplyFixDelta `json:"delta"`
		Reason string        `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "bad body (need id + delta)"})
		return
	}
	// tenant/namespace/requester from the VERIFIED identity, NEVER the body.
	req := ApplyFixRequest{ID: body.ID, Tenant: id.Tenant, Namespace: id.Tenant, Delta: body.Delta, Reason: body.Reason, Requester: id.Subject}
	if err := s.applyfix.Submit(req); err != nil {
		writeJSON(w, 422, map[string]string{"error": err.Error()}) // allowlist or safety-gate rejection
		return
	}
	writeJSON(w, 200, map[string]any{"status": "pending-approval", "id": body.ID, "note": "two-key: requires a DISTINCT approver"})
}

func (s *Server) applyFixApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	id, err := s.verifiedIdentity(r)
	if err != nil || id.Subject == "" {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated approver"})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 501, map[string]string{"error": "apply-fix write-path not enabled"})
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "bad body (need id)"})
		return
	}
	if err := s.applyfix.Approve(body.ID, id.Subject); err != nil {
		writeJSON(w, 422, map[string]string{"error": err.Error()}) // two-key violation or gate re-check
		return
	}
	writeJSON(w, 200, map[string]string{"status": "applied", "id": body.ID})
}

// applyFixGatePreview runs the allowlist + safety gate on a candidate WITHOUT staging it — the UI shows
// "will this pass 1.62×/P3/no-harm?" before the tenant commits. Read-only.
func (s *Server) applyFixGatePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	id, err := s.verifiedIdentity(r)
	if err != nil || id.Tenant == "" {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 501, map[string]string{"error": "apply-fix not enabled"})
		return
	}
	var body struct {
		Delta ApplyFixDelta `json:"delta"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad body"})
		return
	}
	pass, reason := s.applyfix.GatePreview(id.Tenant, body.Delta)
	writeJSON(w, 200, map[string]any{"pass": pass, "reason": reason})
}

func (s *Server) applyFixPending(w http.ResponseWriter, r *http.Request) {
	id, err := s.verifiedIdentity(r)
	if err != nil || id.Tenant == "" {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 200, map[string]any{"pending": []any{}, "applierMode": "disabled"})
		return
	}
	writeJSON(w, 200, map[string]any{"pending": s.applyfix.Pending(id.Tenant), "applierMode": s.applyfix.ApplierMode})
}

func (s *Server) applyFixAudit(w http.ResponseWriter, r *http.Request) {
	id, err := s.verifiedIdentity(r)
	if err != nil || id.Tenant == "" {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 200, map[string]any{"audit": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{"audit": s.applyfix.AuditTrail(id.Tenant)})
}

func (s *Server) registerVCluster(mux *http.ServeMux) {
	mux.HandleFunc("/api/apply-fix/submit", s.withCORS(s.applyFixSubmit))
	mux.HandleFunc("/api/apply-fix/approve", s.withCORS(s.applyFixApprove))
	mux.HandleFunc("/api/apply-fix/gate-preview", s.withCORS(s.applyFixGatePreview))
	mux.HandleFunc("/api/apply-fix/pending", s.withCORS(s.applyFixPending))
	mux.HandleFunc("/api/apply-fix/audit", s.withCORS(s.applyFixAudit))
}
