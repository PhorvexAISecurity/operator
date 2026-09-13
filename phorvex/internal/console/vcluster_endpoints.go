/*
 * Phorvex — the safe apply-fix write-path (submit / two-key approve) behind the verified
 * identity boundary and the per-tenant quota.
 *
 * The demo-trust fallback that used to live here — `?user=` and `?tenant=` when no IdP was
 * configured — is GONE. It was reachable in the shipped default, it made the requester and the
 * tenant self-asserted, and it meant a misconfigured IdP downgraded into an anonymous write
 * path. Identity now comes from the request principal the boundary verified, and the tenant
 * comes from that principal's grant.
 *
 * The two-principal approval safety (a submit and its approval must come from DISTINCT
 * subjects) is unchanged, and rests on verified subjects rather than a query parameter.
 *
 * Approval contract (M-166): an approval names the tenant it acts on (resolved through the grant
 * exactly like a submit — a body or query tenant can never widen scope) and the exact generation
 * the pending listing reported. The response's `status` is what THIS call did; only
 * `status: "applied"` means the applier accepted the candidate. See docs/CONSOLE-APPLY-FIX.md.
 */

package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// requestTenant resolves WHICH granted tenant this request acts on.
//
//   - an explicit ?tenant= (or body "tenant") must be inside the grant;
//   - with no explicit value and exactly one granted tenant, that tenant is used;
//   - with several granted tenants, or a wildcard grant, the caller must say which one — an
//     ambiguous write must not silently pick a tenant on the operator's behalf.
func requestTenant(r *http.Request, bodyTenant string) (string, string) {
	p := principalOf(r)
	if p == nil {
		return "", "unauthenticated"
	}
	asked := strings.TrimSpace(r.URL.Query().Get("tenant"))
	if asked == "" {
		asked = strings.TrimSpace(bodyTenant)
	}
	if asked != "" {
		if !p.AllowsTenant(asked) {
			return "", "tenant " + asked + " is outside this identity's tenant scope"
		}
		return asked, ""
	}
	var only string
	for _, t := range p.Tenants {
		if t == wildcardScope {
			return "", "this identity holds a cross-tenant grant; name the tenant explicitly with ?tenant="
		}
		if only != "" {
			return "", "this identity is granted several tenants; name the one to act on with ?tenant="
		}
		only = t
	}
	if only == "" {
		return "", "this identity is granted no tenant scope"
	}
	return only, ""
}

func (s *Server) applyFixSubmit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID     string        `json:"id"`
		Tenant string        `json:"tenant"`
		Delta  ApplyFixDelta `json:"delta"`
		Reason string        `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "bad body (need id + delta)"})
		return
	}
	tenant, why := requestTenant(r, body.Tenant)
	if tenant == "" {
		writeJSON(w, 403, map[string]string{"error": why})
		return
	}
	if s.quota != nil && !s.quota.Allow(tenant) {
		writeJSON(w, 429, map[string]string{"error": "tenant rate-limited (per-tenant quota exhausted)"})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 501, map[string]string{"error": "apply-fix write-path not enabled"})
		return
	}
	// tenant/namespace/requester from the VERIFIED identity and its grant, NEVER the body.
	req := ApplyFixRequest{ID: body.ID, Tenant: tenant, Namespace: tenant, Delta: body.Delta, Reason: body.Reason, Requester: actorOf(r)}
	res, err := s.applyfix.Submit(req)
	switch {
	case errors.Is(err, ErrApplyFixConflict):
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	case errors.Is(err, ErrApplyFixCapacity):
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, 422, map[string]string{"error": err.Error()}) // allowlist or safety-gate rejection
		return
	}
	status := string(res.State)
	if res.State == ApplyFixPending {
		status = "pending-approval"
	}
	writeJSON(w, 200, map[string]any{"status": status, "id": res.ID, "tenant": res.Tenant, "generation": res.Generation,
		"existing": res.Existing, "note": "two-key: requires a DISTINCT approver naming this generation"})
}

func (s *Server) applyFixApprove(w http.ResponseWriter, r *http.Request) {
	if s.applyfix == nil {
		writeJSON(w, 501, map[string]string{"error": "apply-fix write-path not enabled"})
		return
	}
	var body struct {
		ID         string `json:"id"`
		Tenant     string `json:"tenant"`
		Generation string `json:"generation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" || body.Generation == "" {
		writeJSON(w, 400, map[string]string{"error": "bad body (need id + generation from the pending listing)"})
		return
	}
	// The tenant is resolved through the grant exactly as for a submit: a body/query tenant is a
	// SELECTION among granted tenants, never a widening, and a multi/wildcard grant must name one.
	tenant, why := requestTenant(r, body.Tenant)
	if tenant == "" {
		writeJSON(w, 403, map[string]string{"error": why})
		return
	}
	// The approver is the verified subject. Two-key safety is unchanged: the manager refuses an
	// approval from the same identity that submitted.
	res, err := s.applyfix.Approve(tenant, body.ID, body.Generation, actorOf(r))
	code, status := approveOutcome(err)
	out := map[string]any{"status": status, "id": res.ID, "tenant": res.Tenant, "generation": res.Generation,
		"state": string(res.State), "approver": res.Approver, "retry": res.Retry}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, code, out)
}

// approveOutcome maps ONE approval call's result to an HTTP code and the product status the UI
// interprets. Every path is explicit; only a nil error is "applied".
func approveOutcome(err error) (int, string) {
	switch {
	case err == nil:
		return 200, "applied"
	case errors.Is(err, ErrApplyFixNotFound):
		return 404, "not-found"
	case errors.Is(err, ErrApplyFixGeneration):
		return 409, "stale-generation"
	case errors.Is(err, ErrApplyFixInProgress):
		return 409, "in-progress"
	case errors.Is(err, ErrApplyFixTerminal):
		return 409, "conflict"
	case errors.Is(err, ErrApplyFixStaleBase):
		return 409, "stale"
	case errors.Is(err, ErrApplyFixTwoKey):
		return 422, "refused"
	case errors.Is(err, ErrApplyFixGateRefused):
		return 422, "rejected"
	case errors.Is(err, ErrApplyFixNoApplier):
		return 501, "applier-unavailable"
	case errors.Is(err, ErrApplyFixApplyFailed):
		return 500, "failed"
	}
	return 400, "invalid"
}

// applyFixGatePreview runs the allowlist + safety gate on a candidate WITHOUT staging it — the UI
// shows "will this pass 1.62×/P3/no-harm?" before the tenant commits. Read-only.
func (s *Server) applyFixGatePreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tenant string        `json:"tenant"`
		Delta  ApplyFixDelta `json:"delta"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad body"})
		return
	}
	tenant, why := requestTenant(r, body.Tenant)
	if tenant == "" {
		writeJSON(w, 403, map[string]string{"error": why})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 501, map[string]string{"error": "apply-fix not enabled"})
		return
	}
	pass, reason := s.applyfix.GatePreview(tenant, body.Delta)
	writeJSON(w, 200, map[string]any{"pass": pass, "reason": reason})
}

func (s *Server) applyFixPending(w http.ResponseWriter, r *http.Request) {
	tenant, why := requestTenant(r, "")
	if tenant == "" {
		writeJSON(w, 403, map[string]string{"error": why})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 200, map[string]any{"pending": []any{}, "applierMode": "disabled", "applierWired": false})
		return
	}
	// applierWired is the truth an approval will act on; applierMode is only the deployment's label.
	writeJSON(w, 200, map[string]any{"pending": s.applyfix.Pending(tenant), "applierMode": s.applyfix.ApplierMode, "applierWired": s.applyfix.Apply != nil})
}

func (s *Server) applyFixAudit(w http.ResponseWriter, r *http.Request) {
	tenant, why := requestTenant(r, "")
	if tenant == "" {
		writeJSON(w, 403, map[string]string{"error": why})
		return
	}
	if s.applyfix == nil {
		writeJSON(w, 200, map[string]any{"audit": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{"audit": s.applyfix.AuditTrail(tenant)})
}
