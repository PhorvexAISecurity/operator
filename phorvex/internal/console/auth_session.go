/*
 * Phorvex Console — GET /api/session (M-136).
 *
 * The SPA needs to know what the signed-in identity may actually do, so it can render the lenses
 * and controls the grant supports and give a clear reason when something is unavailable, instead
 * of showing every control and letting each click fail with an opaque 403.
 *
 * This is a CONVENIENCE, not the boundary. Every field here is derived from the same verified
 * principal the middleware already enforced, and the server re-checks on every request: a client
 * that ignores this endpoint gains nothing. It deliberately returns no token, no credential and
 * no other subject's grant.
 */

package console

import "net/http"

type sessionResponse struct {
	Subject string   `json:"subject"`
	Issuer  string   `json:"issuer"`
	Source  string   `json:"source"` // "alb" | "bearer"
	Roles   []string `json:"roles"`
	Tenants []string `json:"tenants"`
	Targets []string `json:"targets"`
	Lens    string   `json:"lens"`    // effective projection for this request
	CanRead bool     `json:"canRead"` // may read the evidence/aggregate group
	CanEdit bool     `json:"canEdit"` // may reach controls and cluster writes
	Modes   []string `json:"authModes"`
	// GrantsConfigured is false when the deployment has bound no subjects at all — the visible
	// form of the rollout prerequisite ("DevOps must supply the subject grants").
	GrantsConfigured    bool     `json:"grantsConfigured"`
	AuditClearAvailable bool     `json:"auditClearAvailable"`
	TrustedOrigins      []string `json:"trustedOrigins"`
	Note                string   `json:"note"`
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if p == nil { // unreachable through the guard; still answered fail-closed rather than panicking
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	roles := make([]string, 0, len(p.Roles))
	for _, role := range p.Roles {
		roles = append(roles, string(role))
	}
	resp := sessionResponse{
		Subject: p.Subject, Issuer: p.Issuer, Source: p.Source,
		Roles:   roles,
		Tenants: append([]string(nil), p.Tenants...),
		Targets: append([]string(nil), p.Targets...),
		Lens:    lensOfRequest(r),
		CanRead: p.CanRead(), CanEdit: p.CanOperate(),
		AuditClearAvailable: s.cfg.AuditSource == nil,
		Note:                "Roles and scope are server-side grants. A lens may narrow this view; it can never widen it.",
	}
	if s.auth != nil {
		resp.Modes = s.auth.Modes()
		resp.GrantsConfigured = s.auth.GrantCount() > 0
		resp.TrustedOrigins = s.auth.TrustedOrigins()
	}
	writeJSON(w, http.StatusOK, resp)
}
