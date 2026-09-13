/*
 * Phorvex Console — the verified principal (M-136).
 *
 * A Principal is what the console knows about a caller AFTER a credential has been
 * cryptographically verified AND the deployment's grant table has been consulted. Both halves
 * are load-bearing:
 *
 *   - authentication (auth_alb.go / auth_bearer.go) proves WHICH issuer+subject is calling;
 *   - authorization (auth_grants.go) says what that issuer+subject may do.
 *
 * Nothing here is ever derived from a request header, query parameter or body. The old
 * X-Phorvex-Lens / ?lens= / ?user= / ?tenant= inputs are presentation hints at most: a lens may
 * NARROW what a principal sees, it can never widen it, and it is not an identity.
 */

package console

import (
	"context"
	"net/http"
	"strings"
)

// Role is a server-granted authorization role. Roles come ONLY from the grant table, keyed by
// verified issuer+subject — never from a token claim (the shipped Cognito user pool carries no
// role/tenant custom claims) and never from the request.
type Role string

const (
	// RoleOwner is a customer-owner: owner-safe projections of its own granted tenants only.
	RoleOwner Role = "owner"
	// RoleInvestor is vendor-side read: the granted evidence and aggregates, and no mutation.
	RoleInvestor Role = "investor"
	// RoleOperator is the only role that may reach controls, within its granted tenant/target scope.
	RoleOperator Role = "operator"
)

// wildcardScope widens a grant's tenants/targets to every tenant/target. DevOps has to write it
// out; an empty list never implies it. An empty list grants nothing (fail closed).
const wildcardScope = "*"

// defaultTargetID names "the cluster this console runs on" — the target a request selects by
// omitting ?target=/?context=. A grant must list it (or the wildcard) to reach that cluster, so
// an omitted parameter can never silently escape the configured scope.
const defaultTargetID = "default"

// inClusterTargetID is what ClusterTargets() emits for that SAME cluster when the console runs as
// a pod with no kubeconfig, and it is what the dashboard's selector then sends back. It names the
// same resource as defaultTargetID and as an omitted parameter.
//
// All three spellings are reconciled in exactly one place — normalizeTargetID — so a grant
// written as the documented ["default"] covers the id the UI actually sends, and the credential
// resolver recognises the same alias set. Letting them drift meant a documented default grant
// denied the console's own cluster.
const inClusterTargetID = "in-cluster"

// isLocalTargetAlias reports whether a target name refers to this console's own cluster.
func isLocalTargetAlias(s string) bool {
	switch strings.TrimSpace(s) {
	case "", inClusterTargetID, defaultTargetID:
		return true
	}
	return false
}

// Principal is an authenticated, authorized console caller.
type Principal struct {
	Issuer  string // verified token issuer (ALB: the Cognito user-pool issuer)
	Subject string // verified `sub` — the identifier the grant table is keyed by
	Source  string // "alb" | "bearer": which verified credential carried the subject
	Roles   []Role
	Tenants []string // tenant / namespace scope; may be []string{wildcardScope}
	Targets []string // cluster target scope; may be []string{wildcardScope}
	// Lens is an informational snapshot of the projection resolved when the request was
	// authenticated. Handlers call lensOfRequest instead, which recomputes it, so this field can
	// never be the thing that decides what a handler renders.
	Lens string
}

// normalizeTargetID maps every spelling of "this console's own cluster" — omitted, "in-cluster",
// or the "default" sentinel — onto one id, so scope checks never treat "unspecified" as
// "unrestricted" and never treat two names for one cluster as two different clusters.
func normalizeTargetID(s string) string {
	t := strings.TrimSpace(s)
	if isLocalTargetAlias(t) {
		return defaultTargetID
	}
	return t
}

func scopeContains(scope []string, want string) bool {
	for _, s := range scope {
		if s == wildcardScope || s == want {
			return true
		}
	}
	return false
}

// HasRole reports whether the grant table gave this principal the role.
func (p *Principal) HasRole(r Role) bool {
	if p == nil {
		return false
	}
	for _, have := range p.Roles {
		if have == r {
			return true
		}
	}
	return false
}

// CanRead reports whether the principal may read the vendor/operator data group.
func (p *Principal) CanRead() bool { return p.HasRole(RoleInvestor) || p.HasRole(RoleOperator) }

// CanOperate reports whether the principal may reach controls. Investor is read-only by
// construction: it never satisfies this.
func (p *Principal) CanOperate() bool { return p.HasRole(RoleOperator) }

// AllowsTenant reports whether a tenant/namespace is inside the principal's granted scope. An
// EMPTY tenant is never allowed: an omitted ?tenant= must not read every tenant.
func (p *Principal) AllowsTenant(tenant string) bool {
	if p == nil {
		return false
	}
	tenant = strings.TrimSpace(tenant)
	if tenant == "" || tenant == wildcardScope {
		return false
	}
	return scopeContains(p.Tenants, tenant)
}

// AllowsTarget reports whether a cluster target/context is inside the principal's granted scope.
// An omitted target is the explicit default-target id, not "any".
func (p *Principal) AllowsTarget(target string) bool {
	if p == nil {
		return false
	}
	t := normalizeTargetID(target)
	if t == wildcardScope {
		return false
	}
	return scopeContains(p.Targets, t)
}

// TenantWildcard reports whether the principal holds cross-tenant scope. Cluster-wide listings
// are filtered to the granted tenants unless this is true.
func (p *Principal) TenantWildcard() bool { return p != nil && scopeContains(p.Tenants, wildcardScope) }

// TargetWildcard reports whether the principal holds cross-target scope.
func (p *Principal) TargetWildcard() bool { return p != nil && scopeContains(p.Targets, wildcardScope) }

// defaultLens is the most capable lens the grant supports.
func (p *Principal) defaultLens() string {
	switch {
	case p.HasRole(RoleOperator):
		return string(RoleOperator)
	case p.HasRole(RoleInvestor):
		return string(RoleInvestor)
	default:
		return string(RoleOwner)
	}
}

// effectiveLens resolves the presentation lens. A request may ask for a lens at or below its
// grant; asking for one it does not hold does NOT widen anything — the grant's own lens is used.
// "owner" is the narrowest projection and is therefore always honoured.
func (p *Principal) effectiveLens(requested string) string {
	switch requested {
	case string(RoleOwner):
		return string(RoleOwner)
	case string(RoleOperator):
		if p.HasRole(RoleOperator) {
			return string(RoleOperator)
		}
	case string(RoleInvestor):
		if p.HasRole(RoleInvestor) {
			return string(RoleInvestor)
		}
	}
	return p.defaultLens()
}

// requestedLens reads the presentation hint. It is NOT an identity and NOT a credential; an
// unknown or absent value simply means "no narrowing requested".
func requestedLens(r *http.Request) string {
	l := r.Header.Get("X-Phorvex-Lens")
	if l == "" {
		l = r.URL.Query().Get("lens")
	}
	switch l {
	case string(RoleInvestor), string(RoleOperator), string(RoleOwner):
		return l
	default:
		return ""
	}
}

type principalCtxKey struct{}

func withPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// principalOf returns the verified principal the auth boundary attached. It returns nil for an
// unauthenticated request; every caller treats nil as "no roles, no scope".
func principalOf(r *http.Request) *Principal {
	if r == nil {
		return nil
	}
	p, _ := r.Context().Value(principalCtxKey{}).(*Principal)
	return p
}

// lensOfRequest is the projection a handler should render for this request. It is always
// recomputed from the grant and this request's hint — never read back from a cached field — so a
// per-request narrowing cannot be lost and a stale value cannot widen anything. Unauthenticated
// requests never reach a handler; the zero case still resolves to the owner projection.
func lensOfRequest(r *http.Request) string {
	p := principalOf(r)
	if p == nil {
		return string(RoleOwner)
	}
	return p.effectiveLens(requestedLens(r))
}

// actorOf identifies the caller for audit records: the VERIFIED subject, never a body field or
// a self-asserted lens. Qualified by issuer so two IdPs cannot collide on one subject string.
func actorOf(r *http.Request) string {
	p := principalOf(r)
	if p == nil || p.Subject == "" {
		return "unauthenticated"
	}
	if p.Issuer == "" {
		return p.Subject
	}
	return p.Issuer + "#" + p.Subject
}
