/*
 * Phorvex Console — the request trust boundary (M-136).
 *
 * Every data, stream and control API request is authenticated and authorized HERE, once, before
 * the handler runs. The rules a route declares (routes.go) are enforced in a fixed order:
 *
 *   CORS/preflight -> auth configured -> credential verified -> method -> role -> scope -> dispatch
 *
 * Consequences that are deliberate:
 *   - a handler can never be reached by an unauthenticated caller, because the mux is built from
 *     the route table and every entry goes through this wrapper;
 *   - a rejected request reaches NO handler, so a mutation dispatcher sees zero calls for it;
 *   - the tenant/target a request names is checked against the grant BEFORE the handler reads
 *     any data, so an out-of-scope identifier cannot leak a record, a count or an error that
 *     discloses one;
 *   - `Origin` is a CSRF defence for the browser/ALB path, never an authentication factor: a
 *     bearer caller (CLI) is unaffected by it.
 */

package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxScopedBodyBytes bounds the body the boundary buffers to read a scoped field out of it.
const maxScopedBodyBytes = 2 << 20

type accessLevel int

const (
	// accessAny: any granted role. Used only by the session endpoint.
	accessAny accessLevel = iota
	// accessOwnerData: the owner-projected surfaces. Any granted role may call them, and the
	// response is always confined to the caller's granted tenants.
	accessOwnerData
	// accessRead: the vendor/operator data group — investor or operator, never owner alone.
	accessRead
	// accessControl: triggers, cluster writes and other controls — operator only.
	accessControl
)

// routeSpec is the declared contract of one API route.
type routeSpec struct {
	methods []string
	access  accessLevel

	// tenantQ names query keys carrying a tenant/namespace. Each present value must be inside
	// the caller's tenant scope. When tenantOptional is false the first key must be present.
	tenantQ        []string
	tenantOptional bool
	// tenantBody: the JSON body's "namespace" is a tenant identifier and must be in scope.
	tenantBody bool
	// fixedTenant: the route always acts on this compile-time namespace.
	fixedTenant string

	// targetQ names query keys carrying a cluster target/context. An omitted value is the
	// explicit default target, which still has to be granted.
	targetQ []string
	// fixedTarget names the cluster a route ALWAYS acts on because it offers no choice — the
	// console's own cluster, reached through the pod ServiceAccount or the default kubeconfig.
	// Without this, a grant with no target scope could still drive kubectl against that cluster:
	// having a tenant is not the same as being allowed to reach the cluster the tenant lives in.
	fixedTarget string
	// targetBody names JSON body keys carrying a cluster target.
	targetBody []string

	// runQ / runBody name where a run id is carried; the run's own target and creator decide
	// whether this caller may see or stop it.
	runQ    string
	runBody bool

	// requireTenantWildcard marks an effect that is INDIVISIBLE across tenants — a global file
	// truncated in one operation, a cluster-wide listing, a job whose output is shared. A grant
	// limited to some tenants cannot perform it at all, because there is no way to confine it to
	// those tenants. Pretending such a route is tenant-scoped is how a tenant-a operator ends up
	// deleting tenant-b's records.
	requireTenantWildcard bool
	// wildcardWhenUnscoped marks a route whose scoped parameter MAY be omitted, where omitting it
	// widens the request to everything. The narrow form stays available to a limited grant; the
	// unscoped form requires the wildcard.
	wildcardWhenUnscoped bool

	// destination resolves the EFFECTIVE targets and tenants a control acts on, AFTER the
	// handler's own defaults and fallbacks. A route that launches a process, or that substitutes
	// its own context/namespace for the one it was given, declares this so the boundary
	// authorizes the real destination rather than the one the request named or omitted.
	destination func(s *Server, r *http.Request, body scopedBody) (runDestination, error)
}

func (rs routeSpec) allowsMethod(m string) bool {
	for _, want := range rs.methods {
		if m == want {
			return true
		}
	}
	return false
}

// route binds a path to its contract and handler.
type route struct {
	path string
	spec routeSpec
	h    http.HandlerFunc
}

// guard wraps one route's handler with the boundary.
func (s *Server) guard(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		s.applyCORS(w, origin)
		if r.Method == http.MethodOptions {
			// Preflight is answered only for an origin the deployment trusts. There is no
			// wildcard: a wildcard ACAO is an implicit grant to every site on the internet.
			if origin != "" && (s.auth == nil || !s.auth.originTrusted(origin)) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin not allowed"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// No verifier configured => no trust boundary => serve nothing. This is the state the
		// old build treated as "demo trust"; it is now a refusal.
		if s.auth == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "console authentication is not configured; the API is closed",
			})
			return
		}
		// The unsigned ALB headers are not identity. Presented without the signed header they can
		// only be an attempt to assert one, so say so rather than ignoring them.
		if unsignedALBHeadersPresent(r) && strings.TrimSpace(r.Header.Get(ALBDataHeader)) == "" {
			s.unauthorized(w, "x-amzn-oidc-identity / x-amzn-oidc-accesstoken are not proof of identity; the signed "+ALBDataHeader+" header is required")
			return
		}
		principal, err := s.auth.Authenticate(r.Context(), r)
		if err != nil {
			switch {
			case errors.Is(err, ErrNoGrant):
				// Authenticated, but the deployment has bound this subject to nothing. This is the
				// visible fail-closed state when the grant table has not been supplied yet.
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "no authorization grant for this identity; a console administrator must bind this subject to a role and tenant scope",
				})
			case errors.Is(err, ErrAmbiguousCredentials):
				s.unauthorized(w, ErrAmbiguousCredentials.Error())
			default:
				s.unauthorized(w, "authentication required")
			}
			return
		}
		if !rt.spec.allowsMethod(r.Method) {
			w.Header().Set("Allow", strings.Join(rt.spec.methods, ", "))
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed; " + rt.path + " accepts " + strings.Join(rt.spec.methods, ", "),
			})
			return
		}
		if !allowedByAccess(principal, rt.spec.access) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": accessDenialMessage(rt.spec.access)})
			return
		}
		// CSRF: a browser request authenticated by the ALB session cookie must come from an origin
		// this deployment trusts. A bearer caller carries its credential deliberately in a header,
		// so it is not subject to (and not authenticated by) Origin.
		if principal.Source == "alb" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.sameOriginOK(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "cross-origin state-changing request refused; this console accepts them only from its configured origins",
				})
				return
			}
		}
		if code, msg, ok := s.checkScope(r, principal, rt.spec); !ok {
			writeJSON(w, code, map[string]string{"error": msg})
			return
		}
		rt.h(w, r.WithContext(withPrincipal(r.Context(), principal)))
	}
}

func (s *Server) unauthorized(w http.ResponseWriter, msg string) {
	if s.auth != nil && s.auth.bearer != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="phorvex-console"`)
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
}

func allowedByAccess(p *Principal, level accessLevel) bool {
	switch level {
	case accessAny, accessOwnerData:
		return len(p.Roles) > 0
	case accessRead:
		return p.CanRead()
	case accessControl:
		return p.CanOperate()
	}
	return false
}

func accessDenialMessage(level accessLevel) string {
	switch level {
	case accessControl:
		return "this control requires the operator role; investor and owner grants are read-only"
	case accessRead:
		return "this data requires an investor or operator grant"
	default:
		return "not authorized"
	}
}

// applyCORS reflects ONLY a configured origin. There is no wildcard and no credentialed
// wildcard; an untrusted origin simply receives no CORS grant and the browser blocks the read.
func (s *Server) applyCORS(w http.ResponseWriter, origin string) {
	w.Header().Add("Vary", "Origin")
	if origin == "" || s.auth == nil || !s.auth.originTrusted(origin) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Phorvex-Lens")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
}

// sameOriginOK enforces the CSRF boundary for cookie/ALB-authenticated state changes. An
// attacker-controlled page is refused whatever lens or body it sends.
func (s *Server) sameOriginOK(r *http.Request) bool {
	if o := strings.TrimSpace(r.Header.Get("Origin")); o != "" {
		return s.auth.originTrusted(o)
	}
	// Some browsers omit Origin on same-origin form posts; Referer is the documented fallback.
	if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Scheme != "" && u.Host != "" {
			return s.auth.originTrusted(u.Scheme + "://" + u.Host)
		}
	}
	// Neither header present: refuse. A console with no configured origin cannot accept a
	// browser-driven state change at all, which is the fail-closed answer.
	return false
}

// scopedBody is the small, bounded view of a request body the boundary needs.
type scopedBody struct {
	Namespace string
	ID        string
	Config    string
	Target    map[string]string
}

// readScopedBody buffers the body (bounded), extracts the scoped fields and restores the body so
// the handler still decodes it normally.
func readScopedBody(r *http.Request, targetKeys []string) (scopedBody, bool) {
	var out scopedBody
	out.Target = map[string]string{}
	if r.Body == nil {
		return out, true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxScopedBodyBytes+1))
	_ = r.Body.Close()
	if err != nil || int64(len(raw)) > maxScopedBodyBytes {
		return out, false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(bytes.TrimSpace(raw)) == 0 {
		return out, true
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		// A body the boundary cannot parse cannot be scope-checked. Handlers decode leniently, so
		// letting it through would skip the check; refuse instead.
		return out, false
	}
	str := func(key string) string {
		var v string
		if b, ok := doc[key]; ok && json.Unmarshal(b, &v) == nil {
			return strings.TrimSpace(v)
		}
		return ""
	}
	out.Namespace = str("namespace")
	out.ID = str("id")
	out.Config = str("config")
	// The scenario route carries its cluster target in the body, and the destination hook needs
	// it even when the route did not declare an explicit targetBody check.
	if _, ok := doc["target"]; ok {
		out.Target["target"] = str("target")
	}
	for _, k := range targetKeys {
		out.Target[k] = str(k)
	}
	return out, true
}

// checkScope enforces the route's declared tenant/target/run ownership against the grant.
func (s *Server) checkScope(r *http.Request, p *Principal, spec routeSpec) (int, string, bool) {
	q := r.URL.Query()

	if spec.fixedTenant != "" && !p.AllowsTenant(spec.fixedTenant) {
		return http.StatusForbidden, "namespace " + spec.fixedTenant + " is outside this identity's tenant scope", false
	}
	if spec.fixedTarget != "" && !p.AllowsTarget(spec.fixedTarget) {
		return http.StatusForbidden, "this route acts on cluster target " + normalizeTargetID(spec.fixedTarget) + ", which is outside this identity's target scope", false
	}

	if spec.requireTenantWildcard && !p.TenantWildcard() {
		return http.StatusForbidden, "this operation is indivisible across tenants and requires a cross-tenant grant; a tenant-limited identity cannot perform it", false
	}

	for i, key := range spec.tenantQ {
		v := strings.TrimSpace(q.Get(key))
		if v == "" {
			if spec.tenantOptional || i > 0 {
				// An omitted scope parameter widens the request to every tenant. Only a
				// cross-tenant grant may ask for that; a limited grant must name its tenant.
				if spec.wildcardWhenUnscoped && i == 0 && !p.TenantWildcard() {
					return http.StatusForbidden, "omitting " + key + " requests every tenant; name a tenant this identity is granted, or hold a cross-tenant grant", false
				}
				continue
			}
			return http.StatusBadRequest, "the " + key + " parameter is required and must name a tenant this identity is granted", false
		}
		if !p.AllowsTenant(v) {
			return http.StatusForbidden, "tenant " + v + " is outside this identity's tenant scope", false
		}
	}

	for _, key := range spec.targetQ {
		if !p.AllowsTarget(q.Get(key)) {
			return http.StatusForbidden, "cluster target " + normalizeTargetID(q.Get(key)) + " is outside this identity's target scope", false
		}
	}

	needBody := spec.tenantBody || spec.runBody || len(spec.targetBody) > 0 || spec.destination != nil
	var body scopedBody
	if needBody {
		var ok bool
		if body, ok = readScopedBody(r, spec.targetBody); !ok {
			return http.StatusBadRequest, "request body is unreadable, too large, or not the JSON object this route requires", false
		}
	}
	if spec.tenantBody {
		if body.Namespace == "" {
			return http.StatusBadRequest, "the namespace field is required and must name a tenant this identity is granted", false
		}
		if !p.AllowsTenant(body.Namespace) {
			return http.StatusForbidden, "namespace " + body.Namespace + " is outside this identity's tenant scope", false
		}
	}
	for _, key := range spec.targetBody {
		if !p.AllowsTarget(body.Target[key]) {
			return http.StatusForbidden, "cluster target " + normalizeTargetID(body.Target[key]) + " is outside this identity's target scope", false
		}
	}

	// The effective destination, after the handler's own defaults — checked BEFORE dispatch, so a
	// substituted context or a forced namespace can never be reached by an unauthorized caller.
	if spec.destination != nil {
		dest, err := spec.destination(s, r, body)
		if err != nil {
			return http.StatusBadRequest, err.Error(), false
		}
		for _, target := range dest.Targets {
			if !p.AllowsTarget(target) {
				return http.StatusForbidden, "this request would act on cluster target " + normalizeTargetID(target) + ", which is outside this identity's target scope", false
			}
		}
		for _, tenant := range dest.Tenants {
			if !p.AllowsTenant(tenant) {
				return http.StatusForbidden, "this request would act on namespace " + tenant + ", which is outside this identity's tenant scope", false
			}
		}
	}

	if spec.runQ != "" || spec.runBody {
		id := ""
		if spec.runQ != "" {
			id = strings.TrimSpace(q.Get(spec.runQ))
		}
		if id == "" && spec.runBody {
			id = body.ID
		}
		if id == "" {
			return http.StatusBadRequest, "a run id is required", false
		}
		if code, msg, ok := s.runInScope(p, id); !ok {
			return code, msg, false
		}
	}
	return 0, "", true
}

// runInScope resolves a run id to its recorded creator and cluster target and decides whether
// this identity may see or steer it. An unknown id is reported as not-found WITHOUT revealing
// anything else, so probing ids leaks no other tenant's run.
func (s *Server) runInScope(p *Principal, id string) (int, string, bool) {
	owner, target, ok := s.runs.Ownership(id)
	if !ok {
		return http.StatusNotFound, "run not found", false
	}
	if p.AllowsTarget(target) {
		return 0, "", true
	}
	// A run this identity created stays reachable to it even if the target grant later narrows.
	if owner != "" && owner == principalKey(p) {
		return 0, "", true
	}
	return http.StatusNotFound, "run not found", false
}

// principalKey is the stable identity string a run records as its creator.
func principalKey(p *Principal) string {
	if p == nil {
		return ""
	}
	return p.Issuer + "#" + p.Subject
}
