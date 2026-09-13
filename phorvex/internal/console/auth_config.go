/*
 * Phorvex Console — the authenticator: credentials + grants + trusted origins (M-136).
 *
 * One place decides "who is calling and what may they do". It is constructed from deployment
 * configuration and validated up front; an incomplete or contradictory configuration is an error
 * the process reports at startup rather than a check that quietly does nothing.
 *
 * Credential ambiguity is refused. If a request carries BOTH an ALB signed header and a bearer
 * token, it is rejected rather than resolved: silently preferring one would let an attacker who
 * can set a header downgrade or upgrade an identity by attaching a second credential, and
 * "invalid bearer, so fall back to the proxy header" is exactly the privilege-escalation shape
 * this fix exists to remove.
 */

package console

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrUnauthenticated means no verified credential was presented.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrAmbiguousCredentials means more than one credential source was presented.
	ErrAmbiguousCredentials = errors.New("ambiguous credentials: present exactly one of the ALB signed identity or a bearer token")
	// ErrNoGrant means the caller authenticated but the deployment grants it nothing.
	ErrNoGrant = errors.New("no authorization grant for this identity")
)

// AuthConfig is the console's complete identity/authorization configuration.
type AuthConfig struct {
	ALB    *ALBConfig    // nil = the ALB browser path is not configured
	Bearer *BearerConfig // nil = the bearer path is not configured
	// GrantsPath is the DevOps-supplied subject grant table. Empty means no bindings exist, which
	// is a fail-closed state, not an open one.
	GrantsPath string
	// TrustedOrigins are the exact browser origins allowed to drive the console (scheme://host[:port]).
	TrustedOrigins []string
	// Transport and Now are test seams; nil selects the real transport and clock.
	Transport http.RoundTripper
	Now       func() time.Time
}

// Authenticator resolves a request to a verified, authorized Principal.
type Authenticator struct {
	alb            *ALBVerifier
	bearer         *BearerVerifier
	grants         *GrantTable
	trustedOrigins map[string]bool
	originList     []string
	grantsPath     string
}

// NewAuthenticator validates every part of the configuration and builds the authenticator.
//
// At least one credential path is REQUIRED: a console with no verifier has no trust boundary,
// and that is the defect this replaces. Grants are separate — an absent grant file leaves the
// console authenticating callers and authorizing none of them, which is the visible fail-closed
// state DevOps resolves by supplying subject bindings before rollout.
func NewAuthenticator(cfg AuthConfig) (*Authenticator, error) {
	if cfg.ALB == nil && cfg.Bearer == nil {
		return nil, fmt.Errorf("console auth: no credential path configured — configure the ALB signed identity (signer/issuer/client) and/or a bearer OIDC issuer/audience/JWKS")
	}
	a := &Authenticator{trustedOrigins: map[string]bool{}, grantsPath: cfg.GrantsPath}
	if cfg.ALB != nil {
		v, err := NewALBVerifier(*cfg.ALB, cfg.Transport, cfg.Now)
		if err != nil {
			return nil, err
		}
		a.alb = v
	}
	if cfg.Bearer != nil {
		v, err := NewBearerVerifier(*cfg.Bearer, cfg.Transport, cfg.Now)
		if err != nil {
			return nil, err
		}
		a.bearer = v
	}
	for _, o := range cfg.TrustedOrigins {
		norm, err := normalizeOrigin(o)
		if err != nil {
			return nil, fmt.Errorf("console auth: trusted origin %q: %w", o, err)
		}
		if !a.trustedOrigins[norm] {
			a.trustedOrigins[norm] = true
			a.originList = append(a.originList, norm)
		}
	}
	if cfg.GrantsPath != "" {
		t, err := LoadGrantFile(cfg.GrantsPath)
		if err != nil {
			return nil, err
		}
		a.grants = t
	} else {
		a.grants = EmptyGrantTable()
	}
	return a, nil
}

// normalizeOrigin reduces an origin to the exact scheme://host[:port] a browser sends.
func normalizeOrigin(raw string) (string, error) {
	s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "/"))
	if s == "" {
		return "", fmt.Errorf("empty")
	}
	if s == "*" {
		return "", fmt.Errorf("a wildcard origin is not a trust boundary; list exact origins")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("must be scheme://host[:port]")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("must not carry a path, query or fragment")
	}
	return u.Scheme + "://" + u.Host, nil
}

// GrantCount reports how many subject bindings are configured. Zero is the unmet-prerequisite
// state the startup log and /api/session both surface.
func (a *Authenticator) GrantCount() int { return a.grants.Size() }

// Modes lists the enabled credential paths, for the session endpoint and the startup log.
func (a *Authenticator) Modes() []string {
	var m []string
	if a.alb != nil {
		m = append(m, "alb")
	}
	if a.bearer != nil {
		m = append(m, "bearer")
	}
	return m
}

// TrustedOrigins returns the configured browser origins.
func (a *Authenticator) TrustedOrigins() []string {
	return append([]string(nil), a.originList...)
}

func (a *Authenticator) originTrusted(origin string) bool {
	norm, err := normalizeOrigin(origin)
	if err != nil {
		return false
	}
	return a.trustedOrigins[norm]
}

// Authenticate verifies exactly one credential and maps it through the grant table.
func (a *Authenticator) Authenticate(ctx context.Context, r *http.Request) (*Principal, error) {
	hasALB := a.alb != nil && strings.TrimSpace(r.Header.Get(ALBDataHeader)) != ""
	rawBearer, bearerErr := bearerToken(r)
	hasBearer := a.bearer != nil && bearerErr == nil

	// Refuse ambiguity outright — never resolve it by preference.
	if hasALB && hasBearer {
		return nil, ErrAmbiguousCredentials
	}
	// A bearer token presented to a console with no bearer path is a configuration/credential
	// mismatch, not an invitation to try the proxy header instead.
	if bearerErr == nil && a.bearer == nil {
		return nil, fmt.Errorf("%w: bearer tokens are not enabled on this console", ErrUnauthenticated)
	}

	var issuer, subject, source string
	var err error
	switch {
	case hasALB:
		issuer, subject, err = a.alb.VerifyRequest(r)
		source = "alb"
	case hasBearer:
		issuer, subject, err = a.bearer.Verify(ctx, rawBearer)
		source = "bearer"
	default:
		return nil, ErrUnauthenticated
	}
	if err != nil {
		// A verification failure is terminal for the request. There is no second path to try:
		// falling through to another credential is how an invalid bearer becomes a proxy identity.
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	granted, ok := a.grants.Lookup(issuer, subject)
	if !ok {
		return nil, ErrNoGrant
	}
	granted.Source = source
	granted.Lens = granted.effectiveLens(requestedLens(r))
	return granted, nil
}

// unsignedALBHeadersPresent reports whether a request carries the ALB headers that are NOT
// identity. It exists so the boundary can refuse them explicitly instead of ignoring them.
func unsignedALBHeadersPresent(r *http.Request) bool {
	for _, h := range albUnsignedHeaders {
		if strings.TrimSpace(r.Header.Get(h)) != "" {
			return true
		}
	}
	return false
}
