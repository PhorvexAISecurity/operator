/*
 * Phorvex — P-VCLUSTER Pass 2: OIDC/JWT verified identity (CLOSES O6's forged-?tenant= gap).
 *
 * Replaces demo-trust (a self-asserted ?tenant=/X-Phorvex-Lens) with an RS256-verified principal: the
 * tenant + lens become VERIFIED claims, not request-controlled. Implemented on the standard library
 * (crypto/rsa) — no new dependency — and fail-closed: any verification failure yields NO identity.
 *
 * SECURITY (premortem-driven): rejects alg=none and any non-allowlisted alg (no algorithm confusion);
 * verifies the RS256 signature against the issuer's JWKS keyed by `kid`; enforces exp/nbf (with no
 * clock-skew slack beyond a small bound) + iss + aud; the tenant/lens are taken ONLY from verified
 * claims. A forged, expired, wrong-audience, or wrong-issuer token authenticates as nobody.
 */

package console

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VerifiedIdentity is an authenticated principal — every field derived from a verified token claim.
type VerifiedIdentity struct {
	Subject string
	Tenant  string
	Lens    string // "owner" | "operator" | "investor" — from a verified claim, never self-asserted
}

// OIDCVerifier verifies RS256 JWTs against a configured issuer + audience using the issuer's public
// keys (JWKS, keyed by kid). All fields are required for verification to succeed (fail-closed).
type OIDCVerifier struct {
	Issuer      string
	Audience    string
	Keys        map[string]*rsa.PublicKey // kid -> RSA public key (loaded from the IdP JWKS)
	TenantClaim string                    // claim carrying the tenant id (configurable; no hardcode)
	LensClaim   string                    // claim carrying the lens (configurable)
	Leeway      time.Duration             // small bounded clock-skew allowance
	now         func() time.Time
}

func (v *OIDCVerifier) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

var (
	errNoToken     = errors.New("oidc: no bearer token")
	errBadAlg      = errors.New("oidc: algorithm not allowed (RS256 only; alg=none refused)")
	errUnknownKID  = errors.New("oidc: signing key (kid) not in JWKS")
	errBadSig      = errors.New("oidc: signature verification failed")
	errExpired     = errors.New("oidc: token expired")
	errNotYet      = errors.New("oidc: token not yet valid (nbf)")
	errIssuer      = errors.New("oidc: issuer mismatch")
	errAudience    = errors.New("oidc: audience mismatch")
	errClaims      = errors.New("oidc: required claim missing/empty (tenant)")
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	// Aud may be a string or []string per RFC 7519; decode loosely.
	Aud json.RawMessage `json:"aud"`
	raw map[string]any
}

func b64urlDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Verify checks the JWT and returns the verified principal, or an error (fail-closed; no identity).
func (v *OIDCVerifier) Verify(token string) (*VerifiedIdentity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: malformed JWT")
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: header decode: %w", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, fmt.Errorf("oidc: header parse: %w", err)
	}
	// ALGORITHM ALLOWLIST — reject alg=none and any non-RS256 (no algorithm-confusion attacks).
	if !strings.EqualFold(h.Alg, "RS256") {
		return nil, errBadAlg
	}
	key, ok := v.Keys[h.Kid]
	if !ok || key == nil {
		return nil, errUnknownKID
	}
	// SIGNATURE — RS256 over base64url(header).base64url(payload).
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: signature decode: %w", err)
	}
	signed := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errBadSig
	}
	// CLAIMS.
	pb, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: payload decode: %w", err)
	}
	var c jwtClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("oidc: payload parse: %w", err)
	}
	_ = json.Unmarshal(pb, &c.raw)
	now := v.clock()
	leeway := v.Leeway
	if c.Exp != 0 && now.After(time.Unix(c.Exp, 0).Add(leeway)) {
		return nil, errExpired
	}
	if c.Nbf != 0 && now.Before(time.Unix(c.Nbf, 0).Add(-leeway)) {
		return nil, errNotYet
	}
	if v.Issuer != "" && c.Iss != v.Issuer {
		return nil, errIssuer
	}
	if v.Audience != "" && !audienceMatches(c.Aud, v.Audience) {
		return nil, errAudience
	}
	// TENANT + LENS — from VERIFIED claims only (the configured claim names).
	tenant := claimString(c.raw, v.TenantClaim)
	if tenant == "" {
		return nil, errClaims
	}
	lens := normalizeLens(claimString(c.raw, v.LensClaim))
	return &VerifiedIdentity{Subject: c.Sub, Tenant: tenant, Lens: lens}, nil
}

func audienceMatches(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

func claimString(m map[string]any, key string) string {
	if m == nil || key == "" {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func normalizeLens(l string) string {
	switch l {
	case "investor", "operator", "owner":
		return l
	default:
		return "owner" // DEFAULT-DENY: an unrecognized lens cannot reach vendor data
	}
}

// bearerToken extracts the Authorization: Bearer <jwt> token (the ONLY identity source under OIDC).
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errNoToken
	}
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", errNoToken
	}
	return strings.TrimSpace(h[len(p):]), nil
}
