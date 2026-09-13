/*
 * Phorvex Console — configured bearer OIDC verification (M-136).
 *
 * The second supported credential: `Authorization: Bearer <jwt>`, for CLI and automation callers
 * that do not go through the browser/ALB flow. It is only available when the deployment
 * configures an issuer, an audience and a JWKS URL; there is no implicit or defaulted IdP.
 *
 * Fail-closed properties:
 *   - the algorithm is checked against an EXACT configured allowlist before any key is chosen,
 *     and the key TYPE must match the algorithm family, so neither `none` nor an RS/ES swap can
 *     make a different key verify;
 *   - issuer and audience are mandatory in configuration AND in the token;
 *   - `exp` is mandatory (a token with no expiry is refused, not treated as eternal), `nbf` is
 *     honoured when present, and the leeway is bounded;
 *   - the subject must be non-empty — it is the key the grant table is read by;
 *   - keys come only from the CONFIGURED JWKS URL. Nothing in the token influences the endpoint,
 *     so a token claiming a different issuer cannot redirect the key fetch;
 *   - rotation is handled by re-reading the JWKS when an unknown kid appears, rate-limited so a
 *     flood of forged arbitrary-kid tokens cannot generate unbounded fetch pressure;
 *   - a JWKS fetch failure fails the request. It never falls back to a cached-but-expired trust
 *     decision, to the ALB path, or to any weaker identity.
 */

package console

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	errBearerNoToken   = errors.New("bearer: no Authorization: Bearer token")
	errBearerMalformed = errors.New("bearer: malformed JWT")
	errBearerAlg       = errors.New("bearer: algorithm not allowed")
	errBearerKID       = errors.New("bearer: invalid or missing key id")
	errBearerUnknownK  = errors.New("bearer: signing key not published by the configured issuer")
	errBearerKeyFetch  = errors.New("bearer: signing keys unavailable")
	errBearerKeyType   = errors.New("bearer: signing key type does not match the algorithm")
	errBearerSignature = errors.New("bearer: signature verification failed")
	errBearerIssuer    = errors.New("bearer: issuer mismatch")
	errBearerAudience  = errors.New("bearer: audience mismatch")
	errBearerNoExpiry  = errors.New("bearer: token carries no exp")
	errBearerExpired   = errors.New("bearer: token expired")
	errBearerNotYet    = errors.New("bearer: token not yet valid (nbf)")
	errBearerNoSubject = errors.New("bearer: token carries no subject")
	errBearerPressure  = errors.New("bearer: key-refresh budget exhausted")
)

// supportedBearerAlgs is the closed set of signature algorithms the console will ever accept.
// `none` and the HMAC family are deliberately absent: a symmetric alg over a public key is the
// classic confusion attack, and there is no shared secret in this deployment model.
var supportedBearerAlgs = map[string]string{
	"RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
	"ES256": "EC", "ES384": "EC", "ES512": "EC",
}

// BearerConfig is the per-deployment bearer IdP surface. Every field is required.
type BearerConfig struct {
	Issuer          string        // exact token `iss`
	Audience        string        // exact required `aud` entry
	JWKSURL         string        // https URL of the issuer's JWKS
	Algorithms      []string      // exact allowlist; defaults to ["RS256"]
	Leeway          time.Duration // bounded clock-skew allowance (default 60s, max 5m)
	RefreshInterval time.Duration // minimum interval between rotation re-reads (default 5m)
}

func (c BearerConfig) validate() (BearerConfig, error) {
	c.Issuer = strings.TrimSpace(c.Issuer)
	c.Audience = strings.TrimSpace(c.Audience)
	c.JWKSURL = strings.TrimSpace(c.JWKSURL)
	if c.Issuer == "" {
		return c, fmt.Errorf("bearer config: issuer is required")
	}
	if c.Audience == "" {
		return c, fmt.Errorf("bearer config: audience is required (an unaudienced token is not accepted)")
	}
	if c.JWKSURL == "" {
		return c, fmt.Errorf("bearer config: jwks url is required")
	}
	u, err := url.Parse(c.JWKSURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return c, fmt.Errorf("bearer config: jwks url %q must be an absolute https URL", c.JWKSURL)
	}
	if len(c.Algorithms) == 0 {
		c.Algorithms = []string{"RS256"}
	}
	clean := make([]string, 0, len(c.Algorithms))
	for _, a := range c.Algorithms {
		a = strings.TrimSpace(a)
		if _, ok := supportedBearerAlgs[a]; !ok {
			return c, fmt.Errorf("bearer config: algorithm %q is not supported (RS256/384/512, ES256/384/512)", a)
		}
		clean = append(clean, a)
	}
	c.Algorithms = clean
	if c.Leeway <= 0 {
		c.Leeway = 60 * time.Second
	}
	if c.Leeway > 5*time.Minute {
		return c, fmt.Errorf("bearer config: leeway %s exceeds the 5m bound", c.Leeway)
	}
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = 5 * time.Minute
	}
	return c, nil
}

// BearerVerifier verifies bearer JWTs against the configured issuer's published keys.
type BearerVerifier struct {
	cfg    BearerConfig
	algs   map[string]bool
	fetch  *boundedFetcher
	budget *missBudget
	flight *singleFlight
	now    func() time.Time

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey
	lastRefresh time.Time
}

// NewBearerVerifier validates the configuration and builds the verifier. It does NOT pre-fetch:
// a transient IdP outage at boot must not silently produce a console with no bearer path.
func NewBearerVerifier(cfg BearerConfig, rt http.RoundTripper, now func() time.Time) (*BearerVerifier, error) {
	valid, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	algs := map[string]bool{}
	for _, a := range valid.Algorithms {
		algs[a] = true
	}
	return &BearerVerifier{
		cfg:    valid,
		algs:   algs,
		fetch:  newBoundedFetcher(rt, keyFetchTimeout, keyMaxBody),
		budget: newMissBudget(1, 10, now),
		flight: newSingleFlight(),
		now:    now,
		keys:   map[string]crypto.PublicKey{},
	}, nil
}

type bearerHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type bearerClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp *int64          `json:"exp"`
	Nbf *int64          `json:"nbf"`
}

// bearerToken extracts the Authorization: Bearer token. It is the ONLY place a bearer credential
// is read from: a token is never accepted from a query parameter, a cookie or a body field, so
// SSE/EventSource callers cannot smuggle one through a URL that ends up in logs and referrers.
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", errBearerNoToken
	}
	tok := strings.TrimSpace(h[len(p):])
	if tok == "" {
		return "", errBearerNoToken
	}
	return tok, nil
}

// Verify checks one bearer JWT end to end and returns the verified issuer and subject.
func (v *BearerVerifier) Verify(ctx context.Context, token string) (issuer, subject string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", errBearerMalformed
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", errBearerMalformed
	}
	var h bearerHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return "", "", errBearerMalformed
	}
	if !v.algs[h.Alg] {
		return "", "", errBearerAlg
	}
	if !validKID(h.Kid) {
		return "", "", errBearerKID
	}
	key, err := v.publicKey(ctx, h.Kid)
	if err != nil {
		return "", "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", errBearerMalformed
	}
	if err := verifyJWS(h.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return "", "", err
	}
	// Claims are read only after the signature holds.
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", errBearerMalformed
	}
	var c bearerClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return "", "", errBearerMalformed
	}
	if c.Iss != v.cfg.Issuer {
		return "", "", errBearerIssuer
	}
	if !audienceContains(c.Aud, v.cfg.Audience) {
		return "", "", errBearerAudience
	}
	if c.Exp == nil {
		return "", "", errBearerNoExpiry
	}
	now := v.now()
	if now.After(time.Unix(*c.Exp, 0).Add(v.cfg.Leeway)) {
		return "", "", errBearerExpired
	}
	if c.Nbf != nil && now.Before(time.Unix(*c.Nbf, 0).Add(-v.cfg.Leeway)) {
		return "", "", errBearerNotYet
	}
	sub := strings.TrimSpace(c.Sub)
	if sub == "" {
		return "", "", errBearerNoSubject
	}
	return c.Iss, sub, nil
}

// verifyJWS checks the signature AND that the key type matches the algorithm family.
func verifyJWS(alg string, key crypto.PublicKey, signing, sig []byte) error {
	family := supportedBearerAlgs[alg]
	var digest []byte
	switch alg {
	case "RS256", "ES256":
		d := sha256.Sum256(signing)
		digest = d[:]
	case "RS384", "ES384":
		d := sha512.Sum384(signing)
		digest = d[:]
	default: // RS512 / ES512
		d := sha512.Sum512(signing)
		digest = d[:]
	}
	switch family {
	case "RSA":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errBearerKeyType
		}
		hash := map[string]crypto.Hash{"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512}[alg]
		if rsa.VerifyPKCS1v15(pub, hash, digest, sig) != nil {
			return errBearerSignature
		}
		return nil
	case "EC":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errBearerKeyType
		}
		n := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return errBearerSignature
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errBearerSignature
		}
		return nil
	}
	return errBearerAlg
}

// audienceContains handles the RFC 7519 string-or-array form. An absent audience never matches.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 || want == "" {
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

func (v *BearerVerifier) publicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	key, ok := v.keys[kid]
	stale := v.lastRefresh.IsZero() || v.now().Sub(v.lastRefresh) > v.cfg.RefreshInterval
	v.mu.Unlock()
	if ok && !stale {
		return key, nil
	}
	if ok {
		// Known kid, stale document: serve the cached key and let the next unknown kid pay for
		// the refresh. A rotation only matters when a kid we do NOT have shows up.
		return key, nil
	}
	// Unknown kid: this is the attacker-influenced path, so budget it before the network.
	if !v.budget.allow() {
		return nil, errBearerPressure
	}
	owner, ch := v.flight.enter("jwks")
	if !owner {
		<-ch
		v.mu.Lock()
		key, ok = v.keys[kid]
		v.mu.Unlock()
		if ok {
			return key, nil
		}
		return nil, errBearerUnknownK
	}
	defer v.flight.leave("jwks", ch)

	body, err := v.fetch.get(ctx, v.cfg.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBearerKeyFetch, err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBearerKeyFetch, err)
	}
	v.mu.Lock()
	v.keys = keys
	v.lastRefresh = v.now()
	key, ok = v.keys[kid]
	v.mu.Unlock()
	if !ok {
		return nil, errBearerUnknownK
	}
	return key, nil
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

// parseJWKS converts the published document into usable public keys. Unusable entries are
// skipped; a document with no usable signing key is an error, never an empty trust set that
// would make every kid "unknown but tolerated".
func parseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if !validKID(k.Kid) {
			continue
		}
		switch k.Kty {
		case "RSA":
			if pub, err := jwkToRSA(k); err == nil {
				out[k.Kid] = pub
			}
		case "EC":
			if pub, err := jwkToEC(k); err == nil {
				out[k.Kid] = pub
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable signing keys in JWKS")
	}
	return out, nil
}

func jwkToRSA(k jwkKey) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 || len(nb) < 128 { // reject a zero exponent and a sub-1024-bit modulus
		return nil, fmt.Errorf("jwk %q: unusable RSA parameters", k.Kid)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

func jwkToEC(k jwkKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwk %q: unsupported curve %q", k.Kid, k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("jwk %q: point is not on %s", k.Kid, k.Crv)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
