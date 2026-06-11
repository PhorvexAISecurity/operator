/*
 * Phorvex — OIDC config surface (the verifier itself is proven in Pass 2; this is the config + JWKS
 * loader the dev team fills in for their IdP). Build an OIDCVerifier from an OIDCConfig by fetching the
 * IdP's JWKS and converting each RSA JWK to a public key.
 *
 * [PENDING-IDP-CONFIG] — the verification logic is tested (Pass 2 oidc_test.go); this config + JWKS fetch
 * are validated against the team's real IdP (issuer / audience / JWKS URL / claim names). See
 * REAL-ENV-VALIDATION.md.
 */

package console

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// OIDCConfig is the per-deployment IdP surface (fill from YOUR IdP; nothing hardcoded).
type OIDCConfig struct {
	Issuer      string `json:"issuer"`        // token `iss` to require, e.g. https://login.example.com/
	Audience    string `json:"audience"`      // token `aud` to require, e.g. phorvex-console
	JWKSURL     string `json:"jwksUrl"`       // the IdP JWKS, e.g. https://login.example.com/.well-known/jwks.json
	TenantClaim string `json:"tenantClaim"`   // claim carrying the tenant id (default "tenant")
	LensClaim   string `json:"lensClaim"`     // claim carrying the lens (default "lens")
	LeewaySec   int    `json:"leewaySeconds"` // clock-skew allowance in seconds (default 30)
}

// ExampleOIDCConfig documents the shape with placeholder values for the dev team to replace.
func ExampleOIDCConfig() OIDCConfig {
	return OIDCConfig{
		Issuer:      "https://YOUR-IDP.example.com/",
		Audience:    "phorvex-console",
		JWKSURL:     "https://YOUR-IDP.example.com/.well-known/jwks.json",
		TenantClaim: "tenant",
		LensClaim:   "lens",
		LeewaySec:   30,
	}
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}
type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWKSFetcher fetches the raw JWKS JSON (injectable; default httpJWKS). [PENDING-IDP-CONFIG].
type JWKSFetcher func(ctx context.Context, url string) ([]byte, error)

func jwkToRSA(k jwkKey) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("jwk %q modulus: %w", k.Kid, err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jwk %q exponent: %w", k.Kid, err)
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("jwk %q: zero exponent", k.Kid)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

// LoadOIDCVerifier builds a (proven) OIDCVerifier from cfg by fetching + parsing the JWKS. fetch may be
// nil (defaults to httpJWKS). Fail-closed: returns an error (and NO verifier) on any config/JWKS problem.
func LoadOIDCVerifier(ctx context.Context, cfg OIDCConfig, fetch JWKSFetcher) (*OIDCVerifier, error) {
	if cfg.Issuer == "" || cfg.JWKSURL == "" {
		return nil, fmt.Errorf("oidc config: issuer and jwksUrl are required [PENDING-IDP-CONFIG]")
	}
	if fetch == nil {
		fetch = httpJWKS
	}
	raw, err := fetch(ctx, cfg.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch JWKS %s: %w", cfg.JWKSURL, err)
	}
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("oidc: parse JWKS: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			continue // skip unusable keys; a usable one must remain (checked below)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("oidc: no usable RSA signing keys in JWKS %s", cfg.JWKSURL)
	}
	tenantClaim := cfg.TenantClaim
	if tenantClaim == "" {
		tenantClaim = "tenant"
	}
	lensClaim := cfg.LensClaim
	if lensClaim == "" {
		lensClaim = "lens"
	}
	leeway := time.Duration(cfg.LeewaySec) * time.Second
	if cfg.LeewaySec == 0 {
		leeway = 30 * time.Second
	}
	return &OIDCVerifier{
		Issuer: cfg.Issuer, Audience: cfg.Audience, Keys: keys,
		TenantClaim: tenantClaim, LensClaim: lensClaim, Leeway: leeway,
	}, nil
}

func httpJWKS(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
