/*
 * Phorvex — OIDC config/JWKS-loader tests (mocked JWKS fetch; no real IdP). Proves LoadOIDCVerifier
 * builds a WORKING verifier from a JWKS (a token signed by the JWKS key verifies; a foreign key is
 * rejected) and fail-closes on a bad config / fetch error / empty JWKS.
 */

package console

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

func rsaToJWK(pub *rsa.PublicKey, kid string) jwkKey {
	return jwkKey{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func TestLoadOIDCVerifier_BuildsWorkingVerifier(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks, _ := json.Marshal(jwksDoc{Keys: []jwkKey{rsaToJWK(&key.PublicKey, "k1")}})
	cfg := OIDCConfig{Issuer: "https://idp.example", Audience: "phorvex-console", JWKSURL: "https://idp.example/jwks"}
	v, err := LoadOIDCVerifier(context.Background(), cfg, func(context.Context, string) ([]byte, error) { return jwks, nil })
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	// a token signed by the JWKS key verifies, tenant from the claim.
	id, err := v.Verify(signJWT(t, key, "k1", "RS256", validClaims(1_700_000_900)))
	if err != nil || id.Tenant != "acme" {
		t.Fatalf("loaded verifier must verify a valid token: id=%v err=%v", id, err)
	}
	// a token signed by a key NOT in the JWKS is rejected.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Verify(signJWT(t, other, "k1", "RS256", validClaims(1_700_000_900))); err == nil {
		t.Error("a token signed by a non-JWKS key must be rejected")
	}
}

func TestLoadOIDCVerifier_FailClosed(t *testing.T) {
	if _, err := LoadOIDCVerifier(context.Background(), OIDCConfig{}, nil); err == nil {
		t.Error("empty config (no issuer/jwksUrl) must fail-closed")
	}
	cfg := OIDCConfig{Issuer: "https://i", JWKSURL: "https://i/jwks"}
	if _, err := LoadOIDCVerifier(context.Background(), cfg, func(context.Context, string) ([]byte, error) { return nil, errors.New("network") }); err == nil {
		t.Error("a JWKS fetch error must propagate (fail-closed)")
	}
	empty, _ := json.Marshal(jwksDoc{})
	if _, err := LoadOIDCVerifier(context.Background(), cfg, func(context.Context, string) ([]byte, error) { return empty, nil }); err == nil {
		t.Error("an empty JWKS (no usable RSA keys) must fail-closed")
	}
}

func TestExampleOIDCConfig_IsPlaceholder(t *testing.T) {
	c := ExampleOIDCConfig()
	if c.TenantClaim == "" || c.Audience == "" || c.JWKSURL == "" {
		t.Error("the example config must document every required field for the dev team")
	}
}
