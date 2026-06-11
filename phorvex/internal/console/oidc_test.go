/*
 * Phorvex — P-VCLUSTER Pass 2: OIDC verifier adversarial tests. Generates an RSA keypair, signs valid
 * and forged tokens, and asserts the verifier accepts ONLY a correctly-signed, unexpired, right-
 * issuer/audience token — and that the tenant/lens come from the VERIFIED claim (O6: a forged ?tenant=
 * cannot override the verified identity).
 */

package console

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func b64j(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }

func signJWT(t *testing.T, key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	signing := b64j(map[string]any{"alg": alg, "kid": kid, "typ": "JWT"}) + "." + b64j(claims)
	if alg == "none" {
		return signing + "." // unsigned
	}
	d := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newVerifier(t *testing.T, key *rsa.PrivateKey) *OIDCVerifier {
	return &OIDCVerifier{
		Issuer: "https://idp.example", Audience: "phorvex-console",
		Keys:        map[string]*rsa.PublicKey{"k1": &key.PublicKey},
		TenantClaim: "tenant", LensClaim: "lens", Leeway: 30 * time.Second,
		now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
}

func validClaims(exp int64) map[string]any {
	return map[string]any{
		"iss": "https://idp.example", "sub": "user-1", "aud": "phorvex-console",
		"exp": exp, "tenant": "acme", "lens": "owner",
	}
}

func TestOIDC_ValidTokenVerifiesTenantFromClaim(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newVerifier(t, key)
	tok := signJWT(t, key, "k1", "RS256", validClaims(1_700_000_900))
	id, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("valid token must verify: %v", err)
	}
	// O6: the tenant is the VERIFIED claim — a request cannot self-assert a different one.
	if id.Tenant != "acme" || id.Lens != "owner" || id.Subject != "user-1" {
		t.Errorf("identity must come from verified claims, got %+v", id)
	}
}

func TestOIDC_ForgedSignatureRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newVerifier(t, key)
	tok := signJWT(t, attacker, "k1", "RS256", validClaims(1_700_000_900)) // signed by the WRONG key
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("a token signed by an unknown key MUST be rejected (forged signature)")
	}
}

func TestOIDC_AlgNoneRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newVerifier(t, key)
	tok := signJWT(t, key, "k1", "none", validClaims(1_700_000_900))
	if _, err := v.Verify(tok); err != errBadAlg {
		t.Fatalf("alg=none MUST be rejected (algorithm confusion), got %v", err)
	}
}

func TestOIDC_ExpiredRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newVerifier(t, key)
	tok := signJWT(t, key, "k1", "RS256", validClaims(1_699_990_000)) // exp in the past
	if _, err := v.Verify(tok); err != errExpired {
		t.Fatalf("expired token MUST be rejected, got %v", err)
	}
}

func TestOIDC_WrongAudienceAndIssuerRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newVerifier(t, key)
	badAud := validClaims(1_700_000_900)
	badAud["aud"] = "some-other-app"
	if _, err := v.Verify(signJWT(t, key, "k1", "RS256", badAud)); err != errAudience {
		t.Fatalf("wrong audience MUST be rejected, got %v", err)
	}
	badIss := validClaims(1_700_000_900)
	badIss["iss"] = "https://evil.example"
	if _, err := v.Verify(signJWT(t, key, "k1", "RS256", badIss)); err != errIssuer {
		t.Fatalf("wrong issuer MUST be rejected, got %v", err)
	}
}

func TestOIDC_UnknownKIDAndMissingTenantRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newVerifier(t, key)
	if _, err := v.Verify(signJWT(t, key, "unknown-kid", "RS256", validClaims(1_700_000_900))); err != errUnknownKID {
		t.Fatalf("unknown kid MUST be rejected, got %v", err)
	}
	noTenant := validClaims(1_700_000_900)
	delete(noTenant, "tenant")
	if _, err := v.Verify(signJWT(t, key, "k1", "RS256", noTenant)); err != errClaims {
		t.Fatalf("missing tenant claim MUST be rejected, got %v", err)
	}
}
