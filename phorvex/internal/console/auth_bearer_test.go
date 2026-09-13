/*
 * Phorvex Console — bearer OIDC verification tests (M-136).
 *
 * Real RSA/ECDSA keys, real signatures, and a bounded local JWKS producer reached through an
 * injected transport. These carry forward the adversarial cases the previous OIDC tests proved
 * (alg confusion, forged signature, expiry, issuer, audience, unknown kid) and add the ones the
 * decision requires: a MANDATORY exp, nbf, key-type/alg mismatch, rotation, bounded fetch and a
 * fetch failure that never downgrades authentication.
 */

package console

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func newTestBearerVerifier(t *testing.T) (*BearerVerifier, *bearerFixture, *keyServer) {
	t.Helper()
	keys := newKeyServer()
	fx := newBearerFixture(t, keys)
	v, err := NewBearerVerifier(*fx.config(), keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return v, fx, keys
}

func TestBearerVerify_ValidTokenYieldsVerifiedSubject(t *testing.T) {
	v, fx, _ := newTestBearerVerifier(t)
	iss, sub, err := v.Verify(context.Background(), fx.mint(t, bearerTok{Sub: "cli-user-7"}))
	if err != nil {
		t.Fatalf("a valid bearer token must verify: %v", err)
	}
	if iss != testBearerIss || sub != "cli-user-7" {
		t.Fatalf("verified identity = %q / %q", iss, sub)
	}
	// An ES256 token signed by the EC key in the same JWKS also verifies, and the key type is
	// selected by the algorithm rather than by whatever key happens to be first.
	if _, sub, err := v.Verify(context.Background(), fx.mint(t, bearerTok{Alg: "ES256", Kid: fx.kid + "-ec", Sub: "ec-user"})); err != nil || sub != "ec-user" {
		t.Fatalf("ES256 token: sub=%q err=%v", sub, err)
	}
}

func TestBearerVerify_RejectionTable(t *testing.T) {
	v, fx, _ := newTestBearerVerifier(t)
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	past := int64(testFixedClock - 3600)
	future := int64(testFixedClock + 3600)

	cases := []struct {
		name  string
		token bearerTok
		want  error
	}{
		{"alg=none", bearerTok{Alg: "none", Unsigned: true}, errBearerAlg},
		{"HMAC alg is not in the allowlist", bearerTok{Alg: "HS256", Unsigned: true}, errBearerAlg},
		{"forged signature (attacker key)", bearerTok{SignWith: attacker}, errBearerSignature},
		{"wrong issuer", bearerTok{Issuer: "https://evil.example.test"}, errBearerIssuer},
		{"wrong audience", bearerTok{Audience: "some-other-app"}, errBearerAudience},
		{"absent audience", bearerTok{Audience: []string{}}, errBearerAudience},
		{"expired", bearerTok{Exp: &past}, errBearerExpired},
		{"no exp at all", bearerTok{OmitExp: true}, errBearerNoExpiry},
		{"not yet valid (nbf)", bearerTok{Nbf: &future}, errBearerNotYet},
		{"empty subject", bearerTok{Sub: " "}, errBearerNoSubject},
		{"unknown kid", bearerTok{Kid: "kid-that-was-never-published"}, errBearerUnknownK},
		{"kid traversal attempt", bearerTok{Kid: "../../../etc/passwd"}, errBearerKID},
		{"EC key used with an RSA algorithm", bearerTok{Alg: "RS256", Kid: fx.kid + "-ec"}, errBearerKeyType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := v.Verify(context.Background(), fx.mint(t, c.token))
			if err == nil {
				t.Fatalf("%s MUST be rejected", c.name)
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("%s: got %v, want %v", c.name, err, c.want)
			}
		})
	}
}

// An audience array containing the configured audience is accepted (RFC 7519 allows both forms).
func TestBearerVerify_AudienceArrayAccepted(t *testing.T) {
	v, fx, _ := newTestBearerVerifier(t)
	tok := fx.mint(t, bearerTok{Audience: []string{"other", testBearerAud}})
	if _, _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("an aud array containing the configured audience must verify: %v", err)
	}
}

// The JWKS is fetched once and shared; an unknown kid triggers ONE rotation re-read.
func TestBearerVerify_JWKSCachingAndRotation(t *testing.T) {
	v, fx, keys := newTestBearerVerifier(t)
	for i := 0; i < 5; i++ {
		if _, _, err := v.Verify(context.Background(), fx.mint(t, bearerTok{})); err != nil {
			t.Fatal(err)
		}
	}
	if hits := keys.hits(testBearerJWKS); hits != 1 {
		t.Fatalf("the JWKS must be fetched once for a known kid; hits=%d", hits)
	}

	// The IdP rotates: a new key appears under a new kid.
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const newKID = "bearer-key-2"
	fx.publish(t, fx.jwks(t, rsaJWK(&rotated.PublicKey, newKID)))
	if _, _, err := v.Verify(context.Background(), fx.mint(t, bearerTok{Kid: newKID, SignWith: rotated})); err != nil {
		t.Fatalf("a rotated signing key must be picked up without a restart: %v", err)
	}
}

// A JWKS fetch failure fails the request closed; it never admits the caller and never falls back.
func TestBearerVerify_JWKSFetchFailureFailsClosed(t *testing.T) {
	keys := newKeyServer()
	fx := newBearerFixture(t, keys)
	v, err := NewBearerVerifier(*fx.config(), keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	keys.setFail(testBearerJWKS, true)
	if _, _, err := v.Verify(context.Background(), fx.mint(t, bearerTok{})); !errors.Is(err, errBearerKeyFetch) {
		t.Fatalf("a JWKS fetch failure must fail closed: %v", err)
	}
	keys.setFail(testBearerJWKS, false)
	if _, _, err := v.Verify(context.Background(), fx.mint(t, bearerTok{})); err != nil {
		t.Fatalf("after recovery the token must verify: %v", err)
	}
}

// Forged arbitrary-kid tokens must not turn the console into a JWKS fetch amplifier.
func TestBearerVerify_ArbitraryKIDFloodIsBudgeted(t *testing.T) {
	v, fx, keys := newTestBearerVerifier(t)
	for i := 0; i < 200; i++ {
		if _, _, err := v.Verify(context.Background(), fx.mint(t, bearerTok{Kid: fmt.Sprintf("unknown-%04d", i)})); err == nil {
			t.Fatal("an unpublished kid must never verify")
		}
	}
	if fetches := keys.total(); fetches > 12 {
		t.Fatalf("forged-kid flood produced %d JWKS fetches; the miss budget must bound them", fetches)
	}
}

// A JWKS with no usable signing key is an error, not an empty trust set.
func TestBearerVerify_EmptyJWKSIsAnError(t *testing.T) {
	keys := newKeyServer()
	fx := newBearerFixture(t, keys)
	v, err := NewBearerVerifier(*fx.config(), keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := json.Marshal(jwksDoc{})
	keys.put(testBearerJWKS, empty)
	if _, _, err := v.Verify(context.Background(), fx.mint(t, bearerTok{Kid: "brand-new-kid"})); !errors.Is(err, errBearerKeyFetch) {
		t.Fatalf("an empty JWKS must fail closed: %v", err)
	}
}

// Configuration is mandatory and validated: no issuer/audience/JWKS means no bearer path, and a
// nonsensical value stops the deployment rather than disabling a check.
func TestBearerConfig_MalformedIsAStartupError(t *testing.T) {
	cases := map[string]BearerConfig{
		"empty":                {},
		"no audience":          {Issuer: testBearerIss, JWKSURL: testBearerJWKS},
		"no jwks":              {Issuer: testBearerIss, Audience: testBearerAud},
		"non-https jwks":       {Issuer: testBearerIss, Audience: testBearerAud, JWKSURL: "http://idp.example.test/jwks"},
		"relative jwks":        {Issuer: testBearerIss, Audience: testBearerAud, JWKSURL: "/jwks"},
		"unsupported alg":      {Issuer: testBearerIss, Audience: testBearerAud, JWKSURL: testBearerJWKS, Algorithms: []string{"HS256"}},
		"alg none":             {Issuer: testBearerIss, Audience: testBearerAud, JWKSURL: testBearerJWKS, Algorithms: []string{"none"}},
		"leeway beyond bounds": {Issuer: testBearerIss, Audience: testBearerAud, JWKSURL: testBearerJWKS, Leeway: time.Hour},
	}
	for name, cfg := range cases {
		if _, err := NewBearerVerifier(cfg, newKeyServer(), testNow); err == nil {
			t.Errorf("%s must be a configuration error", name)
		}
	}
}

// The token never chooses where keys come from.
func TestBearerVerify_KeyEndpointIsConfiguredNotTokenDerived(t *testing.T) {
	keys := newKeyServer()
	fx := newBearerFixture(t, keys)
	v, err := NewBearerVerifier(*fx.config(), keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	// Publish a key the attacker controls at an endpoint the attacker names in the token issuer.
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	evil, _ := json.Marshal(jwksDoc{Keys: []jwkKey{rsaJWK(&attacker.PublicKey, "evil-kid")}})
	keys.put("https://evil.example.test/.well-known/jwks.json", evil)
	tok := fx.mint(t, bearerTok{Issuer: "https://evil.example.test", Kid: "evil-kid", SignWith: attacker})
	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("a token naming its own issuer must not redirect the key fetch")
	}
	if hits := keys.hits("https://evil.example.test/.well-known/jwks.json"); hits != 0 {
		t.Fatalf("the verifier fetched a token-named endpoint %d time(s); it must only read the configured JWKS URL", hits)
	}
}

// bearerToken only ever reads the Authorization header — never a query parameter, so an SSE URL
// cannot carry a credential into logs and referrers.
func TestBearerTokenIsHeaderOnly(t *testing.T) {
	f := newAuthFixture(t, Config{}, bearerOperatorGrant("cli", []string{wildcardScope}, []string{wildcardScope}))
	raw := f.bearer.mint(t, bearerTok{Sub: "cli"})
	w := f.do(httptestNewRequest("GET", "/api/effectiveness?access_token="+raw+"&token="+raw))
	if w.Code != 401 {
		t.Fatalf("a token in the query string must not authenticate: got %d\n%s", w.Code, w.Body.String())
	}
}
