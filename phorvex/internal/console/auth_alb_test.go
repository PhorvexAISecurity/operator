/*
 * Phorvex Console — ALB signed-identity verification tests (M-136).
 *
 * Every case here signs a REAL ES256 token with a REAL P-256 key and serves the matching PEM
 * from a bounded local producer at the exact regional endpoint the verifier constructs. Nothing
 * is stubbed at the decision point: the verifier does the same work it does in the cluster.
 */

package console

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newTestALBVerifier(t *testing.T) (*ALBVerifier, *albFixture, *keyServer) {
	t.Helper()
	keys := newKeyServer()
	fx := newALBFixture(t, keys)
	v, err := NewALBVerifier(*fx.config(), keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return v, fx, keys
}

// The happy path: a correctly signed, in-date token from the configured signer/pool/client
// yields the issuer and the subject FROM THE VERIFIED PAYLOAD.
func TestALBVerify_ValidTokenYieldsVerifiedSubject(t *testing.T) {
	v, fx, _ := newTestALBVerifier(t)
	iss, sub, err := v.Verify(context.Background(), fx.mint(t, albToken{Sub: "cognito-user-42"}))
	if err != nil {
		t.Fatalf("a valid ALB token must verify: %v", err)
	}
	if iss != testALBIssuer || sub != "cognito-user-42" {
		t.Fatalf("verified identity = %q / %q", iss, sub)
	}
}

// AWS documents the signed claims payload as PADDED base64. Both encodings must verify, because
// the signature covers the literal segment bytes either way.
func TestALBVerify_AcceptsAWSPaddedPayloadEncoding(t *testing.T) {
	v, fx, _ := newTestALBVerifier(t)
	if _, sub, err := v.Verify(context.Background(), fx.mint(t, albToken{Sub: "padded-user", PadPayload: true})); err != nil || sub != "padded-user" {
		t.Fatalf("padded-base64 payload must verify: sub=%q err=%v", sub, err)
	}
}

func TestALBVerify_RejectionTable(t *testing.T) {
	v, fx, _ := newTestALBVerifier(t)
	attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token func() string
		want  error
	}{
		{"wrong signer ARN (another load balancer)", func() string {
			return fx.mint(t, albToken{Signer: "arn:aws:elasticloadbalancing:us-east-2:999999999999:loadbalancer/app/evil/deadbeef"})
		}, errALBSigner},
		{"wrong issuer (another user pool)", func() string {
			return fx.mint(t, albToken{Issuer: "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_EVIL"})
		}, errALBIssuer},
		{"wrong app client", func() string {
			return fx.mint(t, albToken{Client: "someone-elses-client"})
		}, errALBClient},
		{"algorithm substitution", func() string {
			return fx.mint(t, albToken{Alg: "RS256"})
		}, errALBAlg},
		{"expired signed header", func() string {
			return fx.mint(t, albToken{Exp: testFixedClock - 3600})
		}, errALBExpired},
		{"no expiry at all", func() string {
			return fx.mint(t, albToken{Exp: -1}) // sentinel handled below
		}, errALBNoExpiry},
		{"forged signature (attacker key)", func() string {
			return fx.mint(t, albToken{SignWith: attacker})
		}, errALBSignature},
		{"unknown key id", func() string {
			return fx.mint(t, albToken{Kid: "99999999-0000-0000-0000-000000000000"})
		}, errALBKeyFetch},
		{"key id with a traversal attempt", func() string {
			return fx.mint(t, albToken{Kid: "../../etc/passwd"})
		}, errALBKID},
		{"empty subject in the verified payload", func() string {
			return fx.mint(t, albToken{Sub: " "})
		}, errALBNoSubject},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := c.token()
			if c.want == errALBNoExpiry {
				tok = mintALBWithoutExp(t, fx)
			}
			_, _, err := v.Verify(context.Background(), tok)
			if err == nil {
				t.Fatalf("%s MUST be rejected", c.name)
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("%s: got %v, want %v", c.name, err, c.want)
			}
		})
	}
}

// mintALBWithoutExp builds an otherwise-valid token whose header omits exp entirely.
func mintALBWithoutExp(t *testing.T, fx *albFixture) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{
		"typ": "JWT", "kid": fx.kid, "alg": "ES256",
		"signer": fx.signer, "iss": fx.issuer, "client": fx.client,
	})
	payload, _ := json.Marshal(map[string]any{"sub": "no-exp-user"})
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256Sum(signing)
	r, s, err := ecdsa.Sign(rand.Reader, fx.key, digest)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// A malformed token is rejected before anything else happens.
func TestALBVerify_MalformedRejected(t *testing.T) {
	v, _, _ := newTestALBVerifier(t)
	for _, tok := range []string{"", "a.b", "a.b.c.d", "not-a-jwt", "..", "%%%.%%%.%%%"} {
		if _, _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatalf("malformed token %q must be rejected", tok)
		}
	}
}

// A key-endpoint failure fails the request closed. It must not authenticate anyone, and it must
// not be cached as a negative "trusted" result either.
func TestALBVerify_KeyFetchFailureFailsClosed(t *testing.T) {
	v, fx, keys := newTestALBVerifier(t)
	keys.setFail(fx.keyURL(fx.kid), true)
	if _, _, err := v.Verify(context.Background(), fx.mint(t, albToken{})); !errors.Is(err, errALBKeyFetch) {
		t.Fatalf("key fetch failure must fail closed: %v", err)
	}
	// Once the endpoint recovers, the same token verifies — the failure was not made sticky.
	keys.setFail(fx.keyURL(fx.kid), false)
	if _, _, err := v.Verify(context.Background(), fx.mint(t, albToken{})); err != nil {
		t.Fatalf("after recovery the token must verify: %v", err)
	}
}

// The key cache is shared and bounded: a repeated valid token costs ONE fetch, and rotation to a
// new kid is picked up without restarting.
func TestALBVerify_KeyCachingAndRotation(t *testing.T) {
	v, fx, keys := newTestALBVerifier(t)
	for i := 0; i < 5; i++ {
		if _, _, err := v.Verify(context.Background(), fx.mint(t, albToken{})); err != nil {
			t.Fatal(err)
		}
	}
	if hits := keys.hits(fx.keyURL(fx.kid)); hits != 1 {
		t.Fatalf("a cached key must be fetched once, not per request; hits=%d", hits)
	}

	// Rotation: the ALB starts signing with a new kid/key.
	rotated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const newKID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	keys.put(fx.keyURL(newKID), ecPublicKeyPEM(t, &rotated.PublicKey))
	fx.key = rotated
	if _, _, err := v.Verify(context.Background(), fx.mint(t, albToken{Kid: newKID})); err != nil {
		t.Fatalf("a rotated signing key must be picked up: %v", err)
	}
}

// A flood of forged arbitrary-kid tokens must not become unbounded fetch pressure on the AWS key
// endpoint. Once the miss budget is spent the verifier refuses without another fetch.
func TestALBVerify_ArbitraryKIDFloodIsBudgeted(t *testing.T) {
	v, fx, keys := newTestALBVerifier(t)
	for i := 0; i < 200; i++ {
		kid := fmt.Sprintf("forged-kid-%04d", i) // every attempt names a DISTINCT unknown kid
		if _, _, err := v.Verify(context.Background(), fx.mint(t, albToken{Kid: kid})); err == nil {
			t.Fatal("a forged kid must never verify")
		}
	}
	if fetches := keys.total(); fetches > 12 { // 10 burst + slack; the clock is pinned so it never refills
		t.Fatalf("forged-kid flood produced %d key fetches; the miss budget must bound them", fetches)
	}
	// A budget-exhausted verifier is still fail-closed, never fail-open.
	if _, _, err := v.Verify(context.Background(), fx.mint(t, albToken{Kid: "another-unknown-kid"})); err == nil {
		t.Fatal("an exhausted key budget must still reject, never admit")
	}
}

// Configuration problems are startup errors, not silently disabled checks.
func TestALBConfig_MalformedIsAStartupError(t *testing.T) {
	base := ALBConfig{SignerARN: testALBSigner, Issuer: testALBIssuer, ClientID: testALBClient}
	cases := map[string]ALBConfig{
		"no signer":        {Issuer: testALBIssuer, ClientID: testALBClient},
		"not an ALB ARN":   {SignerARN: "arn:aws:iam::1:role/x", Issuer: testALBIssuer, ClientID: testALBClient},
		"no issuer":        {SignerARN: testALBSigner, ClientID: testALBClient},
		"no client":        {SignerARN: testALBSigner, Issuer: testALBIssuer},
		"bad region":       {SignerARN: testALBSigner, Issuer: testALBIssuer, ClientID: testALBClient, Region: "not a region"},
		"unbounded leeway": {SignerARN: testALBSigner, Issuer: testALBIssuer, ClientID: testALBClient, Leeway: time.Hour},
	}
	for name, cfg := range cases {
		if _, err := NewALBVerifier(cfg, newKeyServer(), testNow); err == nil {
			t.Errorf("%s must be a configuration error", name)
		}
	}
	if _, err := NewALBVerifier(base, newKeyServer(), testNow); err != nil {
		t.Fatalf("a complete configuration must load: %v", err)
	}
}

// The key endpoint is derived from CONFIGURATION, never from the token.
func TestALBVerify_KeyEndpointIsFixedAndRegional(t *testing.T) {
	v, _, _ := newTestALBVerifier(t)
	url := v.keyURL("some-kid")
	if !strings.HasPrefix(url, "https://public-keys.auth.elb."+testALBRegion+".amazonaws.com/") {
		t.Fatalf("key endpoint must be the fixed regional AWS endpoint, got %q", url)
	}
	if !strings.HasSuffix(url, "/some-kid") || strings.Count(url, "://") != 1 {
		t.Fatalf("key endpoint must interpolate only the validated kid, got %q", url)
	}
}
