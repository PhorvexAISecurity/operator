/*
 * Phorvex Console — signed identity fixtures for the tests (M-136).
 *
 * These helpers mint REAL credentials against REAL local keys and serve the key material over a
 * bounded local HTTP producer through an injected transport. Nothing here disables a check:
 *
 *   - the ALB fixture signs ES256 over the same header.payload bytes the verifier reads, with the
 *     documented signer/iss/client/exp fields, and publishes its PEM key at the exact regional
 *     endpoint the verifier constructs;
 *   - the bearer fixture signs RS256/ES256 and publishes a JWKS at the configured URL;
 *   - the grant table is a real parsed policy document.
 *
 * A test that wants an authorized caller has to be GRANTED one, which is what keeps these tests
 * from quietly becoming an auth bypass that hides a routing defect.
 */

package console

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	testALBSigner  = "arn:aws:elasticloadbalancing:us-east-2:753556437180:loadbalancer/app/k8s-test/0123456789abcdef"
	testALBIssuer  = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_TESTPOOL"
	testALBClient  = "testclientid0123456789"
	testALBRegion  = "us-east-2"
	testALBKID     = "11111111-2222-3333-4444-555555555555"
	testBearerIss  = "https://idp.example.test"
	testBearerAud  = "phorvex-console"
	testBearerJWKS = "https://idp.example.test/.well-known/jwks.json"
	testBearerKID  = "bearer-key-1"
	testOrigin     = "https://console.phorvex.test"
	testFixedClock = 1_700_000_000
)

func testNow() time.Time { return time.Unix(testFixedClock, 0) }

// ---- a bounded local key producer wired in through the transport ----------------------------

// keyServer answers exactly the URLs the verifiers construct, and records every request so a
// test can assert the fetch was bounded and not repeated per forged token.
type keyServer struct {
	mu       sync.Mutex
	routes   map[string][]byte
	requests map[string]int
	fail     map[string]bool
}

func newKeyServer() *keyServer {
	return &keyServer{routes: map[string][]byte{}, requests: map[string]int{}, fail: map[string]bool{}}
}

func (k *keyServer) put(url string, body []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.routes[url] = body
}

func (k *keyServer) setFail(url string, fail bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fail[url] = fail
}

func (k *keyServer) hits(url string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.requests[url]
}

// total is every outbound key request this producer saw — the number a flood test bounds.
func (k *keyServer) total() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, c := range k.requests {
		n += c
	}
	return n
}

func (k *keyServer) RoundTrip(r *http.Request) (*http.Response, error) {
	url := r.URL.String()
	k.mu.Lock()
	k.requests[url]++
	body, ok := k.routes[url]
	failing := k.fail[url]
	k.mu.Unlock()
	if failing {
		return nil, fmt.Errorf("simulated key endpoint failure for %s", url)
	}
	if !ok {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found")), Header: http.Header{}, Request: r}, nil
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}, Request: r}, nil
}

// ---- ALB fixture ------------------------------------------------------------------------------

type albFixture struct {
	key    *ecdsa.PrivateKey
	keys   *keyServer
	signer string
	issuer string
	client string
	region string
	kid    string
}

func newALBFixture(t *testing.T, keys *keyServer) *albFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &albFixture{key: key, keys: keys, signer: testALBSigner, issuer: testALBIssuer, client: testALBClient, region: testALBRegion, kid: testALBKID}
	keys.put(f.keyURL(f.kid), ecPublicKeyPEM(t, &key.PublicKey))
	return f
}

func (f *albFixture) keyURL(kid string) string {
	return "https://public-keys.auth.elb." + f.region + ".amazonaws.com/" + kid
}

func (f *albFixture) config() *ALBConfig {
	return &ALBConfig{SignerARN: f.signer, Issuer: f.issuer, ClientID: f.client, Region: f.region}
}

// albToken is the tunable shape of a signed ALB header, so a test can bend exactly one field.
type albToken struct {
	Kid    string
	Alg    string
	Signer string
	Issuer string
	Client string
	Exp    int64
	Sub    string
	// SignWith overrides the signing key (for the forged-signature case).
	SignWith *ecdsa.PrivateKey
	// PadPayload emits the payload in AWS's padded base64 form rather than raw base64url.
	PadPayload bool
}

func (f *albFixture) mint(t *testing.T, tok albToken) string {
	t.Helper()
	if tok.Kid == "" {
		tok.Kid = f.kid
	}
	if tok.Alg == "" {
		tok.Alg = "ES256"
	}
	if tok.Signer == "" {
		tok.Signer = f.signer
	}
	if tok.Issuer == "" {
		tok.Issuer = f.issuer
	}
	if tok.Client == "" {
		tok.Client = f.client
	}
	if tok.Exp == 0 {
		tok.Exp = testFixedClock + 300
	}
	if tok.Sub == "" {
		tok.Sub = "alb-subject-1"
	}
	header, _ := json.Marshal(map[string]any{
		"typ": "JWT", "kid": tok.Kid, "alg": tok.Alg,
		"signer": tok.Signer, "iss": tok.Issuer, "client": tok.Client, "exp": tok.Exp,
	})
	payload, _ := json.Marshal(map[string]any{"sub": tok.Sub, "email": tok.Sub + "@example.test"})
	encHeader := base64.RawURLEncoding.EncodeToString(header)
	encPayload := base64.RawURLEncoding.EncodeToString(payload)
	if tok.PadPayload {
		encPayload = base64.URLEncoding.EncodeToString(payload) // AWS's padded form
	}
	signing := encHeader + "." + encPayload
	key := f.key
	if tok.SignWith != nil {
		key = tok.SignWith
	}
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	n := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// sha256Sum is the digest helper the hand-built token fixtures share with the verifier.
func sha256Sum(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}

func ecPublicKeyPEM(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// ---- bearer fixture ---------------------------------------------------------------------------

type bearerFixture struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	keys   *keyServer
	kid    string
}

func newBearerFixture(t *testing.T, keys *keyServer) *bearerFixture {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &bearerFixture{rsaKey: rk, ecKey: ek, keys: keys, kid: testBearerKID}
	f.publish(t, f.jwks(t))
	return f
}

func (f *bearerFixture) publish(t *testing.T, doc []byte) {
	t.Helper()
	f.keys.put(testBearerJWKS, doc)
}

func (f *bearerFixture) jwks(t *testing.T, extra ...jwkKey) []byte {
	t.Helper()
	keys := append([]jwkKey{rsaJWK(&f.rsaKey.PublicKey, f.kid), ecJWK(&f.ecKey.PublicKey, f.kid+"-ec")}, extra...)
	b, err := json.Marshal(jwksDoc{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rsaJWK(pub *rsa.PublicKey, kid string) jwkKey {
	return jwkKey{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(pub *ecdsa.PublicKey, kid string) jwkKey {
	return jwkKey{
		Kty: "EC", Kid: kid, Use: "sig", Alg: "ES256", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
	}
}

func (f *bearerFixture) config() *BearerConfig {
	return &BearerConfig{Issuer: testBearerIss, Audience: testBearerAud, JWKSURL: testBearerJWKS, Algorithms: []string{"RS256", "ES256"}}
}

// bearerToken is the tunable shape of a bearer JWT.
type bearerTok struct {
	Kid      string
	Alg      string
	Issuer   string
	Audience any
	Sub      string
	Exp      *int64
	Nbf      *int64
	SignWith *rsa.PrivateKey
	OmitExp  bool
	Unsigned bool
}

func (f *bearerFixture) mint(t *testing.T, tok bearerTok) string {
	t.Helper()
	if tok.Kid == "" {
		tok.Kid = f.kid
	}
	if tok.Alg == "" {
		tok.Alg = "RS256"
	}
	if tok.Issuer == "" {
		tok.Issuer = testBearerIss
	}
	if tok.Audience == nil {
		tok.Audience = testBearerAud
	}
	if tok.Sub == "" {
		tok.Sub = "bearer-subject-1"
	}
	claims := map[string]any{"iss": tok.Issuer, "sub": tok.Sub, "aud": tok.Audience}
	if !tok.OmitExp {
		exp := int64(testFixedClock + 300)
		if tok.Exp != nil {
			exp = *tok.Exp
		}
		claims["exp"] = exp
	}
	if tok.Nbf != nil {
		claims["nbf"] = *tok.Nbf
	}
	header, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": tok.Alg, "kid": tok.Kid})
	body, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	if tok.Unsigned {
		return signing + ".AAAA"
	}
	switch tok.Alg {
	case "ES256":
		digest := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, f.ecKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	default:
		key := f.rsaKey
		if tok.SignWith != nil {
			key = tok.SignWith
		}
		digest := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
}

// ---- grants + server wiring -------------------------------------------------------------------

// grantDoc builds a real grant policy document from entries.
func grantDoc(t *testing.T, subjects ...SubjectGrant) []byte {
	t.Helper()
	b, err := json.Marshal(GrantPolicy{Version: 1, Subjects: subjects})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func grantTable(t *testing.T, subjects ...SubjectGrant) *GrantTable {
	t.Helper()
	tbl, err := ParseGrantPolicy(grantDoc(t, subjects...))
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

// authFixture is a fully wired console with both credential paths and a grant table.
type authFixture struct {
	srv    *Server
	h      http.Handler
	alb    *albFixture
	bearer *bearerFixture
	keys   *keyServer
	auth   *Authenticator
}

// newAuthFixture builds a console whose auth boundary is real: both verifiers configured, keys
// served over the injected transport, the clock pinned, and the supplied grants loaded.
func newAuthFixture(t *testing.T, cfg Config, subjects ...SubjectGrant) *authFixture {
	t.Helper()
	if cfg.StateDir == "" {
		if cfg.HarnessDir != "" {
			cfg.StateDir = cfg.HarnessDir
		} else {
			cfg.StateDir = t.TempDir()
		}
	}
	keys := newKeyServer()
	alb := newALBFixture(t, keys)
	bearer := newBearerFixture(t, keys)
	// The grant table goes through the real file loader, so the tests exercise the same parse
	// and validation path a deployment does.
	grantsPath := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(grantsPath, grantDoc(t, subjects...), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(AuthConfig{
		ALB: alb.config(), Bearer: bearer.config(),
		GrantsPath:     grantsPath,
		TrustedOrigins: []string{testOrigin},
		Transport:      keys, Now: testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(cfg)
	srv.EnableAuth(auth)
	return &authFixture{srv: srv, h: srv.Handler(), alb: alb, bearer: bearer, keys: keys, auth: auth}
}

// albReq builds a request carrying a valid ALB signed identity for subject.
func (f *authFixture) albReq(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	return f.albReqAs(t, method, target, body, "alb-subject-1")
}

func (f *authFixture) albReqAs(t *testing.T, method, target, body, subject string) *http.Request {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(ALBDataHeader, f.alb.mint(t, albToken{Sub: subject}))
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Origin", testOrigin) // the browser CSRF boundary
	}
	return req
}

// bearerReq builds a request carrying a valid bearer token for subject.
func (f *authFixture) bearerReq(t *testing.T, method, target, body, subject string) *http.Request {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+f.bearer.mint(t, bearerTok{Sub: subject}))
	return req
}

func (f *authFixture) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}

// albSubject / bearerSubject name the grant keys the fixtures mint for.
func albSubject(sub string) string    { return sub }
func bearerSubject(sub string) string { return sub }

// operatorGrant / investorGrant / ownerGrant are the common bindings, written out explicitly so
// no test silently relies on a role or scope it did not ask for.
func operatorGrant(subject string, tenants, targets []string) SubjectGrant {
	return SubjectGrant{Issuer: testALBIssuer, Subject: subject, Roles: []string{"operator"}, Tenants: tenants, Targets: targets}
}

func investorGrant(subject string, tenants, targets []string) SubjectGrant {
	return SubjectGrant{Issuer: testALBIssuer, Subject: subject, Roles: []string{"investor"}, Tenants: tenants, Targets: targets}
}

func ownerGrant(subject string, tenants []string) SubjectGrant {
	return SubjectGrant{Issuer: testALBIssuer, Subject: subject, Roles: []string{"owner"}, Tenants: tenants, Targets: []string{defaultTargetID}}
}

func bearerOperatorGrant(subject string, tenants, targets []string) SubjectGrant {
	return SubjectGrant{Issuer: testBearerIss, Subject: subject, Roles: []string{"operator"}, Tenants: tenants, Targets: targets}
}

// testPrincipal attaches a verified principal directly, for the handful of tests that drive a
// handler function rather than the router. It mirrors exactly what the boundary would attach.
func testPrincipal(roles []Role, tenants, targets []string) *Principal {
	p := &Principal{
		Issuer: testALBIssuer, Subject: "direct-handler-subject", Source: "alb",
		Roles: roles, Tenants: tenants, Targets: targets,
	}
	p.Lens = p.defaultLens()
	return p
}

// withTestPrincipal returns r carrying p, as the guard would have left it.
func withTestPrincipal(r *http.Request, p *Principal) *http.Request {
	return r.WithContext(withPrincipal(r.Context(), p))
}

// testOwnerPrincipal / testOperatorPrincipal are the two direct-handler principals the
// data-behaviour tests use when they drive a handler function rather than the router.
func testOwnerPrincipal(tenants ...string) *Principal {
	return testPrincipal([]Role{RoleOwner}, tenants, []string{defaultTargetID})
}

func testOperatorPrincipal(tenants ...string) *Principal {
	if len(tenants) == 0 {
		tenants = []string{wildcardScope}
	}
	return testPrincipal([]Role{RoleOperator}, tenants, []string{wildcardScope})
}

// decisionRec builds one actuated decision record for a tenant — the shape the owner
// projection, the SSE stream and the history page all read.
func decisionRec(tenant, pod string) audit.Record {
	r := audit.ToRecord(model.Decision{
		Tenant: tenant, Namespace: tenant, Pod: pod, Action: model.ActionRotate,
		Selected: true, PerDollar: 13.23, Lambda: 0.6,
	})
	r.Kind = "phorvex.decision"
	r.Selected = true
	r.Actuated = true
	return r
}

// writeDecisionAudit writes records to a temp audit JSONL and returns its path.
func writeDecisionAudit(t *testing.T, recs ...audit.Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var body []byte
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, append(b, '\n')...)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// httptestNewRequest is a short alias so credential-negative tests read as one line.
func httptestNewRequest(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

func doGet(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}
