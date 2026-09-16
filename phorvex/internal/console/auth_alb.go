/*
 * Phorvex Console — AWS ALB Cognito signed-identity verification (M-136).
 *
 * This is the path the SHIPPED browser flow actually uses: console.phorvex.ai is an ALB ingress
 * with alb.ingress.kubernetes.io/auth-type: cognito, so an authenticated request arrives at the
 * pod carrying `x-amzn-oidc-data` — a JWT the load balancer signs with ES256.
 *
 * Protocol reference (primary):
 *   https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
 * It documents the signed user-claims header, the ES256 signature, the `signer` / `iss` / `client`
 * / `exp` header fields, the padded payload encoding, and the region-specific public-key endpoint.
 *
 * What is verified, in order, before ANY claim is believed:
 *   1. three JWS parts, alg is exactly ES256 (no alg substitution, no `none`);
 *   2. the `signer` field equals the CONFIGURED load-balancer ARN exactly — a token minted by a
 *      different load balancer, in a different account, is rejected;
 *   3. `iss` and `client` equal the configured user-pool issuer and app-client id;
 *   4. `exp` (the signed header's own expiry) is present and unexpired within a bounded leeway;
 *   5. the kid passes a charset check and the key is fetched from the FIXED AWS endpoint for the
 *      CONFIGURED region — never a host, path or URL taken from the token;
 *   6. the ES256 signature verifies over the literal `header.payload` bytes as received;
 *   7. only then is `sub` read out of the payload.
 *
 * `x-amzn-oidc-identity` and `x-amzn-oidc-accesstoken` are NOT identity here. They are unsigned
 * (identity) or opaque-to-us (access token) values that any client able to reach the pod could
 * set, so they are never read.
 */

package console

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ALBDataHeader is the signed user-claims header the ALB injects.
const ALBDataHeader = "x-amzn-oidc-data"

// albUnsignedHeaders are the ALB headers that are NOT proof of identity. They are listed so the
// boundary can say so explicitly rather than by omission.
var albUnsignedHeaders = []string{"x-amzn-oidc-identity", "x-amzn-oidc-accesstoken"}

var (
	errALBNoHeader    = errors.New("alb: no x-amzn-oidc-data header")
	errALBMalformed   = errors.New("alb: malformed x-amzn-oidc-data JWT")
	errALBAlg         = errors.New("alb: algorithm not allowed (ES256 only)")
	errALBSigner      = errors.New("alb: signer is not the configured load balancer")
	errALBIssuer      = errors.New("alb: issuer mismatch")
	errALBClient      = errors.New("alb: client mismatch")
	errALBExpired     = errors.New("alb: signed header expired")
	errALBNoExpiry    = errors.New("alb: signed header carries no exp")
	errALBKID         = errors.New("alb: invalid key id")
	errALBKeyFetch    = errors.New("alb: signing key unavailable")
	errALBSignature   = errors.New("alb: signature verification failed")
	errALBNoSubject   = errors.New("alb: verified payload carries no subject")
	errALBKeyPressure = errors.New("alb: key-fetch budget exhausted")
)

// awsRegionRe guards the ONE configured value that is interpolated into the key endpoint host.
var awsRegionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+){1,2}-\d$`)

// ALBConfig is the per-deployment ALB identity surface. Every field is a configuration
// identifier read from the deployment, not a secret and not a default.
type ALBConfig struct {
	// SignerARN is the exact load-balancer ARN whose signature is trusted, e.g.
	// arn:aws:elasticloadbalancing:us-east-2:<account>:loadbalancer/app/<name>/<id>
	SignerARN string
	// AdditionalSignerARNs explicitly trusts other ALBs for the same issuer/client,
	// restricted to the primary signer account, partition and region.
	AdditionalSignerARNs []string
	// Issuer is the Cognito user-pool issuer URL the ALB stamps into `iss`.
	Issuer string
	// ClientID is the user-pool app-client id the ALB stamps into `client`.
	ClientID string
	// Region selects the FIXED AWS public-key endpoint. Defaults to the region parsed out of
	// SignerARN when empty.
	Region string
	// Leeway bounds clock skew on the signed header's expiry (default 60s, capped at 5m).
	Leeway time.Duration
}

func (c ALBConfig) validate() (ALBConfig, error) {
	c.SignerARN = strings.TrimSpace(c.SignerARN)
	c.Issuer = strings.TrimSpace(c.Issuer)
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.Region = strings.TrimSpace(c.Region)
	if c.SignerARN == "" {
		return c, fmt.Errorf("alb config: signer ARN is required")
	}
	if !validALBARN(c.SignerARN) {
		return c, fmt.Errorf("alb config: signer %q is not an application load balancer ARN", c.SignerARN)
	}
	if c.Issuer == "" {
		return c, fmt.Errorf("alb config: issuer is required")
	}
	if c.ClientID == "" {
		return c, fmt.Errorf("alb config: client id is required")
	}
	if c.Region == "" {
		c.Region = regionFromARN(c.SignerARN)
	}
	if !awsRegionRe.MatchString(c.Region) {
		return c, fmt.Errorf("alb config: region %q is not a valid AWS region", c.Region)
	}
	if c.Region != regionFromARN(c.SignerARN) {
		return c, fmt.Errorf("alb config: region must match signer ARN")
	}
	primary := strings.Split(c.SignerARN, ":")
	additional := make([]string, 0, len(c.AdditionalSignerARNs))
	for _, signer := range c.AdditionalSignerARNs {
		signer = strings.TrimSpace(signer)
		if !validALBARN(signer) {
			return c, fmt.Errorf("alb config: invalid additional signer ARN %q", signer)
		}
		parts := strings.Split(signer, ":")
		if parts[1] != primary[1] || parts[3] != primary[3] || parts[4] != primary[4] {
			return c, fmt.Errorf("alb config: additional signer must share primary partition, region and account")
		}
		additional = append(additional, signer)
	}
	c.AdditionalSignerARNs = additional
	if c.Leeway <= 0 {
		c.Leeway = 60 * time.Second
	}
	if c.Leeway > 5*time.Minute {
		return c, fmt.Errorf("alb config: leeway %s exceeds the 5m bound", c.Leeway)
	}
	return c, nil
}

func validALBARN(arn string) bool {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "elasticloadbalancing" || !awsRegionRe.MatchString(parts[3]) {
		return false
	}
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(parts[4]) {
		return false
	}
	return regexp.MustCompile(`^loadbalancer/app/[A-Za-z0-9-]+/[A-Za-z0-9]+$`).MatchString(parts[5])
}

func (c ALBConfig) trustsSigner(signer string) bool {
	if signer == c.SignerARN {
		return true
	}
	for _, allowed := range c.AdditionalSignerARNs {
		if signer == allowed {
			return true
		}
	}
	return false
}

// regionFromARN extracts field 4 of an ARN (arn:partition:service:region:account:resource).
func regionFromARN(arn string) string {
	f := strings.Split(arn, ":")
	if len(f) < 4 {
		return ""
	}
	return f[3]
}

// ALBVerifier verifies x-amzn-oidc-data and caches the ALB's per-kid public keys.
type ALBVerifier struct {
	cfg    ALBConfig
	fetch  *boundedFetcher
	budget *missBudget
	flight *singleFlight
	now    func() time.Time
	keyTTL time.Duration

	mu   sync.Mutex
	keys map[string]albCachedKey
}

type albCachedKey struct {
	key     *ecdsa.PublicKey
	fetched time.Time
}

// NewALBVerifier validates the configuration and builds the verifier. A malformed configuration
// is an error the deployment must fix — never a silently disabled check.
func NewALBVerifier(cfg ALBConfig, rt http.RoundTripper, now func() time.Time) (*ALBVerifier, error) {
	valid, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &ALBVerifier{
		cfg:    valid,
		fetch:  newBoundedFetcher(rt, keyFetchTimeout, keyMaxBody),
		budget: newMissBudget(1, 10, now), // 10 burst, 1/s sustained: rotation is fine, floods are not
		flight: newSingleFlight(),
		now:    now,
		keyTTL: 12 * time.Hour,
		keys:   map[string]albCachedKey{},
	}, nil
}

// albHeader is the JOSE header the ALB uses; it carries the trust fields, not just alg/kid.
type albHeader struct {
	Typ    string `json:"typ"`
	Kid    string `json:"kid"`
	Alg    string `json:"alg"`
	Iss    string `json:"iss"`
	Client string `json:"client"`
	Signer string `json:"signer"`
	Exp    int64  `json:"exp"`
}

// albPayload is the verified user-claims payload. Only `sub` is authorization-relevant; the
// Cognito user pool in use carries no role or tenant custom claims, so nothing else is read
// for authorization and the grant table decides what the subject may do.
type albPayload struct {
	Sub string `json:"sub"`
}

// decodeSegment accepts the encodings AWS emits. The signed-claims payload is documented as
// padded base64, while the JOSE header and the signature are raw base64url. Being liberal about
// PADDING is safe: the bytes are still covered by the signature that is checked afterwards.
func decodeSegment(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("segment is not base64")
}

// VerifyRequest verifies the ALB signed header on r and returns the verified issuer+subject.
func (v *ALBVerifier) VerifyRequest(r *http.Request) (issuer, subject string, err error) {
	raw := strings.TrimSpace(r.Header.Get(ALBDataHeader))
	if raw == "" {
		return "", "", errALBNoHeader
	}
	return v.Verify(r.Context(), raw)
}

// Verify checks one x-amzn-oidc-data token end to end.
func (v *ALBVerifier) Verify(ctx context.Context, token string) (issuer, subject string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", errALBMalformed
	}
	hb, err := decodeSegment(parts[0])
	if err != nil {
		return "", "", errALBMalformed
	}
	var h albHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return "", "", errALBMalformed
	}
	// (1) exact algorithm — before any key lookup, so an alg swap cannot pick a different scheme.
	if h.Alg != "ES256" {
		return "", "", errALBAlg
	}
	// (2)(3) the trust fields: this load balancer, this user pool, this app client.
	if !v.cfg.trustsSigner(h.Signer) {
		return "", "", errALBSigner
	}
	if h.Iss != v.cfg.Issuer {
		return "", "", errALBIssuer
	}
	if h.Client != v.cfg.ClientID {
		return "", "", errALBClient
	}
	// (4) the signed header's own expiry is mandatory.
	if h.Exp == 0 {
		return "", "", errALBNoExpiry
	}
	if v.now().After(time.Unix(h.Exp, 0).Add(v.cfg.Leeway)) {
		return "", "", errALBExpired
	}
	// (5) a validated kid against the fixed regional endpoint.
	if !validKID(h.Kid) {
		return "", "", errALBKID
	}
	key, err := v.publicKey(ctx, h.Kid)
	if err != nil {
		return "", "", err
	}
	// (6) the signature, over the literal bytes as received.
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return "", "", errALBMalformed
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !verifyES256(key, digest[:], sig) {
		return "", "", errALBSignature
	}
	// (7) only now is the payload read.
	pb, err := decodeSegment(parts[1])
	if err != nil {
		return "", "", errALBMalformed
	}
	var p albPayload
	if err := json.Unmarshal(pb, &p); err != nil {
		return "", "", errALBMalformed
	}
	if strings.TrimSpace(p.Sub) == "" {
		return "", "", errALBNoSubject
	}
	return h.Iss, strings.TrimSpace(p.Sub), nil
}

// keyURL builds the FIXED AWS endpoint for the configured region and a validated kid. Nothing
// from the token influences the scheme, host or path beyond that charset-checked id.
func (v *ALBVerifier) keyURL(kid string) string {
	return "https://public-keys.auth.elb." + v.cfg.Region + ".amazonaws.com/" + kid
}

func (v *ALBVerifier) publicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if key, ok := v.cachedKey(kid); ok {
		return key, nil
	}
	// A miss is the attacker-influenced path: budget it before touching the network.
	if !v.budget.allow() {
		return nil, errALBKeyPressure
	}
	owner, ch := v.flight.enter(kid)
	if !owner {
		<-ch
		if key, ok := v.cachedKey(kid); ok {
			return key, nil
		}
		return nil, errALBKeyFetch
	}
	defer v.flight.leave(kid, ch)

	body, err := v.fetch.get(ctx, v.keyURL(kid))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errALBKeyFetch, err)
	}
	key, err := parseECPublicKeyPEM(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errALBKeyFetch, err)
	}
	v.mu.Lock()
	v.keys[kid] = albCachedKey{key: key, fetched: v.now()}
	v.mu.Unlock()
	return key, nil
}

func (v *ALBVerifier) cachedKey(kid string) (*ecdsa.PublicKey, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.keys[kid]
	if !ok {
		return nil, false
	}
	// Expire on TTL so a rotated-out key cannot be honoured indefinitely.
	if v.now().Sub(e.fetched) > v.keyTTL {
		delete(v.keys, kid)
		return nil, false
	}
	return e.key, true
}

// parseECPublicKeyPEM reads the PEM-encoded P-256 public key the AWS endpoint serves.
func parseECPublicKeyPEM(body []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("key parse: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want an ECDSA public key", pub)
	}
	if ec.Curve == nil || ec.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("key is not on a 256-bit curve")
	}
	return ec, nil
}

// verifyES256 accepts the JWS fixed-width r||s encoding and, as a fallback, the ASN.1 form.
// Both are the SAME signature over the same digest under the same key: only the transport
// encoding differs, so accepting either verifies no less than accepting one.
func verifyES256(key *ecdsa.PublicKey, digest, sig []byte) bool {
	if n := (key.Curve.Params().BitSize + 7) / 8; len(sig) == 2*n {
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if ecdsa.Verify(key, digest, r, s) {
			return true
		}
	}
	return ecdsa.VerifyASN1(key, digest, sig)
}
