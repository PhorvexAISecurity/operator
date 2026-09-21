package audittransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

type blockedAuditWriter struct {
	*httptest.ResponseRecorder
	entered chan<- struct{}
	release <-chan struct{}
}

func (w blockedAuditWriter) Write(p []byte) (int, error) {
	w.entered <- struct{}{}
	<-w.release
	return w.ResponseRecorder.Write(p)
}

func TestAuditSourceBoundsSlowResponseWriters(t *testing.T) {
	_, _, path, _, _, _ := fixture(t)
	h := (ServerConfig{AuditPath: path, MaxBackups: 2}).Handler()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	done := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func() {
			h.ServeHTTP(blockedAuditWriter{httptest.NewRecorder(), entered, release}, httptest.NewRequest(http.MethodGet, "/v1/manifest", nil))
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("reader did not reach slow writer")
		}
	}
	fifth := httptest.NewRecorder()
	h.ServeHTTP(fifth, httptest.NewRequest(http.MethodGet, "/v1/manifest", nil))
	if fifth.Code != http.StatusServiceUnavailable {
		close(release)
		t.Fatalf("fifth slow-reader request was not bounded: %d", fifth.Code)
	}
	close(release)
	for i := 0; i < 4; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("reader did not release")
		}
	}
}

func leaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	raw, e := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk})
}

func pki(t *testing.T, dir string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "audit-test-CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "ca.crt")
	if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); e != nil {
		t.Fatal(e)
	}
	return ca, key, path
}

func writeLeaf(t *testing.T, dir, prefix string, cert, key []byte) (string, string) {
	t.Helper()
	c := filepath.Join(dir, prefix+".crt")
	k := filepath.Join(dir, prefix+".key")
	if e := os.WriteFile(c, cert, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(k, key, 0600); e != nil {
		t.Fatal(e)
	}
	return c, k
}

func fixture(t *testing.T) (*httptest.Server, *Client, string, *x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	dir := t.TempDir()
	ca, caKey, caPath := pki(t, dir)
	sc, sk := leaf(t, ca, caKey, "audit-source.test", time.Now().Add(time.Hour))
	serverCert, serverKey := writeLeaf(t, dir, "server", sc, sk)
	cc, ck := leaf(t, ca, caKey, "audit-console.test", time.Now().Add(time.Hour))
	clientCert, clientKey := writeLeaf(t, dir, "client", cc, ck)
	auditPath := filepath.Join(dir, "audit", "live.jsonl")
	if e := os.MkdirAll(filepath.Dir(auditPath), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(auditPath, []byte("{\"kind\":\"phorvex.decision\",\"tenant\":\"one\"}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	cfg := ServerConfig{AuditPath: auditPath, CertFile: serverCert, KeyFile: serverKey, CAFile: caPath, ClientDNSName: "audit-console.test", MaxBackups: 2}
	ts := httptest.NewUnstartedServer(cfg.Handler())
	ts.TLS = cfg.tlsConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	client, e := NewClient(ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: clientCert, KeyFile: clientKey, CAFile: caPath})
	if e != nil {
		t.Fatal(e)
	}
	return ts, client, auditPath, ca, caKey, dir
}

func TestMutualTLSIdentityAndCertificateRotation(t *testing.T) {
	_, client, _, ca, key, dir := fixture(t)
	ctx := context.Background()
	if _, e := client.Manifest(ctx); e != nil {
		t.Fatal(e)
	}
	wrong, wrongKey := leaf(t, ca, key, "other-console.test", time.Now().Add(time.Hour))
	wc, wk := writeLeaf(t, dir, "wrong", wrong, wrongKey)
	bad := *client
	bad.cfg.CertFile = wc
	bad.cfg.KeyFile = wk
	if _, e := bad.Manifest(ctx); e == nil {
		t.Fatal("wrong peer identity accepted")
	}
	bad = *client
	bad.cfg.CertFile = filepath.Join(dir, "absent")
	if _, e := bad.Manifest(ctx); e == nil {
		t.Fatal("missing client certificate accepted")
	}
	expired, expiredKey := leaf(t, ca, key, "audit-console.test", time.Now().Add(-time.Minute))
	ec, ek := writeLeaf(t, dir, "expired", expired, expiredKey)
	bad = *client
	bad.cfg.CertFile = ec
	bad.cfg.KeyFile = ek
	if _, e := bad.Manifest(ctx); e == nil {
		t.Fatal("expired client accepted")
	}
	otherCA, otherKey, otherPath := pki(t, filepath.Join(t.TempDir()))
	rogue, rogueKey := leaf(t, otherCA, otherKey, "audit-console.test", time.Now().Add(time.Hour))
	rc, rk := writeLeaf(t, dir, "rogue", rogue, rogueKey)
	bad = *client
	bad.cfg.CertFile = rc
	bad.cfg.KeyFile = rk
	if _, e := bad.Manifest(ctx); e == nil {
		t.Fatal("untrusted client accepted")
	}
	bad = *client
	bad.cfg.CAFile = otherPath
	if _, e := bad.Manifest(ctx); e == nil {
		t.Fatal("untrusted server accepted")
	}
	// Client key rotation uses the same CA and identity. Each request reloads.
	rotated, rotatedKey := leaf(t, ca, key, "audit-console.test", time.Now().Add(time.Hour))
	if e := os.WriteFile(client.cfg.CertFile, rotated, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(client.cfg.KeyFile, rotatedKey, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := client.Manifest(ctx); e != nil {
		t.Fatalf("rotated client did not reconnect: %v", e)
	}
}

func TestPinnedReaderSurvivesRetainedRotationAndDetectsTruncation(t *testing.T) {
	_, client, path, _, _, _ := fixture(t)
	ctx := context.Background()
	m, e := client.Manifest(ctx)
	if e != nil {
		t.Fatal(e)
	}
	reader := client.Open(ctx, m.Segments[0])
	b := make([]byte, m.Segments[0].Size)
	if _, e = reader.ReadAt(b, 0); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(b, []byte(`"tenant":"one"`)) {
		t.Fatalf("wrong remote bytes %q", b)
	}
	if e = os.Rename(path, path+".1"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte(`{"kind":"phorvex.decision","tenant":"two"}`+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = reader.Verify(); e != nil {
		t.Fatalf("retained pinned generation lost: %v", e)
	}
	appendFile, e := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = appendFile.Write([]byte(`{"kind":"phorvex.decision","tenant":"later"}` + "\n")); e != nil {
		t.Fatal(e)
	}
	appendFile.Close()
	if e = reader.Verify(); e != nil {
		t.Fatalf("append beyond pinned boundary invalidated retained prefix: %v", e)
	}
	if e = os.Truncate(path+".1", 0); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path+".1", []byte(`{"kind":"phorvex.decision","tenant":"reset"}`+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = reader.Verify(); e == nil {
		t.Fatal("truncated and regrown pinned audit accepted")
	}
}

func TestAuditClientRefusesRedirect(t *testing.T) {
	_, client, _, ca, key, dir := fixture(t)
	cert, private := leaf(t, ca, key, "audit-source.test", time.Now().Add(time.Hour))
	sc, sk := writeLeaf(t, dir, "redirect-server", cert, private)
	visits := 0
	cfg := ServerConfig{CertFile: sc, KeyFile: sk, CAFile: filepath.Join(dir, "ca.crt"), ClientDNSName: "audit-console.test"}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visits++
		if r.URL.Path == "/v1/manifest" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		http.Error(w, "redirect target must not be requested", http.StatusForbidden)
	}))
	ts.TLS = cfg.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	other := *client
	other.cfg.URL = ts.URL
	if _, err := other.Manifest(context.Background()); err == nil {
		t.Fatal("redirect accepted as an audit manifest")
	}
	if visits != 1 {
		t.Fatalf("audit redirect followed, visits=%d", visits)
	}
}

func TestPost25M108AuthenticatedParameterMaterialRetrieval(t *testing.T) {
	_, client, auditPath, _, _, _ := fixture(t)
	store, err := audit.NewParameterMaterialStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := model.DecisionParameterManifest{SchemaVersion: model.DecisionParameterManifestV1, ID: "source-a", Parameters: []model.DecisionParameter{{
		Name: "parameter-a", Group: "group-a", Unit: "ratio", Domain: "[0,1]", Default: 0.5,
		Source: "fixture", Provenance: model.ParameterUnknown, Limitations: "fixture only", DependencyGroup: "group-a",
	}}}
	overrides := model.EffectivePolicyOverrides{SchemaVersion: model.DecisionPolicyOverridesV1, ID: "ns/policy@uid:1",
		Values: []model.EffectivePolicyParameter{{Name: "policy-a", Unit: "ratio", Present: true, Value: 0.25}}}
	mh, _ := manifest.CanonicalHash()
	oh, _ := overrides.CanonicalHash()
	ref := &model.ParameterSetReference{SchemaVersion: model.DecisionParameterSetV1, ManifestID: manifest.ID, ManifestHash: mh,
		PolicyOverridesID: overrides.ID, PolicyOverridesHash: oh}
	if err := store.Store(ref, manifest, overrides); err != nil {
		t.Fatal(err)
	}
	raw, err := client.ParameterMaterial(context.Background(), audit.ParameterMaterialManifest, mh)
	if err != nil {
		t.Fatal(err)
	}
	var got model.DecisionParameterManifest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if hash, _ := got.CanonicalHash(); hash != mh {
		t.Fatalf("remote manifest changed hash: %s != %s", hash, mh)
	}
	unknown := "sha256:" + strings.Repeat("0", 64)
	if _, err := client.ParameterMaterial(context.Background(), audit.ParameterMaterialManifest, unknown); err == nil {
		t.Fatal("unknown remote material accepted")
	}
}

func TestPost25M108ClientRejectsWrongParameterMaterialBody(t *testing.T) {
	_, client, _, ca, key, dir := fixture(t)
	cert, private := leaf(t, ca, key, "audit-source.test", time.Now().Add(time.Hour))
	sc, sk := writeLeaf(t, dir, "wrong-material-server", cert, private)
	wanted := "sha256:" + strings.Repeat("1", 64)
	cfg := ServerConfig{CertFile: sc, KeyFile: sk, CAFile: filepath.Join(dir, "ca.crt"), ClientDNSName: "audit-console.test"}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Parameter-Material-Hash", wanted)
		_, _ = w.Write([]byte(`{"wrong":true}`))
	}))
	ts.TLS = cfg.tlsConfig()
	ts.StartTLS()
	defer ts.Close()
	other := *client
	other.cfg.URL = ts.URL
	if _, err := other.ParameterMaterial(context.Background(), audit.ParameterMaterialManifest, wanted); err == nil {
		t.Fatal("wrong-hash parameter material body accepted")
	}
}
