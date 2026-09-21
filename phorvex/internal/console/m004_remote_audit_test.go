package console

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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
)

func m004Certificates(t *testing.T, dir string) (serverCert, serverKey, clientCert, clientKey, caFile string) {
	t.Helper()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "M004 fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	caFile = filepath.Join(dir, "ca.crt")
	if e = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); e != nil {
		t.Fatal(e)
	}
	makeLeaf := func(name, dns string) (string, string) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			t.Fatal(e)
		}
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		pk, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		c, k := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		if e = os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}), 0600); e != nil {
			t.Fatal(e)
		}
		return c, k
	}
	serverCert, serverKey = makeLeaf("server", "audit-source.test")
	clientCert, clientKey = makeLeaf("client", "audit-console.test")
	return
}

func TestRemoteLiveReportsMultiRotationGap(t *testing.T) {
	dir := t.TempDir()
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	path := filepath.Join(dir, "live.jsonl")
	writeHistory(t, path, historyRecord(1, false))
	cfg := audittransport.ServerConfig{AuditPath: path, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 3}
	ts := httptest.NewUnstartedServer(cfg.Handler())
	ts.TLS = cfg.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{AuditSource: client})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.live(w, withTestPrincipal(httptest.NewRequest(http.MethodGet, "/api/live?lens=operator&tail=all", nil).WithContext(ctx), testOperatorPrincipal()))
		close(done)
	}()
	time.Sleep(200 * time.Millisecond) // initial authenticated replay precedes the one-second poll
	if err = os.Rename(path, path+".2"); err != nil {
		t.Fatal(err)
	}
	writeHistory(t, path, historyRecord(2, false))
	if err = os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeHistory(t, path, historyRecord(3, false))
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("live stream did not report retained multi-rotation gap")
	}
	body := w.Body.String()
	if !strings.Contains(body, "More than one audit rotation") {
		t.Fatalf("missing visible gap notice: %s", body)
	}
	if strings.Contains(body, "pod-0003") {
		t.Fatalf("stream resumed across unobserved generation: %s", body)
	}
}

func TestRemoteOwnerCoverageMetadataRespectsTenantGrant(t *testing.T) {
	dir := t.TempDir()
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	path := filepath.Join(dir, "live.jsonl")
	mine := historyRecord(1, false)
	mine.Tenant = "acme"
	mine.Selected = true
	mine.Time = time.Unix(100, 0).UTC()
	other := historyRecord(2, false)
	other.Tenant = "other"
	other.Selected = true
	other.Time = time.Unix(900, 0).UTC()
	writeHistory(t, path, mine, other)
	cfg := audittransport.ServerConfig{AuditPath: path, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 2}
	ts := httptest.NewUnstartedServer(cfg.Handler())
	ts.TLS = cfg.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{AuditSource: client})
	last := historyRecord(3, false)
	last.Tenant = "acme"
	line, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(line); err != nil {
		t.Fatal(err)
	}
	f.Close()
	recs, partial, err := s.readAudit(context.Background())
	if err != nil || !partial || len(recs) != 2 {
		t.Fatalf("unframed last line counted: count=%d partial=%v error=%v", len(recs), partial, err)
	}
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte{'\n'}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	recs, partial, err = s.readAudit(context.Background())
	if err != nil || partial || len(recs) != 3 {
		t.Fatalf("completed last line not counted: count=%d partial=%v error=%v", len(recs), partial, err)
	}
	p := testOperatorPrincipal("acme")
	for _, route := range []string{"/api/owner/events?tenant=acme", "/api/owner/tenants"} {
		w := httptest.NewRecorder()
		r := withTestPrincipal(httptest.NewRequest(http.MethodGet, route, nil), p)
		if strings.Contains(route, "events") {
			s.ownerEvents(w, r)
		} else {
			s.ownerTenants(w, r)
		}
		if w.Code != 200 {
			t.Fatalf("%s returned %d: %s", route, w.Code, w.Body.String())
		}
		if bytes.Contains(w.Body.Bytes(), []byte(`1970-01-01T00:15:00`)) {
			t.Fatalf("%s leaked other tenant activity time: %s", route, w.Body.String())
		}
		if !bytes.Contains(w.Body.Bytes(), []byte(`1970-01-01T00:01:40`)) {
			t.Fatalf("%s missing granted tenant coverage: %s", route, w.Body.String())
		}
	}
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6000; i++ {
		if _, err = f.Write([]byte(fmt.Sprintf("{\"kind\":\"phorvex.decision\",\"tenant\":\"n-%05d\"}\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	recs, partial, err = s.readAudit(context.Background())
	if err != nil || !partial || len(recs) != 5000 || recs[0].Tenant != "n-01000" || recs[len(recs)-1].Tenant != "n-05999" {
		t.Fatalf("decoded latest-record bound failed: len=%d partial=%v first=%q last=%q error=%v", len(recs), partial, func() string {
			if len(recs) > 0 {
				return recs[0].Tenant
			}
			return ""
		}(), func() string {
			if len(recs) > 0 {
				return recs[len(recs)-1].Tenant
			}
			return ""
		}(), err)
	}
}

func TestRemoteAuditFeedsHistoryAndDerivedReaders(t *testing.T) {
	dir := t.TempDir()
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	path := filepath.Join(dir, "manager", "live.jsonl")
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	first := historyRecord(1, false)
	first.Tenant = "acme"
	first.Reason = "observed causal decision"
	second := historyRecord(2, false)
	second.Tenant = "other"
	second.Reason = "observed causal decision"
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, rec := range []any{first, second} {
		if e = json.NewEncoder(f).Encode(rec); e != nil {
			t.Fatal(e)
		}
	}
	f.Close()
	cfg := audittransport.ServerConfig{AuditPath: path, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 2}
	ts := httptest.NewUnstartedServer(cfg.Handler())
	ts.TLS = cfg.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, e := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if e != nil {
		t.Fatal(e)
	}
	s := NewServer(Config{AuditSource: client})
	t.Cleanup(func() { _ = s.Close() })
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := explainabilityFromAuditContext(canceled, "audit://live", client); err == nil {
		t.Fatal("canceled request continued remote explainability read")
	}
	q := url.Values{"lens": {"operator"}, "limit": {"10"}, "includeNoop": {"true"}}
	page, _ := getHistory(t, s, q, 200)
	if len(page.Events) != 2 {
		t.Fatalf("history failed to read complete remote source: %+v", page)
	}
	if _, total, err := explainabilityFromAudit("audit://live", client); err != nil || total != 2 {
		t.Fatalf("derived audit count=%d error=%v", total, err)
	}
	owner := testOperatorPrincipal("acme")
	ownPage, _ := getHistoryAs(t, s, owner, url.Values{"lens": {"operator"}, "tenant": {"acme"}, "includeNoop": {"true"}}, 200)
	if len(ownPage.Events) != 1 {
		t.Fatalf("remote history tenant scope widened: %+v", ownPage)
	}
	if e = os.Rename(path, path+".1"); e != nil {
		t.Fatal(e)
	}
	third := historyRecord(3, false)
	third.Tenant = "acme"
	third.Reason = "after rotation"
	newFile, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.NewEncoder(newFile).Encode(third); e != nil {
		t.Fatal(e)
	}
	newFile.Close()
	page, _ = getHistory(t, s, q, 200)
	if len(page.Events) != 3 {
		t.Fatalf("remote history lost retained rotation: %+v", page)
	}
	paged := url.Values{"lens": {"operator"}, "limit": {"1"}, "includeNoop": {"true"}}
	var pages []historyItem
	for i := 0; i < 4; i++ {
		p, _ := getHistory(t, s, paged, 200)
		pages = append(pages, p.Events...)
		if p.NextCursor == "" {
			break
		}
		paged.Set("cursor", p.NextCursor)
	}
	if len(pages) != 3 {
		t.Fatalf("paged historical source omitted retained decisions: %+v", pages)
	}
	if _, total, err := explainabilityFromAudit("audit://live", client); err != nil || total != 1 {
		t.Fatalf("derived live reader did not follow rotation: %d error=%v", total, err)
	}
	if e = os.Rename(path, path+".outage"); e != nil {
		t.Fatal(e)
	}
	if _, _, err := explainabilityFromAudit("audit://live", client); err == nil {
		t.Fatal("source outage returned a derived count")
	}
	if e = os.Rename(path+".outage", path); e != nil {
		t.Fatal(e)
	}
	if _, total, err := explainabilityFromAudit("audit://live", client); err != nil || total != 1 {
		t.Fatalf("source did not reconnect: count=%d error=%v", total, err)
	}
}
