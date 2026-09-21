package lossobserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type m100BlockingGetClient struct{ client.Client }

func (c m100BlockingGetClient) Get(ctx context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	<-ctx.Done()
	return ctx.Err()
}

func m100CertificateAuthority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "m100-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ca, key, pool
}

func m100LeafCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func m100ObserverConfig(body []byte) ObserverConfig {
	sum := sha256.Sum256(body)
	return ObserverConfig{
		PolicyEpoch:     model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1},
		TargetNamespace: "ns", TargetName: "pod", TargetUID: "pod-uid",
		ProtectedScope: model.ProtectedScope{Tenant: "tenant", Asset: "synthetic", Version: "v1", Property: "confidentiality"},
		EvidenceID:     "evidence", RuleVersion: "rule-v1", RuleDigest: strings.Repeat("b", 64),
		ObserverIdentity: "system:serviceaccount:ns:observer", ExpectedBytes: int64(len(body)),
		ExpectedSHA256: hex.EncodeToString(sum[:]), Timeout: time.Second,
	}
}

func observerObjects() (*runtime.Scheme, []runtime.Object) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = amtdv1beta1.AddToScheme(scheme)
	yes := true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app-rs", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "app", UID: "dep-uid", Controller: &yes}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "app-rs", UID: "rs-uid", Controller: &yes}}}}
	return scheme, []runtime.Object{dep, rs, pod}
}

func TestM100ObserverRequiresExactCompletedTLSResponse(t *testing.T) {
	body := []byte("synthetic-canary")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	ruleDigest := strings.Repeat("b", 64)
	cases := []struct {
		name        string
		status      int
		response    []byte
		wrongDigest bool
		wantEvent   bool
	}{
		{"exact-200", 200, body, false, true}, {"202", 202, body, false, false}, {"206", 206, body, false, false},
		{"404", 404, body, false, false}, {"500", 500, body, false, false}, {"partial", 200, body[:5], false, false},
		{"extra", 200, append(append([]byte(nil), body...), 'x'), false, false}, {"digest", 200, body, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gets atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				gets.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.response)
			}))
			defer server.Close()
			scheme, objects := observerObjects()
			c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
			expected := digest
			if tc.wrongDigest {
				expected = strings.Repeat("c", 64)
			}
			now := time.Unix(100, 0).UTC()
			event, err := ObserveOnce(context.Background(), c, server.Client(), ObserverConfig{
				URL: server.URL, PolicyEpoch: model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1},
				TargetNamespace: "ns", TargetName: "pod", TargetUID: "pod-uid",
				ProtectedScope: model.ProtectedScope{Tenant: "tenant", Asset: "synthetic", Version: "v1", Property: "confidentiality"},
				EvidenceID:     "evidence", RuleVersion: "rule-v1", RuleDigest: ruleDigest,
				ObserverIdentity: "system:serviceaccount:ns:observer",
				ExpectedBytes:    int64(len(body)), ExpectedSHA256: expected, Timeout: time.Second,
			}, func() time.Time { now = now.Add(time.Millisecond); return now })
			if gets.Load() != 1 {
				t.Fatalf("GETs=%d", gets.Load())
			}
			var events amtdv1beta1.SecurityEventList
			if listErr := c.List(context.Background(), &events); listErr != nil {
				t.Fatal(listErr)
			}
			if tc.wantEvent {
				if err != nil || event == nil || len(events.Items) != 1 {
					t.Fatalf("positive event=%v count=%d err=%v", event, len(events.Items), err)
				}
				stored := events.Items[0]
				if stored.Annotations[disclosure.Annotation] == "" || stored.Annotations["phorvex.ai/creator-identity"] != "" {
					t.Fatalf("producer bypassed or forged admission: %+v", stored.Annotations)
				}
				if strings.Contains(stored.Annotations[disclosure.Annotation], string(body)) {
					t.Fatal("canary body leaked into event")
				}
			} else if err == nil || event != nil || len(events.Items) != 0 {
				t.Fatalf("negative emitted event=%v count=%d err=%v", event, len(events.Items), err)
			}
		})
	}

	// The wrong trust root fails before any response can become evidence.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	scheme, objects := observerObjects()
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	_, err := ObserveOnce(context.Background(), c, http.DefaultClient, ObserverConfig{URL: server.URL,
		PolicyEpoch:     model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1},
		TargetNamespace: "ns", TargetName: "pod", TargetUID: "pod-uid",
		ProtectedScope: model.ProtectedScope{Tenant: "tenant", Asset: "synthetic", Version: "v1", Property: "confidentiality"},
		EvidenceID:     "evidence", RuleVersion: "rule-v1", RuleDigest: ruleDigest,
		ObserverIdentity: "system:serviceaccount:ns:observer",
		ExpectedBytes:    int64(len(body)), ExpectedSHA256: digest, Timeout: time.Second}, time.Now)
	if err == nil {
		t.Fatal("wrong CA emitted completed disclosure")
	}
	var events amtdv1beta1.SecurityEventList
	if err := c.List(context.Background(), &events); err != nil || len(events.Items) != 0 {
		t.Fatalf("wrong CA events=%d err=%v", len(events.Items), err)
	}
}

func TestM100ObserverRequiresMTLSIdentityAndPropagatesCancellation(t *testing.T) {
	body := []byte("synthetic-canary")
	ca, caKey, roots := m100CertificateAuthority(t)
	serverCert := m100LeafCertificate(t, ca, caKey, "canary.test", x509.ExtKeyUsageServerAuth)
	goodClient := m100LeafCertificate(t, ca, caKey, "observer.test", x509.ExtKeyUsageClientAuth)
	wrongClient := m100LeafCertificate(t, ca, caKey, "other.test", x509.ExtKeyUsageClientAuth)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("client certificate chain is not singular")
			}
			return state.PeerCertificates[0].VerifyHostname("observer.test")
		},
	}
	server.StartTLS()
	defer server.Close()

	newClient := func(cert tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "canary.test", Certificates: []tls.Certificate{cert},
		}}}
	}
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		want bool
	}{{"bound-client", goodClient, true}, {"wrong-client", wrongClient, false}} {
		t.Run(tc.name, func(t *testing.T) {
			scheme, objects := observerObjects()
			c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
			cfg := m100ObserverConfig(body)
			cfg.URL = server.URL
			event, err := ObserveOnce(context.Background(), c, newClient(tc.cert), cfg, time.Now)
			var events amtdv1beta1.SecurityEventList
			if listErr := c.List(context.Background(), &events); listErr != nil {
				t.Fatal(listErr)
			}
			if tc.want {
				if err != nil || event == nil || len(events.Items) != 1 {
					t.Fatalf("bound client event=%v count=%d err=%v", event, len(events.Items), err)
				}
			} else if err == nil || event != nil || len(events.Items) != 0 {
				t.Fatalf("wrong client emitted event=%v count=%d err=%v", event, len(events.Items), err)
			}
		})
	}

	entered := make(chan struct{})
	blocked := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer blocked.Close()
	scheme, objects := observerObjects()
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	cfg := m100ObserverConfig(body)
	cfg.URL = blocked.URL
	cfg.Timeout = 20 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := ObserveOnce(context.Background(), c, blocked.Client(), cfg, time.Now)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("observer request did not reach blocked server")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("timed-out observation emitted success")
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not propagate request timeout")
	}
	var events amtdv1beta1.SecurityEventList
	if err := c.List(context.Background(), &events); err != nil || len(events.Items) != 0 {
		t.Fatalf("timed-out observation events=%d err=%v", len(events.Items), err)
	}

	// The same configured deadline bounds authoritative Kubernetes identity
	// reads, not only the canary HTTP exchange.
	scheme, objects = observerObjects()
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	cfg = m100ObserverConfig(body)
	cfg.URL = blocked.URL
	cfg.Timeout = 20 * time.Millisecond
	started := time.Now()
	if _, err := ObserveOnce(context.Background(), m100BlockingGetClient{Client: baseClient}, blocked.Client(), cfg, time.Now); err == nil {
		t.Fatal("blocked identity read escaped observation deadline")
	}
	if time.Since(started) > time.Second {
		t.Fatal("blocked identity read did not stop promptly")
	}
}
