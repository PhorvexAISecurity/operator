package scopedoutcome

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func TestPost25M106StartupConfigIsStrictAndBounded(t *testing.T) {
	dir := t.TempDir()
	config := validStartupConfig(t, dir)
	path := filepath.Join(dir, "startup.json")
	writeStartupJSON(t, path, config)
	loaded, httpTimeout, authorityTimeout, err := loadStartupConfig(path)
	if err != nil || loaded.SchemaVersion != StartupConfigSchemaV1 || httpTimeout.String() != "2s" || authorityTimeout.String() != "1s" {
		t.Fatalf("valid startup config did not load: config=%+v http=%v authority=%v err=%v", loaded, httpTimeout, authorityTimeout, err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		code string
	}{
		{name: "relative-path", raw: raw, code: "config-invalid"},
		{name: "duplicate-field", raw: []byte(strings.Replace(string(raw), `"schemaVersion":`, `"schemaVersion":"duplicate","schemaVersion":`, 1)), code: "config-decode"},
		{name: "unknown-field", raw: []byte(strings.TrimSuffix(string(raw), "}") + `,"externalProbe":true}`), code: "config-decode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := path
			if tc.name == "relative-path" {
				candidate = "startup.json"
			} else {
				candidate = filepath.Join(dir, tc.name+".json")
				if err := os.WriteFile(candidate, tc.raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, _, _, err := loadStartupConfig(candidate)
			if StartupErrorCode(err) != tc.code {
				t.Fatalf("error=%v code=%q want %q", err, StartupErrorCode(err), tc.code)
			}
		})
	}
}

func TestPost25M106StartupRejectsTLSBeforeCreatingEvidenceStore(t *testing.T) {
	dir := t.TempDir()
	config := validStartupConfig(t, dir)
	for _, path := range []string{config.CAFile, config.ClientCertFile, config.ClientKeyFile} {
		if err := os.WriteFile(path, []byte("not TLS material"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "startup.json")
	writeStartupJSON(t, path, config)
	producer, err := OpenStartupProducer(t.Context(), path, nil, "process-epoch", nil)
	if producer != nil || StartupErrorCode(err) != "tls-invalid" {
		t.Fatalf("bad TLS configuration crossed startup boundary: producer=%v err=%v code=%q", producer, err, StartupErrorCode(err))
	}
	if _, err := os.Stat(config.EvidenceDirectory); !os.IsNotExist(err) {
		t.Fatalf("evidence store was created before TLS validation: %v", err)
	}
}

func TestPost25M106StartupPreregistersExactMTLSSessionAndCloses(t *testing.T) {
	dir := t.TempDir()
	config := validStartupConfig(t, dir)
	ca, caKey, roots := m106CA(t)
	serverCertificate := m106Leaf(t, ca, caKey, "session.test", x509.ExtKeyUsageServerAuth)
	clientCertificate := m106Leaf(t, ca, caKey, "observer.test", x509.ExtKeyUsageClientAuth)
	config.CAFile, config.ClientCertFile, config.ClientKeyFile = writeStartupTLS(t, dir, ca, clientCertificate.Certificate, clientCertificate.PrivateKey.(*ecdsa.PrivateKey))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: r.URL.Query().Get("session"),
			Challenge: r.URL.Query().Get("challenge"), Present: true, TargetUID: config.Prepare.TargetUID,
			WorkloadScopeSHA256: config.Prepare.Old.WorkloadScopeSHA256})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("unexpected client certificate chain")
			}
			return state.PeerCertificates[0].VerifyHostname("observer.test")
		}}
	server.StartTLS()
	t.Cleanup(server.Close)
	config.Prepare.Old.URL = server.URL
	config.Prepare.Replacement.URL = server.URL

	reader := validStartupReader(t, config)
	path := filepath.Join(dir, "startup.json")
	writeStartupJSON(t, path, config)
	producer, err := OpenStartupProducer(t.Context(), path, reader, "process-epoch", nil)
	if err != nil || producer == nil || producer.Source() != model.ScopedSessionCapability {
		t.Fatalf("exact startup preregistration failed: producer=%v err=%v", producer, err)
	}
	producer.Close()
	producer.Close()
	if info, err := os.Stat(config.EvidenceDirectory); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("private evidence directory was not established: info=%v err=%v", info, err)
	}
}

func TestPost25M106StartupRejectsForeignServerRedirectAndAbsentClient(t *testing.T) {
	dir := t.TempDir()
	base := validStartupConfig(t, dir)
	ca, caKey, roots := m106CA(t)
	clientCertificate := m106Leaf(t, ca, caKey, "observer.test", x509.ExtKeyUsageClientAuth)
	base.CAFile, base.ClientCertFile, base.ClientKeyFile = writeStartupTLS(t, dir, ca, clientCertificate.Certificate, clientCertificate.PrivateKey.(*ecdsa.PrivateKey))
	if client, err := NewMTLSClient(roots, tls.Certificate{}, "session.test", time.Second); err == nil || client != nil {
		t.Fatalf("absent client certificate was accepted: client=%v err=%v", client, err)
	}

	otherCA, otherKey, _ := m106CA(t)
	foreign := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	foreign.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{m106Leaf(t, otherCA, otherKey, "session.test", x509.ExtKeyUsageServerAuth)}}
	foreign.StartTLS()
	t.Cleanup(foreign.Close)
	foreignConfig := base
	foreignConfig.Prepare.Old.URL, foreignConfig.Prepare.Replacement.URL = foreign.URL, foreign.URL
	foreignPath := filepath.Join(dir, "foreign.json")
	writeStartupJSON(t, foreignPath, foreignConfig)
	if producer, err := OpenStartupProducer(t.Context(), foreignPath, validStartupReader(t, foreignConfig), "epoch", nil); producer != nil || StartupErrorCode(err) != "preregistration-refused" {
		t.Fatalf("foreign server was not refused: producer=%v err=%v", producer, err)
	}

	serverCertificate := m106Leaf(t, ca, caKey, "session.test", x509.ExtKeyUsageServerAuth)
	var destinationHits atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHits.Add(1) }))
	t.Cleanup(destination.Close)
	redirect := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	redirect.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	redirect.StartTLS()
	t.Cleanup(redirect.Close)
	redirectConfig := base
	redirectConfig.Prepare.Old.URL, redirectConfig.Prepare.Replacement.URL = redirect.URL, redirect.URL
	redirectConfig.EvidenceDirectory = filepath.Join(dir, "redirect-evidence")
	redirectPath := filepath.Join(dir, "redirect.json")
	writeStartupJSON(t, redirectPath, redirectConfig)
	if producer, err := OpenStartupProducer(t.Context(), redirectPath, validStartupReader(t, redirectConfig), "epoch", nil); producer != nil || StartupErrorCode(err) != "preregistration-refused" || destinationHits.Load() != 0 {
		t.Fatalf("redirect crossed exact endpoint boundary: producer=%v err=%v destinationHits=%d", producer, err, destinationHits.Load())
	}
}

func validStartupReader(t *testing.T, config StartupConfig) client.Client {
	t.Helper()
	controller := true
	replicas := int32(1)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "fixture", Name: "app", UID: "owner-uid"}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "fixture"}}}}
	replicaSet := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "fixture", Name: "app-rs", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name, UID: deployment.UID, Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "fixture"}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "fixture", Name: "old", UID: "old-uid", Labels: map[string]string{"app": "fixture"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: replicaSet.Name, UID: replicaSet.UID, Controller: &controller}}}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &config.Prepare.TargetTerminationGraceSeconds}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "fixture", Name: "policy", UID: "policy-uid", Generation: 1}}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(deployment, replicaSet, pod, policy).Build()
}

func validStartupConfig(t *testing.T, dir string) StartupConfig {
	t.Helper()
	workload := model.PersistenceWorkloadScope{Namespace: "fixture", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner-uid"}
	digest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return StartupConfig{
		SchemaVersion: StartupConfigSchemaV1,
		Prepare: PrepareConfig{
			Policy:   model.PolicyEpoch{Namespace: "fixture", Name: "policy", UID: "policy-uid", Generation: 1},
			Workload: workload, TargetUID: "old-uid", TargetName: "old", TargetTerminationGraceSeconds: 30,
			Old:         SessionEndpoint{URL: "https://session.test/old", SessionID: "old-session", Challenge: "old-challenge", TargetUID: "old-uid", WorkloadScopeSHA256: digest},
			Replacement: SessionEndpoint{URL: "https://session.test/replacement", SessionID: "replacement-session", Challenge: "replacement-challenge", WorkloadScopeSHA256: digest},
		},
		CAFile: filepath.Join(dir, "ca.pem"), ClientCertFile: filepath.Join(dir, "client.pem"), ClientKeyFile: filepath.Join(dir, "client-key.pem"), ServerName: "session.test",
		EvidenceDirectory: filepath.Join(dir, "private-evidence"), EvidenceMaxItems: 8, EvidenceMaxBytes: 1 << 20,
		HTTPTimeout: "2s", AuthorityTimeout: "1s",
	}
}

func writeStartupJSON(t *testing.T, path string, config StartupConfig) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeStartupTLS(t *testing.T, dir string, ca *x509.Certificate, clientCertificate [][]byte, key *ecdsa.PrivateKey) (string, string, string) {
	t.Helper()
	caPath, certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for path, block := range map[string]*pem.Block{
		caPath: {Type: "CERTIFICATE", Bytes: ca.Raw}, certPath: {Type: "CERTIFICATE", Bytes: clientCertificate[0]}, keyPath: {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return caPath, certPath, keyPath
}
