package currentobserver

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
	"fmt"
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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func m100CurrentCertificateAuthority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "m100-current-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
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

func m100CurrentLeafCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestM100CurrentObserverBindsAuthoritativeBytesAndRejectsManifestMismatch(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	controller := true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: types.UID("dep-uid")}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", UID: types.UID("rs-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "app", UID: dep.UID, Controller: &controller}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", UID: types.UID("pod-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "data"}}}}}, Containers: []corev1.Container{{Name: "server", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", ReadOnly: true}}}}}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data", UID: types.UID("cm-uid"), ResourceVersion: "7"}, Data: map[string]string{"payload": "v2"}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: types.UID("policy-uid"), Generation: 2}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: "tenant"}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, cm, policy).Build()
	sum := sha256.Sum256([]byte("v2"))
	digest := hex.EncodeToString(sum[:])
	var responseMode atomic.Int32
	ca, caKey, roots := m100CurrentCertificateAuthority(t)
	serverCert := m100CurrentLeafCertificate(t, ca, caKey, "current.test", x509.ExtKeyUsageServerAuth)
	observerCert := m100CurrentLeafCertificate(t, ca, caKey, "observer.test", x509.ExtKeyUsageClientAuth)
	wrongCert := m100CurrentLeafCertificate(t, ca, caKey, "other.test", x509.ExtKeyUsageClientAuth)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := digest
		if responseMode.Load() == 1 {
			d = strings.Repeat("0", 64)
		}
		if responseMode.Load() == 2 {
			fmt.Fprintf(w, `{"schemaVersion":%q,"schemaVersion":%q,"version":"v2","bytes":2,"sha256":%q}`, model.CurrentInventorySchemaV1, model.CurrentInventorySchemaV1, d)
			return
		}
		fmt.Fprintf(w, `{"schemaVersion":%q,"version":"v2","bytes":2,"sha256":%q}`, model.CurrentInventorySchemaV1, d)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 {
			return errors.New("client certificate chain is not singular")
		}
		return state.PeerCertificates[0].VerifyHostname("observer.test")
	}}
	server.StartTLS()
	defer server.Close()
	newClient := func(cert tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "current.test", Certificates: []tls.Certificate{cert}}}, Timeout: time.Second}
	}
	verifiedClient := newClient(observerCert)
	now := time.Unix(100, 0).UTC()
	cfg := Config{URL: server.URL, PolicyEpoch: model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 2}, TargetNamespace: "ns", TargetName: "pod", TargetUID: "pod-uid", ConfigMapName: "data", ConfigMapKey: "payload", VolumeName: "data", ContainerName: "server", MountPath: "/data", ProjectedPath: "payload", ProtectedScope: model.ProtectedScope{Tenant: "tenant", Asset: "synthetic-data", Version: "v2", Property: "confidentiality"}, EvidenceID: "evidence", RuleDigest: strings.Repeat("b", 64), ObserverIdentity: "system:serviceaccount:ns:observer", TTL: time.Minute, Timeout: time.Second}
	if _, err := ObserveOnce(ctx, kube, verifiedClient, cfg, func() time.Time { return now }); err != nil {
		t.Fatalf("valid observation: %v", err)
	}
	cfg.EvidenceID = "wrong-client"
	if _, err := ObserveOnce(ctx, kube, newClient(wrongCert), cfg, func() time.Time { return now }); err == nil {
		t.Fatal("wrong mTLS observer identity emitted current inventory")
	}
	responseMode.Store(1)
	cfg.EvidenceID = "bad"
	if _, err := ObserveOnce(ctx, kube, verifiedClient, cfg, func() time.Time { return now }); err == nil {
		t.Fatal("manifest digest mismatch accepted")
	}
	responseMode.Store(2)
	cfg.EvidenceID = "duplicate"
	if _, err := ObserveOnce(ctx, kube, verifiedClient, cfg, func() time.Time { return now }); err == nil {
		t.Fatal("duplicate manifest field accepted")
	}
}
