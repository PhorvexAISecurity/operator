package servicetls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newAuthority(t *testing.T, name string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

var serial int64 = 1

// issue writes a leaf certificate for dns, with its key and the CA, and returns their paths.
func (a authority) issue(t *testing.T, dir, dns string, usage x509.ExtKeyUsage) Files {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := Files{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt")}
	for path, content := range map[string][]byte{
		f.Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		f.Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		f.CA:   a.pem,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// serve runs a health service with the given credentials and returns its address.
func serve(t *testing.T, creds credentials.TransportCredentials) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(creds))
	healthpb.RegisterHealthServer(server, health.NewServer())
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	return lis.Addr().String()
}

// check calls the service as name, over creds; nil means the connection was admitted.
func check(t *testing.T, addr, name string, creds credentials.TransportCredentials) error {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds), grpc.WithAuthority(name))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestTheServiceAdmitsOnlyTheDispatcher(t *testing.T) {
	dir := t.TempDir()
	ca := newAuthority(t, "service CA")
	server, err := Server(ca.issue(t, filepath.Join(dir, "brain"), "staging-brain", x509.ExtKeyUsageServerAuth), []string{"staging-dispatcher.phorvex-staging.svc"})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, server)
	client := func(f Files) credentials.TransportCredentials {
		creds, err := Client(f)
		if err != nil {
			t.Fatal(err)
		}
		return creds
	}
	dispatcher := client(ca.issue(t, filepath.Join(dir, "dispatcher"), "staging-dispatcher.phorvex-staging.svc", x509.ExtKeyUsageClientAuth))
	if err := check(t, addr, "staging-brain", dispatcher); err != nil {
		t.Fatalf("the dispatcher was refused: %v", err)
	}
	other := client(ca.issue(t, filepath.Join(dir, "other"), "staging-console.phorvex-staging.svc", x509.ExtKeyUsageClientAuth))
	stranger := newAuthority(t, "another CA")
	forged := ca.issue(t, filepath.Join(dir, "forged"), "staging-dispatcher.phorvex-staging.svc", x509.ExtKeyUsageClientAuth)
	forged.Cert = stranger.issue(t, filepath.Join(dir, "stranger"), "staging-dispatcher.phorvex-staging.svc", x509.ExtKeyUsageClientAuth).Cert
	forged.Key = filepath.Join(dir, "stranger", "tls.key")
	noCert, err := credentials.NewClientTLSFromFile(dispatcherCA(dir), "")
	if err != nil {
		t.Fatal(err)
	}
	for name, creds := range map[string]credentials.TransportCredentials{
		"another identity":       other,
		"another CA's signature": client(forged),
		"no certificate":         noCert,
		"plaintext":              insecure.NewCredentials(),
	} {
		if err := check(t, addr, "staging-brain", creds); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	// The dispatcher admits only the service it dialed.
	if err := check(t, addr, "staging-sensor", dispatcher); err == nil {
		t.Error("the dispatcher accepted the brain's certificate for the sensor")
	}
}

func dispatcherCA(dir string) string { return filepath.Join(dir, "dispatcher", "ca.crt") }

func TestARotatedCertificateTakesEffectWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	ca := newAuthority(t, "service CA")
	files := ca.issue(t, filepath.Join(dir, "brain"), "staging-brain", x509.ExtKeyUsageServerAuth)
	server, err := Server(files, []string{"dispatcher"})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, server)
	dispatcher, err := Client(ca.issue(t, filepath.Join(dir, "dispatcher"), "dispatcher", x509.ExtKeyUsageClientAuth))
	if err != nil {
		t.Fatal(err)
	}
	if err := check(t, addr, "staging-brain", dispatcher); err != nil {
		t.Fatal(err)
	}
	// The Secret now holds a certificate for another name: the next handshake presents it.
	ca.issue(t, filepath.Join(dir, "brain"), "staging-brain-renamed", x509.ExtKeyUsageServerAuth)
	if err := check(t, addr, "staging-brain", dispatcher); err == nil {
		t.Fatal("the service still presented the replaced certificate")
	}
	if err := check(t, addr, "staging-brain-renamed", dispatcher); err != nil {
		t.Fatalf("the rotated certificate was not served: %v", err)
	}
}

func TestAConfigurationIsWholeOrAbsent(t *testing.T) {
	dir := t.TempDir()
	ca := newAuthority(t, "service CA")
	files := ca.issue(t, dir, "staging-brain", x509.ExtKeyUsageServerAuth)
	if err := (Files{}).Validate(); err != nil {
		t.Fatalf("an absent configuration is plaintext, not an error: %v", err)
	}
	for name, f := range map[string]Files{
		"no key":        {Cert: files.Cert, CA: files.CA},
		"no CA":         {Cert: files.Cert, Key: files.Key},
		"missing file":  {Cert: files.Cert, Key: files.Key, CA: filepath.Join(dir, "absent.crt")},
		"key as the CA": {Cert: files.Cert, Key: files.Key, CA: files.Key},
	} {
		if err := f.Validate(); err == nil {
			t.Errorf("%s validated", name)
		}
	}
	if _, err := Server(files, []string{" ", ""}); err == nil || !strings.Contains(err.Error(), "admits no client") {
		t.Fatalf("a service admitting no client started: %v", err)
	}
	if _, err := Client(Files{}); err == nil {
		t.Fatal("an unconfigured client returned credentials")
	}
}
