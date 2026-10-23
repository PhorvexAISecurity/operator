// Package servicetls is the mutual TLS of the services' gRPC (ADR-0001). The
// dispatcher and the sensor, brain and actuator it calls each present a certificate
// one service CA signed: a service admits only the clients it names, and the
// dispatcher admits only the server whose name it dialed.
//
// A service reads its certificate, key and CA on every handshake, so a rotated
// Secret takes effect without a restart. The dispatcher reads its certificate and
// key on every handshake and its CA when it dials.
package servicetls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"google.golang.org/grpc/credentials"
)

// Files names the PEM files of one end: its certificate and key, and the CA that
// signed its peers' certificates.
type Files struct {
	Cert, Key, CA string
}

// Enabled reports whether any file is named.
func (f Files) Enabled() bool { return f.Cert != "" || f.Key != "" || f.CA != "" }

// Validate refuses a partial configuration and files that do not load. An empty
// configuration is valid: the connection is plaintext.
func (f Files) Validate() error {
	if !f.Enabled() {
		return nil
	}
	if f.Cert == "" || f.Key == "" || f.CA == "" {
		return errors.New("service TLS needs the certificate, its key and the CA together")
	}
	if _, err := tls.LoadX509KeyPair(f.Cert, f.Key); err != nil {
		return fmt.Errorf("service TLS key pair: %w", err)
	}
	_, err := certPool(f.CA)
	return err
}

func certPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("service TLS CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("service TLS CA %s holds no certificate", path)
	}
	return pool, nil
}

// Server returns the credentials of a service. It admits a client only when the CA
// signed its certificate for one of peers, a DNS name.
func Server(f Files, peers []string) (credentials.TransportCredentials, error) {
	if !f.Enabled() {
		return nil, errors.New("service TLS is not configured")
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	admitted := names(peers)
	if len(admitted) == 0 {
		return nil, errors.New("service TLS admits no client: name the dispatcher's certificate identity")
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
			if err != nil {
				return nil, err
			}
			cas, err := certPool(f.CA)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    cas,
				// gRPC requires the negotiated protocol; this config replaces the one
				// credentials.NewTLS completed.
				NextProtos: []string{"h2"},
				VerifyConnection: func(state tls.ConnectionState) error {
					return admit(state, admitted)
				},
			}, nil
		},
	}), nil
}

// admit accepts a verified client certificate issued for an admitted name.
func admit(state tls.ConnectionState, admitted []string) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("service TLS: the client presented no certificate")
	}
	for _, name := range state.PeerCertificates[0].DNSNames {
		if slices.Contains(admitted, strings.ToLower(name)) {
			return nil
		}
	}
	return fmt.Errorf("service TLS: client %v is not an admitted peer", state.PeerCertificates[0].DNSNames)
}

// Client returns the credentials the dispatcher dials a service with: it presents
// its own certificate and admits only a server certificate the CA signed for the
// host it dialed.
func Client(f Files) (credentials.TransportCredentials, error) {
	if !f.Enabled() {
		return nil, errors.New("service TLS is not configured")
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	cas, err := certPool(f.CA)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    cas,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}), nil
}

func names(raw []string) []string {
	var out []string
	for _, name := range raw {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}
