// Package grpctlsconfig registers the flags of the services' mutual TLS
// (internal/servicetls): the sensor, brain and actuator serve with them, and the
// dispatcher dials them with its own. Each binary registers them once. Unset, the
// connections are plaintext, as before the flags existed.
package grpctlsconfig

import (
	"flag"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/phorvex/phorvex/internal/servicetls"
)

// Config is one end's TLS files and, for a service, the clients it admits.
type Config struct {
	Files servicetls.Files
	Peers string
}

// RegisterServer defines a service's flags on fs.
func (c *Config) RegisterServer(fs *flag.FlagSet) {
	c.register(fs, "this service presents")
	fs.StringVar(&c.Peers, "grpc-tls-peer", os.Getenv("PHORVEX_GRPC_TLS_PEER"), "[grpc-tls-cert] comma-separated DNS names of the client certificates admitted: the dispatcher's identity.")
}

// RegisterClient defines the dispatcher's flags on fs.
func (c *Config) RegisterClient(fs *flag.FlagSet) {
	c.register(fs, "the dispatcher presents to the sensor, brain and actuator services")
}

func (c *Config) register(fs *flag.FlagSet, presents string) {
	fs.StringVar(&c.Files.Cert, "grpc-tls-cert", os.Getenv("PHORVEX_GRPC_TLS_CERT"), "PEM certificate "+presents+" over gRPC mutual TLS. Empty, with --grpc-tls-key and --grpc-tls-ca, keeps gRPC plaintext.")
	fs.StringVar(&c.Files.Key, "grpc-tls-key", os.Getenv("PHORVEX_GRPC_TLS_KEY"), "[grpc-tls-cert] PEM private key of the certificate.")
	fs.StringVar(&c.Files.CA, "grpc-tls-ca", os.Getenv("PHORVEX_GRPC_TLS_CA"), "[grpc-tls-cert] PEM CA that signed the peers' certificates.")
}

// Enabled reports whether gRPC runs over mutual TLS.
func (c Config) Enabled() bool { return c.Files.Enabled() }

// ServerOptions are the service's transport options: none when plaintext.
func (c Config) ServerOptions() ([]grpc.ServerOption, error) {
	if !c.Enabled() {
		return nil, nil
	}
	creds, err := servicetls.Server(c.Files, strings.Split(c.Peers, ","))
	if err != nil {
		return nil, err
	}
	return []grpc.ServerOption{grpc.Creds(creds)}, nil
}

// DialOption is the dispatcher's transport to a service.
func (c Config) DialOption() (grpc.DialOption, error) {
	if !c.Enabled() {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	creds, err := servicetls.Client(c.Files)
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(creds), nil
}
