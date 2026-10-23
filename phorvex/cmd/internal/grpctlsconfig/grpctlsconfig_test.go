package grpctlsconfig

import (
	"flag"
	"testing"
)

func TestUnsetFlagsKeepGRPCPlaintext(t *testing.T) {
	var c Config
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	c.RegisterServer(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if c.Enabled() {
		t.Fatal("no flag set, yet TLS is enabled")
	}
	if opts, err := c.ServerOptions(); err != nil || opts != nil {
		t.Fatalf("plaintext service options = %v, %v", opts, err)
	}
	if opt, err := c.DialOption(); err != nil || opt == nil {
		t.Fatalf("plaintext dial option = %v, %v", opt, err)
	}
}

func TestAPartialConfigurationRefusesToStart(t *testing.T) {
	for name, args := range map[string][]string{
		"service, certificate only":    {"--grpc-tls-cert=/absent/tls.crt"},
		"service, no admitted peer":    {"--grpc-tls-cert=/absent/tls.crt", "--grpc-tls-key=/absent/tls.key", "--grpc-tls-ca=/absent/ca.crt"},
		"dispatcher, certificate only": {"--grpc-tls-cert=/absent/tls.crt"},
	} {
		t.Run(name, func(t *testing.T) {
			var c Config
			fs := flag.NewFlagSet(name, flag.ContinueOnError)
			if name[:7] == "service" {
				c.RegisterServer(fs)
			} else {
				c.RegisterClient(fs)
			}
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			if _, err := c.ServerOptions(); err == nil {
				t.Error("a service started on a partial configuration")
			}
			if _, err := c.DialOption(); err == nil {
				t.Error("the dispatcher dialed on a partial configuration")
			}
		})
	}
}

func TestOnlyAServiceNamesItsPeers(t *testing.T) {
	var client, server Config
	clientFlags, serverFlags := flag.NewFlagSet("dispatcher", flag.ContinueOnError), flag.NewFlagSet("service", flag.ContinueOnError)
	client.RegisterClient(clientFlags)
	server.RegisterServer(serverFlags)
	if clientFlags.Lookup("grpc-tls-peer") != nil || serverFlags.Lookup("grpc-tls-peer") == nil {
		t.Fatal("--grpc-tls-peer belongs to the services alone")
	}
	for _, name := range []string{"grpc-tls-cert", "grpc-tls-key", "grpc-tls-ca"} {
		if clientFlags.Lookup(name) == nil || serverFlags.Lookup(name) == nil {
			t.Fatalf("--%s is missing", name)
		}
	}
}
