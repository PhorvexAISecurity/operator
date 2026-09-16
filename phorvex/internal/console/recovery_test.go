package console

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestALBAdditionalSignerPreservesIdentityBoundary(t *testing.T) {
	keys := newKeyServer()
	fx := newALBFixture(t, keys)
	second := strings.Replace(testALBSigner, "k8s-test", "production-console", 1)
	cfg := *fx.config()
	cfg.AdditionalSignerARNs = []string{second}
	verifier, err := NewALBVerifier(cfg, keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token albToken
		want  error
	}{
		{"primary", albToken{Sub: "operator"}, nil},
		{"explicit additional", albToken{Signer: second, Sub: "operator"}, nil},
		{"unlisted same account", albToken{Signer: strings.Replace(second, "production-console", "untrusted", 1)}, errALBSigner},
		{"wrong issuer", albToken{Signer: second, Issuer: "https://other.example"}, errALBIssuer},
		{"wrong client", albToken{Signer: second, Client: "other-client"}, errALBClient},
		{"expired", albToken{Signer: second, Exp: testFixedClock - 3600}, errALBExpired},
		{"forged", albToken{Signer: second, SignWith: attacker}, errALBSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := verifier.Verify(context.Background(), fx.mint(t, tc.token))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	// The existing single-signer configuration remains restrictive.
	legacy, err := NewALBVerifier(*fx.config(), keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := legacy.Verify(context.Background(), fx.mint(t, albToken{Signer: second})); !errors.Is(err, errALBSigner) {
		t.Fatalf("legacy accepted extra signer: %v", err)
	}
}

func TestALBAdditionalSignerConfigurationRejectsTrustExpansion(t *testing.T) {
	for _, signer := range []string{
		"", "*", strings.Replace(testALBSigner, "753556437180", "999999999999", 1),
		strings.Replace(testALBSigner, "us-east-2", "us-west-2", 1),
		strings.Replace(testALBSigner, "arn:aws:", "arn:aws-cn:", 1),
		strings.Replace(testALBSigner, "loadbalancer/app/", "loadbalancer/net/", 1),
	} {
		t.Run(signer, func(t *testing.T) {
			cfg := ALBConfig{SignerARN: testALBSigner, Issuer: testALBIssuer, ClientID: testALBClient, AdditionalSignerARNs: []string{signer}}
			if _, err := cfg.validate(); err == nil {
				t.Fatal("accepted invalid additional signer")
			}
		})
	}
}

// Execute a real child process and carry its result through signed authentication and HTTP,
// so failure cannot become a 200 response with zero nodes/pods and a green scan UI.
func TestScanChildFailureAndLocalAliases(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		status       int
	}{
		{"forbidden", "echo 'networkpolicies is forbidden: cannot list resource' >&2; exit 1", http.StatusServiceUnavailable},
		{"partial then failed", "echo 'platform-adapter: eks'; echo 'nodes: 2 pods: 3'; exit 1", http.StatusServiceUnavailable},
		{"empty output", "exit 0", http.StatusServiceUnavailable},
		{"empty cluster valid", "echo 'platform-adapter: generic-k8s'; echo 'nodes: 0 pods: 0'", http.StatusOK},
		{"populated", "echo 'platform-adapter: eks'; echo 'nodes: 2 pods: 3'", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "scan")
			// Both aliases must omit --context: they are console selectors, not kubeconfig entries.
			script := "#!/bin/sh\nfor arg in \"$@\"; do if [ \"$arg\" = --context ]; then echo unexpected-context >&2; exit 9; fi; done\n" + tc.script + "\n"
			if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			f := newAuthFixture(t, Config{Root: root, HarnessDir: root, PhorvexBin: bin}, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
			for _, alias := range []string{"", "default", "in-cluster"} {
				w := f.do(f.albReqAs(t, http.MethodGet, "/api/scan?context="+alias, "", "op"))
				if w.Code != tc.status {
					t.Fatalf("alias %q: %d %s", alias, w.Code, w.Body.String())
				}
				if tc.status != http.StatusOK && (!strings.Contains(w.Body.String(), "live scan unavailable") || strings.Contains(w.Body.String(), `"pods":0`)) {
					t.Fatalf("failure fabricated data: %s", w.Body.String())
				}
			}
		})
	}
}

func TestScanExplicitContextPreserved(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "scan")
	script := "#!/bin/sh\n[ \"$1\" = --scan ] && [ \"$2\" = --context ] && [ \"$3\" = remote ] || exit 9\necho 'platform-adapter: eks'\necho 'nodes: 2 pods: 3'\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{HarnessDir: root, PhorvexBin: bin}
	if _, err := cfg.Scan("", "remote", ""); err != nil {
		t.Fatal(err)
	}
}
