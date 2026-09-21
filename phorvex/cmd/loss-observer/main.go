// loss-observer performs one independently authenticated synthetic canary read.
// It is deliberately a separate binary and ServiceAccount from the manager.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/lossobserver"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	var targetNS, targetName, targetUID, policyNS, policyName string
	var url, serverName, caFile, certFile, keyFile string
	var asset, version, property, evidenceID, ruleVersion, ruleDigest, expectedDigest, observerIdentity string
	var expectedBytes int64
	var timeout time.Duration
	flag.StringVar(&targetNS, "target-namespace", "", "exact target Pod namespace")
	flag.StringVar(&targetName, "target-name", "", "exact target Pod name")
	flag.StringVar(&targetUID, "target-uid", "", "exact API-assigned target Pod UID")
	flag.StringVar(&policyNS, "policy-namespace", "", "exact PhorvexPolicy namespace")
	flag.StringVar(&policyName, "policy-name", "", "exact PhorvexPolicy name")
	flag.StringVar(&url, "canary-url", "", "exact HTTPS synthetic canary URL")
	flag.StringVar(&serverName, "server-name", "", "exact TLS server DNS SAN")
	flag.StringVar(&caFile, "ca-file", "", "trusted synthetic-canary CA bundle")
	flag.StringVar(&certFile, "client-cert-file", "", "observer client certificate")
	flag.StringVar(&keyFile, "client-key-file", "", "observer client private key")
	flag.StringVar(&asset, "protected-asset", "", "protected synthetic asset identity")
	flag.StringVar(&version, "protected-version", "", "protected synthetic data version")
	flag.StringVar(&property, "protected-property", "confidentiality", "protected property")
	flag.StringVar(&evidenceID, "evidence-id", "", "bounded immutable observation identity")
	flag.StringVar(&ruleVersion, "rule-version", "", "authorization classification rule version")
	flag.StringVar(&ruleDigest, "rule-sha256", "", "lowercase SHA-256 of the observer authorization rule")
	flag.StringVar(&observerIdentity, "observer-identity", "", "exact authenticated Kubernetes observer username")
	flag.Int64Var(&expectedBytes, "expected-bytes", 0, "exact positive canary byte length")
	flag.StringVar(&expectedDigest, "expected-sha256", "", "lowercase SHA-256 of exact canary bytes")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "one observation deadline")
	flag.Parse()

	for name, value := range map[string]string{"target-namespace": targetNS, "target-name": targetName, "target-uid": targetUID,
		"policy-namespace": policyNS, "policy-name": policyName, "canary-url": url, "server-name": serverName,
		"ca-file": caFile, "client-cert-file": certFile, "client-key-file": keyFile, "protected-asset": asset,
		"protected-version": version, "protected-property": property, "evidence-id": evidenceID,
		"rule-version": ruleVersion, "rule-sha256": ruleDigest, "observer-identity": observerIdentity, "expected-sha256": expectedDigest} {
		if value == "" {
			fatalf("--%s is required", name)
		}
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		fatalf("read canary CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		fatalf("canary CA bundle contains no certificate")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fatalf("load observer client identity: %v", err)
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: serverName,
	}}, Timeout: timeout}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		fatalf("register Kubernetes scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		fatalf("register policy scheme: %v", err)
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		fatalf("register SecurityEvent scheme: %v", err)
	}
	rest, err := ctrlconfig.GetConfig()
	if err != nil {
		fatalf("load Kubernetes client config: %v", err)
	}
	kube, err := client.New(rest, client.Options{Scheme: scheme})
	if err != nil {
		fatalf("create Kubernetes client: %v", err)
	}
	ctx := context.Background()
	var policy v1alpha1.PhorvexPolicy
	if err := kube.Get(ctx, client.ObjectKey{Namespace: policyNS, Name: policyName}, &policy); err != nil {
		fatalf("read policy: %v", err)
	}
	var pod corev1.Pod
	if err := kube.Get(ctx, client.ObjectKey{Namespace: targetNS, Name: targetName}, &pod); err != nil || string(pod.UID) != targetUID {
		fatalf("target Pod identity mismatch")
	}
	tenant := policy.Spec.Tenant
	if tenant == "" {
		tenant = policy.Namespace
	}
	event, err := lossobserver.ObserveOnce(ctx, kube, httpClient, lossobserver.ObserverConfig{
		URL: url, PolicyEpoch: model.PolicyEpoch{Namespace: policy.Namespace, Name: policy.Name, UID: string(policy.UID), Generation: policy.Generation},
		TargetNamespace: targetNS, TargetName: targetName, TargetUID: targetUID,
		ProtectedScope: model.ProtectedScope{Tenant: tenant, Asset: asset, Version: version, Property: property},
		EvidenceID:     evidenceID, RuleVersion: ruleVersion, RuleDigest: ruleDigest, ObserverIdentity: observerIdentity,
		ExpectedBytes: expectedBytes, ExpectedSHA256: expectedDigest, Timeout: timeout,
	}, time.Now)
	if err != nil {
		fatalf("observation unavailable: %v", err)
	}
	fmt.Printf("completed-disclosure SecurityEvent created: %s uid=%s\n", event.Name, event.UID)
}
