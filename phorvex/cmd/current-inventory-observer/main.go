// current-inventory-observer performs one independently authenticated
// synthetic manifest observation. It never reads the protected body over HTTP.
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
	"github.com/phorvex/phorvex/internal/currentobserver"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }

func main() {
	var targetNS, targetName, targetUID, policyNS, policyName, url, serverName, caFile, certFile, keyFile string
	var cmName, cmKey, volumeName, containerName, mountPath, projectedPath, asset, version, property, evidenceID, ruleDigest, observerIdentity string
	var timeout, ttl time.Duration
	flag.StringVar(&targetNS, "target-namespace", "", "exact target Pod namespace")
	flag.StringVar(&targetName, "target-name", "", "exact target Pod name")
	flag.StringVar(&targetUID, "target-uid", "", "exact target Pod UID")
	flag.StringVar(&policyNS, "policy-namespace", "", "exact policy namespace")
	flag.StringVar(&policyName, "policy-name", "", "exact policy name")
	flag.StringVar(&url, "manifest-url", "", "exact HTTPS serving metadata URL")
	flag.StringVar(&serverName, "server-name", "", "pinned TLS server DNS SAN")
	flag.StringVar(&caFile, "ca-file", "", "trusted serving CA bundle")
	flag.StringVar(&certFile, "client-cert-file", "", "observer client certificate")
	flag.StringVar(&keyFile, "client-key-file", "", "observer client key")
	flag.StringVar(&cmName, "configmap-name", "", "exact mounted ConfigMap name")
	flag.StringVar(&cmKey, "configmap-key", "", "exact ConfigMap key")
	flag.StringVar(&volumeName, "volume-name", "", "exact Pod volume name")
	flag.StringVar(&containerName, "container-name", "", "exact serving container name")
	flag.StringVar(&mountPath, "mount-path", "", "exact read-only volume mount path")
	flag.StringVar(&projectedPath, "projected-path", "", "relative file path beneath the mount")
	flag.StringVar(&asset, "protected-asset", "", "configured synthetic protected asset")
	flag.StringVar(&version, "protected-version", "", "configured synthetic protected version")
	flag.StringVar(&property, "protected-property", "confidentiality", "configured protected property")
	flag.StringVar(&evidenceID, "evidence-id", "", "bounded observation identity")
	flag.StringVar(&ruleDigest, "rule-sha256", "", "lowercase SHA-256 of classification rule")
	flag.StringVar(&observerIdentity, "observer-identity", "", "exact authenticated Kubernetes username")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "one observation deadline")
	flag.DurationVar(&ttl, "ttl", time.Minute, "bounded current observation lifetime")
	flag.Parse()
	for name, value := range map[string]string{"target-namespace": targetNS, "target-name": targetName, "target-uid": targetUID, "policy-namespace": policyNS, "policy-name": policyName, "manifest-url": url, "server-name": serverName, "ca-file": caFile, "client-cert-file": certFile, "client-key-file": keyFile, "configmap-name": cmName, "configmap-key": cmKey, "volume-name": volumeName, "container-name": containerName, "mount-path": mountPath, "projected-path": projectedPath, "protected-asset": asset, "protected-version": version, "protected-property": property, "evidence-id": evidenceID, "rule-sha256": ruleDigest, "observer-identity": observerIdentity} {
		if value == "" {
			fatalf("--%s is required", name)
		}
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		fatalf("read CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		fatalf("CA bundle contains no certificate")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fatalf("load client identity: %v", err)
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: serverName}}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			fatalf("register scheme: %v", err)
		}
	}
	rest, err := ctrlconfig.GetConfig()
	if err != nil {
		fatalf("load Kubernetes config: %v", err)
	}
	kube, err := client.New(rest, client.Options{Scheme: scheme})
	if err != nil {
		fatalf("create Kubernetes client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
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
	event, err := currentobserver.ObserveOnce(ctx, kube, httpClient, currentobserver.Config{URL: url, PolicyEpoch: model.PolicyEpoch{Namespace: policy.Namespace, Name: policy.Name, UID: string(policy.UID), Generation: policy.Generation}, TargetNamespace: targetNS, TargetName: targetName, TargetUID: targetUID, ConfigMapName: cmName, ConfigMapKey: cmKey, VolumeName: volumeName, ContainerName: containerName, MountPath: mountPath, ProjectedPath: projectedPath, ProtectedScope: model.ProtectedScope{Tenant: tenant, Asset: asset, Version: version, Property: property}, EvidenceID: evidenceID, RuleDigest: ruleDigest, ObserverIdentity: observerIdentity, TTL: ttl, Timeout: timeout}, time.Now)
	if err != nil {
		fatalf("observation unavailable: %v", err)
	}
	fmt.Printf("current-inventory SecurityEvent created: %s uid=%s\n", event.Name, event.UID)
}
