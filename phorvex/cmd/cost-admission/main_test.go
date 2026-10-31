package main

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/servingbudget"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestAdmissionConfigDefaultsAreByteForByteCostbenchOpus proves the costbench-opus
// benchmark tenant with no overrides resolves to the exact historical fixed backend, so
// the production/benchmark deployment is unchanged.
func TestAdmissionConfigDefaultsAreByteForByteCostbenchOpus(t *testing.T) {
	ns, backend, uid, err := admissionConfig(env(map[string]string{
		"POD_NAMESPACE": "costbench-opus",
		"POD_UID":       "pod-uid-1",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ns != "costbench-opus" {
		t.Fatalf("namespace = %q, want costbench-opus", ns)
	}
	if backend != "http://cost-target-backend.costbench-opus.svc:8080" {
		t.Fatalf("backend = %q, want the historical fixed costbench-opus backend", backend)
	}
	if uid != "pod-uid-1" {
		t.Fatalf("uid = %q, want pod-uid-1", uid)
	}
	// The default is derived from the shared contract Service name, not a literal.
	if !strings.Contains(backend, servingbudget.BackendName) {
		t.Fatalf("default backend %q does not use the contract backend Service name %q", backend, servingbudget.BackendName)
	}
}

// TestAdmissionConfigServingRateOverride proves the serving-rate (p5-demo) chart env is
// honored exactly: the admission proxy runs in p5-demo and forwards to the p5-demo
// rate-target-backend Service.
func TestAdmissionConfigServingRateOverride(t *testing.T) {
	ns, backend, uid, err := admissionConfig(env(map[string]string{
		"POD_NAMESPACE":            "p5-demo",
		"POD_UID":                  "pod-uid-2",
		"PHORVEX_THROTTLE_BACKEND": "http://rate-target-backend.p5-demo.svc:8080",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ns != "p5-demo" || backend != "http://rate-target-backend.p5-demo.svc:8080" || uid != "pod-uid-2" {
		t.Fatalf("resolved ns=%q backend=%q uid=%q", ns, backend, uid)
	}
}

// TestAdmissionConfigDefaultBackendRoutesToPodNamespace proves backend routing: with no
// override the default backend follows the pod's own namespace, never a stale
// costbench-opus host.
func TestAdmissionConfigDefaultBackendRoutesToPodNamespace(t *testing.T) {
	_, backend, _, err := admissionConfig(env(map[string]string{
		"POD_NAMESPACE": "p5-demo",
		"POD_UID":       "pod-uid-3",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if backend != "http://cost-target-backend.p5-demo.svc:8080" {
		t.Fatalf("backend = %q, want the in-namespace default for p5-demo", backend)
	}
}

// TestAdmissionConfigAcceptsClusterLocalBackend proves the full cluster DNS form routes.
func TestAdmissionConfigAcceptsClusterLocalBackend(t *testing.T) {
	_, backend, _, err := admissionConfig(env(map[string]string{
		"POD_NAMESPACE":            "p5-demo",
		"POD_UID":                  "pod-uid-4",
		"PHORVEX_THROTTLE_BACKEND": "http://rate-target-backend.p5-demo.svc.cluster.local:8080",
	}))
	if err != nil || backend != "http://rate-target-backend.p5-demo.svc.cluster.local:8080" {
		t.Fatalf("cluster.local backend rejected: backend=%q err=%v", backend, err)
	}
}

// TestAdmissionConfigFailsClosed proves every malformed/unsafe input is refused rather
// than silently forwarding to a wrong or cross-namespace backend.
func TestAdmissionConfigFailsClosed(t *testing.T) {
	cases := map[string]map[string]string{
		"missing namespace":       {"POD_UID": "u"},
		"invalid namespace":       {"POD_NAMESPACE": "Bad_NS", "POD_UID": "u"},
		"namespace too long":      {"POD_NAMESPACE": strings.Repeat("a", 64), "POD_UID": "u"},
		"missing uid":             {"POD_NAMESPACE": "p5-demo"},
		"cross-namespace backend": {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "http://rate-target-backend.other-ns.svc:8080"},
		"external backend":        {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "http://evil.example.com:8080"},
		"https backend":           {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "https://rate-target-backend.p5-demo.svc:8080"},
		"backend with path":       {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "http://rate-target-backend.p5-demo.svc:8080/admit"},
		"backend with userinfo":   {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "http://user@rate-target-backend.p5-demo.svc:8080"},
		"ip backend":              {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "http://10.0.0.5:8080"},
		"bare host backend":       {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "http://rate-target-backend:8080"},
		"malformed url":           {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "://nope"},
		"wrong cluster domain":    {"POD_NAMESPACE": "p5-demo", "POD_UID": "u", "PHORVEX_THROTTLE_BACKEND": "http://rate-target-backend.p5-demo.svc.evil.com:8080"},
	}
	for name, envMap := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := admissionConfig(env(envMap)); err == nil {
				t.Fatalf("expected a fail-closed error for %q", name)
			}
		})
	}
}
