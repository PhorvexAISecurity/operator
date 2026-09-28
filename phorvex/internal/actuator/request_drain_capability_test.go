package actuator

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRequestDrainAuthenticatedPreselectionCapability(t *testing.T) {
	cases := []struct {
		name   string
		change func(*drainV11CapabilityResponse)
		want   bool
	}{
		{"real-work-advertised", nil, true},
		{"idle-or-capacity-no-next", func(c *drainV11CapabilityResponse) { c.NextOperationGeneration = "" }, false},
		{"closed", func(c *drainV11CapabilityResponse) { c.Admission = "CLOSED" }, false},
		{"foreign-target", func(c *drainV11CapabilityResponse) { c.PodUID = "other" }, false},
		{"wrong-proxy-source", func(c *drainV11CapabilityResponse) { c.ProxySource = strings.Repeat("c", 64) }, false},
		{"wrong-engine-source", func(c *drainV11CapabilityResponse) { c.EngineSource = strings.Repeat("c", 64) }, false},
		{"malformed-incarnation", func(c *drainV11CapabilityResponse) { c.IncarnationDigest = "" }, false},
		{"unsupported-engine", func(c *drainV11CapabilityResponse) { c.EngineMode = "other" }, false},
		{"skipped-generation", func(c *drainV11CapabilityResponse) { c.NextOperationGeneration = "4" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap, _ := (&mockVLLM{}).DrainV11Capability(t.Context(), servingEndpoint{})
			cap.PodUID = "pod-uid"
			cap.ProxySource = strings.Repeat("a", 64)
			cap.EngineSource = strings.Repeat("b", 64)
			if tc.change != nil {
				tc.change(&cap)
			}
			reads, effects := 0, 0
			f := newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != defaultDrainPath+"/capability" {
					effects++
					w.WriteHeader(500)
					return
				}
				reads++
				if r.Header.Get("Authorization") != "Bearer trusted-token-1" {
					t.Error("trusted admin bearer not used")
					w.WriteHeader(401)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(cap)
			}))
			prepareDrainCapabilityPod(t, f)
			n := f.native(t)
			target := Target{Namespace: f.pod.Namespace, Pod: f.pod.Name, UID: string(f.pod.UID), PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: f.pod.Spec.ServiceAccountName}
			ok, why := n.SupportsAction(t.Context(), model.ActionRequestDrain, target)
			if ok != tc.want || reads != 1 || effects != 0 || (!ok && !strings.HasPrefix(why, "request-drain-capability:")) {
				t.Fatalf("ok=%v why=%q reads=%d effects=%d", ok, why, reads, effects)
			}
			var cms corev1.ConfigMapList
			if err := f.client.List(t.Context(), &cms); err != nil || len(cms.Items) != 0 {
				t.Fatalf("preselection created operation records: %v %+v", err, cms.Items)
			}
		})
	}
}

func prepareDrainCapabilityPod(t *testing.T, f *m093Fixture) {
	t.Helper()
	f.pod.Annotations[annoDrainProxySource] = strings.Repeat("a", 64)
	f.pod.Annotations[annoDrainEngineSource] = strings.Repeat("b", 64)
	if err := f.client.Update(t.Context(), f.pod); err != nil {
		t.Fatal(err)
	}
	fresh := &corev1.Pod{}
	if err := f.client.Get(t.Context(), client.ObjectKeyFromObject(f.pod), fresh); err != nil {
		t.Fatal(err)
	}
	fresh.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "guardrail", ContainerID: "containerd://guardrail"}, {Name: "vllm", ContainerID: "containerd://engine"}}
	fresh.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := f.client.Status().Update(t.Context(), fresh); err != nil {
		t.Fatal(err)
	}

}

func TestRequestDrainPreselectionRefusesCurrentAuthorityDrift(t *testing.T) {
	for _, name := range []string{"container", "service-account", "selector", "serving-declaration"} {
		t.Run(name, func(t *testing.T) {
			cap, _ := (&mockVLLM{}).DrainV11Capability(t.Context(), servingEndpoint{})
			cap.PodUID = "pod-uid"
			cap.ProxySource = strings.Repeat("a", 64)
			cap.EngineSource = strings.Repeat("b", 64)
			var f *m093Fixture
			f = newM093Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != defaultDrainPath+"/capability" || r.Header.Get("Authorization") != "Bearer trusted-token-1" {
					t.Error("unexpected unauthenticated effect request")
					w.WriteHeader(500)
					return
				}
				fresh := &corev1.Pod{}
				if err := f.client.Get(r.Context(), client.ObjectKeyFromObject(f.pod), fresh); err != nil {
					t.Error(err)
				}
				if name == "container" {
					fresh.Status.ContainerStatuses[0].ContainerID = "containerd://restarted"
					if err := f.client.Status().Update(r.Context(), fresh); err != nil {
						t.Error(err)
					}
				} else {
					switch name {
					case "service-account":
						fresh.Spec.ServiceAccountName = "foreign"
					case "selector":
						fresh.Labels["app"] = "foreign"
					case "serving-declaration":
						delete(fresh.Annotations, annoServingPort)
					}
					if err := f.client.Update(r.Context(), fresh); err != nil {
						t.Error(err)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(cap)
			}))
			prepareDrainCapabilityPod(t, f)
			target := Target{Namespace: f.pod.Namespace, Pod: f.pod.Name, UID: string(f.pod.UID), PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: f.pod.Spec.ServiceAccountName}
			if ok, why := f.native(t).SupportsAction(t.Context(), model.ActionRequestDrain, target); ok || !strings.Contains(why, "changed") {
				t.Fatalf("changed current authority accepted: %v %q", ok, why)
			}
			if ok, why := requestDrainCapability(t.Context(), f.client, target, legacyServingSecurityForTest(t)); ok || !strings.Contains(why, "secure target authority unavailable") {
				t.Fatalf("legacy admitted: %v %q", ok, why)
			}
		})
	}
}
