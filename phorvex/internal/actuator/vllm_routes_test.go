/*
 * Phorvex — vLLM route-config tests. Proves every serving-stack route (health, models, reset, lora
 * unload/load, drain) is a per-pod annotation with a documented default — and that ModelReady actually
 * calls the CONFIGURED health/models routes on the wire (no hardcoded literal). Route correctness vs the
 * deployed vLLM version is [PENDING-GPU-VALIDATION]; this proves the config plumbing.
 */

package actuator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVLLMRoutes_DefaultsAndAnnotationOverrides(t *testing.T) {
	// no annotations => documented defaults.
	def := endpointForPod(&corev1.Pod{Status: corev1.PodStatus{PodIP: "1.2.3.4"}})
	if def.resetPath != defaultResetPath || def.healthPath != defaultHealthPath || def.modelsPath != defaultModelsPath ||
		def.unloadPath != defaultUnloadPath || def.loadPath != defaultLoadPath || def.drainPath != defaultDrainPath ||
		def.guardPath != defaultGuardPath || def.kvInvPath != defaultKVInvPath || def.configErr != nil {
		t.Errorf("route defaults wrong: %+v", def)
	}
	// per-pod annotations override EVERY route (no hardcoded literal reaches the wire).
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			annoResetPath: "/r", annoHealthPath: "/h", annoModelsPath: "/m",
			annoUnloadPath: "/u", annoLoadPath: "/l", annoDrainPath: "/d",
			annoGuardrailPath: "/g", annoKVInvalidate: "/k",
		}},
		Status: corev1.PodStatus{PodIP: "1.2.3.4"},
	}
	ep := endpointForPod(pod)
	if ep.resetPath != "/r" || ep.healthPath != "/h" || ep.modelsPath != "/m" ||
		ep.unloadPath != "/u" || ep.loadPath != "/l" || ep.drainPath != "/d" ||
		ep.guardPath != "/g" || ep.kvInvPath != "/k" || ep.configErr != nil {
		t.Errorf("not every route honored its annotation: %+v", ep)
	}
}

func TestVLLMModelReady_HitsConfiguredRoutes(t *testing.T) {
	hitHealth, hitModels := false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/custom-health":
			hitHealth = true
			w.WriteHeader(http.StatusOK)
		case "/custom-models":
			hitModels = true
			_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound) // the hardcoded /health,/v1/models would 404 here
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	ep := servingEndpoint{podIP: host, port: port, healthPath: "/custom-health", modelsPath: "/custom-models"}
	ready, err := newHTTPVLLM().ModelReady(context.Background(), ep)
	if err != nil || !ready {
		t.Fatalf("ModelReady must use the CONFIGURED routes: ready=%v err=%v", ready, err)
	}
	if !hitHealth || !hitModels {
		t.Errorf("ModelReady did not hit the configured routes (health=%v models=%v) — a literal leaked", hitHealth, hitModels)
	}
}
