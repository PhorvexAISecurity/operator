/*
 * Phorvex — M-21: the backend leg of the shared capability witness.
 *
 * Capable is the ONE predicate home both the generator gate and the ActionsSupported
 * status read, so the backend question belongs here and nowhere else. Before M-21 it
 * short-circuited to "supported" for every non-AI action and skipped the backend entirely
 * when none was wired.
 */

package capability

import (
	"context"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func phoenixWitness() Witness {
	return BuildWitness(context.Background(), BuildIndex(nil, nil, nil), nil, nil, actuator.NewPhoenixActuator(nil))
}

func nativeWitness() Witness {
	native := actuator.NewNativeActuator(nil)
	legacy, _ := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	native.SetServingSecurity(legacy)
	return BuildWitness(context.Background(), BuildIndex(nil, nil, nil), nil, nil, native)
}

// TestCapableConsultsBackendForNonAIActions: the old `if !AICapabilityActions[action]
// { return true, "" }` made a whole class of actions unaskable.
func TestCapableConsultsBackendForNonAIActions(t *testing.T) {
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	for _, a := range []model.Action{model.ActionIdentityRotate, model.ActionRouteRotate,
		model.ActionDebugger, model.ActionCustomInject} {
		if AICapabilityActions[a] {
			t.Fatalf("fixture: %s must be a non-AI action", a)
		}
		query := v
		phoenix := phoenixWitness()
		native := nativeWitness()
		if a == model.ActionRouteRotate {
			target := model.Pod{Namespace: "ns", Name: "p", Ready: true, RouteService: "route",
				Labels: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
			peer := target
			peer.Name = "peer"
			service := ingest.ServiceInfo{Namespace: "ns", Name: "route", Selector: map[string]string{
				"app": "web", "phorvex.ai/route-key": "old",
			}}
			index := BuildIndex([]model.Pod{target, peer}, nil, []ingest.ServiceInfo{service})
			query = &model.WorkloadView{Pod: target}
			phoenix = BuildWitness(context.Background(), index, nil, nil, actuator.NewPhoenixActuator(nil))
			native = BuildWitness(context.Background(), index, nil, nil, actuator.NewNativeActuator(nil))
		}
		if ok, why := phoenix.Capable(query, a); ok {
			t.Fatalf("phoenix cannot enact %s; Capable must say so (why=%q)", a, why)
		} else if !strings.Contains(why, actuator.ReasonBackendUnsupported) {
			t.Fatalf("%s must be attributed to the backend, got %q", a, why)
		}
		if a == model.ActionIdentityRotate {
			if ok, why := native.Capable(query, a); ok || !strings.Contains(why, "declared-only") {
				t.Fatalf("native declared identity must refuse %s, got capable=%v why=%q", a, ok, why)
			}
			continue
		}
		if a == model.ActionRouteRotate {
			if ok, why := native.Capable(query, a); !ok {
				t.Fatalf("native valid route must stay capable, got %q", why)
			}
			continue
		}
		if ok, why := native.Capable(query, a); !ok {
			t.Fatalf("native implements %s; Capable must agree, got %q", a, why)
		}
	}
	// rotate/quarantine remain supported on BOTH backends — no default-set regression.
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		for _, w := range []Witness{phoenixWitness(), nativeWitness()} {
			if ok, why := w.Capable(v, a); !ok {
				t.Fatalf("%s must stay supported, got %q", a, why)
			}
		}
	}
}

// TestConfigPredicatesStillPrecedeTheBackend: the cheapest-first, first-failure-wins order
// is preserved. A pod missing its per-target fixture reports THAT, not the backend.
func TestConfigPredicatesStillPrecedeTheBackend(t *testing.T) {
	noGPU := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "cpu"}}
	if ok, why := nativeWitness().Capable(noGPU, model.ActionKVReset); ok {
		t.Fatal("a pod with no serving declaration cannot serve kv-reset")
	} else if why != "pod lacks the action's required GPU, serving, or detector context" {
		t.Fatalf("the config predicate must win, got %q", why)
	}
	noEndpoint := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "declared", ServingDeclared: true}}
	if _, why := nativeWitness().Capable(noEndpoint, model.ActionKVReset); why != "pod has no Ready serving endpoint" {
		t.Fatalf("the config predicate must win, got %q", why)
	}
	// With the fixtures present, the backend is what decides.
	ready := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "served", ServingDeclared: true, ServingEndpointReady: true}}
	if ok, _ := nativeWitness().Capable(ready, model.ActionKVReset); !ok {
		t.Fatal("native must support a fully configured kv-reset target")
	}
	if ok, why := phoenixWitness().Capable(ready, model.ActionKVReset); ok {
		t.Fatal("phoenix must not support kv-reset even on a fully configured target")
	} else if !strings.Contains(why, actuator.ReasonBackendUnsupported) {
		t.Fatalf("the backend must be named as the reason, got %q", why)
	}
}

// TestAbsentBackendEstablishesNothing: an unwired backend is not an affirmative answer.
func TestAbsentBackendEstablishesNothing(t *testing.T) {
	w := BuildWitness(context.Background(), BuildIndex(nil, nil, nil), nil, nil, nil)
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p", HasGPU: true, ServingEndpointReady: true}}
	for _, a := range []model.Action{model.ActionRotate, model.ActionKVReset, model.ActionIdentityRotate} {
		ok, why := w.Capable(v, a)
		if ok {
			t.Fatalf("no backend is wired; %s must not be reported capable", a)
		}
		if !strings.Contains(why, actuator.ReasonBackendUnavailable) {
			t.Fatalf("%s must be attributed to the absent backend, got %q", a, why)
		}
	}
}

// TestEligibleAttributesTheBackendExclusion: the generator gate records the backend
// rejection in its existing capability class with the same detail the status renders, so a
// decision record and the condition cannot disagree.
func TestEligibleAttributesTheBackendExclusion(t *testing.T) {
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p", HasGPU: true, ServingEndpointReady: true}}
	got := phoenixWitness().Eligible(v, model.ActionKVReset, []string{"cover-key"})
	if got == nil || !got.Excluded {
		t.Fatalf("kv-reset on phoenix must be excluded, got %+v", got)
	}
	if got.Kind != ReasonCapability {
		t.Fatalf("a backend rejection belongs to the existing %q class, got %q", ReasonCapability, got.Kind)
	}
	_, capableWhy := phoenixWitness().Capable(v, model.ActionKVReset)
	if got.Detail != capableWhy {
		t.Fatalf("the gate detail %q must equal the witness why %q", got.Detail, capableWhy)
	}
	// Positive control: the same action on a backend that implements it is eligible.
	if got := nativeWitness().Eligible(v, model.ActionKVReset, []string{"cover-key"}); got != nil {
		t.Fatalf("kv-reset on native must be eligible, got %+v", got)
	}
}

// TestCodeExecLegStillReachableOnACapableBackend: M-6 is not weakened. On a backend that
// DOES implement debugger, the admission leg is still the thing that excludes it when the
// deny-policy is unverified.
func TestCodeExecLegStillReachableOnACapableBackend(t *testing.T) {
	w := BuildWitness(context.Background(), BuildIndex(nil, nil, nil), nil, nil, actuator.NewNativeActuator(nil)).
		WithCodeExec(unverifiedAdmission{}, map[string]map[string]string{"ns": {"managed": "true"}})
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	got := w.Eligible(v, model.ActionDebugger, []string{"cover-key"})
	if got == nil || got.Kind != ReasonCodeExec {
		t.Fatalf("the code-exec admission leg must still exclude debugger, got %+v", got)
	}
}

type unverifiedAdmission struct{}

func (unverifiedAdmission) Available(map[string]string) (bool, string) {
	return false, ReasonCodeExec + ": not verified"
}
