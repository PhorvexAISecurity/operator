/*
 * Phorvex Console — per-app attack compatibility.
 *
 * GET /api/workload/attacks?namespace=<ns> answers one question for one app: which attacks are
 * compatible with THIS app's stack, which are armed and can be fired right now, and — when the
 * harness binary is present — which of the full scenario catalogue are meaningful against it.
 *
 * Compatibility is DERIVED from what the app actually runs (its container images and workload
 * kind), never hardcoded per namespace. The two fire endpoints it points at already exist:
 *   - live vLLM attacks   -> POST /api/vllm/attack      (targets the in-cluster vllm namespace)
 *   - live workload attack -> POST /api/workload/attack  (foothold on an armed workload)
 * and the catalogue scenarios launch through POST /api/runs/scenario.
 *
 * "compatible" and "armed" are deliberately separate. Compatible means the stack supports the
 * attack; armed means the console is currently allowed to fire it live. An attack can be
 * compatible-but-not-armed (the honest state for an app that needs arming first), and the UI
 * shows that rather than hiding the attack or pretending it will fire.
 */

package console

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LiveAttack is one attack the console can fire directly at a live workload. The ID is the exact
// `action` value the fire endpoint expects, so the UI needs no translation table.
type LiveAttack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Endpoint    string `json:"endpoint"` // where the UI POSTs to fire it
	MITRE       string `json:"mitre"`
	Expected    string `json:"expectedActuator"`
	StackLabel  string `json:"stack"` // human label of the stack this needs
	Description string `json:"description"`
}

// liveAttackCatalogue is the authoritative list of attacks that fire at REAL pods (as opposed to
// the harness scenarios, which drive the operator against synthetic events). Kept next to the
// handlers that implement them — vllm_attack.go and workload_attack.go — so adding an action
// there and a row here is the whole change needed to surface it per-app.
var liveAttackCatalogue = []LiveAttack{
	{"poison", "Unapproved LoRA load observation", "/api/vllm/attack", "OWASP LLM05 / AML.T0018", "adapter-rotate",
		"vllm-serving", "Checks an unapproved adapter load and reports exact adapter mechanism evidence; no model-behavior mitigation is implied."},
	{"kvcache", "KV reset-effect observation", "/api/vllm/attack", "CWE-208", "kv-reset",
		"vllm-serving", "Sends a bounded repeated-prefix precursor and reports exact reset metadata; no timing leak or eviction verdict is implied."},
	{"endpoint-rotate", "Endpoint route-effect observation", "/api/vllm/attack", "SSRF / model-extraction", "endpoint-rotate",
		"vllm-serving", "Stages an exact route signal and observes route-key/Service effects; SSRF and model-extraction mitigation are not established."},
	{"guardrail-rotate", "Guardrail runtime-effect observation", "/api/vllm/attack", "OWASP LLM01 / ASI01", "guardrail-rotate",
		"vllm-serving", "Stages an exact guardrail signal and observes a runtime variant transition; jailbreak execution or mitigation is not established."},
	{"request-drain", "Request-drain response observation", "/api/vllm/attack", "OWASP LLM10", "request-drain",
		"vllm-serving", "Emits an exact synthetic drain signal; request admission, abort and benign continuity remain unsupported in this console flow."},
	{"kv-migrate-invalidate", "KV migration-effect observation", "/api/vllm/attack", "CWE-208", "kv-migrate-invalidate",
		"vllm-serving", "Sends two bounded identical prefixes and reports protected local/remote completion metadata; cache eviction is not inferred."},
	{"warm-swap", "Warm-swap response observation", "/api/vllm/attack", "GPU co-residency", "warm-swap",
		"vllm-serving-multinode", "Emits an exact synthetic signal; GPU pressure, warm promotion and request continuity are not claimed."},
	{"model-shard-replace", "Model-shard response observation", "/api/vllm/attack", "OWASP LLM05 / supply-chain", "model-shard-replace",
		"vllm-serving", "Emits an exact synthetic signal; model tampering, known-good replacement and behavior mitigation are not claimed."},
	{"foothold", "Container-escape foothold", "/api/workload/attack", "T1611 / lateral", "rotate-or-quarantine",
		"any-workload", "A real SecurityEvent at the workload's pod; Phorvex rotates a stateless pod or quarantines a stateful one."},
	{voiceMemoryScenario, "Cross-call Voice memory contamination", "/api/voice/live/fire", "AML.T0054 / T1565", "voice-memory-note-revoke",
		"voice-memory", "Plants one run-owned stored note, opens real direct Voice WebSocket sessions, and checks exact memory context and benign-note replay after the brain's selected action."},
	{voiceAgencyScenario, "Voice cross-account refund request", voiceAgencyRoute, "AML.T0054 / T1539", voiceAgencyAction,
		"voice-agency", "Measures one model-triggered refund of a run-owned other order, then a labeled test signal, normal brain choice, blocked exact-pair replay and own-order/status controls."},
	{"ai2-unbounded-consumption", "LiteLLM abusive client containment", "/api/litellm/live/fire", "OWASP LLM10", "litellm-client-revoke",
		"litellm-live", "Measures bounded accepted requests, injects a labeled test event, then checks whether the brain revokes that client while legitimate requests continue. It does not measure unlimited spending."},
	{"ai2-query-extraction", "LiteLLM repeated-query client containment", "/api/litellm/live/fire", "AML.T0024", "litellm-client-revoke",
		"litellm-live", "Runs bounded distinct queries through the installed LiteLLM Service and checks client revocation, replay denial and benign continuity. It does not establish successful model replication."},
	{"ai2-sensitive-info-disclosure", "LiteLLM private document disclosure", "/api/litellm/output/fire", "OWASP LLM02", "sensitive-output-policy-activate",
		"litellm-output", "Sends a real model request with a separate server-owned synthetic case record. A test signal follows only if the original completion actually reveals the private record value."},
	{"ai2-system-prompt-leakage", "LiteLLM private instruction leakage", "/api/litellm/output/fire", "OWASP LLM07", "sensitive-output-policy-activate",
		"litellm-output", "Sends a real model request with a separate server-owned private system clause. A test signal follows only if the original completion actually reveals that clause."},
}

// appStack is the set of signals the compatibility rules read off a namespace.
type appStack struct {
	Namespace       string `json:"namespace"`
	ServedModel     bool   `json:"servedModel"`     // runs an LLM/inference server (vLLM, ollama, litellm, triton, ...)
	VLLM            bool   `json:"vllm"`            // runs the vLLM serving image specifically
	GPU             bool   `json:"gpu"`             // schedules onto a GPU node pool
	Stateful        bool   `json:"stateful"`        // has a StatefulSet (rotate is unsafe -> quarantine)
	Workload        bool   `json:"workload"`        // has any Deployment/StatefulSet at all
	Armed           bool   `json:"armed"`           // the console may fire a live attack here right now
	VoiceMemoryHook bool   `json:"voiceMemoryHook"` // declared source and owner-bound rule are installed
	VoiceAgencyLive bool   `json:"voiceAgencyLive"` // reviewed profile and matching Voice source are installed
	LiteLLMLive     bool   `json:"litellmLive"`     // reviewed configuration is present; Fire verifies runtime
	LiteLLMOutput   bool   `json:"litellmOutput"`   // reviewed private-context output configuration is present
}

// servedModelImage matches the serving stacks the AI attacks are meaningful against. Substring
// match on the image ref is intentionally loose — a registry prefix or tag must not hide it.
func servedModelImage(img string) (served, vllm bool) {
	l := strings.ToLower(img)
	vllm = strings.Contains(l, "vllm")
	served = vllm || strings.Contains(l, "ollama") || strings.Contains(l, "litellm") ||
		strings.Contains(l, "triton") || strings.Contains(l, "tgi") ||
		strings.Contains(l, "text-generation-inference") || strings.Contains(l, "/nim") ||
		strings.Contains(l, "sglang")
	return served, vllm
}

// stackOf reads one namespace and folds its workloads into the signals the rules need. gpu is a
// cluster-wide fact (the fire path schedules onto whatever GPU node pool exists), so it is passed
// in from the same nodes list /api/capabilities uses rather than re-listed here.
func (s *Server) stackOf(ctx context.Context, ns string, gpu bool) (appStack, error) {
	st := appStack{Namespace: ns, GPU: gpu}
	cs, err := clientForContext("")
	if err != nil {
		return st, err
	}
	if deps, e := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{}); e == nil {
		for i := range deps.Items {
			st.Workload = true
			if ns == "voice" && deps.Items[i].Name == "voice-bot" &&
				deps.Items[i].Spec.Template.Annotations["phorvex.ai/voice-memory-source-sha256"] == voiceMemorySourceSHA256 &&
				deps.Items[i].Spec.Template.Annotations["phorvex.ai/voice-memory-policy-configmap"] == "voice-memory-policy" {
				st.VoiceMemoryHook = true
			}
			if ns == "voice" && deps.Items[i].Name == "voice-bot" {
				if p, e := loadVoiceAgencyProfile(s.cfg); e == nil &&
					deps.Items[i].Spec.Template.Annotations["phorvex.ai/voice-refund-source-sha256"] == p.SourceSHA256 &&
					deps.Items[i].Spec.Template.Annotations["phorvex.ai/voice-refund-policy-configmap"] == voiceAgencyConfigMapName {
					st.VoiceAgencyLive = true
				}
			}
			for _, img := range containerImages(deps.Items[i].Spec.Template.Spec.Containers) {
				if served, vllm := servedModelImage(img); served {
					st.ServedModel = true
					st.VLLM = st.VLLM || vllm
				}
			}
		}
	} else {
		return st, e
	}
	if sts, e := cs.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{}); e == nil {
		for i := range sts.Items {
			st.Workload = true
			st.Stateful = true
			for _, img := range containerImages(sts.Items[i].Spec.Template.Spec.Containers) {
				if served, vllm := servedModelImage(img); served {
					st.ServedModel = true
					st.VLLM = st.VLLM || vllm
				}
			}
		}
	}
	st.Armed = ns == vllmAttackNS || armedWorkloads[ns] || s.namespaceHasPolicy(ns)
	if ns == "litellm" {
		_, _, err := loadLiteLiveProfile(s.cfg)
		st.LiteLLMLive = err == nil
		_, _, outputErr := loadLiteOutputProfile(s.cfg)
		st.LiteLLMOutput = st.LiteLLMLive && outputErr == nil
	}
	if st.VoiceMemoryHook {
		_, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, "voice-memory-policy", metav1.GetOptions{})
		st.VoiceMemoryHook = err == nil
	}
	if st.VoiceAgencyLive {
		_, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, voiceAgencyConfigMapName, metav1.GetOptions{})
		st.VoiceAgencyLive = err == nil
	}
	return st, nil
}

// namespaceHasPolicy reports whether Phorvex governs this namespace — i.e. it has at least one
// PhorvexPolicy. This is the arming test the fire endpoints share (workload_attack.go): an
// attack only demonstrates a defense where a defense exists, so "armed" means "governed".
func (s *Server) namespaceHasPolicy(ns string) bool {
	if ns == "" || !nsRe.MatchString(ns) {
		return false
	}
	out, err := s.cfg.execText(6*time.Second, "kubectl", "-n", ns, "get", "phorvexpolicy", "-o", "name")
	return err == nil && strings.TrimSpace(out) != ""
}

// compatEntry is one row in the per-app answer: an attack plus whether this app's stack supports
// it, whether it is armed to fire now, and the plain-English reason for both.
type compatEntry struct {
	LiveAttack
	Compatible bool   `json:"compatible"`
	Armed      bool   `json:"armed"`
	Reason     string `json:"reason"`
}

// applicablePolicyActuators returns the CRD actuators whose handler is MEANINGFUL for this app's
// stack — the set a human should be allowed to put in the policy's allowlist, and the set the
// brain then chooses from. It is deliberately narrower than the full CRD enum: the serving-only
// actuators (route-rotate, endpoint-rotate, kv-reset, model-shard-replace) and the GPU-only ones
// (warm-swap, mig-rebind) do nothing on a plain workload, and enabling one there is exactly the
// bug that made the optimiser SELECT route-rotate on voice and then fail to actuate it (no
// handler) — a critical A06 failure. The brain still decides WHICH actuator runs; this only keeps
// it from ever being offered one the app cannot run.
func applicablePolicyActuators(st appStack) []string {
	// Generic actuators act on any pod (rotate a stateless pod, quarantine a stateful one, or
	// the identity/response family), so every governed app gets them.
	out := []string{"rotate", "quarantine", "noop", "identity-rotate", "debugger", "custom-inject"}
	if st.ServedModel || st.VLLM {
		out = append(out, "kv-reset", "endpoint-rotate", "route-rotate", "model-shard-replace")
	}
	if st.GPU {
		out = append(out, "warm-swap", "mig-rebind")
	}
	if st.VoiceMemoryHook {
		out = append(out, "voice-memory-note-revoke")
	}
	if st.VoiceAgencyLive {
		out = append(out, voiceAgencyAction)
	}
	if st.LiteLLMLive {
		out = append(out, "litellm-client-revoke")
	}
	if st.LiteLLMOutput {
		out = append(out, "sensitive-output-policy-activate")
	}
	return out
}

// compatibleLive applies each live attack's stack rule to one app.
func compatibleLive(st appStack) []compatEntry {
	out := make([]compatEntry, 0, len(liveAttackCatalogue))
	for _, a := range liveAttackCatalogue {
		e := compatEntry{LiveAttack: a}
		switch a.StackLabel {
		case "voice-agency":
			e.Compatible = st.Namespace == "voice" && st.Workload
			e.Armed = e.Compatible && st.Armed && st.VoiceAgencyLive
			if e.Armed {
				e.Reason = "Reviewed Voice agency profile and source are present; Fire verifies owned CRM records, current Pods, policy and rule before the trial"
			} else {
				e.Reason = "Voice agency profile, source, owned rule or governance is unavailable"
			}
		case "litellm-output":
			e.Compatible = st.Namespace == "litellm" && st.Workload
			e.Armed = e.Compatible && st.Armed && st.LiteLLMOutput
			if e.Armed {
				e.Reason = "LiteLLM output profile is present; Fire verifies current Service, private source and policy before any signal"
			} else {
				e.Reason = "LiteLLM private-context output hook, reviewed profile or governance is unavailable"
			}
		case "litellm-live":
			e.Compatible = st.Namespace == "litellm" && st.Workload
			e.Armed = e.Compatible && st.Armed && st.LiteLLMLive
			if e.Armed {
				e.Reason = "LiteLLM Live configuration is present; Fire verifies current Service, Pods, policy and control paths before running"
			} else {
				e.Reason = "LiteLLM Live gateway, console configuration or governance is unavailable"
			}
		case "voice-memory":
			e.Compatible = st.Namespace == "voice" && st.Workload
			e.Armed = e.Compatible && st.Armed && st.VoiceMemoryHook
			if e.Armed {
				e.Reason = "Voice source and owned rule are declared; Fire verifies every Pod and policy identity before mutation"
			} else {
				e.Reason = "Voice memory source/rule rollout or governance is unavailable"
			}
		case "vllm-serving":
			// The vLLM fire path only targets the in-cluster vllm namespace, so "compatible AND
			// armed" collapses to that namespace; another namespace running vLLM is compatible in
			// principle but the console cannot yet fire at it.
			e.Compatible = st.VLLM
			e.Armed = st.VLLM && st.Namespace == vllmAttackNS
			if !e.Compatible {
				e.Reason = "no vLLM serving image in this app"
			} else if e.Armed {
				e.Reason = "vLLM serving stack detected — armed"
			} else {
				e.Reason = "vLLM stack, but only the in-cluster vllm namespace is wired to fire"
			}
		case "vllm-serving-multinode":
			e.Compatible = st.VLLM && st.GPU
			e.Armed = e.Compatible && st.Namespace == vllmAttackNS
			if !st.VLLM {
				e.Reason = "no vLLM serving image in this app"
			} else if !st.GPU {
				e.Reason = "needs a GPU node pool (>=2 GPU nodes for the warm-swap to land)"
			} else if e.Armed {
				e.Reason = "vLLM on GPU — armed"
			} else {
				e.Reason = "vLLM+GPU stack, but only the vllm namespace is wired to fire"
			}
		case "any-workload":
			e.Compatible = st.Workload
			e.Armed = st.Armed    // governed by a policy (or the static allowlist) => fireable
			e.Expected = "rotate" // refined below for stateful apps
			if st.Stateful {
				e.Expected = "quarantine"
			}
			if !e.Compatible {
				e.Reason = "no Deployment or StatefulSet to gain a foothold in"
			} else if e.Armed {
				e.Reason = "armed workload — a real foothold event will fire"
			} else {
				e.Reason = "compatible, but this namespace is not armed for live attacks yet"
			}
		default:
			e.Compatible = false
			e.Reason = "unknown stack requirement"
		}
		out = append(out, e)
	}
	return out
}

// compatibleCatalogue filters the harness scenario catalogue down to what is meaningful against
// this app's stack. Empty when the harness binary is absent from the image (the catalogue is not
// enumerable then); the handler says so rather than returning a misleading empty list.
func (s *Server) compatibleCatalogue(st appStack) ([]map[string]any, bool) {
	items := s.cfg.Catalog()
	if items == nil {
		return nil, false
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		compatible, reason := scenarioFitsStack(it, st)
		out = append(out, catalogueCompatProjection(it, compatible, reason))
	}
	return out, true
}

func catalogueCompatProjection(it CatalogItem, compatible bool, reason string) map[string]any {
	signalEligible, signalReason := catalogueSignalEligibility(it)
	return map[string]any{
		"name": it.Name, "product": it.Product, "category": it.Category,
		"techniques": it.Techniques, "exercisedTechniques": it.ExercisedTechniques,
		"realism": it.Realism, "benignControl": it.BenignControl,
		"expectedActuators":     it.ExpectedActuators,
		"responseGuidanceBasis": it.ResponseGuidanceBasis,
		"responseGuidance":      it.ResponseGuidance,
		"prereqs":               it.Prereqs, "compatible": compatible, "reason": reason,
		"signalEligible": signalEligible, "signalEligibilityReason": signalReason,
	}
}

// scenarioFitsStack applies one catalogue scenario's product/caps to an app's stack. An AI
// scenario is meaningful only on a served model; a GPU-capability scenario needs a GPU node pool;
// a structural/k8s scenario runs wherever there is a pod to gain a foothold in.
func scenarioFitsStack(it CatalogItem, st appStack) (bool, string) {
	if it.Name == voiceAgencyScenario && st.Namespace == "voice" {
		if st.VoiceAgencyLive {
			return true, "reviewed Voice agency source and rule are declared; Live Fire verifies current ownership and all serving Pods"
		}
		return false, "Voice agency profile/source or owned rule rollout is unavailable"
	}
	if it.Name == voiceMemoryScenario && st.Namespace == "voice" {
		if st.VoiceMemoryHook {
			return true, "actual Voice memory source and rule are declared; Live Fire verifies runtime readiness"
		}
		return false, "Voice memory source/rule rollout is unavailable"
	}
	needsGPU := false
	for _, c := range it.Caps {
		if c == "CapGPU" {
			needsGPU = true
		}
	}
	if it.Product == "ai" && !st.ServedModel {
		return false, "AI scenario needs a served-model / inference workload"
	}
	if needsGPU && !st.GPU {
		return false, "needs a GPU node pool"
	}
	if !st.Workload {
		return false, "no workload to attack in this namespace"
	}
	return true, "stack supports this scenario"
}

// clusterHasGPU is the same allocatable check /api/capabilities does, reduced to the one bit the
// compatibility rules need.
func (s *Server) clusterHasGPU(ctx context.Context) bool {
	cs, err := clientForContext("")
	if err != nil {
		return false
	}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false
	}
	for i := range nodes.Items {
		for res, q := range nodes.Items[i].Status.Allocatable {
			if string(res) == "nvidia.com/gpu" && q.Value() > 0 {
				return true
			}
		}
	}
	return false
}

// workloadAttacks serves GET /api/workload/attacks?namespace=<ns>.
func (s *Server) workloadAttacks(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	if ns == "" {
		writeJSON(w, 400, map[string]string{"error": "namespace query parameter is required"})
		return
	}
	if !nsRe.MatchString(ns) {
		writeJSON(w, 400, map[string]string{"error": "invalid namespace"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	gpu := s.clusterHasGPU(ctx)
	st, err := s.stackOf(ctx, ns, gpu)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "cannot read workload stack: " + err.Error()})
		return
	}

	live := compatibleLive(st)
	sort.SliceStable(live, func(i, j int) bool {
		if live[i].Armed != live[j].Armed {
			return live[i].Armed // armed attacks float to the top
		}
		if live[i].Compatible != live[j].Compatible {
			return live[i].Compatible
		}
		return live[i].Name < live[j].Name
	})

	catalogue, haveCatalogue := s.compatibleCatalogue(st)
	resp := map[string]any{
		"namespace":       ns,
		"stack":           st,
		"live":            live,
		"policyActuators": applicablePolicyActuators(st),
	}
	if haveCatalogue {
		resp["catalog"] = catalogue
	} else {
		resp["catalog"] = []any{}
		resp["catalogNote"] = "The scenario catalogue could not be read from the harness. Its executable, output format, or execution may be unavailable."
	}
	writeJSON(w, 200, resp)
}
