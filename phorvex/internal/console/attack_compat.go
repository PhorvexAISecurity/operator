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
	{"poison", "Poisoned LoRA injection", "/api/vllm/attack", "OWASP LLM05 / AML.T0018", "adapter-rotate",
		"vllm-serving", "Loads an unauthorised LoRA adapter; Phorvex evicts it by rotating the adapter, pod stays alive."},
	{"kvcache", "Prefix-cache occupancy oracle", "/api/vllm/attack", "CWE-208", "kv-reset",
		"vllm-serving", "Primes a secret prefix into the shared KV cache; Phorvex flushes it in place, no restart."},
	{"endpoint-rotate", "Inference-endpoint pinning", "/api/vllm/attack", "SSRF / model-extraction", "endpoint-rotate",
		"vllm-serving", "Pins the serving route; Phorvex re-keys and restitches the Service."},
	{"guardrail-rotate", "Guardrail bypass (jailbreak)", "/api/vllm/attack", "OWASP LLM01 / ASI01", "guardrail-rotate",
		"vllm-serving", "A many-shot jailbreak the active guardrail misses; Phorvex hot-swaps the guardrail variant."},
	{"request-drain", "Denial-of-wallet flood", "/api/vllm/attack", "OWASP LLM10", "request-drain",
		"vllm-serving", "An expensive-turn flood; Phorvex aborts in-flight requests without restarting the pod."},
	{"kv-migrate-invalidate", "Disaggregated-KV poisoning", "/api/vllm/attack", "CWE-208", "kv-migrate-invalidate",
		"vllm-serving", "Plants a crafted long prefix across disaggregated KV peers; Phorvex migrates and invalidates it."},
	{"warm-swap", "GPU co-tenant eviction", "/api/vllm/attack", "GPU co-residency", "warm-swap",
		"vllm-serving-multinode", "A co-residency side channel; Phorvex warm-swaps the pod to a fresh GPU node (needs >=2 GPU nodes)."},
	{"model-shard-replace", "Model weight tamper / extraction", "/api/vllm/attack", "OWASP LLM05 / supply-chain", "model-shard-replace",
		"vllm-serving", "Fingerprint-drift on the served model; Phorvex warm-cuts over to a shadow and retires the leader."},
	{"foothold", "Container-escape foothold", "/api/workload/attack", "T1611 / lateral", "rotate-or-quarantine",
		"any-workload", "A real SecurityEvent at the workload's pod; Phorvex rotates a stateless pod or quarantines a stateful one."},
}

// appStack is the set of signals the compatibility rules read off a namespace.
type appStack struct {
	Namespace   string `json:"namespace"`
	ServedModel bool   `json:"servedModel"` // runs an LLM/inference server (vLLM, ollama, litellm, triton, ...)
	VLLM        bool   `json:"vllm"`        // runs the vLLM serving image specifically
	GPU         bool   `json:"gpu"`         // schedules onto a GPU node pool
	Stateful    bool   `json:"stateful"`    // has a StatefulSet (rotate is unsafe -> quarantine)
	Workload    bool   `json:"workload"`    // has any Deployment/StatefulSet at all
	Armed       bool   `json:"armed"`       // the console may fire a live attack here right now
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

// compatibleLive applies each live attack's stack rule to one app.
func compatibleLive(st appStack) []compatEntry {
	out := make([]compatEntry, 0, len(liveAttackCatalogue))
	for _, a := range liveAttackCatalogue {
		e := compatEntry{LiveAttack: a}
		switch a.StackLabel {
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
			e.Armed = st.Armed // governed by a policy (or the static allowlist) => fireable
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
		out = append(out, map[string]any{
			"name": it.Name, "product": it.Product, "category": it.Category,
			"techniques": it.Techniques, "expectedActuators": it.ExpectedActuators,
			"prereqs": it.Prereqs, "compatible": compatible, "reason": reason,
		})
	}
	return out, true
}

// scenarioFitsStack applies one catalogue scenario's product/caps to an app's stack. An AI
// scenario is meaningful only on a served model; a GPU-capability scenario needs a GPU node pool;
// a structural/k8s scenario runs wherever there is a pod to gain a foothold in.
func scenarioFitsStack(it CatalogItem, st appStack) (bool, string) {
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
		"namespace": ns,
		"stack":     st,
		"live":      live,
	}
	if haveCatalogue {
		resp["catalog"] = catalogue
	} else {
		resp["catalog"] = []any{}
		resp["catalogNote"] = "the harness binary is not present in this console image, so the scenario catalogue cannot be enumerated"
	}
	writeJSON(w, 200, resp)
}
