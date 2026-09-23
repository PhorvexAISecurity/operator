/*
 * Phorvex Console — SCENARIO METADATA: per-attack actuator mapping + runnability explanation.
 *
 * The harness scenarios do not declare an actuator mapping or explain their prerequisites.
 * This derives name-based hints and prerequisites for display. A hint does not establish
 * an available or selected response, a working actuator, or a security outcome.
 *
 * The keyword map preserves the legacy expectedActuators field for compatibility.
 */

package console

import "strings"

// ScenarioMeta is derived guidance surfaced on the catalog/Attack-Lab.
type ScenarioMeta struct {
	ExpectedActuators     []string `json:"expectedActuators"` // legacy compatibility; hints, not eligibility or outcomes
	ResponseGuidanceBasis string   `json:"responseGuidanceBasis"`
	ResponseGuidance      string   `json:"responseGuidance"`
	MeaningfulWhen        string   `json:"meaningfulWhen"` // when this attack matters
	RunnableNote          string   `json:"runnableNote"`   // what it needs to RUN (hardware/workload)
	Prereqs               []string `json:"prereqs"`        // explicit prerequisite chips
}

// expectedActuatorsFor retains legacy actuator hints derived from the scenario name. Keyword
// order matters (most specific first). AI scenarios map to the AI actuators (kv-reset etc.);
// structural scenarios map to the K8s moving-target actuators (rotate/quarantine).
func expectedActuatorsFor(name string) []string {
	n := strings.ToLower(name)
	if n == "c1-credtheft-rbac" {
		// An off-Pod replay is beyond network quarantine of the source Pod. Rotation
		// is only a conditional hint for a Pod-bound credential, not a detector claim.
		return []string{"rotate"}
	}
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("kvcache", "kv-cache", "prompt-injection", "cross-session"):
		return []string{"kv-reset", "kv-migrate-invalidate"}
	case has("memory-contamination", "agent-injection", "rogue-tool"):
		return []string{"kv-reset", "guardrail-rotate"}
	case has("model-theft", "model-artifact", "model-registry", "model-poisoning", "data-model", "malicious-model"):
		return []string{"model-shard-replace", "guardrail-rotate"}
	case has("llm-jacking", "query-extraction", "excessive-agency"):
		return []string{"request-drain", "route-rotate", "endpoint-rotate"}
	// [PHVX-25a/26a] Narrow claim. Neither action breaks GPU CO-LOCATION on this fleet:
	//   mig-rebind severs the memory/cache/SM CONTENTION path by repartitioning the device, but the
	//   pod does not move, so the attacker's knowledge of who shares it survives — and MIG
	//   reconfiguration needs zero CUDA contexts device-wide, so it works on an idle GPU, not during
	//   a live multi-tenant incident.
	//   warm-swap performs a cutover with no cold load. Valuable, and unrelated to co-residency:
	//   nothing constrains where the scheduler places the shadow, so it may land on the same device.
	// mig-rebind is listed for the side-channel case only, and only as the contention-path remedy.
	case has("side-channel"):
		return []string{"mig-rebind"}
	case has("co-location"):
		// No autonomous remedy today. Co-residency is a PROVISIONING property — the real fix is
		// device-plugin capacity, not a moving-target action. Listing an actuator here would name a
		// defence that cannot deliver.
		return []string{}
	case has("gpu"):
		return []string{"mig-rebind"}
	case has("rag", "retrieval", "embedding"):
		return []string{"guardrail-rotate", "adapter-rotate"}
	case has("mcp", "tool-poisoning", "rogue-server", "response-injection"):
		return []string{"guardrail-rotate", "route-rotate"}
	case has("inference-manipulation", "system-prompt", "sensitive-info", "disclosure", "agent"):
		return []string{"guardrail-rotate", "endpoint-rotate"}
	case has("panic-mutation", "pillar03"):
		return []string{"warm-swap", "rotate"}
	case has("persist", "persistence", "dwell"):
		return []string{"rotate", "kv-reset"}
	case has("lateral", "co-tenant", "cross-tenant"):
		return []string{"quarantine"}
	case has("fast-attacker", "escape", "cve", "rotation", "credtheft", "imds", "evict"):
		return []string{"rotate", "quarantine"}
	default:
		// product fallback: AI scenarios lean on the AI control-plane actuators; the rest on K8s MTD.
		if strings.HasPrefix(n, "ai") {
			return []string{"guardrail-rotate", "endpoint-rotate"}
		}
		return []string{"rotate", "quarantine"}
	}
}

// aiResetActuators are the AI/SP-0 actuators that need a vLLM-shaped control plane (phorvex.ai/*
// annotations) to actually fire — used to add the right prerequisite chip.
var aiResetActuators = map[string]bool{
	"kv-reset": true, "kv-migrate-invalidate": true, "warm-swap": true, "mig-rebind": true,
	"endpoint-rotate": true, "model-shard-replace": true,
}

// deriveScenarioMeta builds the full per-attack guidance from the scenario name + its capability
// requirements (caps) + product class. Nothing is fabricated: the prereqs come from the SAME caps
// the harness gates on, and the actuator mapping is a declared keyword table.
func deriveScenarioMeta(name, product string, caps []string, benign bool) ScenarioMeta {
	if benign {
		return deriveBenignScenarioMeta(name, caps)
	}
	acts := expectedActuatorsFor(name)
	guidance := "Name-based actuator hints only. Availability, selection, effect, and security outcome require case-specific evidence."
	if len(acts) == 0 {
		guidance = "No autonomous actuator is mapped by the name heuristic. Detection, feasible response, and security outcome require case-specific evidence."
	}
	if name == "c1-credtheft-rbac" {
		guidance = "A captured Pod-bound API token may stop authenticating after its binding Pod is deleted; initial disclosure persists. Quarantine cannot revoke an off-Pod bearer token. No automatic detector or manager response is asserted."
	}
	capSet := map[string]bool{}
	for _, c := range caps {
		capSet[c] = true
	}
	prereqs := []string{}
	notes := []string{}

	if name == "c1-credtheft-rbac" {
		prereqs = append(prereqs, "a credential-bearing source Pod and an off-Pod API replay")
		notes = append(notes, "Measures whether the same captured credential still authorizes API access after the observation window; binding and any response must be observed.")
	} else if product == "ai" {
		prereqs = append(prereqs, "a served model / inference workload")
		notes = append(notes, "Requires a matching served-model fixture. The failure path, detector, feasible response and behavioral oracle depend on this scenario and must be verified.")
	} else {
		prereqs = append(prereqs, "a workload or fixture matching this scenario's preconditions")
		notes = append(notes, "Requires scenario-specific foothold or objective evidence. Whether a response interrupts it depends on detection, action feasibility and an observed oracle.")
	}
	if capSet["CapGPU"] {
		prereqs = append(prereqs, "a GPU node pool")
		notes = append(notes, "Needs a GPU node (Tesla T4+); GPU magnitudes are not hardware-validated in the sandbox (PHORVEXSEC-87), so the oracle may not fully land here.")
	}
	if capSet["CapMultiNode"] {
		prereqs = append(prereqs, "≥2 nodes")
	}
	if capSet["CapMIG"] {
		prereqs = append(prereqs, "MIG-partitioned GPU")
	}
	// does the expected actuator need the AI control plane?
	for _, a := range acts {
		if aiResetActuators[a] {
			prereqs = append(prereqs, "vLLM-shaped control plane (phorvex.ai/* annotations) for the reset actuators to fire")
			break
		}
	}
	runnable := "No special hardware is declared; verify this scenario's fixture and oracle before running."
	if capSet["CapGPU"] && capSet["CapMultiNode"] {
		runnable = "Requires a GPU node pool AND ≥2 nodes."
	} else if capSet["CapGPU"] {
		runnable = "Requires a GPU node pool (GPU oracle hardware validation: PHORVEXSEC-87)."
	} else if capSet["CapMultiNode"] {
		runnable = "Requires ≥2 nodes."
	} else if product == "ai" {
		runnable = "Requires a matching served-model fixture; verify this scenario's actual oracle."
	}
	return ScenarioMeta{
		ExpectedActuators:     acts,
		ResponseGuidanceBasis: "name-heuristic",
		ResponseGuidance:      guidance,
		MeaningfulWhen:        strings.Join(notes, " "),
		RunnableNote:          runnable,
		Prereqs:               prereqs,
	}
}

func deriveBenignScenarioMeta(name string, caps []string) ScenarioMeta {
	prereqs := []string{"a disposable harness namespace"}
	runnable := "Runs as a synthetic functional fixture; it does not exercise an installed application."
	for _, capability := range caps {
		if capability == "CapGPU" {
			prereqs = append(prereqs, "an exact configured GPU functional fixture")
			runnable = "Requires the exact configured GPU fixture and runs a bounded real-protocol functional control."
			break
		}
	}
	meaning := "Benign functional control; security outcome and defense efficacy are not measured."
	if name == "c2-voice-websocket-continuity" {
		meaning = "Synthetic Twilio-shaped WebSocket continuity fixture; it does not evaluate the installed Pipecat service, a provider call, speech quality, or brain efficacy."
	}
	return ScenarioMeta{
		ExpectedActuators:     []string{},
		ResponseGuidanceBasis: "none",
		ResponseGuidance:      "Benign functional control; no actuator response or security outcome is asserted.",
		MeaningfulWhen:        meaning,
		RunnableNote:          runnable,
		Prereqs:               prereqs,
	}
}
