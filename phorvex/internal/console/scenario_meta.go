/*
 * Phorvex Console — SCENARIO METADATA: per-attack actuator mapping + runnability explanation.
 *
 * The harness scenarios do not declare WHICH actuator they should trigger, nor a plain-English
 * "when is this meaningful / what does it need to run". This derives both from the scenario name +
 * its capability requirements (the same caps the harness uses to skip-gate), so the Attack Lab can
 * badge every attack with its expected actuator(s) and explain its prerequisites — and so a run's
 * RESULT can be scored for coordination (did Phorvex pick the expected actuator?).
 *
 * Derivation, not hand-authored per-scenario: a keyword map over the ~53 scenarios keeps it honest
 * and complete as the registry grows.
 */

package console

import "strings"

// ScenarioMeta is the derived per-attack guidance surfaced on the catalog/Attack-Lab.
type ScenarioMeta struct {
	ExpectedActuators []string `json:"expectedActuators"` // actuator(s) this attack should trigger
	MeaningfulWhen    string   `json:"meaningfulWhen"`    // when this attack matters
	RunnableNote      string   `json:"runnableNote"`      // what it needs to RUN (hardware/workload)
	Prereqs           []string `json:"prereqs"`           // explicit prerequisite chips
}

// expectedActuatorsFor maps a scenario to the actuator(s) Phorvex SHOULD select against it. Keyword
// order matters (most specific first). AI scenarios map to the AI actuators (kv-reset etc.);
// structural scenarios map to the K8s moving-target actuators (rotate/quarantine).
func expectedActuatorsFor(name string) []string {
	n := strings.ToLower(name)
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
	capSet := map[string]bool{}
	for _, c := range caps {
		capSet[c] = true
	}
	prereqs := []string{}
	notes := []string{}

	if product == "ai" {
		prereqs = append(prereqs, "a served model / inference workload")
		notes = append(notes, "Meaningful on a live LLM/inference service — the attacker abuses the model's serving path (KV-cache, endpoint, weights, or agent tools), which a blind pod-rotation often can't cleanly evict.")
	} else {
		prereqs = append(prereqs, "any pod with a reachable foothold")
		notes = append(notes, "Meaningful wherever an attacker can gain + dwell in a foothold — moving-target rotation/quarantine invalidates the foothold faster than the attacker can use it.")
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
	runnable := "Runs on any pod — no special hardware."
	if capSet["CapGPU"] && capSet["CapMultiNode"] {
		runnable = "Requires a GPU node pool AND ≥2 nodes."
	} else if capSet["CapGPU"] {
		runnable = "Requires a GPU node pool (GPU oracle hardware validation: PHORVEXSEC-87)."
	} else if capSet["CapMultiNode"] {
		runnable = "Requires ≥2 nodes."
	} else if product == "ai" {
		runnable = "Runs on any served-model workload; the oracle measures the model-serving path."
	}
	return ScenarioMeta{
		ExpectedActuators: acts,
		MeaningfulWhen:    strings.Join(notes, " "),
		RunnableNote:      runnable,
		Prereqs:           prereqs,
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
		ExpectedActuators: []string{},
		MeaningfulWhen:    meaning,
		RunnableNote:      runnable,
		Prereqs:           prereqs,
	}
}
