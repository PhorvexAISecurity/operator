/*
 * Phorvex Console — LIVE PhorvexPolicy control.
 *
 * POST /api/policy/edit is a REAL cluster write: it patches a PhorvexPolicy CR with kubectl
 * (--type merge), exactly as scopeVllmPolicy already does for the attack path. It makes the
 * operator-facing knobs editable from the dashboard — mode (active/observe), the per-tick move
 * budget, and the enabled actuator set — instead of an out-of-band kubectl/Helm change.
 *
 * This is safe to expose now because the console.phorvex.ai ALB enforces Cognito login before
 * any request reaches the pod (values-eks.yaml auth-* annotations), and the endpoint is scoped
 * to the operator lens. Before that auth gate this would have been an unauthenticated
 * internet-facing cluster write, which is exactly why the console was read-only-by-default.
 */

package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// policyEditReq is a partial edit: every field is optional and only the present ones are
// patched, so the UI can change one knob without having to resend the whole policy.
type policyEditReq struct {
	Namespace       string   `json:"namespace"`
	Name            string   `json:"name"`
	MaxMovesPerTick *int     `json:"maxMovesPerTick,omitempty"`
	Mode            string   `json:"mode,omitempty"` // "" leaves it; else "active" | "observe"
	EnabledActions  []string `json:"enabledActions,omitempty"`
}

// policyActuators is the CRD's spec.actions.enabled enum, verified against
// phorvexpolicies.phorvex.ai (kubectl get crd ... .enum). It is DELIBERATELY narrower than the
// actuator handler registry: several handlers (guardrail-rotate, adapter-rotate, request-drain,
// kv-migrate-invalidate) are reachable by the attack path but are NOT policy-enablable, so the
// CRD rejects them. Validating against the registry — the first version's bug — let a value like
// "guardrail-rotate" through to a patch the API server then refused as an invalid enum value.
var policyActuators = map[string]bool{
	"rotate": true, "quarantine": true, "noop": true, "debugger": true, "custom-inject": true,
	"identity-rotate": true, "route-rotate": true, "warm-swap": true, "mig-rebind": true,
	"kv-reset": true, "endpoint-rotate": true, "model-shard-replace": true,
}

func (s *Server) policyEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var req policyEditReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	ns := strings.TrimSpace(req.Namespace)
	name := strings.TrimSpace(req.Name)
	if ns == "" || name == "" {
		writeJSON(w, 400, map[string]string{"error": "namespace and name are required"})
		return
	}
	// The same name shape kubectl accepts; keeps a crafted value out of the exec args.
	if !nsRe.MatchString(ns) || !nsRe.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "invalid namespace or policy name"})
		return
	}

	// Build the merge patch from only the fields that were provided.
	spec := map[string]any{}
	if req.MaxMovesPerTick != nil {
		if *req.MaxMovesPerTick < 0 || *req.MaxMovesPerTick > 100 {
			writeJSON(w, 400, map[string]string{"error": "maxMovesPerTick out of range [0,100]"})
			return
		}
		spec["budget"] = map[string]any{"maxMovesPerTick": *req.MaxMovesPerTick}
	}
	if req.Mode != "" {
		if req.Mode != "active" && req.Mode != "observe" {
			writeJSON(w, 400, map[string]string{"error": "mode must be \"active\" or \"observe\""})
			return
		}
		spec["mode"] = req.Mode
	}
	// dryRun is intentionally NOT patched: the PhorvexPolicy CRD has no spec.dryRun field
	// (verified against the schema), so sending it produced an "unknown field" warning and
	// contributed nothing. "Decide but never enact" is expressed by mode=observe instead.
	if req.EnabledActions != nil {
		// Validate against the CRD enum (policyActuators), NOT the handler registry — the CRD
		// is stricter, and a value it rejects makes the whole patch fail. An empty list is
		// legal (decide, enact nothing), so only non-empty entries are checked.
		clean := make([]string, 0, len(req.EnabledActions))
		bad := []string{}
		for _, a := range req.EnabledActions {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if !policyActuators[a] {
				bad = append(bad, a)
			}
			clean = append(clean, a)
		}
		if len(bad) > 0 {
			writeJSON(w, 400, map[string]string{
				"error": "not a policy actuator: " + strings.Join(bad, ", ") +
					" — allowed: rotate, quarantine, noop, debugger, custom-inject, " +
					"identity-rotate, route-rotate, warm-swap, mig-rebind, kv-reset, " +
					"endpoint-rotate, model-shard-replace"})
			return
		}
		spec["actions"] = map[string]any{"enabled": clean}
	}
	if len(spec) == 0 {
		writeJSON(w, 400, map[string]string{"error": "no editable field provided"})
		return
	}

	patch, _ := json.Marshal(map[string]any{"spec": spec})
	out, err := s.cfg.execText(10*time.Second, "kubectl", "-n", ns, "patch", "phorvexpolicy", name,
		"--type", "merge", "-p", string(patch))
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "patch failed: " + strings.TrimSpace(out)})
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "namespace": ns, "name": name, "patched": spec,
		"result": strings.TrimSpace(out),
	})
}
