/*
 * Phorvex Console — LIVE PhorvexPolicy control.
 *
 * POST /api/policy/edit is a REAL cluster write: it patches a PhorvexPolicy CR with kubectl
 * (--type merge), exactly as scopeVllmPolicy already does for the attack path. It makes the
 * operator-facing knobs editable from the dashboard — mode (active/observe), dryRun, the
 * per-tick move budget, and the enabled actuator set — instead of an out-of-band kubectl/Helm
 * change.
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
	Mode            string   `json:"mode,omitempty"`   // "" leaves it; else "active" | "observe"
	DryRun          *bool    `json:"dryRun,omitempty"` // nil leaves it
	EnabledActions  []string `json:"enabledActions,omitempty"`
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
	if req.DryRun != nil {
		spec["dryRun"] = *req.DryRun
	}
	if req.EnabledActions != nil {
		// Validate each against the actuator handler registry so a typo can't disable the
		// whole policy by naming an action no handler serves. An empty list is legal (it
		// means "decide but enact nothing"), so only NON-empty entries are checked.
		known := handlerNameSet()
		bad := []string{}
		for _, a := range req.EnabledActions {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if !known[a] {
				bad = append(bad, a)
			}
		}
		if len(bad) > 0 {
			writeJSON(w, 400, map[string]string{"error": "unknown actuator(s): " + strings.Join(bad, ", ")})
			return
		}
		spec["actions"] = map[string]any{"enabled": req.EnabledActions}
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

// handlerNameSet is the set of actuator names the registry serves — the same list B03 in the
// End-to-End suite asserts against. Used to reject an enabled-action typo before it reaches
// the CRD.
func handlerNameSet() map[string]bool {
	out := map[string]bool{"noop": true}
	for _, name := range HandlerRegistryView().Names {
		out[name] = true
	}
	return out
}
