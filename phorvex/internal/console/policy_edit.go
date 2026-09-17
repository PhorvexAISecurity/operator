/*
 * Phorvex Console — LIVE PhorvexPolicy control.
 *
 * POST /api/policy/edit is a REAL cluster write: it patches a PhorvexPolicy CR with kubectl
 * (--type merge). It makes the
 * operator-facing knobs editable from the dashboard — mode (active/dryRun), the per-tick move
 * budget, and the enabled actuator set — instead of an out-of-band kubectl/Helm change.
 *
 * This is safe to expose now because the console.phorvex.ai ALB enforces Cognito login before
 * any request reaches the pod (values-eks.yaml auth-* annotations), and the endpoint is scoped
 * to the operator lens. Before that auth gate this would have been an unauthenticated
 * internet-facing cluster write, which is exactly why the console was read-only-by-default.
 */

package console

import (
	"context"
	"encoding/json"
	"fmt"
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
	Mode            string   `json:"mode,omitempty"` // "" leaves it; else "active" | "dryRun"
	EnabledActions  []string `json:"enabledActions,omitempty"`
}

// The set of actuators a policy may enable is computed per app by applicablePolicyActuators
// (attack_compat.go): the generic ones on any workload, the serving/GPU ones only where the stack
// supports them. That subset of the CRD's spec.actions.enabled enum is BOTH schema-valid AND
// runnable, which is what keeps the brain from being handed an actuator it will select but cannot
// actuate (the route-rotate-on-voice A06 failure).

func (s *Server) policyEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	var req policyEditReq
	if b, _ := json.Marshal(raw); json.Unmarshal(b, &req) != nil {
		writeJSON(w, 400, map[string]string{"error": "bad JSON: field types"})
		return
	}
	ns := strings.TrimSpace(req.Namespace)
	name := strings.TrimSpace(req.Name)

	// PHORVEXSEC-205 / M-145 — the tenant KEY is not editable from the console. spec.tenant is
	// the name every learned store (cost dual, kill-chain memory, exposure clock, metrics) is
	// keyed by; rewriting it onto an in-use name silently merges two workloads' economics and
	// even a rename to a fresh name is a state reset, not a migration (M-140). The console never
	// offered this field; it now REFUSES it explicitly instead of silently dropping it, and the
	// refusal is audited. Merging duals is a product + Math decision, filed, not built. This
	// console check is UX and honesty only — kubectl bypasses it; the authoritative guard is
	// M-140's key decision / the admission webhook (PX-P-003).
	if key, present := tenantWriteAttempt(raw); present {
		msg := fmt.Sprintf("%s is not editable from the console: spec.tenant keys the tenant's learned state; "+
			"merging duals is not supported and a rename is a state reset (M-140) — change it deliberately with kubectl", key)
		if err := s.auditConsoleMutation(consoleMutation{
			Actor: actorOf(r), Endpoint: "/api/policy/edit", Namespace: ns, Policy: name,
			Field: "spec.tenant", Verdict: "rejected-tenant-key-write", Message: msg,
		}); err != nil {
			writeJSON(w, 503, map[string]string{"error": "mutation evidence unavailable: " + err.Error(), "verdict": "refused-evidence-unavailable"})
			return
		}
		writeJSON(w, 409, map[string]string{"error": msg, "verdict": "rejected-tenant-key-write"})
		return
	}
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
		if req.Mode != "active" && req.Mode != "dryRun" {
			writeJSON(w, 400, map[string]string{"error": "mode must be \"active\" or \"dryRun\""})
			return
		}
		spec["mode"] = req.Mode
	}
	// dryRun is intentionally NOT patched: the PhorvexPolicy CRD has no spec.dryRun field
	// (verified against the schema), so sending it produced an "unknown field" warning and
	// contributed nothing. "Decide but never enact" is expressed by mode=dryRun instead.
	if req.EnabledActions != nil {
		// Validate against the actuators APPLICABLE to this app's stack, not just the CRD enum.
		// The CRD accepts route-rotate on any policy, but route-rotate has no handler on a plain
		// workload — the brain would still SELECT it (higher coverage) and then fail to actuate,
		// which is the exact A06 critical failure this guards against. The brain keeps deciding;
		// it just never gets offered an actuator the app cannot run.
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		st, _ := s.stackOf(ctx, ns, s.clusterHasGPU(ctx))
		allowed := map[string]bool{}
		for _, a := range applicablePolicyActuators(st) {
			allowed[a] = true
		}
		clean := make([]string, 0, len(req.EnabledActions))
		bad := []string{}
		for _, a := range req.EnabledActions {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if !allowed[a] {
				bad = append(bad, a)
			}
			clean = append(clean, a)
		}
		if len(bad) > 0 {
			writeJSON(w, 400, map[string]string{
				"error": "actuator(s) not runnable on this app's stack: " + strings.Join(bad, ", ") +
					" — allowed here: " + strings.Join(applicablePolicyActuators(st), ", ")})
			return
		}
		spec["actions"] = map[string]any{"enabled": clean}
	}
	if len(spec) == 0 {
		writeJSON(w, 400, map[string]string{"error": "no editable field provided"})
		return
	}

	patch, _ := json.Marshal(map[string]any{"spec": spec})
	// Intent is durable before kubectl. If this fails, no cluster write is attempted.
	if err := s.auditConsoleMutation(consoleMutation{Actor: actorOf(r), Endpoint: "/api/policy/edit", Namespace: ns, Policy: name,
		Field: "spec", Patch: string(patch), Verdict: "intent"}); err != nil {
		writeJSON(w, 503, map[string]string{"error": "mutation refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}
	out, err := s.cfg.execText(10*time.Second, "kubectl", "-n", ns, "patch", "phorvexpolicy", name,
		"--type", "merge", "-p", string(patch))
	verdict := strings.TrimSpace(out)
	if err != nil {
		// Only an authoritative API response proves rejection. Transport failure or timeout after
		// dispatch has an unknown effect and must not invite an automatic retry.
		status, outcome := 502, "effect-unknown"
		if apiServerRejected(verdict) {
			status = 422
			outcome = "rejected-by-apiserver"
		}
		if auditErr := s.auditConsoleMutation(consoleMutation{
			Actor: actorOf(r), Endpoint: "/api/policy/edit", Namespace: ns, Policy: name,
			Field: "spec", Patch: string(patch), Verdict: outcome, Message: verdict,
		}); auditErr != nil {
			writeJSON(w, 503, map[string]any{"ok": false, "effectUnknown": outcome == "effect-unknown", "unsafeToRetry": true, "error": "patch outcome and evidence are unavailable: " + auditErr.Error(), "verdict": "partial-evidence-unavailable"})
			return
		}
		if outcome == "effect-unknown" {
			writeJSON(w, status, map[string]any{"ok": false, "effectUnknown": true, "unsafeToRetry": true, "error": "patch result unknown: " + verdict, "verdict": outcome})
			return
		}
		writeJSON(w, status, map[string]any{"ok": false, "error": "patch rejected: " + verdict, "verdict": outcome})
		return
	}
	if auditErr := s.auditConsoleMutation(consoleMutation{
		Actor: actorOf(r), Endpoint: "/api/policy/edit", Namespace: ns, Policy: name,
		Field: "spec", Patch: string(patch), Verdict: "applied", Message: verdict,
	}); auditErr != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "applied": true, "unsafeToRetry": true,
			"error": "patch applied but outcome evidence is unavailable: " + auditErr.Error(), "verdict": "applied-partial-evidence-unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "namespace": ns, "name": name, "patched": spec,
		"result": verdict,
	})
}

// tenantWriteAttempt reports whether the request body tries to write the tenant key, at the
// top level ("tenant") or nested ("spec": {"tenant": ...}). Returns the path it found.
func tenantWriteAttempt(raw map[string]json.RawMessage) (string, bool) {
	if _, ok := raw["tenant"]; ok {
		return "tenant", true
	}
	if specRaw, ok := raw["spec"]; ok {
		var spec map[string]json.RawMessage
		if json.Unmarshal(specRaw, &spec) == nil {
			if _, ok := spec["tenant"]; ok {
				return "spec.tenant", true
			}
		}
	}
	return "", false
}

// apiServerRejected recognises kubectl's transcription of a server-side rejection (validation,
// admission webhook, forbidden) as opposed to a transport or exec failure.
func apiServerRejected(out string) bool {
	l := strings.ToLower(out)
	for _, marker := range []string{"invalid", "admission webhook", "denied the request", "forbidden", "validation", "unknown field"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}
