// agent-sim is the lane fixture for the agent-action-deny actuator: a tiny agent workload
// that consults an operator-owned deny-guard ConfigMap (mounted read-only) on EVERY request
// to decide whether a (caller, action) pair is allowed. It is the generic analog of the
// mini-CRM deny-guard. No auth, no state beyond the guard — the brain defends it by writing
// the one abused pair into the guard, after which this app refuses exactly that pair.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
)

const defaultGuardFile = "/etc/phorvex-agent-guard/denied.json"

type guard struct {
	DeniedAgentActions []string `json:"denied_agent_actions"`
}

func readGuard() guard {
	path := os.Getenv("GUARD_FILE")
	if path == "" {
		path = defaultGuardFile
	}
	g := guard{DeniedAgentActions: []string{}}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return g
	}
	var parsed guard
	if json.Unmarshal(raw, &parsed) == nil && parsed.DeniedAgentActions != nil {
		g.DeniedAgentActions = parsed.DeniedAgentActions
	}
	return g
}

func denied(g guard, key string) bool {
	for _, k := range g.DeniedAgentActions {
		if k == key {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// Readback endpoint the actuator polls: exactly {"denied_agent_actions":[sorted]}.
	mux.HandleFunc("/phorvex-guard/state", func(w http.ResponseWriter, _ *http.Request) {
		g := readGuard()
		ids := append([]string(nil), g.DeniedAgentActions...)
		sort.Strings(ids)
		writeJSON(w, http.StatusOK, guard{DeniedAgentActions: ids})
	})
	// The agent action: ALLOW unless the exact (caller, action) pair is in the deny-guard.
	mux.HandleFunc("/act", func(w http.ResponseWriter, r *http.Request) {
		caller := r.URL.Query().Get("caller")
		action := r.URL.Query().Get("action")
		if caller == "" || action == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "caller and action required"})
			return
		}
		key := caller + "::" + action
		if denied(readGuard(), key) {
			writeJSON(w, http.StatusForbidden, map[string]string{"decision": "deny", "caller": caller, "action": action})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"decision": "allow", "caller": caller, "action": action})
	})
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	// Trim any accidental whitespace from env.
	srv := &http.Server{Addr: strings.TrimSpace(addr), Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}
