// agent-sim is the lane fixture for the agent-action-deny actuator: a tiny agent workload
// that consults an operator-owned deny-guard ConfigMap (mounted read-only) on EVERY request
// to decide whether a (caller, action) pair is allowed. It is the generic analog of the
// mini-CRM deny-guard. No auth, no state beyond the guard — the brain defends it by writing
// the one abused pair into the guard, after which this app refuses exactly that pair.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const defaultGuardFile = "/etc/phorvex-agent-guard/denied.json"

type guard struct {
	DeniedAgentActions []string `json:"denied_agent_actions"`
}

var actionKeyPattern = regexp.MustCompile(`^[A-Za-z0-9:_.-]{1,64}::[A-Za-z0-9:_.-]{1,64}$`)

func readGuard(path string) (guard, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		return guard{}, errors.New("guard unavailable")
	}
	var parsed guard
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&parsed) != nil || decoder.Decode(new(any)) != io.EOF || parsed.DeniedAgentActions == nil {
		return guard{}, errors.New("guard malformed")
	}
	seen := map[string]bool{}
	for _, key := range parsed.DeniedAgentActions {
		if !actionKeyPattern.MatchString(key) || seen[key] {
			return guard{}, errors.New("guard entry invalid")
		}
		seen[key] = true
	}
	return parsed, nil
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

func newHandler(guardFile string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := readGuard(guardFile); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "guard-unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// Readback endpoint the actuator polls: exactly {"denied_agent_actions":[sorted]}.
	mux.HandleFunc("/phorvex-guard/state", func(w http.ResponseWriter, _ *http.Request) {
		g, err := readGuard(guardFile)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "guard unavailable"})
			return
		}
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
		if !actionKeyPattern.MatchString(caller + "::" + action) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "caller or action invalid"})
			return
		}
		key := caller + "::" + action
		g, err := readGuard(guardFile)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "guard unavailable"})
			return
		}
		if denied(g, key) {
			writeJSON(w, http.StatusForbidden, map[string]string{"decision": "deny", "caller": caller, "action": action})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"decision": "allow", "caller": caller, "action": action})
	})
	return mux
}

func main() {
	guardFile := strings.TrimSpace(os.Getenv("GUARD_FILE"))
	if guardFile == "" {
		guardFile = defaultGuardFile
	}
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	// Trim any accidental whitespace from env.
	srv := &http.Server{Addr: strings.TrimSpace(addr), Handler: newHandler(guardFile),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}
