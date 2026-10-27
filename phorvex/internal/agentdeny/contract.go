// Package agentdeny defines the narrow agent-action deny-guard contract that the
// agent-action-deny actuator writes and an agent workload enforces. It is the
// NAMESPACE-PARAMETRIC generalization of the crm-refund deny-guard: identical
// deny-guard shape, but the namespace is carried by the trusted observation and the
// live pod rather than pinned to one app namespace. It has authority only over the
// operator-owned deny-list of one abused (caller, action) pair; it never authenticates
// callers and never touches any other agent state. The agent app re-reads the guard
// ConfigMap per request; an empty or absent guard preserves the original behaviour.
package agentdeny

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"
)

// Identity surface. Unlike crmrefund, there is NO package-level Namespace constant:
// the namespace is a parameter threaded from the observation/pod so any lane's agent
// workload (e.g. p4-demo) is defended without a hard-coded app namespace. The guard,
// service and app-label names are a fixed convention for the "agent" workload type.
const (
	ServiceName           = "agent-sim"
	AppLabel              = "app"
	AppLabelValue         = "agent-sim"
	GuardConfigMapName    = "agent-deny-guard"
	GuardKey              = "denied.json"
	StateKey              = "state.json" // operator-owned ledger; app ignores it and reads GuardKey
	GuardMountPath        = "/etc/phorvex-agent-guard"
	AppGuardField         = "denied_agent_actions"
	GuardUIDAnnotation    = "phorvex.ai/agent-deny-guard-configmap-uid"
	ServiceUIDAnnotation  = "phorvex.ai/agent-sim-service-uid"
	ObservationAnnotation = "phorvex.ai/agent-action-observation-v1"
	ReadbackPath          = "/phorvex-guard/state"
	Objective             = "ai2-agent-action-abuse"
	RuleType              = "phorvex.attack.agent-action"
	ServingPort           = 8080
)

var (
	shaPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9:_.-]{1,64}$`)
	actionKeyPat = regexp.MustCompile(`^[A-Za-z0-9:_.-]{1,64}::[A-Za-z0-9:_.-]{1,64}$`)
	nsPattern    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

func SHA256(raw []byte) string     { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ValidSHA(s string) bool       { return shaPattern.MatchString(s) }
func ValidID(s string) bool        { return idPattern.MatchString(s) }
func ValidNamespace(s string) bool { return nsPattern.MatchString(s) }
func ValidActionKey(s string) bool { return actionKeyPat.MatchString(s) }

// ActionKey is the canonical deny-list element: one caller forbidden from one action.
func ActionKey(callerID, actionID string) string { return callerID + "::" + actionID }

// Guard is the operator-owned deny-list the agent app re-reads per request. The app
// keeps only denied_agent_actions; this type adds a revision/operation ledger so the
// actuator's writes are idempotent and auditable. App-facing bytes are produced by
// EncodeAppGuard (just {"denied_agent_actions":[...]}); EncodeState carries the full
// ledger for the actuator's own ConfigMap-state key.
type Guard struct {
	Version  int     `json:"version"`
	Revision uint64  `json:"revision"`
	Entries  []Entry `json:"entries"`
}

type Entry struct {
	Active      bool   `json:"active"`
	ActionKey   string `json:"actionKey"`
	OperationID string `json:"operationId"`
}

// EncodeAppGuard returns exactly what the agent app reads: {"denied_agent_actions":[sorted keys]}.
func (g Guard) EncodeAppGuard() string {
	keys := make([]string, 0, len(g.Entries))
	for _, e := range g.Entries {
		if e.Active {
			keys = append(keys, e.ActionKey)
		}
	}
	sort.Strings(keys)
	raw, _ := json.Marshal(map[string]any{AppGuardField: keys})
	return string(raw)
}

// AppGuardMatches reports whether the app-facing denied.json bytes deny exactly the
// ledger's active action keys. It compares meaning, not bytes: the guard is installed by
// hand as YAML ({"denied_agent_actions": []} plus a trailing newline) before the actuator
// writes its canonical encoding, and that formatting difference must not read as an
// out-of-band writer. Unknown keys, duplicates or a different set still disagree.
func AppGuardMatches(raw string, g Guard) bool {
	if len(raw) > 65536 {
		return false
	}
	var app struct {
		DeniedAgentActions []string `json:"denied_agent_actions"`
	}
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&app) != nil || d.Decode(new(any)) != io.EOF || app.DeniedAgentActions == nil {
		return false
	}
	want := map[string]bool{}
	for _, e := range g.Entries {
		if e.Active {
			want[e.ActionKey] = true
		}
	}
	seen := map[string]bool{}
	for _, k := range app.DeniedAgentActions {
		if !want[k] || seen[k] {
			return false
		}
		seen[k] = true
	}
	return len(seen) == len(want)
}

func (g Guard) Entry(actionKey string) (Entry, bool) {
	for _, e := range g.Entries {
		if e.ActionKey == actionKey {
			return e, true
		}
	}
	return Entry{}, false
}

// Append denies one (caller, action) pair under a unique operation id. It refuses a
// repeated pair, a reused operation id, a malformed key, or capacity overflow.
func (g Guard) Append(actionKey, operationID string) (Guard, error) {
	if !ValidActionKey(actionKey) || operationID == "" || len(operationID) > 128 || len(g.Entries) >= 256 {
		return Guard{}, errors.New("agent deny guard capacity or proposed entry invalid")
	}
	if _, exists := g.Entry(actionKey); exists {
		return Guard{}, errors.New("agent action already denied for this pair")
	}
	for _, e := range g.Entries {
		if e.OperationID == operationID {
			return Guard{}, errors.New("agent deny decision already used")
		}
	}
	next := Guard{Version: 2, Revision: g.Revision + 1, Entries: append([]Entry(nil), g.Entries...)}
	next.Entries = append(next.Entries, Entry{Active: true, ActionKey: actionKey, OperationID: operationID})
	sort.Slice(next.Entries, func(i, j int) bool { return next.Entries[i].ActionKey < next.Entries[j].ActionKey })
	return next, nil
}

func EncodeState(g Guard) (string, error) {
	raw, e := json.Marshal(map[string]any{"version": g.Version, "revision": g.Revision, "entries": g.Entries})
	if e != nil {
		return "", e
	}
	if _, e = ParseState(string(raw)); e != nil {
		return "", e
	}
	return string(raw), nil
}

func ParseState(raw string) (Guard, error) {
	var g Guard
	if e := decodeExactBound(raw, map[string]bool{"version": true, "revision": true, "entries": true}, &g, 65536); e != nil {
		return Guard{}, e
	}
	if g.Version != 2 || g.Entries == nil || len(g.Entries) > 256 || g.Revision != uint64(len(g.Entries)) {
		return Guard{}, errors.New("agent deny guard state invalid")
	}
	prev := ""
	seenOps := map[string]bool{}
	for _, e := range g.Entries {
		if !e.Active || !ValidActionKey(e.ActionKey) || e.ActionKey <= prev ||
			e.OperationID == "" || len(e.OperationID) > 128 || seenOps[e.OperationID] {
			return Guard{}, errors.New("agent deny guard entry invalid or repeated")
		}
		prev = e.ActionKey
		seenOps[e.OperationID] = true
	}
	canonical, _ := json.Marshal(map[string]any{"version": g.Version, "revision": g.Revision, "entries": g.Entries})
	if raw != string(canonical) {
		return Guard{}, errors.New("agent deny guard state not canonical")
	}
	return g, nil
}

// Observation is the trusted, admission-stamped evidence that an unauthorized agent
// action landed. The actuator denies exactly ActionKey(CallerID, ActionID) in the
// Namespace the observation names (parametric — no hard-coded app namespace).
type Observation struct {
	Version           int       `json:"version"`
	Namespace         string    `json:"namespace"`
	AgentName         string    `json:"agentName"`
	CallerID          string    `json:"callerId"`
	ActionID          string    `json:"actionId"`
	GuardConfigMapUID string    `json:"guardConfigMapUID"`
	ServiceUID        string    `json:"serviceUID"`
	TargetPodUID      string    `json:"targetPodUID"`
	Objective         string    `json:"objective"`
	ObservedAt        time.Time `json:"observedAt"`
	PolicyName        string    `json:"policyName"`
	PolicyUID         string    `json:"policyUID"`
	PolicyGeneration  int64     `json:"policyGeneration"`
}

func ParseObservation(raw string) (Observation, error) {
	var o Observation
	e := decodeExactBound(raw, map[string]bool{"version": true, "namespace": true, "agentName": true,
		"callerId": true, "actionId": true, "guardConfigMapUID": true, "serviceUID": true, "targetPodUID": true,
		"objective": true, "observedAt": true, "policyName": true, "policyUID": true,
		"policyGeneration": true}, &o, 2048)
	if e != nil {
		return Observation{}, e
	}
	if o.Version != 1 || !ValidNamespace(o.Namespace) || !ValidID(o.AgentName) || !ValidID(o.CallerID) ||
		!ValidID(o.ActionID) || o.GuardConfigMapUID == "" || o.ServiceUID == "" || o.TargetPodUID == "" ||
		o.Objective != Objective || o.ObservedAt.IsZero() ||
		o.PolicyName == "" || o.PolicyUID == "" || o.PolicyGeneration < 1 {
		return Observation{}, errors.New("agent deny observation invalid")
	}
	return o, nil
}

func decodeExactBound(raw string, keys map[string]bool, into any, maxBytes int) error {
	if len(raw) == 0 || len(raw) > maxBytes {
		return errors.New("agent deny JSON size")
	}
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return errors.New("agent deny JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		v, e := d.Token()
		if e != nil {
			return errors.New("agent deny JSON key")
		}
		k, ok := v.(string)
		if !ok || !keys[k] || seen[k] {
			return errors.New("agent deny JSON key")
		}
		seen[k] = true
		var value json.RawMessage
		if e = d.Decode(&value); e != nil {
			return e
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != len(keys) {
		return errors.New("agent deny JSON keyset")
	}
	if _, e = d.Token(); e != io.EOF {
		return errors.New("agent deny JSON trailing value")
	}
	typed := json.NewDecoder(bytes.NewReader([]byte(raw)))
	typed.DisallowUnknownFields()
	return typed.Decode(into)
}
