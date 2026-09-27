// Package litellmclient defines the narrow owned-client gateway policy contract.
// It has no authority over LiteLLM's master key or unowned client channels.
package litellmclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const (
	Namespace              = "litellm"
	ServiceName            = "litellm"
	SourceConfigMapName    = "phorvex-litellm-admission-gateway"
	ClientsConfigMapName   = "phorvex-litellm-live-clients"
	PolicyConfigMapName    = "phorvex-litellm-client-policy"
	GatewayContainerName   = "litellm-admission-gateway"
	SourceKey              = "gateway.py"
	PolicyKey              = "state.json"
	ClientsKey             = "clients.json"
	SourceSHAAnnotation    = "phorvex.ai/litellm-gateway-source-sha256"
	GatewayImageAnnotation = "phorvex.ai/litellm-gateway-image"
	PolicyUIDAnnotation    = "phorvex.ai/litellm-client-policy-configmap-uid"
	ServiceUIDAnnotation   = "phorvex.ai/litellm-live-service-uid"
	ClientSHAAnnotation    = "phorvex.ai/litellm-owned-client-sha256"
	ObservationAnnotation  = "phorvex.ai/litellm-client-observation-v1"
	RuleType               = "phorvex.attack.litellm-client-abuse"
	ApprovedSourceSHA256   = "85a1face6bc0429b65ab128fbbee29007bc4a3ead296f4c41706ab5dc6f15c4e"
	// An installation must fill this from its reviewed, immutable gateway image.
	// Empty deliberately makes the native action unavailable.
	ApprovedGatewayImage = ""
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func SHA256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ValidSHA(s string) bool   { return shaPattern.MatchString(s) }

type State struct {
	Version      int    `json:"version"`
	Active       bool   `json:"active"`
	Revision     uint64 `json:"revision"`
	OperationID  string `json:"operationId"`
	ClientSHA256 string `json:"clientSHA256"`
}

type Clients struct {
	Version        int    `json:"version"`
	AttackerSHA256 string `json:"attackerSHA256"`
	ControlSHA256  string `json:"controlSHA256"`
	ModelAlias     string `json:"modelAlias"`
}

type Observation struct {
	Version          int       `json:"version"`
	ClientSHA256     string    `json:"clientSHA256"`
	ConfigMapUID     string    `json:"configMapUID"`
	ServiceUID       string    `json:"serviceUID"`
	TargetPodUID     string    `json:"targetPodUID"`
	PeerPodUID       string    `json:"peerPodUID"`
	RequestPath      string    `json:"requestPath"`
	Objective        string    `json:"objective"`
	ObservedAt       time.Time `json:"observedAt"`
	PolicyName       string    `json:"policyName"`
	PolicyUID        string    `json:"policyUID"`
	PolicyGeneration int64     `json:"policyGeneration"`
}

func ParseObservation(raw string) (Observation, error) {
	var o Observation
	e := decodeExact(raw, map[string]bool{"version": true, "clientSHA256": true, "configMapUID": true,
		"serviceUID": true, "targetPodUID": true, "peerPodUID": true, "requestPath": true,
		"objective": true, "observedAt": true, "policyName": true, "policyUID": true,
		"policyGeneration": true}, &o)
	if e != nil {
		return Observation{}, e
	}
	if o.Version != 1 || !ValidSHA(o.ClientSHA256) || o.ConfigMapUID == "" || o.ServiceUID == "" ||
		o.TargetPodUID == "" || o.PeerPodUID == "" || o.TargetPodUID == o.PeerPodUID ||
		o.RequestPath != "/v1/chat/completions" ||
		(o.Objective != "ai2-unbounded-consumption" && o.Objective != "ai2-query-extraction") ||
		o.ObservedAt.IsZero() || o.PolicyName == "" || o.PolicyUID == "" || o.PolicyGeneration < 1 {
		return Observation{}, errors.New("owned-client observation invalid")
	}
	return o, nil
}

// decodeExact accepts only the specified keys once, including no case aliases.
func decodeExact(raw string, keys map[string]bool, into any) error {
	if len(raw) == 0 || len(raw) > 2048 {
		return errors.New("owned-client JSON size")
	}
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return errors.New("owned-client JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		v, e := d.Token()
		if e != nil {
			return errors.New("owned-client JSON key")
		}
		k, ok := v.(string)
		if !ok || !keys[k] || seen[k] {
			return errors.New("owned-client JSON key")
		}
		seen[k] = true
		var value json.RawMessage
		if e = d.Decode(&value); e != nil {
			return e
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != len(keys) {
		return errors.New("owned-client JSON keyset")
	}
	if _, e = d.Token(); e != io.EOF {
		return errors.New("owned-client JSON trailing value")
	}
	typed := json.NewDecoder(bytes.NewReader([]byte(raw)))
	typed.DisallowUnknownFields()
	if e = typed.Decode(into); e != nil {
		return e
	}
	return nil
}

func ParseState(raw string) (State, error) {
	var s State
	e := decodeExact(raw, map[string]bool{"version": true, "active": true, "revision": true, "operationId": true, "clientSHA256": true}, &s)
	if e != nil {
		return State{}, e
	}
	if s.Version != 1 || !ValidSHA(s.ClientSHA256) || (!s.Active && (s.Revision != 0 || s.OperationID != "")) ||
		(s.Active && (s.Revision != 1 || s.OperationID == "" || len(s.OperationID) > 128)) {
		return State{}, errors.New("owned-client policy state invalid")
	}
	canonical, _ := json.Marshal(map[string]any{"version": s.Version, "active": s.Active, "revision": s.Revision,
		"operationId": s.OperationID, "clientSHA256": s.ClientSHA256})
	if raw != string(canonical) {
		return State{}, errors.New("owned-client policy state not canonical")
	}
	return s, nil
}

func EncodeState(s State) (string, error) {
	raw, e := json.Marshal(map[string]any{"version": s.Version, "active": s.Active, "revision": s.Revision,
		"operationId": s.OperationID, "clientSHA256": s.ClientSHA256})
	if e != nil {
		return "", e
	}
	if _, e = ParseState(string(raw)); e != nil {
		return "", e
	}
	return string(raw), nil
}

func ParseClients(raw string) (Clients, error) {
	var c Clients
	e := decodeExact(raw, map[string]bool{"version": true, "attackerSHA256": true, "controlSHA256": true, "modelAlias": true}, &c)
	if e != nil {
		return Clients{}, e
	}
	if c.Version != 1 || !ValidSHA(c.AttackerSHA256) || !ValidSHA(c.ControlSHA256) ||
		c.AttackerSHA256 == c.ControlSHA256 || c.ModelAlias != "gpt-4o-mini" {
		return Clients{}, errors.New("owned-client credential inventory invalid")
	}
	canonical, _ := json.Marshal(map[string]any{"version": c.Version, "attackerSHA256": c.AttackerSHA256,
		"controlSHA256": c.ControlSHA256, "modelAlias": c.ModelAlias})
	if raw != string(canonical) {
		return Clients{}, errors.New("owned-client credential inventory not canonical")
	}
	return c, nil
}
