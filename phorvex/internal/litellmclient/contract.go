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
	"sort"
	"time"
)

const (
	Namespace              = "litellm"
	ServiceName            = "litellm"
	SourceConfigMapName    = "phorvex-litellm-admission-gateway-4bf046ce690c"
	ClientsConfigMapName   = "phorvex-litellm-live-clients"
	PolicyConfigMapName    = "phorvex-litellm-client-policy"
	TrialSeedSecretName    = "phorvex-litellm-trial-seed"
	GatewayContainerName   = "litellm-admission-gateway"
	JournalName            = "phorvex-litellm-revoke-journal"
	JournalKey             = "receipts.json"
	JournalLabel           = "phorvex.ai/litellm-client-revoke-journal"
	SourceKey              = "gateway.py"
	PolicyKey              = "state.json"
	ClientsKey             = "clients.json"
	SourceSHAAnnotation    = "phorvex.ai/litellm-gateway-source-sha256"
	GatewayImageAnnotation = "phorvex.ai/litellm-gateway-image"
	PolicyUIDAnnotation    = "phorvex.ai/litellm-client-policy-configmap-uid"
	ServiceUIDAnnotation   = "phorvex.ai/litellm-live-service-uid"
	ClientSHAAnnotation    = "phorvex.ai/litellm-owned-client-sha256"
	SeedSHAAnnotation      = "phorvex.ai/litellm-trial-seed-sha256"
	ObservationAnnotation  = "phorvex.ai/litellm-client-observation-v1"
	RuleType               = "phorvex.attack.litellm-client-abuse"
	ApprovedSourceSHA256   = "4bf046ce690c280da4b4f0f613ac52d2b4511285454f18c25b2e144b574d5cc1"
	ApprovedGatewayImage   = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
	MetricsSourceSHA256    = "f550b9890b20da4b02b68fac5c102a99a0313e6f419dc41dd0c409b2bdd165c1"
	ApprovedRuntimeImage   = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:91cd4812dcb808d0498ddd0f7f768d64c34e86d05229cec25250abdd1402db32"
)

// ApprovedSourceConfigMap derives a name only for reviewed complete source hashes.
// Keep the legacy approval through convergence and rollback; a SHA prefix alone
// is never authority to read or execute another ConfigMap.
func ApprovedSourceConfigMap(sha string) string {
	if sha != ApprovedSourceSHA256 && sha != MetricsSourceSHA256 {
		return ""
	}
	return "phorvex-litellm-admission-gateway-" + sha[:12]
}

func ApprovedSource(sha string) bool { return ApprovedSourceConfigMap(sha) != "" }

// The source-free runtime is the published image from image-contract.json.
// The original Python runtime remains approved only for the legacy source.
func ApprovedRuntime(sha, image string) bool {
	return ApprovedSource(sha) && (image == ApprovedRuntimeImage ||
		(sha == ApprovedSourceSHA256 && image == ApprovedGatewayImage))
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func SHA256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ValidSHA(s string) bool   { return shaPattern.MatchString(s) }

type State struct {
	Version  int     `json:"version"`
	Revision uint64  `json:"revision"`
	Entries  []Entry `json:"entries"`
}

type Entry struct {
	Active       bool   `json:"active"`
	ClientSHA256 string `json:"clientSHA256"`
	OperationID  string `json:"operationId"`
}

type Clients struct {
	Version    int    `json:"version"`
	ModelAlias string `json:"modelAlias"`
	SeedSHA256 string `json:"seedSHA256"`
}

type Observation struct {
	Version             int       `json:"version"`
	ClientSHA256        string    `json:"clientSHA256"`
	ConfigMapUID        string    `json:"configMapUID"`
	ClientsConfigMapUID string    `json:"clientsConfigMapUID"`
	SeedSHA256          string    `json:"seedSHA256"`
	ServiceUID          string    `json:"serviceUID"`
	TargetPodUID        string    `json:"targetPodUID"`
	PeerPodUID          string    `json:"peerPodUID"`
	RequestPath         string    `json:"requestPath"`
	Objective           string    `json:"objective"`
	ObservedAt          time.Time `json:"observedAt"`
	PolicyName          string    `json:"policyName"`
	PolicyUID           string    `json:"policyUID"`
	PolicyGeneration    int64     `json:"policyGeneration"`
}

func ParseObservation(raw string) (Observation, error) {
	var o Observation
	e := decodeExact(raw, map[string]bool{"version": true, "clientSHA256": true, "configMapUID": true,
		"clientsConfigMapUID": true, "seedSHA256": true,
		"serviceUID": true, "targetPodUID": true, "peerPodUID": true, "requestPath": true,
		"objective": true, "observedAt": true, "policyName": true, "policyUID": true,
		"policyGeneration": true}, &o)
	if e != nil {
		return Observation{}, e
	}
	if o.Version != 2 || !ValidSHA(o.ClientSHA256) || o.ConfigMapUID == "" || o.ClientsConfigMapUID == "" ||
		!ValidSHA(o.SeedSHA256) || o.ServiceUID == "" ||
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
	return decodeExactBound(raw, keys, into, 2048)
}

func decodeExactBound(raw string, keys map[string]bool, into any, maxBytes int) error {
	if len(raw) == 0 || len(raw) > maxBytes {
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
	e := decodeExactBound(raw, map[string]bool{"version": true, "revision": true, "entries": true}, &s, 65536)
	if e != nil {
		return State{}, e
	}
	if s.Version != 2 || s.Entries == nil || len(s.Entries) > 256 || s.Revision != uint64(len(s.Entries)) {
		return State{}, errors.New("owned-client policy state invalid")
	}
	prev := ""
	seenOperations := map[string]bool{}
	for _, entry := range s.Entries {
		if !entry.Active || !ValidSHA(entry.ClientSHA256) || entry.ClientSHA256 <= prev ||
			entry.OperationID == "" || len(entry.OperationID) > 128 || seenOperations[entry.OperationID] {
			return State{}, errors.New("owned-client policy entry invalid or repeated")
		}
		prev = entry.ClientSHA256
		seenOperations[entry.OperationID] = true
	}
	canonical, _ := json.Marshal(map[string]any{"version": s.Version, "revision": s.Revision, "entries": s.Entries})
	if raw != string(canonical) {
		return State{}, errors.New("owned-client policy state not canonical")
	}
	return s, nil
}

func EncodeState(s State) (string, error) {
	raw, e := json.Marshal(map[string]any{"version": s.Version, "revision": s.Revision, "entries": s.Entries})
	if e != nil {
		return "", e
	}
	if _, e = ParseState(string(raw)); e != nil {
		return "", e
	}
	return string(raw), nil
}

func (s State) Entry(clientSHA string) (Entry, bool) {
	for _, entry := range s.Entries {
		if entry.ClientSHA256 == clientSHA {
			return entry, true
		}
	}
	return Entry{}, false
}

func (s State) Append(clientSHA, operationID string) (State, error) {
	if !ValidSHA(clientSHA) || operationID == "" || len(operationID) > 128 || len(s.Entries) >= 256 {
		return State{}, errors.New("owned-client policy capacity or proposed entry invalid")
	}
	if _, exists := s.Entry(clientSHA); exists {
		return State{}, errors.New("owned-client credential already revoked")
	}
	for _, entry := range s.Entries {
		if entry.OperationID == operationID {
			return State{}, errors.New("owned-client decision already used")
		}
	}
	next := State{Version: 2, Revision: s.Revision + 1, Entries: append([]Entry(nil), s.Entries...)}
	next.Entries = append(next.Entries, Entry{Active: true, ClientSHA256: clientSHA, OperationID: operationID})
	sort.Slice(next.Entries, func(i, j int) bool { return next.Entries[i].ClientSHA256 < next.Entries[j].ClientSHA256 })
	return next, nil
}

func ParseClients(raw string) (Clients, error) {
	var c Clients
	e := decodeExact(raw, map[string]bool{"version": true, "seedSHA256": true, "modelAlias": true}, &c)
	if e != nil {
		return Clients{}, e
	}
	if c.Version != 2 || !ValidSHA(c.SeedSHA256) || c.ModelAlias != "gpt-4o-mini" {
		return Clients{}, errors.New("owned-client credential inventory invalid")
	}
	canonical, _ := json.Marshal(map[string]any{"version": c.Version, "seedSHA256": c.SeedSHA256,
		"modelAlias": c.ModelAlias})
	if raw != string(canonical) {
		return Clients{}, errors.New("owned-client credential inventory not canonical")
	}
	return c, nil
}
