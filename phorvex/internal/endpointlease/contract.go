// Package endpointlease defines the narrow durable public-inference caller lease.
// It contains no credential material and cannot grant access without the proxy's
// independently authenticated Secret and current Kubernetes policy read.
package endpointlease

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
	Namespace                 = "vllm"
	ServiceName               = "vllm"
	PolicyConfigMapName       = "phorvex-endpoint-lease-policy"
	PolicyKey                 = "state.json"
	SourceConfigMapName       = "guardrail-proxy"
	SecretName                = "phorvex-endpoint-lease-keys"
	JournalName               = "phorvex-endpoint-lease-journal"
	JournalKey                = "receipts.json"
	JournalLabel              = "phorvex.ai/endpoint-lease-journal"
	ObservationAnnotation     = "phorvex.ai/endpoint-lease-observation-v1"
	RuleType                  = "phorvex.attack.endpoint-lease-reuse"
	SourceSHAAnnotation       = "phorvex.ai/endpoint-lease-source-sha256"
	SourceConfigMapAnnotation = "phorvex.ai/endpoint-lease-source-configmap"
	PolicyUIDAnnotation       = "phorvex.ai/endpoint-lease-policy-configmap-uid"
	ProxyContainerName        = "guardrail"
	StatusPath                = "/v1/endpoint-lease/state"
	MaxStateBytes             = 16 << 10
	MaxObservationBytes       = 4 << 10
	MaxStatusBytes            = 8 << 10
	MaxRevision               = (1 << 53) - 1
)

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var operationRE = regexp.MustCompile(`^[0-9a-f]{32,64}$`)
var uidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func ValidSHA(value string) bool         { return digestRE.MatchString(value) }
func ValidOperationID(value string) bool { return operationRE.MatchString(value) }
func ValidUID(value string) bool         { return uidRE.MatchString(value) }
func SHA256(raw []byte) string           { digest := sha256.Sum256(raw); return hex.EncodeToString(digest[:]) }

// SourceSHA256 covers the exact executable import/init closure in source order.
// The old one-file and provisional three-file digests never authorize a lease.
func SourceSHA256(proxy, boundary, lease, drain, drainInit []byte) string {
	parts := [][]byte{proxy, boundary, lease, drain, drainInit}
	h := sha256.New()
	for i, part := range parts {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type State struct {
	Version            int      `json:"version"`
	Revision           uint64   `json:"revision"`
	ServiceUID         string   `json:"serviceUID"`
	ProxySourceSHA256  string   `json:"proxySourceSHA256"`
	SecretUID          string   `json:"secretUID"`
	SeedSHA256         string   `json:"seedSHA256"`
	AllowedClientHMACs []string `json:"allowedClientHMACs"`
	RevokedClientHMACs []string `json:"revokedClientHMACs"`
	LastOperationID    string   `json:"lastOperationID"`
}

func stateMap(s State) map[string]any {
	return map[string]any{"version": s.Version, "revision": s.Revision, "serviceUID": s.ServiceUID,
		"proxySourceSHA256": s.ProxySourceSHA256, "secretUID": s.SecretUID, "seedSHA256": s.SeedSHA256,
		"allowedClientHMACs": s.AllowedClientHMACs, "revokedClientHMACs": s.RevokedClientHMACs,
		"lastOperationID": s.LastOperationID}
}

func EncodeState(s State) (string, error) {
	if err := validateState(s); err != nil {
		return "", err
	}
	raw, err := json.Marshal(stateMap(s))
	if len(raw) > MaxStateBytes {
		return "", errors.New("endpoint lease state exceeds byte bound")
	}
	return string(raw), err
}

func ParseState(raw string) (State, error) {
	var s State
	if err := decodeCanonical(raw, MaxStateBytes, stateKeys, &s); err != nil {
		return State{}, err
	}
	if err := validateState(s); err != nil {
		return State{}, err
	}
	encoded, _ := EncodeState(s)
	if raw != encoded {
		return State{}, errors.New("endpoint lease state is not canonical")
	}
	return s, nil
}

func validateState(s State) error {
	if s.Version != 1 || s.Revision > MaxRevision || !ValidUID(s.ServiceUID) || !ValidUID(s.SecretUID) ||
		!ValidSHA(s.ProxySourceSHA256) || !ValidSHA(s.SeedSHA256) || len(s.AllowedClientHMACs) == 0 ||
		len(s.AllowedClientHMACs) > 256 || len(s.RevokedClientHMACs) > 256 ||
		(s.Revision == 0 && s.LastOperationID != "") || (s.Revision > 0 && !ValidOperationID(s.LastOperationID)) {
		return errors.New("endpoint lease state identity or revision invalid")
	}
	prev := ""
	seen := map[string]bool{}
	for _, id := range s.AllowedClientHMACs {
		if !ValidSHA(id) || id <= prev {
			return errors.New("endpoint lease allowed HMAC order invalid")
		}
		prev = id
		seen[id] = true
	}
	prev = ""
	for _, id := range s.RevokedClientHMACs {
		if !ValidSHA(id) || id <= prev || seen[id] {
			return errors.New("endpoint lease revoked HMAC order or overlap invalid")
		}
		prev = id
	}
	return nil
}

func (s State) Revoke(oldID, retainedID, operationID string) (State, error) {
	if !ValidSHA(oldID) || !ValidSHA(retainedID) || oldID == retainedID || !ValidOperationID(operationID) || s.Revision >= MaxRevision || s.LastOperationID == operationID {
		return State{}, errors.New("endpoint lease proposed revocation invalid")
	}
	if _, err := EncodeState(s); err != nil {
		return State{}, err
	}
	oldFound, retainedFound := false, false
	next := s
	next.AllowedClientHMACs = make([]string, 0, len(s.AllowedClientHMACs)-1)
	for _, id := range s.AllowedClientHMACs {
		if id == oldID {
			oldFound = true
			continue
		}
		if id == retainedID {
			retainedFound = true
		}
		next.AllowedClientHMACs = append(next.AllowedClientHMACs, id)
	}
	if !oldFound || !retainedFound {
		return State{}, errors.New("endpoint lease observed pair is not currently allowed")
	}
	next.RevokedClientHMACs = append([]string(nil), s.RevokedClientHMACs...)
	next.RevokedClientHMACs = append(next.RevokedClientHMACs, oldID)
	sort.Strings(next.RevokedClientHMACs)
	next.Revision++
	next.LastOperationID = operationID
	if _, err := EncodeState(next); err != nil {
		return State{}, err
	}
	return next, nil
}

type Observation struct {
	Version                        int       `json:"version"`
	ScenarioID                     string    `json:"scenarioId"`
	EvidenceSource                 string    `json:"evidenceSource"`
	PolicyName                     string    `json:"policyName"`
	PolicyUID                      string    `json:"policyUID"`
	PolicyGeneration               int64     `json:"policyGeneration"`
	TargetPodUID                   string    `json:"targetPodUID"`
	ServiceUID                     string    `json:"serviceUID"`
	PolicyConfigMapUID             string    `json:"policyConfigMapUID"`
	ProxySourceSHA256              string    `json:"proxySourceSHA256"`
	SecretUID                      string    `json:"secretUID"`
	SeedSHA256                     string    `json:"seedSHA256"`
	PriorRevision                  uint64    `json:"priorRevision"`
	RevokedClientHMAC              string    `json:"revokedClientHMAC"`
	RetainedClientHMAC             string    `json:"retainedClientHMAC"`
	AcceptedStatus                 int       `json:"acceptedStatus"`
	AcceptedResponseSHA256         string    `json:"acceptedResponseSHA256"`
	RetainedBaselineStatus         int       `json:"retainedBaselineStatus"`
	RetainedBaselineResponseSHA256 string    `json:"retainedBaselineResponseSHA256"`
	ObservedAt                     time.Time `json:"observedAt"`
}

func ParseObservation(raw string) (Observation, error) {
	var o Observation
	if err := decodeCanonical(raw, MaxObservationBytes, observationKeys, &o); err != nil {
		return Observation{}, err
	}
	if o.Version != 1 || o.ScenarioID != "ai2-endpoint-security" || o.EvidenceSource != "TEST_INJECTED" || o.PolicyName == "" ||
		!ValidUID(o.PolicyUID) || o.PolicyGeneration < 1 || !ValidUID(o.TargetPodUID) || !ValidUID(o.ServiceUID) ||
		!ValidUID(o.PolicyConfigMapUID) || !ValidSHA(o.ProxySourceSHA256) || !ValidUID(o.SecretUID) || !ValidSHA(o.SeedSHA256) ||
		o.PriorRevision > MaxRevision || !ValidSHA(o.RevokedClientHMAC) || !ValidSHA(o.RetainedClientHMAC) || o.RevokedClientHMAC == o.RetainedClientHMAC ||
		o.AcceptedStatus != 200 || !ValidSHA(o.AcceptedResponseSHA256) || o.RetainedBaselineStatus != 200 || !ValidSHA(o.RetainedBaselineResponseSHA256) || o.ObservedAt.IsZero() {
		return Observation{}, errors.New("endpoint lease observation invalid")
	}
	canonical, _ := json.Marshal(o)
	// Struct order is not canonical. Decode through a map solely to compare the
	// exact sorted bytes, after exact-key and typed validation above.
	var values map[string]any
	_ = json.Unmarshal(canonical, &values)
	ordered, _ := json.Marshal(values)
	if raw != string(ordered) {
		return Observation{}, errors.New("endpoint lease observation is not canonical")
	}
	return o, nil
}

// Status is the authenticated proxy's current API-backed policy and Secret
// binding, with a query for two HMAC IDs. It contains no bearer or seed bytes.
type Status struct {
	Version               int    `json:"version"`
	PodUID                string `json:"podUID"`
	ServiceUID            string `json:"serviceUID"`
	ProxySourceSHA256     string `json:"proxySourceSHA256"`
	PolicyConfigMapUID    string `json:"policyConfigMapUID"`
	SecretUID             string `json:"secretUID"`
	SeedSHA256            string `json:"seedSHA256"`
	Revision              uint64 `json:"revision"`
	LastOperationID       string `json:"lastOperationID"`
	StateSHA256           string `json:"stateSHA256"`
	RevokedClientHMAC     string `json:"revokedClientHMAC"`
	RetainedClientHMAC    string `json:"retainedClientHMAC"`
	RevokedClientAllowed  bool   `json:"revokedClientAllowed"`
	RetainedClientAllowed bool   `json:"retainedClientAllowed"`
	OldRevisionInFlight   uint64 `json:"oldRevisionInFlight"`
	Ready                 bool   `json:"ready"`
}

func ParseStatus(raw string) (Status, error) {
	var s Status
	if err := decodeCanonical(raw, MaxStatusBytes, statusKeys, &s); err != nil {
		return Status{}, err
	}
	if s.Version != 1 || !ValidUID(s.PodUID) || !ValidUID(s.ServiceUID) ||
		!ValidSHA(s.ProxySourceSHA256) || !ValidUID(s.PolicyConfigMapUID) || !ValidUID(s.SecretUID) ||
		!ValidSHA(s.SeedSHA256) || s.Revision > MaxRevision || !ValidSHA(s.StateSHA256) ||
		!ValidSHA(s.RevokedClientHMAC) || !ValidSHA(s.RetainedClientHMAC) || s.RevokedClientHMAC == s.RetainedClientHMAC ||
		(s.Revision == 0 && s.LastOperationID != "") || (s.Revision > 0 && !ValidOperationID(s.LastOperationID)) {
		return Status{}, errors.New("endpoint lease proxy status invalid")
	}
	canonical, _ := json.Marshal(s)
	var values map[string]any
	_ = json.Unmarshal(canonical, &values)
	ordered, _ := json.Marshal(values)
	if raw != string(ordered) {
		return Status{}, errors.New("endpoint lease proxy status is not canonical")
	}
	return s, nil
}

var stateKeys = keyset("version", "revision", "serviceUID", "proxySourceSHA256", "secretUID", "seedSHA256", "allowedClientHMACs", "revokedClientHMACs", "lastOperationID")
var observationKeys = keyset("version", "scenarioId", "evidenceSource", "policyName", "policyUID", "policyGeneration", "targetPodUID", "serviceUID", "policyConfigMapUID", "proxySourceSHA256", "secretUID", "seedSHA256", "priorRevision", "revokedClientHMAC", "retainedClientHMAC", "acceptedStatus", "acceptedResponseSHA256", "retainedBaselineStatus", "retainedBaselineResponseSHA256", "observedAt")
var statusKeys = keyset("version", "podUID", "serviceUID", "proxySourceSHA256", "policyConfigMapUID", "secretUID", "seedSHA256", "revision", "lastOperationID", "stateSHA256", "revokedClientHMAC", "retainedClientHMAC", "revokedClientAllowed", "retainedClientAllowed", "oldRevisionInFlight", "ready")

func keyset(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func decodeCanonical(raw string, max int, keys map[string]bool, into any) error {
	if len(raw) == 0 || len(raw) > max {
		return errors.New("endpoint lease JSON size invalid")
	}
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("endpoint lease JSON object required")
	}
	seen := map[string]bool{}
	for d.More() {
		v, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := v.(string)
		if !ok || !keys[key] || seen[key] {
			return errors.New("endpoint lease JSON duplicate or unknown key")
		}
		seen[key] = true
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(keys) {
		return errors.New("endpoint lease JSON keyset invalid")
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("endpoint lease JSON trailing value")
	}
	d = json.NewDecoder(bytes.NewReader([]byte(raw)))
	d.DisallowUnknownFields()
	if err = d.Decode(into); err != nil {
		return err
	}
	return nil
}
