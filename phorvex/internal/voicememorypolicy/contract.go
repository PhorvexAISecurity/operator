package voicememorypolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

const (
	Namespace     = "voice"
	ConfigMapName = "voice-memory-policy"
	RuleKey       = "rule.json"
	MaxEntries    = 32
	StatePath     = "/v1/voice-memory-policy/state"
)

var (
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	callerPattern = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)
)

type Entry struct {
	CallerID    string `json:"callerId"`
	NoteSHA256  string `json:"noteSHA256"`
	OperationID string `json:"operationId"`
}

type Rule struct {
	Version       int     `json:"version"`
	DeploymentUID string  `json:"deploymentUID"`
	PolicyUID     string  `json:"policyUID"`
	SourceSHA256  string  `json:"sourceSHA256"`
	Revision      uint64  `json:"revision"`
	OperationID   string  `json:"operationId"`
	Entries       []Entry `json:"entries"`
}

func (r Rule) Bytes() []byte {
	// All values are ASCII by validation. encoding/json sorts map keys and emits
	// the same compact UTF-8 bytes as the Voice hook's sorted-key encoder.
	b, _ := json.Marshal(map[string]any{
		"version": r.Version, "deploymentUID": r.DeploymentUID,
		"policyUID": r.PolicyUID, "sourceSHA256": r.SourceSHA256,
		"revision": r.Revision, "operationId": r.OperationID, "entries": r.Entries,
	})
	return b
}

func (r Rule) SHA256() string {
	h := sha256.Sum256(r.Bytes())
	return hex.EncodeToString(h[:])
}

func ValidSHA(s string) bool    { return shaPattern.MatchString(s) }
func ValidUID(s string) bool    { return uidPattern.MatchString(s) }
func ValidCaller(s string) bool { return callerPattern.MatchString(s) }

func (r Rule) Valid() bool {
	if r.Version != 1 || !ValidUID(r.DeploymentUID) || !ValidUID(r.PolicyUID) || !ValidSHA(r.SourceSHA256) ||
		r.Revision > (1<<53)-1 || r.Entries == nil || len(r.Entries) > MaxEntries ||
		(r.Revision == 0 && (r.OperationID != "" || len(r.Entries) != 0)) ||
		(r.Revision > 0 && (!ValidSHA(r.OperationID) || len(r.Entries) == 0)) {
		return false
	}
	previous := ""
	latest := false
	for _, e := range r.Entries {
		if !ValidCaller(e.CallerID) || !ValidSHA(e.NoteSHA256) || !ValidSHA(e.OperationID) {
			return false
		}
		key := e.CallerID + "\x00" + e.NoteSHA256
		if previous != "" && key <= previous {
			return false
		}
		previous = key
		latest = latest || e.OperationID == r.OperationID
	}
	return r.Revision == 0 || latest
}

func Parse(raw string) (Rule, error) {
	var r Rule
	if len(raw) == 0 || len(raw) > 8192 || json.Unmarshal([]byte(raw), &r) != nil ||
		!r.Valid() || !bytes.Equal([]byte(raw), r.Bytes()) {
		return Rule{}, fmt.Errorf("voice memory rule invalid or noncanonical")
	}
	return r, nil
}

func Append(prior Rule, add Entry, operationID string) (Rule, error) {
	if !prior.Valid() || !ValidCaller(add.CallerID) || !ValidSHA(add.NoteSHA256) ||
		!ValidSHA(operationID) || len(prior.Entries) >= MaxEntries {
		return Rule{}, fmt.Errorf("voice memory quarantine capacity or identity invalid")
	}
	for _, old := range prior.Entries {
		if old.CallerID == add.CallerID && old.NoteSHA256 == add.NoteSHA256 {
			return Rule{}, fmt.Errorf("voice memory caller/note already quarantined")
		}
	}
	add.OperationID = operationID
	next := prior
	next.Revision++
	next.OperationID = operationID
	next.Entries = append(slices.Clone(prior.Entries), add)
	slices.SortFunc(next.Entries, func(a, b Entry) int {
		if a.CallerID < b.CallerID {
			return -1
		}
		if a.CallerID > b.CallerID {
			return 1
		}
		if a.NoteSHA256 < b.NoteSHA256 {
			return -1
		}
		if a.NoteSHA256 > b.NoteSHA256 {
			return 1
		}
		return 0
	})
	if !next.Valid() {
		return Rule{}, fmt.Errorf("voice memory appended rule invalid")
	}
	return next, nil
}
