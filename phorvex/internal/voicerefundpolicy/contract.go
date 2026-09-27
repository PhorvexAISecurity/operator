package voicerefundpolicy

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
	ConfigMapName = "voice-refund-policy"
	RuleKey       = "rule.json"
	StatePath     = "/v1/voice-refund-policy/state"
	MaxEntries    = 256
	MaxBytes      = 65536
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidSHA(s string) bool { return shaPattern.MatchString(s) }
func ValidUID(s string) bool { return uidPattern.MatchString(s) }

// Field order is the Python app's sorted-key JSON order, including nested entries.
type Entry struct {
	AssertedCallerSHA256 string `json:"assertedCallerSHA256"`
	OperationID          string `json:"operationId"`
	OrderSHA256          string `json:"orderSHA256"`
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
	b, _ := json.Marshal(map[string]any{
		"version": r.Version, "deploymentUID": r.DeploymentUID, "policyUID": r.PolicyUID,
		"sourceSHA256": r.SourceSHA256, "revision": r.Revision,
		"operationId": r.OperationID, "entries": r.Entries,
	})
	return b
}

func (r Rule) SHA256() string {
	h := sha256.Sum256(r.Bytes())
	return hex.EncodeToString(h[:])
}

func (r Rule) Valid() bool {
	if r.Version != 1 || !ValidUID(r.DeploymentUID) || !ValidUID(r.PolicyUID) || !ValidSHA(r.SourceSHA256) ||
		r.Revision > (1<<53)-1 || r.Entries == nil || len(r.Entries) > MaxEntries || r.Revision != uint64(len(r.Entries)) ||
		(r.Revision == 0 && (r.OperationID != "" || len(r.Entries) != 0)) ||
		(r.Revision > 0 && (!ValidSHA(r.OperationID) || len(r.Entries) == 0)) {
		return false
	}
	previous := ""
	latest := false
	for _, e := range r.Entries {
		if !ValidSHA(e.AssertedCallerSHA256) || !ValidSHA(e.OrderSHA256) || !ValidSHA(e.OperationID) {
			return false
		}
		key := e.AssertedCallerSHA256 + "\x00" + e.OrderSHA256
		if previous != "" && key <= previous {
			return false
		}
		previous = key
		latest = latest || e.OperationID == r.OperationID
	}
	return (r.Revision == 0 || latest) && len(r.Bytes()) <= MaxBytes
}

func Parse(raw string) (Rule, error) {
	var r Rule
	if len(raw) == 0 || len(raw) > MaxBytes || json.Unmarshal([]byte(raw), &r) != nil || !r.Valid() || !bytes.Equal([]byte(raw), r.Bytes()) {
		return Rule{}, fmt.Errorf("voice refund rule invalid or noncanonical")
	}
	return r, nil
}

func Append(prior Rule, add Entry, operationID string) (Rule, error) {
	if !prior.Valid() || !ValidSHA(add.AssertedCallerSHA256) || !ValidSHA(add.OrderSHA256) ||
		!ValidSHA(operationID) || len(prior.Entries) >= MaxEntries || prior.Revision >= (1<<53)-1 {
		return Rule{}, fmt.Errorf("voice refund policy capacity or identity invalid")
	}
	for _, old := range prior.Entries {
		if old.AssertedCallerSHA256 == add.AssertedCallerSHA256 && old.OrderSHA256 == add.OrderSHA256 {
			return Rule{}, fmt.Errorf("voice refund pair already denied")
		}
	}
	add.OperationID = operationID
	next := prior
	next.Revision++
	next.OperationID = operationID
	next.Entries = append(slices.Clone(prior.Entries), add)
	slices.SortFunc(next.Entries, func(a, b Entry) int {
		if a.AssertedCallerSHA256 < b.AssertedCallerSHA256 {
			return -1
		}
		if a.AssertedCallerSHA256 > b.AssertedCallerSHA256 {
			return 1
		}
		if a.OrderSHA256 < b.OrderSHA256 {
			return -1
		}
		if a.OrderSHA256 > b.OrderSHA256 {
			return 1
		}
		return 0
	})
	if !next.Valid() {
		return Rule{}, fmt.Errorf("voice refund appended rule invalid")
	}
	return next, nil
}
