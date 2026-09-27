package voiceoutputpolicy

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
	ConfigMapName = "voice-output-policy"
	RuleKey       = "rule.json"
	StatePath     = "/v1/voice-output-policy/state"
	MaxEntries    = 256
	MaxBytes      = 65536
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidSHA(s string) bool { return shaPattern.MatchString(s) }
func ValidUID(s string) bool { return uidPattern.MatchString(s) }

// The Python app emits sorted-key compact JSON. Entries are sorted by marker hash.
type Entry struct {
	MarkerSHA256 string `json:"markerSHA256"`
	OperationID  string `json:"operationId"`
}

type Rule struct {
	Version       int     `json:"version"`
	DeploymentUID string  `json:"deploymentUID"`
	ConfigMapUID  string  `json:"configMapUID"`
	PolicyUID     string  `json:"policyUID"`
	SourceSHA256  string  `json:"sourceSHA256"`
	Revision      uint64  `json:"revision"`
	OperationID   string  `json:"operationId"`
	Entries       []Entry `json:"entries"`
}

func (r Rule) Bytes() []byte {
	b, _ := json.Marshal(map[string]any{"version": r.Version, "deploymentUID": r.DeploymentUID, "configMapUID": r.ConfigMapUID,
		"policyUID": r.PolicyUID, "sourceSHA256": r.SourceSHA256, "revision": r.Revision,
		"operationId": r.OperationID, "entries": r.Entries})
	return b
}

func (r Rule) SHA256() string {
	h := sha256.Sum256(r.Bytes())
	return hex.EncodeToString(h[:])
}

func (r Rule) Valid() bool {
	if r.Version != 1 || !ValidUID(r.DeploymentUID) || !ValidUID(r.ConfigMapUID) || !ValidUID(r.PolicyUID) || !ValidSHA(r.SourceSHA256) ||
		r.Revision > (1<<53)-1 || r.Entries == nil || len(r.Entries) > MaxEntries || r.Revision != uint64(len(r.Entries)) ||
		(r.Revision == 0 && r.OperationID != "") || (r.Revision > 0 && !ValidSHA(r.OperationID)) {
		return false
	}
	previous, latest := "", false
	for _, e := range r.Entries {
		if !ValidSHA(e.MarkerSHA256) || !ValidSHA(e.OperationID) || (previous != "" && e.MarkerSHA256 <= previous) {
			return false
		}
		previous = e.MarkerSHA256
		latest = latest || e.OperationID == r.OperationID
	}
	return (r.Revision == 0 || latest) && len(r.Bytes()) <= MaxBytes
}

func Parse(raw string) (Rule, error) {
	var r Rule
	if len(raw) == 0 || len(raw) > MaxBytes || json.Unmarshal([]byte(raw), &r) != nil || !r.Valid() || !bytes.Equal([]byte(raw), r.Bytes()) {
		return Rule{}, fmt.Errorf("Voice output rule invalid or noncanonical")
	}
	return r, nil
}

func Append(prior Rule, markerSHA, operationID string) (Rule, error) {
	if !prior.Valid() || !ValidSHA(markerSHA) || !ValidSHA(operationID) || len(prior.Entries) >= MaxEntries || prior.Revision >= (1<<53)-1 {
		return Rule{}, fmt.Errorf("Voice output policy capacity or identity invalid")
	}
	for _, old := range prior.Entries {
		if old.MarkerSHA256 == markerSHA {
			return Rule{}, fmt.Errorf("Voice output marker already blocked")
		}
	}
	next := prior
	next.Revision++
	next.OperationID = operationID
	next.Entries = append(slices.Clone(prior.Entries), Entry{MarkerSHA256: markerSHA, OperationID: operationID})
	slices.SortFunc(next.Entries, func(a, b Entry) int {
		if a.MarkerSHA256 < b.MarkerSHA256 {
			return -1
		}
		if a.MarkerSHA256 > b.MarkerSHA256 {
			return 1
		}
		return 0
	})
	if !next.Valid() {
		return Rule{}, fmt.Errorf("Voice output appended rule invalid")
	}
	return next, nil
}
