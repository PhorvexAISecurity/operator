package voicemcppolicy

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
	ConfigMapName = "voice-mcp-tool-policy"
	RuleKey       = "rule.json"
	StatePath     = "/v1/voice-mcp-tool-policy/state"
	MaxBytes      = 8192
	MaxEntries    = 2

	StoreDirectory            = "store_directory"
	CheckPromotions           = "check_promotions"
	StoreDirectoryGoodSHA256  = "a4b965102419d4a81c4fd23cb3c93891f9932b8560b18bcd17f48aea81a337c8"
	CheckPromotionsGoodSHA256 = "d5439e3b030abc50693b18b92cf45788ca803fa2d430afcd5a25e3e89b0771e6"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidSHA(s string) bool { return shaPattern.MatchString(s) }
func ValidUID(s string) bool { return uidPattern.MatchString(s) }

func GoodDescriptorSHA256(tool string) string {
	switch tool {
	case StoreDirectory:
		return StoreDirectoryGoodSHA256
	case CheckPromotions:
		return CheckPromotionsGoodSHA256
	default:
		return ""
	}
}

// Entry's field order is the app's sorted-key canonical JSON order.
type Entry struct {
	GoodDescriptorSHA256 string `json:"goodDescriptorSHA256"`
	OperationID          string `json:"operationId"`
	ToolName             string `json:"toolName"`
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
		"version": r.Version, "deploymentUID": r.DeploymentUID,
		"policyUID": r.PolicyUID, "sourceSHA256": r.SourceSHA256,
		"revision": r.Revision, "operationId": r.OperationID,
		"entries": r.Entries,
	})
	return b
}

func (r Rule) SHA256() string {
	h := sha256.Sum256(r.Bytes())
	return hex.EncodeToString(h[:])
}

func (r Rule) Valid() bool {
	if r.Version != 1 || !ValidUID(r.DeploymentUID) || !ValidUID(r.PolicyUID) || !ValidSHA(r.SourceSHA256) ||
		r.Entries == nil || len(r.Entries) > MaxEntries || r.Revision > (1<<53)-1 || r.Revision != uint64(len(r.Entries)) ||
		(r.Revision == 0 && (r.OperationID != "" || len(r.Entries) != 0)) ||
		(r.Revision > 0 && !ValidSHA(r.OperationID)) {
		return false
	}
	previous := ""
	latest := false
	for _, e := range r.Entries {
		if e.ToolName <= previous || e.GoodDescriptorSHA256 != GoodDescriptorSHA256(e.ToolName) || !ValidSHA(e.OperationID) {
			return false
		}
		previous = e.ToolName
		latest = latest || e.OperationID == r.OperationID
	}
	return (r.Revision == 0 || latest) && len(r.Bytes()) <= MaxBytes
}

func Parse(raw string) (Rule, error) {
	var r Rule
	if len(raw) == 0 || len(raw) > MaxBytes || json.Unmarshal([]byte(raw), &r) != nil || !r.Valid() || !bytes.Equal([]byte(raw), r.Bytes()) {
		return Rule{}, fmt.Errorf("voice MCP rule invalid or noncanonical")
	}
	return r, nil
}

func Append(prior Rule, tool, operationID string) (Rule, error) {
	good := GoodDescriptorSHA256(tool)
	if !prior.Valid() || good == "" || !ValidSHA(operationID) || len(prior.Entries) >= MaxEntries || prior.Revision >= (1<<53)-1 {
		return Rule{}, fmt.Errorf("voice MCP tool pin capacity or identity invalid")
	}
	for _, old := range prior.Entries {
		if old.ToolName == tool {
			return Rule{}, fmt.Errorf("voice MCP tool already pinned")
		}
	}
	next := prior
	next.Revision++
	next.OperationID = operationID
	next.Entries = append(slices.Clone(prior.Entries), Entry{ToolName: tool, GoodDescriptorSHA256: good, OperationID: operationID})
	slices.SortFunc(next.Entries, func(a, b Entry) int {
		if a.ToolName < b.ToolName {
			return -1
		}
		if a.ToolName > b.ToolName {
			return 1
		}
		return 0
	})
	if !next.Valid() {
		return Rule{}, fmt.Errorf("voice MCP tool pin invalid")
	}
	return next, nil
}
