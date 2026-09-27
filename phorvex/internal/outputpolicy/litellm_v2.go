package outputpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LiteNamespace             = "litellm"
	LitePolicyConfigMap       = "litellm-output-policy"
	LitePolicyKey             = "policy.json"
	LiteRuleKey               = "rule.json"
	LiteRulePrefix            = "litellm-output-rule-"
	LiteDocumentObjective     = "ai2-sensitive-info-disclosure"
	LitePromptObjective       = "ai2-system-prompt-leakage"
	LiteDocumentSecret        = "phorvex-litellm-output-document"
	LitePromptSecret          = "phorvex-litellm-output-prompt"
	LiteObservationAnnotation = "phorvex.ai/sensitive-output-observation-v2"
	LiteJournalLabel          = "phorvex.ai/litellm-output-policy-journal"
	LiteJournalName           = "phorvex-litellm-output-journal"
	LiteJournalKey            = "receipts.json"
	LiteMaxEntries            = 32
	LiteMaxJournalBytes       = 900 * 1024
)

var liteNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)
var liteRuleSlot = regexp.MustCompile(`^litellm-output-rule-(0[0-9]|[12][0-9]|3[01])$`)

func LiteObjectiveSecret(id string) string {
	switch id {
	case LiteDocumentObjective:
		return LiteDocumentSecret
	case LitePromptObjective:
		return LitePromptSecret
	default:
		return ""
	}
}

func LiteRuleSlotName(index int) string {
	if index < 0 || index >= LiteMaxEntries {
		return ""
	}
	return LiteRulePrefix + string([]byte{'0' + byte(index/10), '0' + byte(index%10)})
}

func LiteValidRuleSlotName(name string) bool { return liteRuleSlot.MatchString(name) }

func LiteSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

type LiteRule struct {
	Version           int    `json:"version"`
	ObjectiveID       string `json:"objectiveId"`
	RunNonce          string `json:"runNonce"`
	Method            string `json:"method"`
	Path              string `json:"path"`
	FieldPath         []any  `json:"fieldPath"`
	MaxResponseBytes  int    `json:"maxResponseBytes"`
	ProtectedSHA256   string `json:"protectedSHA256"`
	SourceSHA256      string `json:"sourceSHA256"`
	ServiceUID        string `json:"serviceUID"`
	DeploymentUID     string `json:"deploymentUID"`
	TargetPodUID      string `json:"targetPodUID"`
	PeerPodUID        string `json:"peerPodUID"`
	ContextSecretUID  string `json:"contextSecretUID"`
	ContextSeedSHA256 string `json:"contextSeedSHA256"`
}

// LiteCanonicalJSON uses the same recursively sorted-key encoding as the
// gateway and console. json.Number keeps integer identities exact.
func LiteCanonicalJSON(value any) []byte {
	raw, _ := json.Marshal(value)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	_ = dec.Decode(&tree)
	canonical, _ := json.Marshal(tree)
	return canonical
}

func (r LiteRule) Bytes() []byte  { return LiteCanonicalJSON(r) }
func (r LiteRule) SHA256() string { return LiteSHA(r.Bytes()) }

func ParseLiteRule(raw string) (LiteRule, error) {
	var r LiteRule
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal([]byte(raw), &r) != nil || !bytes.Equal([]byte(raw), r.Bytes()) ||
		r.Version != 2 || LiteObjectiveSecret(r.ObjectiveID) == "" || !liteNonce.MatchString(r.RunNonce) ||
		r.Method != "POST" || r.Path != "/v1/chat/completions" || r.MaxResponseBytes != 131072 ||
		len(r.FieldPath) != 4 || r.FieldPath[0] != "choices" || r.FieldPath[1] != float64(0) || r.FieldPath[2] != "message" || r.FieldPath[3] != "content" ||
		!ValidSHA(r.ProtectedSHA256) || !ValidSHA(r.SourceSHA256) || !ValidSHA(r.ContextSeedSHA256) ||
		r.ServiceUID == "" || r.DeploymentUID == "" || r.TargetPodUID == "" || r.PeerPodUID == "" || r.TargetPodUID == r.PeerPodUID || r.ContextSecretUID == "" {
		return LiteRule{}, errors.New("LiteLLM output rule invalid or noncanonical")
	}
	return r, nil
}

type LiteEntry struct {
	ObjectiveID       string `json:"objectiveId"`
	RunNonce          string `json:"runNonce"`
	RuleSHA256        string `json:"ruleSHA256"`
	ProtectedSHA256   string `json:"protectedSHA256"`
	OperationID       string `json:"operationId"`
	ServiceUID        string `json:"serviceUID"`
	DeploymentUID     string `json:"deploymentUID"`
	TargetPodUID      string `json:"targetPodUID"`
	PeerPodUID        string `json:"peerPodUID"`
	SourceSHA256      string `json:"sourceSHA256"`
	ContextSecretUID  string `json:"contextSecretUID"`
	ContextSeedSHA256 string `json:"contextSeedSHA256"`
}

func (e LiteEntry) Key() string { return e.ObjectiveID + "/" + e.RunNonce }
func (e LiteEntry) Matches(r LiteRule) bool {
	return e.ObjectiveID == r.ObjectiveID && e.RunNonce == r.RunNonce && e.RuleSHA256 == r.SHA256() &&
		e.ProtectedSHA256 == r.ProtectedSHA256 && e.ServiceUID == r.ServiceUID && e.DeploymentUID == r.DeploymentUID &&
		e.TargetPodUID == r.TargetPodUID && e.PeerPodUID == r.PeerPodUID && e.SourceSHA256 == r.SourceSHA256 &&
		e.ContextSecretUID == r.ContextSecretUID && e.ContextSeedSHA256 == r.ContextSeedSHA256 && ValidOperationID(e.OperationID)
}

type LiteState struct {
	Entries  []LiteEntry `json:"entries"`
	Revision uint64      `json:"revision"`
	Version  int         `json:"version"`
}

func (s LiteState) Bytes() []byte { return LiteCanonicalJSON(s) }

func ParseLiteState(raw string) (LiteState, error) {
	var s LiteState
	if len(raw) == 0 || len(raw) > 65536 || json.Unmarshal([]byte(raw), &s) != nil || !bytes.Equal([]byte(raw), s.Bytes()) ||
		s.Version != 2 || s.Entries == nil || len(s.Entries) > LiteMaxEntries || s.Revision != uint64(len(s.Entries)) {
		return LiteState{}, errors.New("LiteLLM output policy invalid or noncanonical")
	}
	prev := ""
	seenOp := map[string]bool{}
	for _, e := range s.Entries {
		if LiteObjectiveSecret(e.ObjectiveID) == "" || !liteNonce.MatchString(e.RunNonce) || e.Key() <= prev ||
			!ValidSHA(e.RuleSHA256) || !ValidSHA(e.ProtectedSHA256) || !ValidSHA(e.SourceSHA256) || !ValidSHA(e.ContextSeedSHA256) ||
			!ValidOperationID(e.OperationID) || seenOp[e.OperationID] || e.ServiceUID == "" || e.DeploymentUID == "" ||
			e.TargetPodUID == "" || e.PeerPodUID == "" || e.TargetPodUID == e.PeerPodUID || e.ContextSecretUID == "" {
			return LiteState{}, errors.New("LiteLLM output policy entry invalid")
		}
		prev = e.Key()
		seenOp[e.OperationID] = true
	}
	return s, nil
}

func (s LiteState) Append(e LiteEntry) (LiteState, error) {
	if len(s.Entries) >= LiteMaxEntries {
		return LiteState{}, errors.New("LiteLLM output policy full")
	}
	next := LiteState{Version: 2, Revision: s.Revision + 1, Entries: append(append([]LiteEntry(nil), s.Entries...), e)}
	sort.Slice(next.Entries, func(i, j int) bool { return next.Entries[i].Key() < next.Entries[j].Key() })
	if _, err := ParseLiteState(string(next.Bytes())); err != nil {
		return LiteState{}, err
	}
	return next, nil
}

func LiteOwner(cm *corev1.ConfigMap, deploymentUID string) bool {
	if cm == nil || cm.DeletionTimestamp != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.Namespace != LiteNamespace || len(cm.BinaryData) != 0 {
		return false
	}
	o := metav1.GetControllerOf(cm)
	return o != nil && o.APIVersion == "apps/v1" && o.Kind == "Deployment" && o.Name == "litellm" && string(o.UID) == deploymentUID
}

// LiteObservation is a digest-only assertion by the installed console. The
// SecurityEvent's stamped creator and the live Kubernetes objects remain the
// authority; parsing this object alone never licenses an action.
type LiteObservation struct {
	Version                  int       `json:"version"`
	ObjectiveID              string    `json:"objectiveId"`
	RunNonce                 string    `json:"runNonce"`
	RuleSHA256               string    `json:"ruleSHA256"`
	ProtectedSHA256          string    `json:"protectedSHA256"`
	SourceSHA256             string    `json:"sourceSHA256"`
	RuleConfigMapName        string    `json:"ruleConfigMapName"`
	RuleConfigMapUID         string    `json:"ruleConfigMapUID"`
	PolicyConfigMapUID       string    `json:"policyConfigMapUID"`
	ServiceUID               string    `json:"serviceUID"`
	DeploymentUID            string    `json:"deploymentUID"`
	TargetPodUID             string    `json:"targetPodUID"`
	PeerPodUID               string    `json:"peerPodUID"`
	ContextSecretUID         string    `json:"contextSecretUID"`
	ContextSeedSHA256        string    `json:"contextSeedSHA256"`
	PolicyName               string    `json:"policyName"`
	PolicyUID                string    `json:"policyUID"`
	PolicyGeneration         int64     `json:"policyGeneration"`
	RequestSHA256            string    `json:"requestSHA256"`
	OriginalCompletionSHA256 string    `json:"originalCompletionSHA256"`
	ObservedAt               time.Time `json:"observedAt"`
}

func (o LiteObservation) Bytes() []byte { return LiteCanonicalJSON(o) }

func ParseLiteObservation(raw string) (LiteObservation, error) {
	var o LiteObservation
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal([]byte(raw), &o) != nil || !bytes.Equal([]byte(raw), o.Bytes()) ||
		o.Version != 2 || LiteObjectiveSecret(o.ObjectiveID) == "" || !liteNonce.MatchString(o.RunNonce) ||
		!ValidSHA(o.RuleSHA256) || !ValidSHA(o.ProtectedSHA256) || !ValidSHA(o.SourceSHA256) ||
		!ValidSHA(o.ContextSeedSHA256) || !ValidSHA(o.RequestSHA256) || !ValidSHA(o.OriginalCompletionSHA256) ||
		!LiteValidRuleSlotName(o.RuleConfigMapName) || o.RuleConfigMapUID == "" || o.PolicyConfigMapUID == "" || o.ServiceUID == "" || o.DeploymentUID == "" ||
		o.TargetPodUID == "" || o.PeerPodUID == "" || o.TargetPodUID == o.PeerPodUID || o.ContextSecretUID == "" ||
		o.PolicyName != "litellm-defense" || o.PolicyUID == "" || o.PolicyGeneration < 1 || o.ObservedAt.IsZero() {
		return LiteObservation{}, errors.New("LiteLLM output observation invalid or noncanonical")
	}
	return o, nil
}
