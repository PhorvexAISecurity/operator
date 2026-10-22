package voiceadmissionpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/phorvex/phorvex/internal/eventtrust"
)

type Receipt struct {
	Version                int     `json:"version"`
	Phase                  string  `json:"phase"`
	PolicyName             string  `json:"policyName"`
	PolicyUID              string  `json:"policyUID"`
	PolicyGeneration       int64   `json:"policyGeneration"`
	DeploymentUID          string  `json:"deploymentUID"`
	TargetName             string  `json:"targetName"`
	TargetPodUID           string  `json:"targetPodUID"`
	EventName              string  `json:"eventName"`
	EventUID               string  `json:"eventUID"`
	CreatorIdentity        string  `json:"creatorIdentity"`
	TickID                 string  `json:"tickId"`
	SelectionDecisionID    string  `json:"selectionDecisionId"`
	ConfigMapUID           string  `json:"configMapUID"`
	SourceConfigMapUID     string  `json:"sourceConfigMapUID"`
	SessionID              string  `json:"sessionID"`
	RunSHA256              string  `json:"runSHA256"`
	ReceiptSHA256          string  `json:"receiptSHA256"`
	ProviderEvidenceSHA256 string  `json:"providerEvidenceSHA256"`
	Prior                  Rule    `json:"prior"`
	Desired                Rule    `json:"desired"`
	OperationID            string  `json:"operationId"`
	PodReceipts            []State `json:"podReceipts"`
}
type Journal struct {
	Receipts []Receipt `json:"receipts"`
	Version  int       `json:"version"`
}

func (j Journal) Bytes() []byte { return CanonicalBytes(j) }
func ParseJournal(raw string) (Journal, error) {
	var j Journal
	if len(raw) == 0 || len(raw) > 262144 || json.Unmarshal([]byte(raw), &j) != nil || j.Version != 1 || j.Receipts == nil || len(j.Receipts) > 1 || !bytes.Equal([]byte(raw), j.Bytes()) {
		return Journal{}, errors.New("Voice admission protected journal noncanonical or invalid")
	}
	for _, r := range j.Receipts {
		op, e := OperationID(r.DeploymentUID, r.ConfigMapUID, r.PolicyUID, r.PolicyGeneration, r.EventUID, r.TickID, r.SelectionDecisionID, r.Prior.SHA256())
		next, ne := Enforce(r.Prior, r.OperationID)
		if r.Version != 1 || (r.Phase != "prepared" && r.Phase != "terminal-full") || r.PolicyName == "" || r.TargetName == "" || !ValidUID(r.TargetPodUID) || r.EventName == "" || r.CreatorIdentity != eventtrust.Injector() || !ValidUID(r.SourceConfigMapUID) || !ValidUID(r.SessionID) || !ValidSHA(r.RunSHA256) || !ValidSHA(r.ReceiptSHA256) || !ValidSHA(r.ProviderEvidenceSHA256) || e != nil || op != r.OperationID || ne != nil || !bytes.Equal(next.Bytes(), r.Desired.Bytes()) || r.Prior.DeploymentUID != r.DeploymentUID || r.Prior.SecurityPolicyUID != r.PolicyUID || r.Prior.WrapperCMUID != r.SourceConfigMapUID || r.PodReceipts == nil {
			return Journal{}, errors.New("Voice admission protected receipt authority invalid")
		}
		if r.Phase == "prepared" && len(r.PodReceipts) != 0 || r.Phase == "terminal-full" && (len(r.PodReceipts) == 0 || len(r.PodReceipts) > 128) {
			return Journal{}, errors.New("Voice admission protected barrier receipt invalid")
		}
		seen := map[string]bool{}
		rv := ""
		for _, s := range r.PodReceipts {
			parsed, e := ParseState(CanonicalBytes(s))
			if e != nil || !parsed.Settled || seen[s.PodUID] || (rv != "" && rv != s.PolicyResourceVersion) || s.DeploymentUID != r.DeploymentUID || s.PolicyCMUID != r.ConfigMapUID || s.RuleSHA256 != r.Desired.SHA256() || s.Revision != r.Desired.Revision || s.OperationID != r.OperationID || s.AdmissionSourceSHA256 != r.Desired.AdmissionSourceSHA256 || s.LegacyBundleSHA256 != r.Desired.LegacyBundleSHA256 || s.AuthProfileSHA256 != r.Desired.AuthProfileSHA256 {
				return Journal{}, errors.New("Voice admission protected serving receipt invalid")
			}
			seen[s.PodUID] = true
			rv = s.PolicyResourceVersion
		}
		if r.Phase == "terminal-full" && !seen[r.TargetPodUID] {
			return Journal{}, errors.New("Voice admission terminal target absent from barrier")
		}
	}
	return j, nil
}
