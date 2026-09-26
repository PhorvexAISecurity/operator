package outputpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	RuleID                  = "support-internal-audit-marker-v1"
	Route                   = "/v1/support/case"
	RuleKey                 = "rule.json"
	ActivationKey           = "activation.json"
	PodConfigMapAnnotation  = "phorvex.ai/output-policy-configmap"
	PodRuleSHAAnnotation    = "phorvex.ai/output-policy-rule-sha256"
	PodProxySHAAnnotation   = "phorvex.ai/output-proxy-source-sha256"
	PodSupportSHAAnnotation = "phorvex.ai/output-support-source-sha256"
	EventAnnotation         = "phorvex.ai/sensitive-output-observation-v1"
	JournalLabel            = "phorvex.ai/output-policy-journal"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var operationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// RuleBytes is the single fixed response-field rule; Go's map encoding sorts
// keys lexicographically, matching the proxy's compact sorted-key encoding.
func RuleBytes(podUID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"version": 1, "ruleId": RuleID, "podUID": podUID,
		"method": "POST", "path": Route, "contentType": "application/json",
		"fieldPath":        []string{"diagnostics", "internalAuditMarker"},
		"maxResponseBytes": 65536,
	})
	return b
}

func RuleSHA256(podUID string) string {
	sum := sha256.Sum256(RuleBytes(podUID))
	return hex.EncodeToString(sum[:])
}

type Activation struct {
	Version      int    `json:"version"`
	RuleID       string `json:"ruleId"`
	ConfigMapUID string `json:"configMapUID"`
	Active       bool   `json:"active"`
	Revision     uint64 `json:"revision"`
	OperationID  string `json:"operationId"`
}

func (a Activation) Bytes() []byte {
	b, _ := json.Marshal(map[string]any{
		"version": a.Version, "ruleId": a.RuleID, "configMapUID": a.ConfigMapUID,
		"active": a.Active, "revision": a.Revision, "operationId": a.OperationID,
	})
	return b
}

func ParseActivation(raw string, uid string) (Activation, error) {
	var a Activation
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal([]byte(raw), &a) != nil ||
		!bytes.Equal([]byte(raw), a.Bytes()) || a.Version != 1 || a.RuleID != RuleID ||
		!uidPattern.MatchString(a.ConfigMapUID) || a.ConfigMapUID != uid || a.Revision >= 1<<63 ||
		(a.OperationID != "" && !ValidOperationID(a.OperationID)) ||
		(a.Revision == 0 && (a.Active || a.OperationID != "")) ||
		(a.Revision > 0 && a.OperationID == "") {
		return Activation{}, fmt.Errorf("output policy activation invalid or noncanonical")
	}
	return a, nil
}

func ValidSHA(s string) bool { return shaPattern.MatchString(s) }

// ValidateConfigMap rejects a copied rule, stale Pod binding or changed rule
// bytes. The activation state alone is mutable after owner provisioning.
func ValidateConfigMap(cm *corev1.ConfigMap, pod *corev1.Pod) (Activation, error) {
	if cm == nil || pod == nil || cm.Namespace != pod.Namespace ||
		cm.Name != pod.Annotations[PodConfigMapAnnotation] || cm.Name != "phorvex-output-policy-"+pod.Name ||
		cm.UID == "" || cm.ResourceVersion == "" || pod.UID == "" ||
		cm.DeletionTimestamp != nil || pod.DeletionTimestamp != nil {
		return Activation{}, fmt.Errorf("output policy ConfigMap/Pod identity mismatch")
	}
	owner := metav1.GetControllerOf(cm)
	if owner == nil || owner.Kind != "Pod" || owner.APIVersion != "v1" || owner.Name != pod.Name || owner.UID != pod.UID {
		return Activation{}, fmt.Errorf("output policy ConfigMap is not controlled by exact Pod")
	}
	if len(cm.Data) != 2 || cm.Data[RuleKey] != string(RuleBytes(string(pod.UID))) ||
		pod.Annotations[PodRuleSHAAnnotation] != RuleSHA256(string(pod.UID)) ||
		!ValidSHA(pod.Annotations[PodProxySHAAnnotation]) || !ValidSHA(pod.Annotations[PodSupportSHAAnnotation]) {
		return Activation{}, fmt.Errorf("output policy rule or source binding mismatch")
	}
	return ParseActivation(cm.Data[ActivationKey], string(cm.UID))
}

func JournalName(podUID string) string {
	sum := sha256.Sum256([]byte(podUID))
	return "phorvex-output-" + hex.EncodeToString(sum[:16])
}

func ValidOperationID(id string) bool {
	return operationPattern.MatchString(id)
}
