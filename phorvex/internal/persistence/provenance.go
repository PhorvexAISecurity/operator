package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ProvenanceName is deliberately separate from the GitOps-managed inventory.
// The supervisor owns finite CREATE attestations; chart reconciliation cannot erase them.
const ProvenanceName = "phorvex-persistence-provenance"

const OptInLabel = "phorvex.ai/persistence-opt-in"

var authority struct {
	sync.RWMutex
	identity   string
	operatorNS string
	namespaces map[string]bool
}

// ConfigureAuthority is separate from general detector trust. Empty configuration
// disables removal and gives this identity no general-purpose belief authority.
func ConfigureAuthority(identity string, namespaces []string, operatorNamespace ...string) {
	authority.Lock()
	defer authority.Unlock()
	authority.identity = identity
	authority.operatorNS = ""
	parts := strings.Split(identity, ":")
	if len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
		authority.operatorNS = parts[2]
	}
	if len(operatorNamespace) > 0 && operatorNamespace[0] != "" {
		authority.operatorNS = operatorNamespace[0]
	}
	authority.namespaces = map[string]bool{}
	for _, ns := range namespaces {
		if ns != "" {
			authority.namespaces[ns] = true
		}
	}
}
func ObserverAllowed(identity, namespace string) bool {
	authority.RLock()
	defer authority.RUnlock()
	return identity != "" && identity == authority.identity && authority.namespaces[namespace]
}
func ProvenanceNamespace() string {
	authority.RLock()
	defer authority.RUnlock()
	return authority.operatorNS
}
func IsObserver(identity string) bool {
	authority.RLock()
	defer authority.RUnlock()
	return identity != "" && identity == authority.identity
}

// AttackerProvenance is an operator-protected positive attestation of an exact
// controller CREATE by the exercise attacker. It is NOT controller metadata or an
// inventory exclusion. Only the operator may publish these records, after checking
// the authenticated CREATE audit/admission receipt or owned exercise CREATE receipt.
// The observer has GET only and this code reads only; the workload/attacker has
// no write grant. The operator principal remains trusted (its existing journal
// Role already permits ConfigMap writes in the operator namespace).
// Unknown controllers, including ordinary kubectl-create workloads, have no record.
type AttackerProvenance struct {
	Namespace       string    `json:"namespace"`
	NamespaceUID    string    `json:"namespaceUID"`
	Kind            string    `json:"kind"`
	Name            string    `json:"name"`
	ControllerUID   string    `json:"controllerUID"`
	CreatorIdentity string    `json:"creatorIdentity"`
	EvidenceID      string    `json:"evidenceID"`
	EvidenceKind    string    `json:"evidenceKind"`
	OperationID     string    `json:"operationID"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// CheckAttackerProvenance retains the original rejection contract.
func CheckAttackerProvenance(ctx context.Context, r client.Reader, operatorNS string, o Owner) error {
	_, err := ReadAttackerProvenance(ctx, r, operatorNS, o)
	return err
}

// ReadAttackerProvenance returns only the exact record accepted by the same guards.
func ReadAttackerProvenance(ctx context.Context, r client.Reader, operatorNS string, o Owner) (AttackerProvenance, error) {
	if r == nil || operatorNS == "" {
		return AttackerProvenance{}, fmt.Errorf("protected attacker provenance namespace unavailable")
	}
	var ns corev1.Namespace
	if err := r.Get(ctx, client.ObjectKey{Name: o.Object.GetNamespace()}, &ns); err != nil {
		return AttackerProvenance{}, err
	}
	operation := ns.Labels[OptInLabel]
	if operation == "" || ns.UID == "" || ns.DeletionTimestamp != nil {
		return AttackerProvenance{}, fmt.Errorf("namespace has no explicit persistence opt-in")
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, client.ObjectKey{Namespace: operatorNS, Name: ProvenanceName}, &cm); err != nil {
		return AttackerProvenance{}, err
	}
	if cm.DeletionTimestamp != nil {
		return AttackerProvenance{}, fmt.Errorf("positive attacker provenance is being revoked")
	}
	records := map[string]AttackerProvenance{}
	if err := json.Unmarshal([]byte(cm.Data["attacker-provenance.json"]), &records); err != nil {
		return AttackerProvenance{}, fmt.Errorf("positive attacker provenance unavailable: %w", err)
	}
	a, ok := records[string(o.Object.GetUID())]
	now := time.Now()
	if !ok || a.ControllerUID != string(o.Object.GetUID()) || a.Namespace != ns.Name || a.NamespaceUID != string(ns.UID) || a.Kind != o.Kind || a.Name != o.Object.GetName() || a.OperationID != operation ||
		a.CreatorIdentity == "" || a.EvidenceID == "" ||
		(a.EvidenceKind != "authenticated-create" && a.EvidenceKind != "owned-exercise-create") || !now.Before(a.ExpiresAt) || a.ExpiresAt.Sub(now) > Horizon {
		return AttackerProvenance{}, fmt.Errorf("positive UID-bound attacker CREATE provenance absent, expired or mismatched")
	}
	return a, nil
}
