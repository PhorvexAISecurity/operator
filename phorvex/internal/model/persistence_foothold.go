package model

import "time"

// PersistenceFootholdObservation identifies the one fresh, trusted detector assertion
// that authorizes whole-owner removal (controller-stop) of an attacker-created
// controller. It is the controller-scoped analogue of AdapterObservation. The binding
// is to the OWNER (controller) UID, not merely a Pod UID, because the end-state is
// "owner no longer recreating". The authority assertions are deliberately explicit and
// falsifiable:
//   - Unmanaged: the owner has no GitOps/Helm/operator provenance (created directly).
//   - NoLegitimateServiceRole: no legitimate Service's ready-member floor depends on it.
//   - OwnerDeclaredMinAvailable: the owner's OWN declared availability guarantee. An
//     unmanaged attacker owner declares none (PDB absent) => 0. This is the floor the
//     controller-removal-authority feasibility law evaluates against — NOT the shared
//     tenant MinAvailableReplicas, which still gates rotate/quarantine on every Pod.
//   - ObservedRecreation: child Pods re-appeared after a prior removal within the
//     detector's window — the active-persistence signal that distinguishes a durable
//     foothold from a one-shot Pod.
//
// Conflicting/again-UID-mismatched assertions suppress it (HasBoundPersistenceObservation).
// NOTE: this is deliberately NOT the unrelated model.PersistenceObservation type.
type PersistenceFootholdObservation struct {
	TargetPodUID              string    `json:"targetPodUID"`
	RemovedPodUID             string    `json:"removedPodUID"`
	ReplacementPodUID         string    `json:"replacementPodUID"`
	ObservedAt                time.Time `json:"observedAt"`
	Replicas                  int       `json:"replicas"`
	EventName                 string    `json:"eventName"`
	EventUID                  string    `json:"eventUID"`
	CreatorIdentity           string    `json:"creatorIdentity"`
	ControllerTargetUID       string    `json:"controllerTargetUID"`
	ControllerName            string    `json:"controllerName"`
	OwnerKind                 string    `json:"ownerKind"`
	Namespace                 string    `json:"namespace"`
	OwnerDeclaredMinAvailable int       `json:"ownerDeclaredMinAvailable"`
	Unmanaged                 bool      `json:"unmanaged"`
	NoLegitimateServiceRole   bool      `json:"noLegitimateServiceRole"`
	ObservedRecreation        bool      `json:"observedRecreation"`
	PolicyName                string    `json:"policyName"`
	PolicyUID                 string    `json:"policyUID"`
	PolicyGeneration          int64     `json:"policyGeneration"`
	CreatedAt                 time.Time `json:"createdAt"`
}

// HasBoundPersistenceObservation is the narrow detector authority for controller
// removal. It binds the assertion to this Pod's exact controller UID, requires the
// unmanaged + no-legitimate-serving-role + zero-declared-floor + observed-recreation
// assertions, and requires the authenticated event identity. Absent any of these the
// controller-removal-authority feasibility law refuses controller-stop and the
// persistence recon fact is not minted.
func (p Pod) HasBoundPersistenceObservation() bool {
	o := p.PersistenceFootholdObservation
	return o != nil && p.UID != "" && p.SuspectController != "" && p.ControllerUID != "" &&
		o.ControllerTargetUID == p.PersistenceOwnerUID() && o.ControllerName == p.SuspectController &&
		o.Namespace == p.Namespace && (o.OwnerKind == "Deployment" || o.OwnerKind == "ReplicaSet" || o.OwnerKind == "StatefulSet") &&
		o.TargetPodUID == p.UID && o.RemovedPodUID != "" && o.ReplacementPodUID != "" && o.RemovedPodUID != o.ReplacementPodUID && !o.ObservedAt.IsZero() && o.Replicas > 0 &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
		o.Unmanaged && o.NoLegitimateServiceRole && o.ObservedRecreation &&
		o.OwnerDeclaredMinAvailable == 0 &&
		o.PolicyName != "" && o.PolicyUID != "" && o.PolicyGeneration > 0 && !o.CreatedAt.IsZero()
}

// PersistenceOwnerUID is separate from the immediate controller used by capacity.
func (p Pod) PersistenceOwnerUID() string {
	if p.PersistenceControllerUID != "" {
		return p.PersistenceControllerUID
	}
	return p.ControllerUID
}

// ControllerStopReceipt records bounded native absence, never permanent erasure.
type ControllerStopChild struct {
	Name               string `json:"name"`
	UID                string `json:"uid"`
	DeleteAcknowledged bool   `json:"deleteAcknowledged"`
	Absent404          bool   `json:"absent404"`
}

type ControllerStopReceipt struct {
	OperationID          string                `json:"operationID"`
	PolicyUID            string                `json:"policyUID"`
	PolicyGeneration     int64                 `json:"policyGeneration"`
	EventUID             string                `json:"eventUID"`
	Namespace            string                `json:"namespace"`
	OwnerKind            string                `json:"ownerKind"`
	OwnerName            string                `json:"ownerName"`
	OwnerUID             string                `json:"ownerUID"`
	StartedAt            time.Time             `json:"startedAt"`
	ScaleAcknowledged    bool                  `json:"scaleAcknowledged"`
	Children             []ControllerStopChild `json:"children"`
	Samples              int                   `json:"samples"`
	LastObservedAt       time.Time             `json:"lastObservedAt"`
	AbsentSince          time.Time             `json:"absentSince"`
	ObservationWindow    time.Duration         `json:"observationWindow"`
	NoRecreationObserved bool                  `json:"noRecreationObserved"`
}

func CloneControllerStopReceipt(in *ControllerStopReceipt) *ControllerStopReceipt {
	if in == nil {
		return nil
	}
	out := *in
	out.Children = append([]ControllerStopChild(nil), in.Children...)
	return &out
}
