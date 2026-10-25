package ingest

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/persistence"
)

// bindPersistenceObservation grants the controller-stop candidate authority for one fresh
// event that is (a) generally trusted — its creator-identity was admission-stamped and is in
// the detector allowlist — AND (b) the dedicated, namespace-scoped persistence observer
// (persistence.ObserverAllowed, a separate authority channel from general detector trust),
// bound to THIS Pod's exact owner UID. The owner must additionally carry a positive,
// operator-protected attacker-CREATE attestation (CheckAttackerProvenance): generic Pod drift
// or an ordinary workload is never authority to remove a whole owner. The selecting policy
// epoch must be current and still enable controller-stop. Any competing/again-UID-mismatched
// assertion suppresses the observation. The authoritative re-check runs again at enact time in
// validateControllerStop + persistence.CheckSafety.
func bindPersistenceObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.SuspectController = ""
	p.PersistenceFootholdObservation = nil
	p.PersistenceControllerUID = ""
	if reader == nil || p.UID == "" || p.Namespace == "" {
		return
	}
	// Any trusted persistence candidate at all? (Cheap read-free filter before any Get.)
	hasCandidate := false
	for i := range events {
		e := &events[i]
		if e.Trust == eventtrust.TrustTrusted && e.TargetsPod && e.Type == model.AttackVectorControllerPersistence &&
			persistence.ObserverAllowed(e.CreatorIdentity, p.Namespace) && e.ConsoleTargetPodUID == p.UID {
			hasCandidate = true
			break
		}
	}
	if !hasCandidate {
		return
	}

	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, pod); err != nil || string(pod.UID) != p.UID || pod.DeletionTimestamp != nil {
		return
	}
	owner, err := persistence.ResolvePodOwner(ctx, reader, pod)
	if err != nil {
		return
	}
	ownerUID := string(owner.Object.GetUID())
	// Positive, operator-protected attacker-CREATE attestation for THIS exact owner. Absent,
	// expired or mismatched provenance carries no removal authority (fail-closed).
	if persistence.CheckAttackerProvenance(ctx, reader, persistence.ProvenanceNamespace(), owner) != nil {
		return
	}

	var chosen *model.SecurityEventInfo
	var payload persistence.Assertion
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorControllerPersistence ||
			!persistence.ObserverAllowed(e.CreatorIdentity, p.Namespace) || e.Name == "" || e.UID == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= persistence.Horizon ||
			e.ConsoleTargetPodUID != p.UID || e.ControllerTargetUID != ownerUID {
			continue
		}
		a, parseErr := persistence.Decode(e.PersistenceRaw)
		if parseErr != nil || a.Namespace != p.Namespace || a.TargetPodUID != p.UID ||
			a.ControllerName != owner.Object.GetName() || a.OwnerKind != owner.Kind ||
			a.ObservedAt.After(e.CreatedAt.Add(time.Second)) || e.CreatedAt.Sub(a.ObservedAt) > persistence.Horizon ||
			a.Replicas <= 0 {
			continue
		}
		if chosen != nil { // a competing assertion disputes the binding; suppress
			return
		}
		chosen, payload = e, a
	}
	if chosen == nil {
		return
	}

	// Selecting policy epoch is current, still enables controller-stop, and selects this child.
	if persistence.CurrentPolicy(ctx, reader, p.Namespace, payload.PolicyName, payload.PolicyUID, payload.PolicyGeneration, []corev1.Pod{*pod}) != nil {
		return
	}

	replicas := payload.Replicas
	if int(owner.Desired) > replicas {
		replicas = int(owner.Desired)
	}
	if int(owner.Ready) > replicas {
		replicas = int(owner.Ready)
	}
	p.PersistenceControllerUID = ownerUID
	p.SuspectController = owner.Object.GetName()
	p.PersistenceFootholdObservation = &model.PersistenceFootholdObservation{
		TargetPodUID: p.UID, RemovedPodUID: payload.RemovedPodUID, ReplacementPodUID: payload.ReplacementPodUID,
		ObservedAt: payload.ObservedAt, Replicas: replicas, EventName: chosen.Name, EventUID: chosen.UID,
		CreatorIdentity: chosen.CreatorIdentity, ControllerTargetUID: ownerUID, ControllerName: owner.Object.GetName(),
		OwnerKind: owner.Kind, Namespace: p.Namespace, OwnerDeclaredMinAvailable: 0, Unmanaged: true,
		NoLegitimateServiceRole: true, ObservedRecreation: true, PolicyName: payload.PolicyName,
		PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration, CreatedAt: chosen.CreatedAt,
	}
}
