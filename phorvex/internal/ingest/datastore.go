package ingest

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/datastore"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

const datastoreHorizon = 5 * time.Minute

// bindDatastoreRestoreObservation grants the datastore-restore candidate fact only for one
// fresh TRUSTED datastore-poisoning event whose typed identities match the live store, the
// operator-owned trusted snapshot, the Service, the selecting policy and the target Pod — in
// the Pod's OWN namespace (parametric: no hard-coded app namespace). It does not pin a specific
// injector identity; any allowlisted trusted detector (e.g. an isolated lane's p3-attacks) is
// honored, with the console-target-pod-UID binding still required and the authoritative re-check
// still done at enact time in datastoreRestoreAuthority. The fact is granted only while the live
// store is STILL poisoned (its canonical sha differs from the operator snapshot); any competing
// assertion suppresses the fact.
func bindDatastoreRestoreObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.DatastoreRestoreObservation = nil
	if p.Namespace == "" || p.UID == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload datastore.Observation
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorDatastorePoison ||
			e.CreatorIdentity == "" || e.Name == "" || e.UID == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= datastoreHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		candidate, parseErr := datastore.ParseObservation(e.DatastoreRaw)
		if parseErr != nil || candidate.Namespace != p.Namespace || candidate.TargetPodUID != p.UID {
			continue
		}
		observedAt, timeErr := time.Parse(time.RFC3339Nano, candidate.ObservedAt)
		if timeErr != nil || observedAt.After(e.CreatedAt.Add(time.Second)) ||
			e.CreatedAt.Sub(observedAt) > datastoreHorizon ||
			e.CreatedAt.Add(e.Age).Sub(observedAt) >= datastoreHorizon {
			continue
		}
		if chosen != nil {
			return
		}
		chosen, payload = e, candidate
	}
	if chosen == nil {
		return
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, payload.ObservedAt)
	live, e := datastore.ValidateLive(ctx, reader, payload.Namespace, payload.TargetPodUID)
	if e != nil || live.StoreUID != payload.StoreConfigMapUID || live.TrustedUID != payload.TrustedSnapshotConfigMapUID ||
		live.ServiceUID != payload.ServiceUID || live.CurrentSHA != payload.PoisonedSHA256 ||
		live.TrustedSHA != payload.TrustedSHA256 || live.CurrentSHA == live.TrustedSHA {
		return
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: payload.PolicyName}, policy); e != nil ||
		string(policy.UID) != payload.PolicyUID || policy.Generation != payload.PolicyGeneration {
		return
	}
	selector, e := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if e != nil || selector.Empty() {
		return
	}
	pod := &corev1.Pod{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, pod); e != nil || string(pod.UID) != p.UID ||
		!selector.Matches(labels.Set(pod.Labels)) {
		return
	}
	p.DatastoreRestoreObservation = &model.DatastoreRestoreObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		Namespace: payload.Namespace, StoreName: payload.StoreName,
		StoreConfigMapUID: payload.StoreConfigMapUID, TrustedSnapshotConfigMapUID: payload.TrustedSnapshotConfigMapUID,
		ServiceUID: payload.ServiceUID, TargetPodUID: payload.TargetPodUID,
		PoisonedSHA256: payload.PoisonedSHA256, TrustedSHA256: payload.TrustedSHA256,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		ObservedAt: observedAt,
	}
}
