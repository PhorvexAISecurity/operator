package ingest

import (
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// Adapter events carry both values themselves. The creator annotation is protected
// by the existing M94 admission stamp and validating deny binding. No Pod field is
// allowed to fill a missing event value.
const AdapterNameAnnotation = "phorvex.ai/adapter-name"
const AdapterTargetUIDAnnotation = "phorvex.ai/target-pod-uid"
const adapterEvidenceHorizon = 15 * time.Minute

func validAdapterName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func bindAdapterObservation(p *model.Pod, events []model.SecurityEventInfo) {
	p.SuspectAdapter, p.AdapterObservation = "", nil
	if p.UID == "" {
		return
	}
	var observations []model.AdapterObservation
	for _, e := range events {
		if e.Trust != TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorAdapter ||
			e.CreatorIdentity == "" || e.UID == "" || e.Name == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= adapterEvidenceHorizon ||
			e.AdapterTargetUID != p.UID || !validAdapterName(e.AdapterName) {
			continue
		}
		observations = append(observations, model.AdapterObservation{
			EventName: e.Name, EventUID: e.UID, CreatorIdentity: e.CreatorIdentity,
			TargetPodUID: p.UID, AdapterName: e.AdapterName, CreatedAt: e.CreatedAt,
		})
	}
	sort.Slice(observations, func(i, j int) bool {
		if !observations[i].CreatedAt.Equal(observations[j].CreatedAt) {
			return observations[i].CreatedAt.After(observations[j].CreatedAt)
		}
		if observations[i].EventName != observations[j].EventName {
			return observations[i].EventName < observations[j].EventName
		}
		return observations[i].EventUID < observations[j].EventUID
	})
	if len(observations) == 0 {
		return
	}
	for _, o := range observations[1:] {
		if o.AdapterName != observations[0].AdapterName {
			return
		} // conflicting identities fail closed
	}
	p.SuspectAdapter = observations[0].AdapterName
	p.AdapterObservation = &observations[0]
}
