package ingest

import (
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

// Config-object drift events carry the flagged ConfigMap name, the observed live-data hash and
// the asserted trusted-snapshot hash themselves. The creator annotation is protected by the
// existing M94 admission stamp and validating deny binding. No Pod field is allowed to fill a
// missing event value, and a drift observation REQUIRES observed != trusted (a ConfigMap already
// on its trusted snapshot is no threat). This binder is namespace-PARAMETRIC: it never reads a
// hard-coded namespace or object name.
const ConfigObjectNameAnnotation = "phorvex.ai/config-object-name"
const ConfigObservedSHA256Annotation = "phorvex.ai/config-observed-sha256"
const ConfigTrustedSHA256Annotation = "phorvex.ai/config-trusted-sha256"
const ConfigTargetUIDAnnotation = "phorvex.ai/target-pod-uid"
const configObjectEvidenceHorizon = 15 * time.Minute

// validConfigObjectName accepts a DNS-subdomain-shaped ConfigMap name (the kube object-name
// character set). It is the SELECTION target only; the handler re-reads the authoritative object.
func validConfigObjectName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// validConfigSHA accepts exactly a canonical `sha256:<64 lowercase hex>` content hash. A bare
// name or a non-hex value is rejected: the observation keys on the content hash, not a name.
func validConfigSHA(s string) bool {
	const prefix = "sha256:"
	if len(s) != len(prefix)+64 {
		return false
	}
	if s[:len(prefix)] != prefix {
		return false
	}
	for _, c := range s[len(prefix):] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// bindK8sObjectRevertObservation mirrors bindAdapterObservation: it binds the one fresh, trusted,
// UID-targeting config-object-drift observation to this exact Pod. Conflicting observed hashes or
// object names across events fail closed.
func bindK8sObjectRevertObservation(p *model.Pod, events []model.SecurityEventInfo) {
	p.SuspectConfigObject, p.K8sObjectRevertObservation = "", nil
	if p.UID == "" {
		return
	}
	var observations []model.K8sObjectRevertObservation
	for _, e := range events {
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorConfigObject ||
			e.CreatorIdentity == "" || e.UID == "" || e.Name == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= configObjectEvidenceHorizon ||
			e.ConfigTargetUID != p.UID ||
			!validConfigObjectName(e.ConfigObjectName) ||
			!validConfigSHA(e.ConfigObservedSHA256) || !validConfigSHA(e.ConfigTrustedSHA256) ||
			e.ConfigObservedSHA256 == e.ConfigTrustedSHA256 {
			continue
		}
		observations = append(observations, model.K8sObjectRevertObservation{
			EventName: e.Name, EventUID: e.UID, CreatorIdentity: e.CreatorIdentity,
			TargetPodUID: p.UID, ConfigMapName: e.ConfigObjectName,
			ObservedSHA256: e.ConfigObservedSHA256, TrustedSHA256: e.ConfigTrustedSHA256,
			CreatedAt: e.CreatedAt,
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
		if o.ConfigMapName != observations[0].ConfigMapName || o.ObservedSHA256 != observations[0].ObservedSHA256 {
			return
		} // conflicting target object or observed hash fails closed
	}
	p.SuspectConfigObject = observations[0].ConfigMapName
	p.K8sObjectRevertObservation = &observations[0]
}
