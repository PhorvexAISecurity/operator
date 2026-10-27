package ingest

import (
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

// Image-drift events carry both digests themselves. The creator annotation is protected by the
// existing M94 admission stamp and validating deny binding (same guard as adapter events). No Pod
// field is allowed to fill a missing event value, and the trusted pin the actuator rolls TO is
// re-read from the live controller at dispatch, never trusted from here.
const (
	RunningImageDigestAnnotation = "phorvex.ai/running-image-digest"
	TrustedImageDigestAnnotation = "phorvex.ai/trusted-image-digest"
)

const imageEvidenceHorizon = 15 * time.Minute

// validImageDigest accepts a bounded `sha256:<64 hex>` content digest, or a bounded
// `repo[:tag]@sha256:<64 hex>` reference. It never accepts whitespace, so an annotation cannot
// smuggle a second value. The exactness is deliberate: the digest is the whole evidence.
func validImageDigest(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			return false
		}
	}
	// Accept a bare "sha256:<hex>" or any "...@sha256:<hex>" suffix.
	j := indexSHA256(s)
	if j < 0 {
		return false
	}
	hex := s[j+len("sha256:"):]
	if len(hex) != 64 {
		return false
	}
	for _, c := range hex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// indexSHA256 returns the index of the LAST "sha256:" token in s, or -1. A reference pins its
// digest as the final "@sha256:..." segment, so the last occurrence is the content digest.
func indexSHA256(s string) int {
	const tok = "sha256:"
	last := -1
	for i := 0; i+len(tok) <= len(s); i++ {
		if s[i:i+len(tok)] == tok {
			last = i
		}
	}
	return last
}

// digestOf normalizes a running imageID / trusted ref to its bare "sha256:<hex>" content digest
// so the drift comparison is on the digest alone, independent of repo/tag/runtime prefix.
func digestOf(s string) string {
	if j := indexSHA256(s); j >= 0 {
		return s[j:]
	}
	return s
}

// bindImageObservation sets p.SuspectImageDigest + p.ImageObservation from the one fresh, trusted,
// pod-targeting image-drift event (AttackVectorImage). It mirrors bindAdapterObservation: only a
// trusted, admission-stamped, unexpired event that targets THIS pod and whose observed running
// digest differs from the trusted pin becomes belief evidence. Conflicting running digests fail
// closed. An identical running==pin is not a drift and mints nothing.
func bindImageObservation(p *model.Pod, events []model.SecurityEventInfo) {
	p.SuspectImageDigest, p.ImageObservation = "", nil
	if p.UID == "" {
		return
	}
	var observations []model.ImageObservation
	for _, e := range events {
		running := digestOf(e.ImageRunningDigest)
		pin := digestOf(e.ImageTrustedPin)
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorImage ||
			e.CreatorIdentity == "" || e.UID == "" || e.Name == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= imageEvidenceHorizon ||
			e.AdapterTargetUID != p.UID ||
			!validImageDigest(e.ImageRunningDigest) || !validImageDigest(e.ImageTrustedPin) ||
			running == pin {
			continue
		}
		observations = append(observations, model.ImageObservation{
			EventName: e.Name, EventUID: e.UID, CreatorIdentity: e.CreatorIdentity,
			TargetPodUID: p.UID, RunningDigest: running, TrustedPin: pin, CreatedAt: e.CreatedAt,
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
		if o.RunningDigest != observations[0].RunningDigest {
			return
		} // conflicting running digests fail closed
	}
	p.SuspectImageDigest = observations[0].RunningDigest
	p.ImageObservation = &observations[0]
}
