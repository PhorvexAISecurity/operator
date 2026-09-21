package ingest

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/model"
)

// AdmitCompletedDisclosures is the dedicated producer-to-ledger transaction.
// Every authority input is API-observed; malformed or forged evidence remains
// an explicit gap and never disables unrelated selection or actuation.
func AdmitCompletedDisclosures(ctx context.Context, reader client.Reader, store losshistory.Ledger, events []model.SecurityEventInfo, p model.Policy, now time.Time, log logr.Logger) []string {
	if store == nil {
		return []string{"retained-loss-history-source-unavailable"}
	}
	boundary, reason := CheckCompletedDisclosureBoundary(ctx, reader)
	if reason != "ready" {
		return []string{reason}
	}
	gaps := []string{}
	for _, event := range events {
		if event.CompletedDisclosureRaw == "" {
			continue
		}
		payload, canonical, digest, err := disclosure.Parse(event.CompletedDisclosureRaw)
		if err != nil || string(canonical) != event.CompletedDisclosureRaw {
			gaps = append(gaps, "completed-disclosure-invalid-payload")
			continue
		}
		if payload.PolicyEpoch.UID != p.PolicyUID {
			continue // exact policy isolation; another policy owns this event
		}
		if store.ContainsExact(p.PolicyUID, payload.EvidenceID, digest, event.UID) {
			continue // retained immutable history survives policy generation changes
		}
		if payload.PolicyEpoch.Namespace != p.Namespace || payload.PolicyEpoch.Name != p.PolicyName {
			gaps = append(gaps, "completed-disclosure-policy-epoch-mismatch")
			continue
		}
		if event.Type != model.CompletedDisclosureRuleType || event.Source != model.CompletedDisclosureSource || event.ThreatLevel != "high" ||
			event.Description != model.CompletedDisclosureDescription ||
			len(event.ResolvedTargets) != 1 || len(event.UnresolvedTargets) != 0 || event.ResolvedTargets[0] != payload.DecisionAsset.Namespace+"/"+payload.DecisionAsset.Name {
			gaps = append(gaps, "completed-disclosure-event-binding-mismatch")
			continue
		}
		if event.UID == "" || event.TimestampMissing || event.CreatedAt.Before(boundary.ActivationTime) || event.CreatedAt.After(now) {
			gaps = append(gaps, "completed-disclosure-event-identity-unavailable")
			continue
		}
		admittedAt, err := time.Parse(time.RFC3339Nano, event.CompletedDisclosureAdmittedAt)
		// Kubernetes CreationTimestamp is serialized at second precision. The
		// admission annotation retains the exact webhook clock: it must fall in
		// that one-second creation interval and after the completed observation.
		if err != nil || event.CompletedDisclosureAdmissionContract != disclosure.BoundaryContract ||
			admittedAt.Before(boundary.ActivationTime) || admittedAt.Before(event.CreatedAt) || !admittedAt.Before(event.CreatedAt.Add(time.Second)) || admittedAt.After(now) ||
			payload.Observation.StartedAt.Before(boundary.ActivationTime) || payload.Observation.CompletedAt.After(admittedAt) {
			gaps = append(gaps, "completed-disclosure-observation-time-unbound")
			continue
		}
		if !CompletedDisclosureTrust().Allows(event.CreatorIdentity) {
			gaps = append(gaps, "completed-disclosure-creator-untrusted")
			continue
		}
		if payload.Classification.ObserverIdentity != event.CreatorIdentity {
			gaps = append(gaps, "completed-disclosure-observer-identity-mismatch")
			continue
		}
		// The fail-closed admission transaction already bound the exact policy
		// epoch, Pod UID and stable owner before persistence. Re-resolving the
		// original Pod here would discard an accepted observation if rotation
		// deletes it between admission and the first ledger tick.
		record := model.AdmittedLossV1{
			SchemaVersion: model.AdmittedLossSchemaV1, Disclosure: payload, CanonicalPayloadSHA256: digest,
			SecurityEvent:        model.SecurityEventIdentity{Name: event.Name, UID: event.UID, CreationTimestamp: event.CreatedAt},
			AdmissionTime:        admittedAt,
			AuthenticatedCreator: event.CreatorIdentity, TrustBoundary: boundary, IngestedAt: now,
		}
		if err := store.Put(record); err != nil {
			log.Error(err, "completed disclosure retention failed", "event", event.Name, "evidenceID", payload.EvidenceID)
			gaps = append(gaps, "completed-disclosure-retention-failed")
		}
	}
	return gaps
}
