package losshistory

import (
	"context"
	"slices"
	"time"

	"github.com/go-logr/logr"
	admission "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

// Admit is the dedicated completed-disclosure producer-to-ledger transaction.
// Every authority input is API-observed; malformed or forged evidence remains
// an explicit gap and never disables unrelated selection or actuation.
func Admit(ctx context.Context, reader client.Reader, store Ledger, events []model.SecurityEventInfo, p model.Policy, now time.Time, log logr.Logger) []string {
	if store == nil {
		return []string{"retained-loss-history-source-unavailable"}
	}
	boundary, reason := CheckBoundary(ctx, reader)
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
		if !eventtrust.CompletedDisclosureTrust().Allows(event.CreatorIdentity) {
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

const CompletedDisclosureMatch = "(has(object.metadata.annotations) && 'phorvex.ai/completed-disclosure-v1' in object.metadata.annotations) || (request.operation == 'UPDATE' && has(oldObject.metadata.annotations) && 'phorvex.ai/completed-disclosure-v1' in oldObject.metadata.annotations)"

// CheckBoundary verifies the independent fail-closed M100
// webhook. The generic detector boundary does not authorize loss evidence.
func CheckBoundary(ctx context.Context, c client.Reader) (model.DisclosureTrustBoundary, string) {
	if eventtrust.CompletedDisclosureTrust().Empty() {
		return model.DisclosureTrustBoundary{}, "no-loss-observer-allowlist"
	}
	if c == nil {
		return model.DisclosureTrustBoundary{}, "loss-boundary-reader-unavailable"
	}
	var list admission.MutatingWebhookConfigurationList
	if err := c.List(ctx, &list); err != nil {
		return model.DisclosureTrustBoundary{}, "loss-webhook-configuration-unavailable"
	}
	for i := range list.Items {
		cfg := &list.Items[i]
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			if w.Name != "stamp-completed-disclosures.phorvex.ai" {
				continue
			}
			if cfg.UID == "" || cfg.ResourceVersion == "" || cfg.CreationTimestamp.IsZero() {
				return model.DisclosureTrustBoundary{}, "loss-boundary-identity-unavailable"
			}
			if cfg.Annotations[disclosure.BoundaryContractAnnotation] != disclosure.BoundaryContract {
				return model.DisclosureTrustBoundary{}, "loss-boundary-contract-unverified"
			}
			if w.FailurePolicy == nil || *w.FailurePolicy != admission.Fail {
				return model.DisclosureTrustBoundary{}, "loss-stamp-not-fail-closed"
			}
			if w.ObjectSelector != nil && (len(w.ObjectSelector.MatchLabels) != 0 || len(w.ObjectSelector.MatchExpressions) != 0) {
				return model.DisclosureTrustBoundary{}, "loss-stamp-object-selector-gap"
			}
			if w.NamespaceSelector != nil && (len(w.NamespaceSelector.MatchLabels) != 0 || len(w.NamespaceSelector.MatchExpressions) != 0) {
				return model.DisclosureTrustBoundary{}, "loss-stamp-namespace-selector-gap"
			}
			if len(w.MatchConditions) != 1 || w.MatchConditions[0].Expression != CompletedDisclosureMatch {
				return model.DisclosureTrustBoundary{}, "loss-stamp-match-condition-gap"
			}
			svc := w.ClientConfig.Service
			if svc == nil || svc.Path == nil || *svc.Path != eventtrust.StampWebhookPath || len(w.ClientConfig.CABundle) == 0 {
				return model.DisclosureTrustBoundary{}, "loss-stamp-endpoint-unverified"
			}
			create, update := false, false
			for _, rule := range w.Rules {
				if !slices.Contains(rule.APIGroups, "amtd.r6security.com") || !slices.Contains(rule.APIVersions, "v1beta1") ||
					!slices.Contains(rule.Resources, "securityevents") || (rule.Scope != nil && *rule.Scope == admission.NamespacedScope) {
					continue
				}
				create = create || slices.Contains(rule.Operations, admission.Create)
				update = update || slices.Contains(rule.Operations, admission.Update)
			}
			if !create || !update {
				return model.DisclosureTrustBoundary{}, "loss-stamp-operation-gap"
			}
			return model.DisclosureTrustBoundary{
				ConfigurationUID: string(cfg.UID), ConfigurationResourceVersion: cfg.ResourceVersion,
				ActivationTime: cfg.CreationTimestamp.Time, ContractVersion: disclosure.BoundaryContract,
			}, "ready"
		}
	}
	return model.DisclosureTrustBoundary{}, "loss-stamp-missing"
}
