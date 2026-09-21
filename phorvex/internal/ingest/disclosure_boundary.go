package ingest

import (
	"context"
	"slices"

	admission "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/model"
)

const CompletedDisclosureMatch = "has(object.metadata.annotations) && 'phorvex.ai/completed-disclosure-v1' in object.metadata.annotations"

// CheckCompletedDisclosureBoundary verifies the independent fail-closed M100
// webhook. The generic detector boundary does not authorize loss evidence.
func CheckCompletedDisclosureBoundary(ctx context.Context, c client.Reader) (model.DisclosureTrustBoundary, string) {
	if CompletedDisclosureTrust().Empty() {
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
			if svc == nil || svc.Path == nil || *svc.Path != securityEventStampPath || len(w.ClientConfig.CABundle) == 0 {
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

// Duplicated intentionally from controller's unexported route so ingest can
// verify the installed endpoint without importing controller (which imports ingest).
const securityEventStampPath = "/stamp-amtd-r6security-com-v1beta1-securityevent"
