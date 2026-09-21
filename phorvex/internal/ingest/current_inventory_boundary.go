package ingest

import (
	"context"
	"slices"

	admission "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/model"
)

const CurrentInventoryMatch = "(has(object.metadata.annotations) && 'phorvex.ai/current-protected-inventory-v1' in object.metadata.annotations) || (request.operation == 'UPDATE' && has(oldObject.metadata.annotations) && 'phorvex.ai/current-protected-inventory-v1' in oldObject.metadata.annotations)"

func CheckCurrentInventoryBoundary(ctx context.Context, c client.Reader) (model.DisclosureTrustBoundary, string) {
	if CurrentInventoryTrust().Empty() {
		return model.DisclosureTrustBoundary{}, "current-inventory-observer-authority-unavailable"
	}
	if c == nil {
		return model.DisclosureTrustBoundary{}, "current-inventory-boundary-reader-unavailable"
	}
	var list admission.MutatingWebhookConfigurationList
	if err := c.List(ctx, &list); err != nil {
		return model.DisclosureTrustBoundary{}, "current-inventory-boundary-read-failed"
	}
	for i := range list.Items {
		cfg := &list.Items[i]
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			if w.Name != "stamp-current-protected-inventory.phorvex.ai" {
				continue
			}
			if cfg.UID == "" || cfg.ResourceVersion == "" || cfg.CreationTimestamp.IsZero() || cfg.Annotations[currentinventory.BoundaryContractAnnotation] != currentinventory.BoundaryContract || w.FailurePolicy == nil || *w.FailurePolicy != admission.Fail || w.ClientConfig.Service == nil || w.ClientConfig.Service.Path == nil || *w.ClientConfig.Service.Path != securityEventStampPath || len(w.ClientConfig.CABundle) == 0 || len(w.MatchConditions) != 1 || w.MatchConditions[0].Expression != CurrentInventoryMatch {
				return model.DisclosureTrustBoundary{}, "current-inventory-boundary-invalid"
			}
			if (w.ObjectSelector != nil && (len(w.ObjectSelector.MatchLabels) != 0 || len(w.ObjectSelector.MatchExpressions) != 0)) || (w.NamespaceSelector != nil && (len(w.NamespaceSelector.MatchLabels) != 0 || len(w.NamespaceSelector.MatchExpressions) != 0)) {
				return model.DisclosureTrustBoundary{}, "current-inventory-boundary-selector-gap"
			}
			create, update := false, false
			for _, rule := range w.Rules {
				if slices.Contains(rule.APIGroups, "amtd.r6security.com") && slices.Contains(rule.APIVersions, "v1beta1") && slices.Contains(rule.Resources, "securityevents") && (rule.Scope == nil || *rule.Scope != admission.NamespacedScope) {
					create = create || slices.Contains(rule.Operations, admission.Create)
					update = update || slices.Contains(rule.Operations, admission.Update)
				}
			}
			if !create || !update {
				return model.DisclosureTrustBoundary{}, "current-inventory-boundary-operation-gap"
			}
			return model.DisclosureTrustBoundary{ConfigurationUID: string(cfg.UID), ConfigurationResourceVersion: cfg.ResourceVersion, ActivationTime: cfg.CreationTimestamp.Time.UTC(), ContractVersion: currentinventory.BoundaryContract}, "ready"
		}
	}
	return model.DisclosureTrustBoundary{}, "current-inventory-boundary-unavailable"
}
