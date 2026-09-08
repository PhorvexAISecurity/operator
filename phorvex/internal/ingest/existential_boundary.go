package ingest

import (
	"context"
	"slices"
	"time"

	admission "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const ProtectedOutcomeMatch = "has(object.metadata.annotations) && 'phorvex.ai/protected-outcomes-v1' in object.metadata.annotations"

// CheckExistentialBoundary requires enforcement, not merely a merged allowlist.
// Failure-open admission can preserve a forged client stamp during an outage.
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;list
func CheckExistentialBoundary(ctx context.Context, c client.Reader) (bool, string, time.Time) {
	if EventTrust().Empty() {
		return false, "no-allowlist", time.Time{}
	}
	var list admission.MutatingWebhookConfigurationList
	if err := c.List(ctx, &list); err != nil {
		return false, "webhook-configuration-unavailable", time.Time{}
	}
	for _, cfg := range list.Items {
		for _, w := range cfg.Webhooks {
			if w.Name != "stamp-protected-outcomes.phorvex.ai" {
				continue
			}
			if w.FailurePolicy == nil || *w.FailurePolicy != admission.Fail {
				return false, "stamp-failure-policy-not-fail-closed", time.Time{}
			}
			if w.ObjectSelector != nil && (len(w.ObjectSelector.MatchLabels) > 0 || len(w.ObjectSelector.MatchExpressions) > 0) {
				return false, "stamp-object-selector-gap", time.Time{}
			}
			if w.NamespaceSelector != nil && (len(w.NamespaceSelector.MatchLabels) > 0 || len(w.NamespaceSelector.MatchExpressions) > 0) {
				return false, "stamp-namespace-selector-gap", time.Time{}
			}
			if len(w.MatchConditions) != 1 || w.MatchConditions[0].Expression != ProtectedOutcomeMatch {
				return false, "stamp-match-condition-gap", time.Time{}
			}
			svc := w.ClientConfig.Service
			if svc == nil || svc.Path == nil || *svc.Path != "/stamp-amtd-r6security-com-v1beta1-securityevent" || len(w.ClientConfig.CABundle) == 0 {
				return false, "stamp-endpoint-unverified", time.Time{}
			}
			create, update := false, false
			for _, r := range w.Rules {
				if !slices.Contains(r.APIGroups, "amtd.r6security.com") || !slices.Contains(r.APIVersions, "v1beta1") || !slices.Contains(r.Resources, "securityevents") {
					continue
				}
				if r.Scope != nil && *r.Scope == admission.NamespacedScope {
					continue
				}
				create = create || slices.Contains(r.Operations, admission.Create) || slices.Contains(r.Operations, admission.OperationAll)
				update = update || slices.Contains(r.Operations, admission.Update) || slices.Contains(r.Operations, admission.OperationAll)
			}
			if create && update {
				if cfg.CreationTimestamp.IsZero() {
					return false, "stamp-activation-time-unknown", time.Time{}
				}
				since := cfg.CreationTimestamp.Time
				for _, field := range cfg.ManagedFields {
					if field.Time != nil && field.Time.Time.After(since) {
						since = field.Time.Time
					}
				}
				return true, "fail-closed-create-update-stamp-configured", since
			}
			return false, "stamp-operation-gap", time.Time{}
		}
	}
	return false, "stamp-webhook-absent", time.Time{}
}
