package currentinventory

import (
	"context"
	"slices"
	"time"

	"github.com/go-logr/logr"
	admission "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/ownership"
)

// Admit is the second, current-evidence admission transaction.
// Unlike completed history, every source binding must still be current when it
// enters the expiring inventory ledger.
func Admit(ctx context.Context, reader client.Reader, store Ledger, events []model.SecurityEventInfo, p model.Policy, now time.Time, log logr.Logger) []string {
	if store == nil {
		return []string{"current-inventory-source-unavailable"}
	}
	boundary, reason := CheckBoundary(ctx, reader)
	if reason != "ready" {
		return []string{reason}
	}
	for _, event := range events {
		if event.CurrentInventoryRaw == "" {
			continue
		}
		payload, canonical, digest, err := Parse(event.CurrentInventoryRaw)
		if err != nil || string(canonical) != event.CurrentInventoryRaw {
			log.Info("current inventory observation rejected", "event", event.Name, "reason", "current-inventory-invalid-payload")
			continue
		}
		if payload.PolicyEpoch.UID != p.PolicyUID {
			continue
		}
		if payload.PolicyEpoch.Namespace != p.Namespace || payload.PolicyEpoch.Name != p.PolicyName || payload.PolicyEpoch.Generation != p.PolicyGeneration || payload.ProtectedScope.Tenant != p.Tenant {
			log.Info("current inventory observation rejected", "event", event.Name, "reason", "current-inventory-policy-epoch-mismatch")
			continue
		}
		if event.Type != model.CurrentInventoryRuleType || event.Source != model.CurrentInventorySource || event.ThreatLevel != "high" || event.Description != model.CurrentInventoryDescription || len(event.ResolvedTargets) != 1 || len(event.UnresolvedTargets) != 0 || event.ResolvedTargets[0] != payload.DecisionAsset.Namespace+"/"+payload.DecisionAsset.Name {
			log.Info("current inventory observation rejected", "event", event.Name, "reason", "current-inventory-event-binding-mismatch")
			continue
		}
		admittedAt, parseErr := time.Parse(time.RFC3339Nano, event.CurrentInventoryAdmittedAt)
		if event.UID == "" || event.TimestampMissing || parseErr != nil || event.CurrentInventoryAdmissionContract != BoundaryContract || event.CreatedAt.Before(boundary.ActivationTime) || event.CreatedAt.After(now) || admittedAt.Before(event.CreatedAt) || !admittedAt.Before(event.CreatedAt.Add(time.Second)) || admittedAt.After(now) || payload.Observation.StartedAt.Before(boundary.ActivationTime) || payload.Observation.CompletedAt.After(admittedAt) || !now.Before(payload.Observation.ValidUntil) {
			log.Info("current inventory observation rejected", "event", event.Name, "reason", "current-inventory-observation-time-unbound")
			continue
		}
		if !eventtrust.CurrentInventoryTrust().Allows(event.CreatorIdentity) || payload.Classification.ObserverIdentity != event.CreatorIdentity {
			log.Info("current inventory observation rejected", "event", event.Name, "reason", "current-inventory-creator-untrusted")
			continue
		}
		var pod corev1.Pod
		var cm corev1.ConfigMap
		if reader == nil || reader.Get(ctx, client.ObjectKey{Namespace: payload.DecisionAsset.Namespace, Name: payload.DecisionAsset.Name}, &pod) != nil || string(pod.UID) != payload.DecisionAsset.TargetUID ||
			reader.Get(ctx, client.ObjectKey{Namespace: payload.SourceBinding.ConfigMap.Namespace, Name: payload.SourceBinding.ConfigMap.Name}, &cm) != nil || string(cm.UID) != payload.SourceBinding.ConfigMap.UID || cm.ResourceVersion != payload.SourceBinding.ResourceVersion {
			log.Info("current inventory observation rejected", "event", event.Name, "reason", "current-inventory-source-identity-stale")
			continue
		}
		binding, bindErr := BindingFor(&pod, &cm, payload.SourceBinding.Key, payload.SourceBinding.VolumeName, payload.SourceBinding.ContainerName, payload.SourceBinding.MountPath, payload.SourceBinding.ProjectedPath)
		immediate, stable, ownerErr := ownership.ResolveStableWorkloadOwner(ctx, reader, payload.DecisionAsset.Namespace, payload.DecisionAsset.Name, payload.DecisionAsset.TargetUID)
		if bindErr != nil || ownerErr != nil || !SameBinding(binding, payload.SourceBinding) || immediate != payload.ImmediateController || stable != payload.StableWorkloadOwner {
			log.Info("current inventory observation rejected", "event", event.Name, "reason", "current-inventory-live-binding-mismatch")
			continue
		}
		record := model.AdmittedCurrentInventory{SchemaVersion: model.AdmittedCurrentInventorySchemaV1, Inventory: payload, CanonicalPayloadSHA256: digest, SecurityEvent: model.SecurityEventIdentity{Name: event.Name, UID: event.UID, CreationTimestamp: event.CreatedAt}, AdmissionTime: admittedAt, AuthenticatedCreator: event.CreatorIdentity, TrustBoundary: boundary, IngestedAt: now}
		if err := store.Put(record); err != nil {
			log.Error(err, "current inventory retention failed", "event", event.Name, "evidenceID", payload.EvidenceID)
		}
	}
	return nil
}

const CurrentInventoryMatch = "(has(object.metadata.annotations) && 'phorvex.ai/current-protected-inventory-v1' in object.metadata.annotations) || (request.operation == 'UPDATE' && has(oldObject.metadata.annotations) && 'phorvex.ai/current-protected-inventory-v1' in oldObject.metadata.annotations)"

// CheckBoundary verifies the fail-closed current-inventory admission webhook.
func CheckBoundary(ctx context.Context, c client.Reader) (model.DisclosureTrustBoundary, string) {
	if eventtrust.CurrentInventoryTrust().Empty() {
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
			if cfg.UID == "" || cfg.ResourceVersion == "" || cfg.CreationTimestamp.IsZero() || cfg.Annotations[BoundaryContractAnnotation] != BoundaryContract || w.FailurePolicy == nil || *w.FailurePolicy != admission.Fail || w.ClientConfig.Service == nil || w.ClientConfig.Service.Path == nil || *w.ClientConfig.Service.Path != eventtrust.StampWebhookPath || len(w.ClientConfig.CABundle) == 0 || len(w.MatchConditions) != 1 || w.MatchConditions[0].Expression != CurrentInventoryMatch {
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
			return model.DisclosureTrustBoundary{ConfigurationUID: string(cfg.UID), ConfigurationResourceVersion: cfg.ResourceVersion, ActivationTime: cfg.CreationTimestamp.Time.UTC(), ContractVersion: BoundaryContract}, "ready"
		}
	}
	return model.DisclosureTrustBoundary{}, "current-inventory-boundary-unavailable"
}
