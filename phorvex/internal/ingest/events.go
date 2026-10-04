/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"context"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// ConsoleTargetPodUIDAnnotation binds a newly emitted catalogue signal to the
// exact Pod lifetime. It is a target check, never detector trust authority.
const ConsoleTargetPodUIDAnnotation = model.ConsoleTargetPodUIDAnnotation

var consoleTargetUIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// EvidenceEvents removes UID-rejected catalogue events from inventory consumers
// that do not use EventByPod (protected outcomes and disclosure ledgers). The
// original records remain in Snapshot.Events for diagnostics.
func EvidenceEvents(events []model.SecurityEventInfo) []model.SecurityEventInfo {
	out := make([]model.SecurityEventInfo, 0, len(events))
	for _, event := range events {
		if event.TargetBindingReason == "" {
			out = append(out, event)
		}
	}
	return out
}

// collectEvents reads the cluster's SecurityEvent stream (the SAME feed Phoenix
// ingests) and projects it to per-pod belief evidence. Phorvex's OWN controller
// events (Source=PhorvexController) are EXCLUDED so Phorvex never treats its own
// actuation as threat evidence (no feedback loop).
//
// M-94 trust boundary: `spec.rule.source` is a self-declared string, so it decides
// nothing. Only an event whose ADMISSION-STAMPED creator identity is an allowlisted
// detector becomes belief evidence (byPod); everything else is ingested and recorded
// with its Trust verdict but carries no evidence. See eventtrust.go.
func collectEvents(ctx context.Context, c client.Reader, now time.Time) ([]model.SecurityEventInfo, map[string][]model.SecurityEventInfo, error) {
	all, byPod, _, err := collectEventsAndReceipts(ctx, c, now)
	return all, byPod, err
}

func collectEventsAndReceipts(ctx context.Context, c client.Reader, now time.Time, currentPodUIDs ...map[string]string) ([]model.SecurityEventInfo, map[string][]model.SecurityEventInfo, map[string]model.PhoenixExecutionReceipt, error) {
	var seList amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &seList); err != nil {
		return nil, nil, nil, err
	}
	all := make([]model.SecurityEventInfo, 0, len(seList.Items))
	byPod := map[string][]model.SecurityEventInfo{}
	receipts := map[string]model.PhoenixExecutionReceipt{}
	for i := range seList.Items {
		se := &seList.Items[i]
		if se.Spec.Rule.Source == actuator.RuleSource {
			metrics.RecordSecurityEvent(TrustSelf)
			// A finalizer-retained deleting event is no longer durable execution
			// evidence. Keep it outside belief, but do not project a receipt that could
			// authorize learning or cost attribution after deletion began.
			if se.Spec.Rule.Type == actuator.RuleTypeRotate && se.DeletionTimestamp == nil {
				targets := append([]string(nil), se.Spec.Targets...)
				receipts[se.Name] = model.PhoenixExecutionReceipt{
					EventName: se.Name, EventUID: string(se.UID), RuleType: se.Spec.Rule.Type,
					ThreatLevel: se.Spec.Rule.ThreatLevel, RuleSource: se.Spec.Rule.Source, Targets: targets,
					TargetUID:     se.Annotations[actuator.PhoenixRotateTargetUIDAnnotation],
					AppliedAction: se.Status.AppliedAction, CreatedAt: se.CreationTimestamp.Time,
					ProcessedAt: se.Status.ProcessedAt.Time,
				}
			}
			continue // skip Phorvex's own emitted events
		}
		identity := se.Annotations[CreatorIdentityAnnotation]
		trust := classifyEvent(identity)
		metrics.RecordSecurityEvent(trust)
		score := -1.0
		if se.Spec.AnomalyScore != nil {
			// ParseFloat accepts the literal strings "NaN"/"Inf" WITHOUT error, and a detector can
			// emit either. Admitting one would carry NaN into the decision path, so an unusable
			// score stays honest-absent (-1) rather than poisoning the view.
			if f, err := strconv.ParseFloat(strings.TrimSpace(*se.Spec.AnomalyScore), 64); err == nil &&
				!math.IsNaN(f) && !math.IsInf(f, 0) {
				score = f
			}
		}
		// M-27: age per event. A CR with no usable CreationTimestamp is NOT a fresh event —
		// its age is untrusted, so it is recorded present=false and carries weight 0.
		missing := se.CreationTimestamp.IsZero() || se.CreationTimestamp.Time.After(now) || se.DeletionTimestamp != nil
		age := time.Duration(0)
		if !missing {
			age = now.Sub(se.CreationTimestamp.Time)
			// A future or deleting object is marked timestamp-unusable above.
		}
		base := model.SecurityEventInfo{
			CreatedAt:                            se.CreationTimestamp.Time,
			Name:                                 se.Name,
			UID:                                  string(se.UID),
			Trust:                                trust,
			CreatorIdentity:                      identity,
			CompletedDisclosureRaw:               se.Annotations[disclosure.Annotation],
			CompletedDisclosureAdmittedAt:        se.Annotations[disclosure.AdmissionTimeAnnotation],
			CompletedDisclosureAdmissionContract: se.Annotations[disclosure.AdmissionContractAnnotation],
			CurrentInventoryRaw:                  se.Annotations[currentinventory.Annotation],
			CurrentInventoryAdmittedAt:           se.Annotations[currentinventory.AdmissionTimeAnnotation],
			CurrentInventoryAdmissionContract:    se.Annotations[currentinventory.AdmissionContractAnnotation],
			TimestampMissing:                     missing,
			Type:                                 se.Spec.Rule.Type,
			ThreatLevel:                          se.Spec.Rule.ThreatLevel,
			Source:                               se.Spec.Rule.Source,
			Description:                          se.Spec.Description,
			AnomalyScore:                         score,
			Age:                                  age,
			AdapterName:                          se.Annotations["phorvex.ai/adapter-name"],
			AdapterTargetUID:                     se.Annotations["phorvex.ai/target-pod-uid"],
			SensitiveOutputRaw:                   se.Annotations["phorvex.ai/sensitive-output-observation-v1"],
			VoiceMemoryRaw:                       se.Annotations["phorvex.ai/voice-memory-observation-v1"],
			VoiceRefundRaw:                       se.Annotations["phorvex.ai/voice-refund-observation-v1"],
			SensitiveOutputV2Raw:                 se.Annotations["phorvex.ai/sensitive-output-observation-v2"],
			VoiceMCPRaw:                          se.Annotations["phorvex.ai/voice-mcp-observation-v1"],
			VoiceOutputRaw:                       se.Annotations["phorvex.ai/voice-output-observation-v1"],
			VoiceAdmissionRaw:                    se.Annotations["phorvex.ai/voice-admission-observation-v1"],
			LiteLLMClientRaw:                     se.Annotations["phorvex.ai/litellm-client-observation-v1"],
		CRMRefundRaw:                         se.Annotations["phorvex.ai/crm-refund-observation-v1"],
			EndpointLeaseRaw:                     se.Annotations["phorvex.ai/endpoint-lease-observation-v1"],
		}
		// A cluster-scoped target ("/name") has no namespace, so it cannot be keyed to a pod.
		// It used to be turned into a bare name that matched no key — silently dropped. It is
		// now recorded on the event with a reason and counted.
		resolved := make([]string, 0, len(se.Spec.Targets))
		for _, target := range se.Spec.Targets {
			key, ok := normalizeTarget(target)
			if !ok {
				base.UnresolvedTargets = append(base.UnresolvedTargets, strings.TrimSpace(target))
				metrics.RecordSecurityEvent(TargetUnresolvd)
				continue
			}
			resolved = append(resolved, key)
		}
		base.ResolvedTargets = resolved
		namespaces := make([]string, 0, len(resolved))
		for _, key := range resolved {
			ns, _, _ := strings.Cut(key, "/")
			namespaces = append(namespaces, ns)
		}
		metrics.RecordSecurityEventFirstSeen(string(se.UID), trust, namespaces)
		if boundUID, bound := se.Annotations[ConsoleTargetPodUIDAnnotation]; bound {
			base.ConsoleTargetPodUID = boundUID
			switch {
			case !consoleTargetUIDPattern.MatchString(boundUID):
				base.TargetBindingReason = "console-target-uid-malformed"
			case len(se.Spec.Targets) != 1 || len(resolved) != 1 || len(base.UnresolvedTargets) != 0:
				base.TargetBindingReason = "console-target-must-be-one-pod"
			case len(currentPodUIDs) == 0 || currentPodUIDs[0][resolved[0]] == "":
				base.TargetBindingReason = "console-target-absent-from-pod-snapshot"
			case currentPodUIDs[0][resolved[0]] != boundUID:
				base.TargetBindingReason = "console-target-pod-uid-mismatch"
			}
		}
		if raw := se.Annotations["phorvex.ai/protected-outcomes-v1"]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &base.Outcomes); err != nil {
				base.OutcomeParseError = "protected-outcomes-invalid-json"
				base.Outcomes = nil
			}
		}
		all = append(all, base)
		// Dedicated current-inventory events feed only the independently admitted
		// reporting ledger. Even if an operator accidentally also allowlists the
		// observer as a generic detector, its required high severity must never
		// become kill-chain evidence or change PHold, ranking, or cadence.
		if base.CurrentInventoryRaw != "" && base.Type == model.CurrentInventoryRuleType && base.Source == model.CurrentInventorySource {
			continue
		}
		if trust != TrustTrusted || base.TargetBindingReason != "" {
			continue // recorded above; an unauthenticated detector supplies no belief evidence
		}
		for _, key := range resolved {
			ev := base
			ev.TargetsPod = true
			byPod[key] = append(byPod[key], ev)
		}
	}
	return all, byPod, receipts, nil
}

// normalizeTarget canonicalizes a SecurityEvent target ("namespace/name") to a pod key.
// ok=false for a reference that carries no namespace ("/name" or a bare "name"): the pod
// map is keyed "namespace/name", so such a target identifies no pod. It used to be turned
// into a bare name that matched nothing — a silent drop (M-94). The caller records it.
func normalizeTarget(target string) (string, bool) {
	target = strings.TrimSpace(target)
	ns, name, ok := strings.Cut(target, "/")
	if !ok || ns == "" || name == "" {
		return "", false
	}
	return target, true
}
