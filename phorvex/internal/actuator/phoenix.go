/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"context"
	"fmt"
	"math"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	// PhoenixRotateTargetUIDAnnotation binds a controlled asynchronous rotate to
	// the exact Pod identity selected by the runner. The Phoenix consumer verifies
	// it immediately before any target mutation.
	PhoenixRotateTargetUIDAnnotation        = "phorvex.ai/rotate-target-uid"
	phorvexQuarantineTargetUIDAnnotation    = "phorvex.ai/quarantine-target-uid"
	phorvexQuarantineNamespaceUIDAnnotation = "phorvex.ai/quarantine-namespace-uid"
	phorvexQuarantineOperationAnnotation    = "phorvex.ai/quarantine-operation"
)

// PhoenixActuator is the Phase-1 actuator (Seam 1). It actuates through the
// extended Phoenix SecurityEvent contract:
//
//  1. EnsurePolicy maintains a per-tenant AdaptiveMovingTargetDefense whose
//     PodSelector is the tenant's guest list and whose Strategy[] maps Phorvex's
//     controlled rules ({phorvex.rotate|phorvex.quarantine, high, PhorvexController})
//     to Phoenix's Delete / Quarantine actions.
//  2. Actuate creates a cluster-scoped SecurityEvent targeting one pod with one of
//     those controlled rules. Phoenix's SecurityEvent controller finds the matching
//     strategy and executes the action.
//
// Phorvex NEVER touches pods directly — it only writes SecurityEvent + AMTD CRs
// (least privilege, NFR4). Because Phorvex authors both the event AND the strategy,
// the exact-match matcher always fires (PRD §4.3).
type PhoenixActuator struct {
	Client client.Client
	// Now lets tests inject time; nil uses metav1.Now.
	now func() metav1.Time
}

// NewPhoenixActuator constructs a PhoenixActuator over a controller-runtime client.
func NewPhoenixActuator(c client.Client) *PhoenixActuator {
	return &PhoenixActuator{Client: c}
}

// Name implements Actuator.
func (*PhoenixActuator) Name() string { return "phoenix" }

// SupportsAction answers from the SAME predicate Actuate dispatches on (RuleTypeFor), so
// this adapter can never claim an action it would then refuse. [M-21]
//
// Two answers, deliberately distinct:
//   - An action Phoenix maps (rotate, quarantine) is ACCEPTED, but qualified UNVERIFIED:
//     the adapter takes the move, yet this layer verifies no per-target AMTD fixture, so
//     acceptance is never reported as proof the move executed or had any security effect
//     (T1-E's rule that a stub returns capable-but-unverified, never a silent false).
//   - Any other action — every AI-native move, the native-only K8s moves, the noop
//     sentinel and anything outside the vocabulary — is REJECTED, naming the backend, the
//     action and the reason. Before M-21 all of these were claimed as supported while
//     Actuate rejected them, which is exactly how a GPU fleet on the default backend
//     reported ActionsSupported: True and could enact nothing.
func (*PhoenixActuator) SupportsAction(_ context.Context, a model.Action, _ Target) (bool, string) {
	if ok, detail := phoenixAccepts(a); !ok {
		return false, unsupportedWhy(BackendPhoenix, a, detail)
	}
	return true, whyPhoenixUnverified
}

func (p *PhoenixActuator) timestamp() metav1.Time {
	if p.now != nil {
		return p.now()
	}
	return metav1.Now()
}

// amtdName is the deterministic, Kubernetes-valid AMTD name Phorvex derives for a
// tenant. Valid legacy names remain unchanged. Phoenix's "AMTD RuleIDs collision"
// path compares complete Rule triples for AMTDs with overlapping pod selectors; AMTD
// naming does not make those rules unique and this encoder does not claim to fix that.
func amtdName(namespace, tenant string) string {
	return boundedAMTDName(namespace, tenant)
}

// EnsurePolicy idempotently maintains the tenant's AMTD strategy. Implements Actuator.
func (p *PhoenixActuator) EnsurePolicy(ctx context.Context, target TenantTarget) error {
	selector, err := phoenixEqualities(targetSelector(target))
	if err != nil {
		return fmt.Errorf("phoenix actuator: tenant %q selector preparation refused: %w", target.Tenant, err)
	}
	name := amtdName(target.Namespace, target.Tenant)
	identity := identityAnnotations(target.Namespace, target.Tenant)
	if err := validateIdentityMetadata(target.Namespace, identity); err != nil {
		return fmt.Errorf("phoenix actuator: %w", err)
	}
	desired := buildStrategies(target.EnabledActions)

	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	err = p.Client.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: name}, &amtd)
	if err != nil {
		if !apiNotFound(err) {
			return fmt.Errorf("get AMTD %s/%s: %w", target.Namespace, name, err)
		}
		amtd = amtdv1beta1.AdaptiveMovingTargetDefense{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   target.Namespace,
				Labels:      map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": tenantLabel(target.Tenant)},
				Annotations: identity,
			},
			Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
				PodSelector: selector,
				Strategy:    desired,
				MatcherMode: amtdv1beta1.MatcherModeExact,
			},
		}
		if verr := validateObjectMetadata(&amtd.ObjectMeta); verr != nil {
			return fmt.Errorf("create AMTD %s/%s metadata: %w", target.Namespace, name, verr)
		}
		if cerr := p.Client.Create(ctx, &amtd); cerr != nil {
			return fmt.Errorf("create AMTD %s/%s: %w", target.Namespace, name, cerr)
		}
		return nil
	}

	if oerr := validateAMTDOwnership(&amtd, target, name); oerr != nil {
		return fmt.Errorf("refuse AMTD update %s/%s: %w", target.Namespace, name, oerr)
	}
	amtd.Annotations = mergeAnnotations(amtd.Annotations, identity)
	if amtd.Labels == nil {
		amtd.Labels = map[string]string{}
	}
	amtd.Labels["app.kubernetes.io/managed-by"] = "phorvex"
	amtd.Labels["phorvex.ai/tenant"] = tenantLabel(target.Tenant)
	// Update in place if the selector or strategy drifted.
	amtd.Spec.PodSelector = selector
	amtd.Spec.Strategy = desired
	if amtd.Spec.MatcherMode == "" {
		amtd.Spec.MatcherMode = amtdv1beta1.MatcherModeExact
	}
	if verr := validateObjectMetadata(&amtd.ObjectMeta); verr != nil {
		return fmt.Errorf("update AMTD %s/%s metadata: %w", target.Namespace, name, verr)
	}
	if uerr := p.Client.Update(ctx, &amtd); uerr != nil {
		return fmt.Errorf("update AMTD %s/%s: %w", target.Namespace, name, uerr)
	}
	return nil
}

func validateAMTDOwnership(amtd *amtdv1beta1.AdaptiveMovingTargetDefense, target TenantTarget, expectedName string) error {
	if amtd.Labels["app.kubernetes.io/managed-by"] != "phorvex" {
		return fmt.Errorf("managed-by marker is not phorvex")
	}
	annotations := amtd.Annotations
	version, hasVersion := annotations[identityVersionAnnotation]
	rawNamespace, hasNamespace := annotations[rawNamespaceAnnotation]
	rawTenant, hasTenant := annotations[rawTenantAnnotation]
	if hasVersion || hasNamespace || hasTenant {
		if !hasVersion || !hasNamespace || !hasTenant {
			return fmt.Errorf("identity annotations are incomplete")
		}
		if version != metadataIdentityVersion {
			return fmt.Errorf("unsupported identity version %q", version)
		}
		if rawNamespace != target.Namespace || rawTenant != target.Tenant {
			return fmt.Errorf("identity annotations belong to namespace %q tenant %q", rawNamespace, rawTenant)
		}
		return nil
	}
	legacyName := "phorvex-" + sanitize(target.Namespace) + "-" + sanitize(target.Tenant)
	if target.Tenant != sanitize(target.Tenant) {
		return fmt.Errorf("annotation-free legacy identity for noncanonical tenant %q is ambiguous; operator migration required", target.Tenant)
	}
	if amtd.Namespace != target.Namespace || amtd.Name != expectedName || expectedName != legacyName || amtd.Labels["phorvex.ai/tenant"] != target.Tenant {
		return fmt.Errorf("annotation-free legacy metadata does not exactly match canonical identity")
	}
	return nil
}

// Actuate emits the controlled SecurityEvent for one move. Implements Actuator.
func (p *PhoenixActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	ruleType := RuleTypeFor(req.Action)
	if ruleType == "" {
		return Result{}, fmt.Errorf("phoenix actuator: unsupported action %q", req.Action)
	}
	if req.Action == model.ActionQuarantine && (req.TargetUID == "" || len(req.TargetUID) > 128 || req.TargetNamespaceUID == "" || len(req.TargetNamespaceUID) > 128 || len(req.OperationID) != 40) {
		return Result{}, RefusedWithoutEffect(fmt.Errorf("phoenix actuator: controlled quarantine requires protected target, namespace and operation identity"))
	}
	if req.Action == model.ActionRotate && (req.TargetUID == "" || len(req.TargetUID) > 128) {
		return Result{}, RefusedWithoutEffect(fmt.Errorf("phoenix actuator: controlled rotate requires protected target identity"))
	}
	identity := identityAnnotations(req.Namespace, req.Tenant)
	if err := validateIdentityMetadata(req.Namespace, identity); err != nil {
		return Result{}, fmt.Errorf("phoenix actuator: %w", err)
	}
	se := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("phorvex-%s-", string(req.Action)),
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "phorvex",
				"phorvex.ai/tenant":            tenantLabel(req.Tenant),
				"phorvex.ai/action":            string(req.Action),
			},
			Annotations: identity,
		},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets: []string{req.Namespace + "/" + req.Pod},
			Rule: amtdv1beta1.Rule{
				Type:        ruleType,
				ThreatLevel: RuleThreatLevel,
				Source:      RuleSource,
			},
			Description: phorvexDescription(req),
		},
	}
	if req.Action == model.ActionQuarantine {
		se.Annotations[phorvexQuarantineTargetUIDAnnotation] = req.TargetUID
		se.Annotations[phorvexQuarantineNamespaceUIDAnnotation] = req.TargetNamespaceUID
		se.Annotations[phorvexQuarantineOperationAnnotation] = req.OperationID
	}
	if req.Action == model.ActionRotate {
		se.Annotations[PhoenixRotateTargetUIDAnnotation] = req.TargetUID
	}
	if req.CoverageValue != nil {
		se.Annotations["phorvex.ai/coverage-contract"] = "selection-fact-weight-v1"
		value := *req.CoverageValue
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			se.Annotations["phorvex.ai/coverage-status"] = "invalid-source-value"
		} else {
			se.Spec.Metrics = map[string]string{"coverageValue": strconv.FormatFloat(value, 'g', -1, 64)}
			se.Annotations["phorvex.ai/coverage-status"] = "present"
		}
	} else if req.Score >= 0 {
		s := fmt.Sprintf("%.4f", req.Score)
		se.Spec.AnomalyScore = &s
	}
	if verr := validateObjectMetadata(&se.ObjectMeta); verr != nil {
		return Result{}, fmt.Errorf("emit SecurityEvent for %s/%s metadata: %w", req.Namespace, req.Pod, verr)
	}
	if err := p.Client.Create(ctx, se); err != nil {
		return Result{}, fmt.Errorf("emit SecurityEvent for %s/%s: %w", req.Namespace, req.Pod, err)
	}
	// [M-18] Create decoded the API server's response back into se, which is exactly how
	// se.Name (assigned from GenerateName) is already read here. se.UID comes from that
	// same acknowledged response, so it costs no additional read or permission. Both are
	// reached only after Create returned nil: a rejected create takes the branch above
	// and fabricates nothing.
	return Result{
		Actuator:        p.Name(),
		AMTDName:        amtdName(req.Namespace, req.Tenant),
		EventName:       se.Name,
		EventUID:        string(se.UID),
		RuleType:        ruleType,
		RuleThreatLevel: RuleThreatLevel,
		RuleSource:      RuleSource,
		Emitted:         true,
	}, nil
}

// buildStrategies maps the enabled Phorvex actions to Phoenix strategies.
func buildStrategies(enabled map[model.Action]bool) []amtdv1beta1.ResponseStrategy {
	var out []amtdv1beta1.ResponseStrategy
	if enabled == nil || enabled[model.ActionRotate] {
		out = append(out, amtdv1beta1.ResponseStrategy{
			Rule:   amtdv1beta1.Rule{Type: RuleTypeRotate, ThreatLevel: RuleThreatLevel, Source: RuleSource},
			Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
		})
	}
	if enabled == nil || enabled[model.ActionQuarantine] {
		out = append(out, amtdv1beta1.ResponseStrategy{
			Rule:   amtdv1beta1.Rule{Type: RuleTypeQuarantine, ThreatLevel: RuleThreatLevel, Source: RuleSource},
			Action: amtdv1beta1.AMTDAction{Quarantine: &amtdv1beta1.QuarantineAction{}},
		})
	}
	// A standing policy must carry at least one strategy (Phoenix requires MinItems=1);
	// if somehow nothing is enabled, default to the rotate strategy.
	if len(out) == 0 {
		out = append(out, amtdv1beta1.ResponseStrategy{
			Rule:   amtdv1beta1.Rule{Type: RuleTypeRotate, ThreatLevel: RuleThreatLevel, Source: RuleSource},
			Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
		})
	}
	return out
}

func phorvexDescription(req Request) string {
	if req.Reason != "" {
		return fmt.Sprintf("phorvex %s %s/%s: %s", req.Action, req.Namespace, req.Pod, req.Reason)
	}
	return fmt.Sprintf("phorvex %s %s/%s", req.Action, req.Namespace, req.Pod)
}
