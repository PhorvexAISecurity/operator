/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
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

// SupportsAction answers from the SAME predicate Actuate dispatches on, so
// this adapter can never claim an action it would then refuse. [M-21]
//
// Two answers, deliberately distinct:
//   - Controlled quarantine is ACCEPTED, but qualified UNVERIFIED:
//     the adapter takes the move, yet this layer verifies no per-target AMTD fixture, so
//     acceptance is never reported as proof the move executed or had any security effect
//     (T1-E's rule that a stub returns capable-but-unverified, never a silent false).
//   - Bounded rotate and every other action — the AI-native moves, the native-only
//     K8s moves, the noop
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

type phoenixPolicyDesired struct {
	name       string
	tenant     string
	selector   map[string]string
	strategies []amtdv1beta1.ResponseStrategy
	identity   map[string]string
}

func desiredPhoenixPolicy(target TenantTarget) (phoenixPolicyDesired, error) {
	if target.PolicyOwnerCount > 1 {
		return phoenixPolicyDesired{}, fmt.Errorf("phoenix actuator: namespace %q tenant %q has %d current policy owners; refusing shared strategy", target.Namespace, target.Tenant, target.PolicyOwnerCount)
	}
	selector, err := phoenixEqualities(targetSelector(target))
	if err != nil {
		return phoenixPolicyDesired{}, fmt.Errorf("phoenix actuator: tenant %q selector preparation refused: %w", target.Tenant, err)
	}
	name := amtdName(target.Namespace, target.Tenant)
	identity := mergeAnnotations(identityAnnotations(target.Namespace, target.Tenant), policyIdentityAnnotations(target))
	if err := validateIdentityMetadata(target.Namespace, identity); err != nil {
		return phoenixPolicyDesired{}, fmt.Errorf("phoenix actuator: %w", err)
	}
	return phoenixPolicyDesired{name: name, tenant: tenantLabel(target.Tenant), selector: selector, strategies: buildStrategies(target.EnabledActions), identity: identity}, nil
}

func phoenixPolicyInSync(amtd *amtdv1beta1.AdaptiveMovingTargetDefense, desired phoenixPolicyDesired) bool {
	if !reflect.DeepEqual(amtd.Spec.PodSelector, desired.selector) ||
		!reflect.DeepEqual(amtd.Spec.Strategy, desired.strategies) ||
		amtd.Spec.MatcherMode != amtdv1beta1.MatcherModeExact ||
		amtd.Labels["app.kubernetes.io/managed-by"] != "phorvex" ||
		amtd.Labels["phorvex.ai/tenant"] != desired.tenant {
		return false
	}
	for key, value := range desired.identity {
		if amtd.Annotations[key] != value {
			return false
		}
	}
	return true
}

func phoenixMaintenanceResult(state PolicyMaintenanceState, detail string, err error) PolicyMaintenanceResult {
	result := PolicyMaintenanceResult{
		Preparation: RoutePreparation{PhoenixErr: err, NativeSkipped: true},
		Phoenix:     PolicyRouteMaintenance{State: state, Detail: detail},
		Native:      PolicyRouteMaintenance{State: PolicyMaintenanceNotRequired, Detail: "native route not required"},
	}
	return result
}

func (p *PhoenixActuator) observeStandingPolicy(ctx context.Context, target TenantTarget) (PolicyMaintenanceState, string, error) {
	desired, err := desiredPhoenixPolicy(target)
	if err != nil {
		return PolicyMaintenanceOwnershipRefused, err.Error(), err
	}
	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	if err := p.Client.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: desired.name}, &amtd); err != nil {
		if apiNotFound(err) {
			return PolicyMaintenanceMissing, "managed Phoenix strategy is absent", nil
		}
		return PolicyMaintenanceUnknown, err.Error(), fmt.Errorf("get AMTD %s/%s: %w", target.Namespace, desired.name, err)
	}
	if err := validateAMTDOwnership(&amtd, target, desired.name); err != nil {
		return PolicyMaintenanceOwnershipRefused, err.Error(), fmt.Errorf("refuse AMTD update %s/%s: %w", target.Namespace, desired.name, err)
	}
	if phoenixPolicyInSync(&amtd, desired) {
		return PolicyMaintenanceInSync, "managed Phoenix strategy matches owned desired fields", nil
	}
	return PolicyMaintenanceDrifted, "managed Phoenix strategy differs in owned desired fields", nil
}

// ObserveStandingPolicy performs a genuinely read-only drift check.
func (p *PhoenixActuator) ObserveStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult {
	state, detail, err := p.observeStandingPolicy(ctx, target)
	return phoenixMaintenanceResult(state, detail, err)
}

// ReconcileStandingPolicy maintains the AMTD without emitting a SecurityEvent.
// A matching object is a zero-write success.
func (p *PhoenixActuator) ReconcileStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult {
	desired, err := desiredPhoenixPolicy(target)
	if err != nil {
		return phoenixMaintenanceResult(PolicyMaintenanceOwnershipRefused, err.Error(), err)
	}

	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	err = p.Client.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: desired.name}, &amtd)
	if err != nil {
		if !apiNotFound(err) {
			err = fmt.Errorf("get AMTD %s/%s: %w", target.Namespace, desired.name, err)
			return phoenixMaintenanceResult(PolicyMaintenanceUnknown, err.Error(), err)
		}
		amtd = amtdv1beta1.AdaptiveMovingTargetDefense{
			ObjectMeta: metav1.ObjectMeta{
				Name:        desired.name,
				Namespace:   target.Namespace,
				Labels:      map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": tenantLabel(target.Tenant)},
				Annotations: desired.identity,
			},
			Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
				PodSelector: desired.selector,
				Strategy:    desired.strategies,
				MatcherMode: amtdv1beta1.MatcherModeExact,
			},
		}
		if verr := validateObjectMetadata(&amtd.ObjectMeta); verr != nil {
			err = fmt.Errorf("create AMTD %s/%s metadata: %w", target.Namespace, desired.name, verr)
			return phoenixMaintenanceResult(PolicyMaintenanceUnknown, err.Error(), err)
		}
		if cerr := p.Client.Create(ctx, &amtd); cerr != nil {
			err = fmt.Errorf("create AMTD %s/%s: %w", target.Namespace, desired.name, cerr)
			return phoenixMaintenanceResult(PolicyMaintenanceUnknown, err.Error(), err)
		}
		return phoenixMaintenanceResult(PolicyMaintenanceRepaired, "created missing managed Phoenix strategy", nil)
	}

	if oerr := validateAMTDOwnership(&amtd, target, desired.name); oerr != nil {
		err = fmt.Errorf("refuse AMTD update %s/%s: %w", target.Namespace, desired.name, oerr)
		return phoenixMaintenanceResult(PolicyMaintenanceOwnershipRefused, err.Error(), err)
	}
	if phoenixPolicyInSync(&amtd, desired) {
		return phoenixMaintenanceResult(PolicyMaintenanceInSync, "managed Phoenix strategy matches owned desired fields", nil)
	}
	amtd.Annotations = mergeAnnotations(amtd.Annotations, desired.identity)
	if amtd.Labels == nil {
		amtd.Labels = map[string]string{}
	}
	amtd.Labels["app.kubernetes.io/managed-by"] = "phorvex"
	amtd.Labels["phorvex.ai/tenant"] = tenantLabel(target.Tenant)
	amtd.Spec.PodSelector = desired.selector
	amtd.Spec.Strategy = desired.strategies
	amtd.Spec.MatcherMode = amtdv1beta1.MatcherModeExact
	if verr := validateObjectMetadata(&amtd.ObjectMeta); verr != nil {
		err = fmt.Errorf("update AMTD %s/%s metadata: %w", target.Namespace, desired.name, verr)
		return phoenixMaintenanceResult(PolicyMaintenanceUnknown, err.Error(), err)
	}
	if uerr := p.Client.Update(ctx, &amtd); uerr != nil {
		err = fmt.Errorf("update AMTD %s/%s: %w", target.Namespace, desired.name, uerr)
		return phoenixMaintenanceResult(PolicyMaintenanceUnknown, err.Error(), err)
	}
	return phoenixMaintenanceResult(PolicyMaintenanceRepaired, "repaired drifted managed Phoenix strategy", nil)
}

// EnsurePolicy preserves the Actuator interface while delegating to the typed
// standing-policy result used by the runner.
func (p *PhoenixActuator) EnsurePolicy(ctx context.Context, target TenantTarget) error {
	return p.ReconcileStandingPolicy(ctx, target).Preparation.PhoenixErr
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
		policyName, hasPolicyName := annotations[policyNameAnnotation]
		policyUID, hasPolicyUID := annotations[policyUIDAnnotation]
		policyGeneration, hasPolicyGeneration := annotations[policyGenerationAnnotation]
		if hasPolicyName || hasPolicyUID || hasPolicyGeneration {
			if !hasPolicyName || !hasPolicyUID || !hasPolicyGeneration {
				return fmt.Errorf("policy owner annotations are incomplete")
			}
			if target.PolicyUID == "" || policyName != target.PolicyName || policyUID != target.PolicyUID {
				return fmt.Errorf("policy owner annotations belong to name %q uid %q generation %q", policyName, policyUID, policyGeneration)
			}
			if _, err := strconv.ParseInt(policyGeneration, 10, 64); err != nil {
				return fmt.Errorf("policy owner generation %q is malformed", policyGeneration)
			}
		} else if target.PolicyUID != "" {
			return fmt.Errorf("legacy AMTD has no exact policy owner identity; explicit migration is required")
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

var _ StandingPolicyMaintainer = (*PhoenixActuator)(nil)

// Actuate emits the controlled SecurityEvent for one move. Implements Actuator.
func (p *PhoenixActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	if req.Action == model.ActionRotate {
		return Result{Actuator: p.Name(), NoEffect: NoEffectRefused}, RefusedWithoutEffect(fmt.Errorf("phoenix actuator: bounded rotate refused: %s", detailGraceCapUnsupported))
	}
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
				ThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel,
				Source:      amtdv1beta1.PhorvexRuleSource,
			},
			Description: phorvexDescription(req),
		},
	}
	if req.Action == model.ActionQuarantine {
		se.Annotations[amtdv1beta1.PhorvexQuarantineTargetUIDAnnotation] = req.TargetUID
		se.Annotations[amtdv1beta1.PhorvexQuarantineNamespaceUIDAnnotation] = req.TargetNamespaceUID
		se.Annotations[amtdv1beta1.PhorvexQuarantineOperationAnnotation] = req.OperationID
	}
	if req.Action == model.ActionRotate {
		se.Annotations[amtdv1beta1.PhorvexRotateTargetUIDAnnotation] = req.TargetUID
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
		RuleThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel,
		RuleSource:      amtdv1beta1.PhorvexRuleSource,
		Emitted:         true,
	}, nil
}

// buildStrategies maps the enabled Phorvex actions to Phoenix strategies.
func buildStrategies(enabled map[model.Action]bool) []amtdv1beta1.ResponseStrategy {
	var out []amtdv1beta1.ResponseStrategy
	if enabled == nil || enabled[model.ActionRotate] {
		out = append(out, amtdv1beta1.ResponseStrategy{
			Rule:   amtdv1beta1.Rule{Type: amtdv1beta1.PhorvexRuleTypeRotate, ThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel, Source: amtdv1beta1.PhorvexRuleSource},
			Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
		})
	}
	if enabled == nil || enabled[model.ActionQuarantine] {
		out = append(out, amtdv1beta1.ResponseStrategy{
			Rule:   amtdv1beta1.Rule{Type: amtdv1beta1.PhorvexRuleTypeQuarantine, ThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel, Source: amtdv1beta1.PhorvexRuleSource},
			Action: amtdv1beta1.AMTDAction{Quarantine: &amtdv1beta1.QuarantineAction{}},
		})
	}
	// A standing policy must carry at least one strategy (Phoenix requires MinItems=1);
	// if somehow nothing is enabled, default to the rotate strategy.
	if len(out) == 0 {
		out = append(out, amtdv1beta1.ResponseStrategy{
			Rule:   amtdv1beta1.Rule{Type: amtdv1beta1.PhorvexRuleTypeRotate, ThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel, Source: amtdv1beta1.PhorvexRuleSource},
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
