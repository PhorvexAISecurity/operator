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

// PhoenixActuator is the Phase-1 actuator (Seam 1). It actuates by speaking
// UNMODIFIED Phoenix's existing contract:
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

// SupportsAction is a stub for the Phoenix path (T1-E): Phoenix maps rotate/quarantine to
// AMTD rules, whose per-target repertoire is not verified as a runtime fixture at this
// layer yet. Per the ticket, stubs return capable-but-UNVERIFIED (never a silent false),
// so an unverified capability can never masquerade as a checked one. P-08 fills this in.
func (*PhoenixActuator) SupportsAction(_ context.Context, _ model.Action, _ Target) (bool, string) {
	return true, "unverified: phoenix-amtd-repertoire — P-08"
}

func (p *PhoenixActuator) timestamp() metav1.Time {
	if p.now != nil {
		return p.now()
	}
	return metav1.Now()
}

// amtdName is the deterministic AMTD name Phorvex owns for a tenant. It is qualified by
// namespace because the Phoenix/r6security controller treats the AMTD NAME as a
// CLUSTER-GLOBAL RuleID: two AMTDs that share a name — even in different namespaces —
// collide ("AMTD RuleIDs collision") and the AMTD controller stops reconciling ALL of them,
// which silently kills every decision/actuation. That is exactly what a set of policies
// cloned with the same spec.tenant produced (five `phorvex-voice` AMTDs across namespaces).
// Prefixing the namespace makes the name globally unique regardless of the tenant value, so a
// duplicate tenant can never jam the operator again. (Within ONE namespace two policies must
// still use distinct tenants — that is a local, obvious misconfiguration, not a silent
// cross-namespace trap.)
func amtdName(namespace, tenant string) string {
	return "phorvex-" + sanitize(namespace) + "-" + sanitize(tenant)
}

// EnsurePolicy idempotently maintains the tenant's AMTD strategy. Implements Actuator.
func (p *PhoenixActuator) EnsurePolicy(ctx context.Context, target TenantTarget) error {
	if len(target.MatchLabels) == 0 {
		return fmt.Errorf("phoenix actuator: tenant %q has no matchLabels selector; P0 active-mode requires a matchLabels-expressible selector for the AMTD guest list", target.Tenant)
	}
	name := amtdName(target.Namespace, target.Tenant)
	desired := buildStrategies(target.EnabledActions)

	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	err := p.Client.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: name}, &amtd)
	if err != nil {
		if !apiNotFound(err) {
			return fmt.Errorf("get AMTD %s/%s: %w", target.Namespace, name, err)
		}
		amtd = amtdv1beta1.AdaptiveMovingTargetDefense{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: target.Namespace,
				Labels:    map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": sanitize(target.Tenant)},
			},
			Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
				PodSelector: target.MatchLabels,
				Strategy:    desired,
				MatcherMode: amtdv1beta1.MatcherModeExact,
			},
		}
		if cerr := p.Client.Create(ctx, &amtd); cerr != nil {
			return fmt.Errorf("create AMTD %s/%s: %w", target.Namespace, name, cerr)
		}
		return nil
	}

	// Update in place if the selector or strategy drifted.
	amtd.Spec.PodSelector = target.MatchLabels
	amtd.Spec.Strategy = desired
	if amtd.Spec.MatcherMode == "" {
		amtd.Spec.MatcherMode = amtdv1beta1.MatcherModeExact
	}
	if uerr := p.Client.Update(ctx, &amtd); uerr != nil {
		return fmt.Errorf("update AMTD %s/%s: %w", target.Namespace, name, uerr)
	}
	return nil
}

// Actuate emits the controlled SecurityEvent for one move. Implements Actuator.
func (p *PhoenixActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	ruleType := RuleTypeFor(req.Action)
	if ruleType == "" {
		return Result{}, fmt.Errorf("phoenix actuator: unsupported action %q", req.Action)
	}
	se := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("phorvex-%s-", string(req.Action)),
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "phorvex",
				"phorvex.ai/tenant":            sanitize(req.Tenant),
				"phorvex.ai/action":            string(req.Action),
			},
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
	if req.CoverageValue != nil {
		se.Annotations = map[string]string{"phorvex.ai/coverage-contract": "selection-fact-weight-v1"}
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
