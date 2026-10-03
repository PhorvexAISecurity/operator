package console

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// A LiteLLM/Voice live-probe attack records only its brain decision id (no observed stimulus
// event), so fillReasoning's exact-event-uid path never binds its objective math. The
// decision-id correlation must attach the same reason + economics the vLLM path attaches, so
// the per-attack report no longer shows a bare 0 for a decision that was really made.
func TestLiveProbeDecisionAttachesMathByDecisionID(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	trace := caseTraceValidTrace(now.Add(time.Second), true, false)
	if err := trace.Validate(); err != nil {
		t.Fatalf("fixture trace invalid: %v", err)
	}
	economics := &model.EconomicsMetadata{
		Version:                  model.EconomicsFixedDisruptionAversionV1,
		DisruptionAversion:       model.OptionalFloat{Present: true, Value: 0.00004},
		LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 0.123456789},
		EffectiveCostCoefficient: 0.00004,
		CoefficientSource:        model.CostCoefficientSourceBeta,
	}
	rec := audit.Record{
		Kind: "phorvex.decision", Time: now.Add(time.Second),
		Namespace: "litellm", Pod: "litellm-0", Action: "rotate",
		Selected: true, Actuated: true,
		Reason:        "rotate: strict gain 3.20 > 0 (fullValue=3.50 ECost=0.30 lambdaRuntimeLegacy=0.1235); stage=query-abuse hazard=0.00 pHold=0.70",
		Lambda:        0.1235,
		Economics:     economics,
		DecisionTrace: trace,
	}
	path := writeDecisionAudit(t, rec)
	s := NewServer(Config{AuditPath: path, Now: func() time.Time { return now.Add(3 * time.Second) }})
	r := &attackRecord{
		FiredAt: now.Format(time.RFC3339Nano), Namespace: "litellm", Service: "litellm",
		EvidenceKind:     "litellm-live-client-policy",
		ObservationStart: now.Format(time.RFC3339Nano),
		ObservationEnd:   now.Add(8 * time.Second).Format(time.RFC3339Nano),
		LiteLLMLiveProbe: &liteLLMLiveProbeResult{SelectionDecisionID: "decision-1", SelectedAction: "rotate"},
	}

	s.attachLiveProbeDecision("", r)

	if r.DecisionEvidence == nil {
		t.Fatalf("decision evidence not attached for a live-probe attack carrying a decision id")
	}
	if r.DecisionEvidence.Correlation != "exact-decision-id" || r.DecisionEvidence.DecisionID != "decision-1" ||
		r.DecisionEvidence.Action != "rotate" || r.DecisionEvidence.Reason != rec.Reason {
		t.Fatalf("wrong decision evidence: %+v", r.DecisionEvidence)
	}
	if !r.EconomicsAvailable || !r.LambdaAvailable || r.Lambda != 0.1235 {
		t.Fatalf("economics not attached: available=%v lambdaAvailable=%v lambda=%v", r.EconomicsAvailable, r.LambdaAvailable, r.Lambda)
	}
	if r.DecisionAuditCoverage != "sampled-live-tail" || len(r.DecisionTraceEvidence) != 1 {
		t.Fatalf("coverage=%q traceEvidence=%d", r.DecisionAuditCoverage, len(r.DecisionTraceEvidence))
	}
}

// Production decision traces read from the audit wire do not always pass the full V7
// Validate() (seen live: LiteLLM decisions matched by id but were skipped because the match
// required Validate()==nil). The correlation must still attach the real reason + economics +
// decisionId from an id-matching trace that does not fully validate.
func TestLiveProbeDecisionAttachesWhenTraceDoesNotValidate(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	trace := caseTraceValidTrace(now.Add(time.Second), true, false)
	trace.LambdaRuntime = 99 // out of the 0..10 bound -> Validate() fails, id unchanged
	if trace.Validate() == nil {
		t.Fatal("fixture precondition: trace must NOT validate")
	}
	economics := &model.EconomicsMetadata{
		Version:                  model.EconomicsFixedDisruptionAversionV1,
		DisruptionAversion:       model.OptionalFloat{Present: true, Value: 0.00004},
		LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 0.123456789},
		EffectiveCostCoefficient: 0.00004,
		CoefficientSource:        model.CostCoefficientSourceBeta,
	}
	rec := audit.Record{
		Kind: "phorvex.decision", Time: now.Add(time.Second), Namespace: "litellm", Pod: "litellm-0",
		Action: "rotate", Selected: true, Actuated: true,
		Reason: "rotate: strict gain 3.20 > 0 (fullValue=3.50 ECost=0.30 lambdaRuntimeLegacy=0.1235); stage=query-abuse hazard=0.00 pHold=0.70",
		Lambda: 0.1235, Economics: economics, DecisionTrace: trace,
	}
	path := writeDecisionAudit(t, rec)
	s := NewServer(Config{AuditPath: path, Now: func() time.Time { return now.Add(3 * time.Second) }})
	r := &attackRecord{
		FiredAt: now.Format(time.RFC3339Nano), Namespace: "litellm", EvidenceKind: "litellm-live-client-policy",
		ObservationStart: now.Format(time.RFC3339Nano), ObservationEnd: now.Add(8 * time.Second).Format(time.RFC3339Nano),
		LiteLLMLiveProbe: &liteLLMLiveProbeResult{SelectionDecisionID: "decision-1", SelectedAction: "rotate"},
	}

	s.attachLiveProbeDecision("", r)

	if r.DecisionEvidence == nil || r.DecisionEvidence.Reason != rec.Reason {
		t.Fatalf("reason not attached from a non-validating trace: %+v", r.DecisionEvidence)
	}
	if r.DecisionEvidence.DecisionID != "decision-1" {
		t.Fatalf("decisionId not backfilled from non-validating trace: %+v", r.DecisionEvidence)
	}
	if !r.EconomicsAvailable || r.Lambda != 0.1235 {
		t.Fatalf("economics not attached: available=%v lambda=%v", r.EconomicsAvailable, r.Lambda)
	}
}

// A live-probe attack that never produced a decision (e.g. it did not land) carries no probe
// decision id, and the enrichment must leave the record truthfully blank rather than inventing
// a correlation.
func TestLiveProbeDecisionNoopWhenNoDecisionID(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	trace := caseTraceValidTrace(now.Add(time.Second), true, false)
	rec := audit.Record{
		Kind: "phorvex.decision", Time: now.Add(time.Second), Namespace: "voice", Pod: "voice-0",
		Action: "rotate", Selected: true, Actuated: true, Reason: "rotate: strict gain 1 > 0", DecisionTrace: trace,
	}
	path := writeDecisionAudit(t, rec)
	s := NewServer(Config{AuditPath: path, Now: func() time.Time { return now.Add(3 * time.Second) }})
	r := &attackRecord{
		FiredAt: now.Format(time.RFC3339Nano), Namespace: "voice", EvidenceKind: "voice-agency-live",
		ObservationStart: now.Format(time.RFC3339Nano), ObservationEnd: now.Add(8 * time.Second).Format(time.RFC3339Nano),
		VoiceAgencyProbe: &voiceAgencyProbeResult{SelectedDecisionID: "", SelectedAction: ""},
	}

	s.attachLiveProbeDecision("", r)

	if r.DecisionEvidence != nil || r.EconomicsAvailable || r.DecisionAuditCoverage != "" {
		t.Fatalf("no-decision live probe must stay blank: evidence=%+v econ=%v coverage=%q",
			r.DecisionEvidence, r.EconomicsAvailable, r.DecisionAuditCoverage)
	}
}
