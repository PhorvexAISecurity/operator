/*
 * Phorvex Console (P-DASHBOARD) — the IP-WALL (Requirement C).
 *
 * The platform-OWNER view leaks ZERO Phorvex IP, enforced SERVER-SIDE by a WHITELIST DTO.
 * VERIFIED NECESSITY: audit.Record carries every IP field inline (CoverageValue/ThreatRisk/
 * Cost/Net/Residual/ThreatPosture/Exposure/PHold/AssetValue/BlastRadius/PerDollar/CoveredWeight/Lambda/
 * ProactiveRate/Attribution + the raw Reason, which itself inlines cov/$/per-$/lambda/hazard/
 * pHold math). A naive json.Marshal(Record) on the owner path would leak the entire moat.
 *
 * toOwnerEvent builds an OwnerEvent by EXPLICIT FIELD-COPY of the whitelisted, owner-safe
 * fields ONLY — it NEVER marshals the Record/Decision and NEVER passes the raw Reason. The
 * redaction_test.go asserts the owner JSON contains NONE of the redacted field names; THAT
 * test is the eligibility gate. Because it is a whitelist, a newly-added IP field can never
 * leak by default.
 */

package console

import (
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// OwnerEvent is the ONLY shape the owner endpoint returns — the outcome, never the math.
// Every field here is owner-safe by construction (an owner sees what changed in THEIR
// platform + that it helped). NO EMR / scarcity / fact-weight / per-dollar / lambda /
// hazard / pHold / attribution / raw-risk field appears, by design.
type OwnerEvent struct {
	Representation  OwnerRepresentation `json:"representation"`
	Claim           model.ClaimScope    `json:"claim"`
	OutcomeEvidence string              `json:"outcomeEvidence"`
	Tenant          string              `json:"tenant"`
	Time            string              `json:"time,omitempty"` // RFC3339 decision timestamp (owner-safe: when, not score)
	Namespace       string              `json:"namespace"`
	Pod             string              `json:"pod"`
	Action          string              `json:"action"`
	Actuated        bool                `json:"actuated"`
	DryRun          bool                `json:"dryRun"`
	Handler         string              `json:"handler,omitempty"`
	ObjectsTouched  []string            `json:"objectsTouched,omitempty"`
	Reversible      bool                `json:"reversible"`      // mutationKind -> reversible|forward-only chip
	AttackPrevented bool                `json:"attackPrevented"` // Deprecated: always false, confirmation unavailable
	WorkPreserved   bool                `json:"workPreserved"`   // Deprecated: always false, confirmation unavailable
	HarmCaused      bool                `json:"harmCaused"`
	SLOKept         bool                `json:"sloKept"`      // Deprecated: always false, confirmation unavailable
	AttackStage     string              `json:"attackStage"`  // COARSE plain-English label, not the raw enum
	Why             string              `json:"why"`          // SERVER-AUTHORED, owner-safe outputs only
	BlindOutcome    string              `json:"blindOutcome"` // r6 counterfactual OUTCOME, sanitized
}

// coarseStage maps the internal kill-chain stage enum to a customer-facing label (never the
// raw enum / hazard math).
func coarseStage(stage string) string {
	switch stage {
	case "", "recon":
		return "early reconnaissance"
	case "exploit", "lateral", "exploitation":
		return "active intrusion"
	case "impact", "exfil":
		return "high-impact attempt"
	}
	if len(stage) > 0 {
		return "active threat"
	}
	return "monitored"
}

// ownerWhy authors a plain-English rationale from OWNER-SAFE outputs only. It NEVER reads
// rec.Reason / rec.CounterfactualNote (those inline the EMR/lambda/per-$ math verbatim).
//
// Dispatch is not effect confirmation. This legacy helper is used only after
// ownerRecordWhy has interpreted explicit outcome/mode fields conservatively.
func ownerWhy(action string, actuated, reversible, workPreserved, harm bool) string {
	if !actuated {
		if action == "" || action == "noop" {
			return "Evaluated this workload and took no action. This does not establish absence of a threat."
		}
		return "Action selected. No execution result recorded."
	}
	switch {
	case action == "quarantine":
		return "Attempted network isolation in place. Attacker removal, workload preservation and out-of-band gains are not confirmed by this record."
	case action == "rotate":
		return "Dispatched a rotation request. Pod replacement and security effect are not confirmed by this record."
	case action == "kv-reset":
		return "Dispatched a cache reset to attempt removal of modeled session state. Security effect is not independently confirmed by this record."
	case reversible:
		return "Dispatched a reversible protective change. Security effect and service availability require separate confirmation."
	default:
		return "Dispatched a targeted protective action. Security effect and workload preservation require separate confirmation."
	}
}

// blindOutcome sanitizes the R6 counterfactual to the OUTCOME only (what blind rotation
// would have done), never the underlying math. Gated on `actuated` for the same reason as
// ownerWhy: a counterfactual comparison is meaningless (and flattering) when Phorvex itself
// did nothing.
func blindOutcome(action string, actuated, workPreserved bool) string {
	return "No verified comparison with a scheduled defense is available for this record."
}

// ownerOutcome interprets existing evidence only. No generic confirmation flag,
// future field, or elapsed time can promote a record to confirmed effect.
func ownerOutcome(rec audit.Record) string {
	dispatch := ""
	if rec.DecisionTrace != nil {
		dispatch = rec.DecisionTrace.DispatchOutcome
	}
	if rec.DryRun {
		if rec.Actuated || dispatch == model.DispatchEmitted || dispatch == model.DispatchError {
			return "unknown"
		}
		return "dry-run"
	}
	switch dispatch {
	case model.DispatchError:
		return "unknown"
	case model.DispatchNotAttempted:
		if rec.Actuated {
			return "unknown"
		}
		return "not-attempted"
	case model.DispatchEmitted:
		if !rec.Actuated {
			return "unknown"
		}
		return "emitted-unconfirmed"
	case model.DispatchEmittedFalse:
		if rec.Actuated {
			return "unknown"
		}
		if ownerRefusal(rec) != "" {
			return "not-emitted"
		}
		return "unknown"
	case "":
		if rec.Actuated {
			return "emitted-unconfirmed"
		}
		if ownerRefusal(rec) != "" {
			return "not-emitted"
		}
		if rec.Selected {
			return "selected"
		}
		return "unknown"
	default:
		return "unknown"
	}
}

// ToOwnerEvent is the WHITELIST projection: explicit field-copy of owner-safe fields ONLY.
// It is the single construction point for the owner payload — never marshal a Record here.
func ToOwnerEvent(rec audit.Record) OwnerEvent {
	reversible := rec.MutationKind == "reversible" || rec.MutationKind == "swap"
	workPreserved := false
	harm := false
	claim := model.NewClaimScope(nil, false, "", "")
	if rec.DecisionTrace != nil {
		claim = model.NewClaimScope(nil, false, rec.DecisionTrace.BrainImage, rec.DecisionTrace.GitSHA)
	}
	if rec.Claim != nil {
		claim = model.NewClaimScope(rec.Claim.DetectorSet, rec.Claim.DetectorSetKnown, rec.Claim.BrainImage, rec.Claim.GitSHA)
	}
	return OwnerEvent{
		Representation:  ownerRepresentation(rec),
		Claim:           claim,
		OutcomeEvidence: ownerOutcome(rec),
		Tenant:          rec.Tenant,
		Time:            rec.Time.Format(time.RFC3339),
		Namespace:       rec.Namespace,
		Pod:             rec.Pod,
		Action:          rec.Action,
		Actuated:        rec.Actuated,
		DryRun:          rec.DryRun,
		Handler:         rec.Handler,
		ObjectsTouched:  rec.ObjectsTouched,
		Reversible:      reversible,
		AttackPrevented: false,
		WorkPreserved:   workPreserved,
		HarmCaused:      harm,
		SLOKept:         false, // Legacy field disabled: no measured outcome available.
		AttackStage:     coarseStage(rec.Stage),
		Why:             ownerRecordWhy(rec, reversible, workPreserved, harm),
		BlindOutcome:    blindOutcome(rec.Action, rec.Actuated, workPreserved),
	}
}

// redactedFieldNames are the IP-internal JSON keys/substrings that MUST NOT appear in any
// owner payload. redaction_test.go asserts the marshaled OwnerEvent contains none of them.
var redactedFieldNames = []string{
	"emr", "scarcity", "imagerarity", "epss", "coresidency", "modelrarity", "dispersion",
	"factweight", "coveredweight", "coveredfacts", "coverkeys", "factkind",
	"perdollar", "lambda", "proactiverate", "costceiling", "shadowprice",
	"residual", "threatposture", "exposure", "belief", "phold", "stagehazard",
	"preemptmargin", "projectednextstagesec", "assetvalue", "blastradius",
	"attribution", "coveragevalue", "threatrisk", "\"risk\"", "\"cost\"", "\"net\"", "\"reason\"", "counterfactualnote",
	"submodular", "greedy",
}

func mustNoIP(jsonBody string) (string, bool) {
	low := toLower(jsonBody)
	for _, n := range redactedFieldNames {
		if containsStr(low, n) {
			return n, false
		}
	}
	return "", true
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
func containsStr(haystack, needle string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return len(needle) == 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Only fixed, reviewed native refusal reasons may enter the owner-safe narrative.
func ownerRefusal(rec audit.Record) string {
	if rec.Action == "rotate" && !rec.Actuated && rec.DecisionTrace != nil {
		switch rec.DecisionTrace.DispatchReason {
		case "Rotation not performed: ownerless", "Rotation not performed: owner-unresolved", "Rotation not performed: owner-uid-mismatch", "Rotation not performed: owner-terminating", "Rotation not performed: owner-kind-unsupported", "Rotation not performed: owner-state-ineligible":
			return "Rotation not performed: no verified replacement controller."
		case "Rotation not performed: mirror-pod":
			return "Rotation not performed: this is a mirror of a static Pod."
		case "Rotation not performed: target-uid-mismatch", "Rotation not performed: target-changed-before-delete":
			return "Rotation not performed: the target changed before deletion."
		}
	}
	return ""
}

func ownerRecordWhy(rec audit.Record, reversible, workPreserved, harm bool) string {
	switch ownerOutcome(rec) {
	case "emitted-unconfirmed":
		return ownerWhy(rec.Action, true, reversible, false, false)
	case "not-emitted":
		return ownerRefusal(rec)
	case "dry-run":
		return "Dry-run: action recommended, execution disabled."
	case "selected":
		return "Action selected. No execution result recorded."
	case "not-attempted":
		return "Action selected but not dispatched by this attempt."
	default:
		return "Action outcome unknown. Completion and security effect are not confirmed."
	}
}
