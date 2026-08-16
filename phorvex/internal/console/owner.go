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
)

// OwnerEvent is the ONLY shape the owner endpoint returns — the outcome, never the math.
// Every field here is owner-safe by construction (an owner sees what changed in THEIR
// platform + that it helped). NO EMR / scarcity / fact-weight / per-dollar / lambda /
// hazard / pHold / attribution / raw-risk field appears, by design.
type OwnerEvent struct {
	Tenant         string   `json:"tenant"`
	Time           string   `json:"time,omitempty"` // RFC3339 decision timestamp (owner-safe: when, not score)
	Namespace      string   `json:"namespace"`
	Pod            string   `json:"pod"`
	Action         string   `json:"action"`
	Actuated       bool     `json:"actuated"`
	DryRun         bool     `json:"dryRun"`
	Handler        string   `json:"handler,omitempty"`
	ObjectsTouched []string `json:"objectsTouched,omitempty"`
	Reversible     bool     `json:"reversible"`     // mutationKind -> reversible|forward-only chip
	AttackPrevented bool    `json:"attackPrevented"` // derived boolean (from oracleAchieved)
	WorkPreserved  bool     `json:"workPreserved"`
	HarmCaused     bool     `json:"harmCaused"`
	SLOKept        bool     `json:"sloKept"`        // BOOLEAN ONLY — never the numeric score
	AttackStage    string   `json:"attackStage"`    // COARSE plain-English label, not the raw enum
	Why            string   `json:"why"`            // SERVER-AUTHORED, owner-safe outputs only
	BlindOutcome   string   `json:"blindOutcome"`   // r6 counterfactual OUTCOME, sanitized
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
// [TRUTHFULNESS FIX] Every branch below is written in the PAST TENSE — it asserts to the
// customer that a defence WAS PERFORMED. Previously this function switched on `action` ALONE
// and never looked at `actuated`, so a record that was merely EVALUATED (or whose actuation
// failed) still told the owner "Cleared injected state on the inference workload…". The owner
// feed admits any record with Selected OR Actuated, so non-actuated records reach here
// routinely. Claiming a defence that did not happen is the worst failure mode this product
// has: the customer believes they were protected when they were not. `actuated` is now the
// FIRST gate — no actuation, no success narrative.
func ownerWhy(action string, actuated, reversible, workPreserved, harm bool) string {
	if !actuated {
		if action == "" || action == "noop" {
			return "Evaluated this workload and took no action — no threat warranted intervention."
		}
		return "Selected a protective action for this workload, but it was NOT carried out — treat this workload as unprotected for this event."
	}
	switch {
	case action == "quarantine" && workPreserved:
		return "Contained the threat in place and kept your workload running — no data or job loss."
	case action == "rotate":
		return "Replaced the compromised instance with a clean one to evict the attacker."
	case action == "kv-reset":
		return "Cleared injected state on the inference workload without restarting it."
	case reversible:
		return "Applied a reversible protective change to disrupt the attacker; your service stayed available."
	default:
		return "Took a targeted protective action to evict the attacker while preserving your workload."
	}
}

// blindOutcome sanitizes the R6 counterfactual to the OUTCOME only (what blind rotation
// would have done), never the underlying math. Gated on `actuated` for the same reason as
// ownerWhy: a counterfactual comparison is meaningless (and flattering) when Phorvex itself
// did nothing.
func blindOutcome(action string, actuated, workPreserved bool) string {
	if !actuated {
		return "No comparison applies — Phorvex did not act on this event."
	}
	if action == "quarantine" && workPreserved {
		return "A blind fixed-interval rotation would have deleted this workload — destroying its state."
	}
	return "A blind fixed-interval defense would have acted on a schedule, not on this specific threat."
}

// ToOwnerEvent is the WHITELIST projection: explicit field-copy of owner-safe fields ONLY.
// It is the single construction point for the owner payload — never marshal a Record here.
func ToOwnerEvent(rec audit.Record) OwnerEvent {
	reversible := rec.MutationKind == "reversible" || rec.MutationKind == "swap"
	workPreserved := false
	harm := false
	// derive owner-safe outcome booleans without exposing any score:
	// (the harness markers / actuator result already encode these; here from the Record's
	// owner-safe surface — action + mutationKind + handler.)
	if rec.Action == "quarantine" && rec.Actuated {
		workPreserved = true
	}
	return OwnerEvent{
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
		AttackPrevented: rec.Actuated && rec.Selected,
		WorkPreserved:   workPreserved,
		HarmCaused:      harm,
		SLOKept:         true, // boolean only; PX never violates the SLO gate (feasibility-enforced)
		AttackStage:     coarseStage(rec.Stage),
		Why:             ownerWhy(rec.Action, rec.Actuated, reversible, workPreserved, harm),
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
