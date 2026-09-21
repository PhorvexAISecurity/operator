package model

import (
	"encoding/json"
	"fmt"
	"math"
	"unicode/utf8"
)

const (
	ScopedOutcomeEvidenceCapacity = 1024
	ScopedOutcomeCohortCapacity   = 64
	ScopedOutcomeOwnerCapacity    = 1024
	ScopedOutcomeWilson95Z        = 1.959963984540054
	ScopedOutcomeIntervalWilson95 = "wilson-95-raw-held-proportion"
)

// ScopedOutcomeCohortKey prevents a synthetic session result from being
// generalized across policy generations, workloads, capabilities or actions.
type ScopedOutcomeCohortKey struct {
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	WorkloadScopeSHA256 string `json:"workloadScopeSHA256"`
	Capability          string `json:"capability"`
	Action              Action `json:"action"`
	ContractVersion     string `json:"contractVersion"`
}

func (k ScopedOutcomeCohortKey) Validate() error {
	if k.PolicyUID == "" || len(k.PolicyUID) > 253 || !utf8.ValidString(k.PolicyUID) || k.PolicyGeneration <= 0 ||
		!validLowerSHA256(k.WorkloadScopeSHA256) || k.Capability != ScopedSessionCapability ||
		k.Action != ActionRotate || k.ContractVersion != ScopedSessionNativeRotateV1 {
		return fmt.Errorf("invalid scoped outcome cohort key")
	}
	return nil
}

type ScopedOutcomeInterval struct {
	Method string  `json:"method"`
	Lower  float64 `json:"lower"`
	Upper  float64 `json:"upper"`
}

// ScopedOutcomeCohort is descriptive reporting for one exact synthetic
// capability population. Calibrated must remain false until a separate fitting
// and held-out evaluation contract is delivered.
type ScopedOutcomeCohort struct {
	Key             ScopedOutcomeCohortKey `json:"key"`
	Held            int                    `json:"held"`
	Revoked         int                    `json:"revoked"`
	Unknown         int                    `json:"unknown"`
	Censored        int                    `json:"censored"`
	N               int                    `json:"n"`
	PriorAlpha      float64                `json:"priorAlpha"`
	PriorBeta       float64                `json:"priorBeta"`
	PosteriorMean   float64                `json:"posteriorMean"`
	RawHeldInterval *ScopedOutcomeInterval `json:"rawHeldInterval,omitempty"`
	Calibrated      bool                   `json:"calibrated"`
}

// ScopedOutcomeReport is an audit snapshot. It never enters PHold, cost or
// selection. Cohorts are sorted by their canonical key before publication.
type ScopedOutcomeReport struct {
	SchemaVersion         string                `json:"schemaVersion"`
	Source                string                `json:"source"`
	ProcessEpochID        string                `json:"processEpochID"`
	ResetBoundary         string                `json:"resetBoundary"`
	Disposition           string                `json:"disposition"`
	Reason                string                `json:"reason,omitempty"`
	Policy                *PolicyEpoch          `json:"policy,omitempty"`
	EvidenceID            string                `json:"evidenceID,omitempty"`
	Outcome               string                `json:"outcome,omitempty"`
	Cohorts               []ScopedOutcomeCohort `json:"cohorts,omitempty"`
	ReplayEntries         int                   `json:"replayEntries"`
	ReplayCapacity        int                   `json:"replayCapacity"`
	CohortCapacity        int                   `json:"cohortCapacity"`
	LifetimeOwners        int                   `json:"lifetimeOwners"`
	LifetimeOwnerCapacity int                   `json:"lifetimeOwnerCapacity"`
}

func ValidateScopedOutcomeReport(report *ScopedOutcomeReport) error {
	if report == nil {
		return nil
	}
	if report.SchemaVersion != ScopedOutcomeReportSchemaV1 || report.Source == "" || report.ProcessEpochID == "" ||
		report.ResetBoundary != "process-start" || report.Disposition == "" ||
		len(report.Source) > 128 || len(report.ProcessEpochID) > 253 || !utf8.ValidString(report.Source) || !utf8.ValidString(report.ProcessEpochID) {
		return fmt.Errorf("scoped outcome report lacks valid schema, source, process epoch, reset boundary or disposition")
	}
	if report.Policy != nil {
		if err := report.Policy.Validate(); err != nil {
			return fmt.Errorf("scoped outcome policy: %w", err)
		}
	}
	if report.ReplayEntries < 0 || report.ReplayCapacity != ScopedOutcomeEvidenceCapacity || report.ReplayEntries > report.ReplayCapacity ||
		report.CohortCapacity != ScopedOutcomeCohortCapacity || len(report.Cohorts) > report.CohortCapacity ||
		report.LifetimeOwners < 0 || report.LifetimeOwnerCapacity != ScopedOutcomeOwnerCapacity || report.LifetimeOwners > report.LifetimeOwnerCapacity {
		return fmt.Errorf("scoped outcome report capacities are contradictory")
	}
	if report.EvidenceID != "" && (len(report.EvidenceID) > 253 || !utf8.ValidString(report.EvidenceID)) {
		return fmt.Errorf("scoped outcome evidence identity is invalid")
	}
	if len(report.Reason) > 253 || !utf8.ValidString(report.Reason) {
		return fmt.Errorf("scoped outcome reason is oversized or invalid UTF-8")
	}
	switch report.Disposition {
	case PersistenceDispositionNoProducer, PersistenceDispositionNoLabel, PersistenceDispositionApplied,
		PersistenceDispositionDuplicate, PersistenceDispositionConflict, PersistenceDispositionSaturated,
		PersistenceDispositionExpired, PersistenceDispositionRejected, PersistenceDispositionUnresolved,
		PersistenceDispositionEarly, PersistenceDispositionUnavailable:
	default:
		return fmt.Errorf("unknown scoped outcome disposition %q", report.Disposition)
	}
	if report.Outcome != "" && !validPersistenceOutcome(report.Outcome) {
		return fmt.Errorf("unknown scoped outcome %q", report.Outcome)
	}
	if (report.EvidenceID == "") != (report.Outcome == "") {
		return fmt.Errorf("scoped outcome evidence identity and outcome presence differ")
	}
	if len(report.Cohorts) > 0 && (report.Policy == nil || report.Source != ScopedSessionCapability || report.ProcessEpochID == "unconfigured") {
		return fmt.Errorf("scoped outcome cohorts lack exact policy, source, or process provenance")
	}
	switch report.Disposition {
	case PersistenceDispositionApplied, PersistenceDispositionDuplicate, PersistenceDispositionConflict:
		if report.EvidenceID == "" {
			return fmt.Errorf("scoped outcome disposition %q lacks evidence identity", report.Disposition)
		}
	case PersistenceDispositionNoLabel, PersistenceDispositionUnavailable:
		if report.EvidenceID != "" {
			return fmt.Errorf("scoped outcome disposition %q carries unrelated evidence", report.Disposition)
		}
	}
	if report.Disposition == PersistenceDispositionNoProducer && (report.Source != "none" || report.ProcessEpochID != "unconfigured" || report.EvidenceID != "" || report.Outcome != "" || report.ReplayEntries != 0 || len(report.Cohorts) != 0) {
		return fmt.Errorf("no-producer scoped outcome report carries producer or evidence state")
	}
	if report.Disposition == PersistenceDispositionNoLabel && (report.Source != ScopedSessionCapability || report.ProcessEpochID == "unconfigured" || report.Policy == nil || report.EvidenceID != "" || report.Outcome != "") {
		return fmt.Errorf("no-label scoped outcome report is contradictory")
	}
	previousKey := ""
	total := 0
	for i := range report.Cohorts {
		if err := validateScopedOutcomeCohort(report.Cohorts[i]); err != nil {
			return fmt.Errorf("scoped outcome cohort %d: %w", i, err)
		}
		// One owner report intentionally retains prior-generation cohorts behind
		// the current policy epoch. A cohort can never belong to another UID or a
		// future generation.
		if report.Policy == nil || report.Cohorts[i].Key.PolicyUID != report.Policy.UID || report.Cohorts[i].Key.PolicyGeneration > report.Policy.Generation {
			return fmt.Errorf("scoped outcome cohort %d contradicts report policy", i)
		}
		if report.Disposition == PersistenceDispositionNoLabel && report.Cohorts[i].Key.PolicyGeneration == report.Policy.Generation {
			return fmt.Errorf("no-label scoped outcome report carries a current-generation cohort")
		}
		encoded, _ := json.Marshal(report.Cohorts[i].Key)
		key := string(encoded)
		if i > 0 && key <= previousKey {
			return fmt.Errorf("scoped outcome cohorts are duplicated or not canonical")
		}
		previousKey = key
		counts := []int{report.Cohorts[i].Held, report.Cohorts[i].Revoked, report.Cohorts[i].Unknown, report.Cohorts[i].Censored}
		for _, count := range counts {
			if count < 0 || count > ScopedOutcomeEvidenceCapacity || total > ScopedOutcomeEvidenceCapacity-count {
				return fmt.Errorf("scoped outcome counts exceed the replay capacity")
			}
			total += count
		}
	}
	if total != report.ReplayEntries {
		return fmt.Errorf("scoped outcome counts do not match replay entries")
	}
	return nil
}

func validateScopedOutcomeCohort(c ScopedOutcomeCohort) error {
	if err := c.Key.Validate(); err != nil {
		return err
	}
	if c.Held < 0 || c.Held > ScopedOutcomeEvidenceCapacity || c.Revoked < 0 || c.Revoked > ScopedOutcomeEvidenceCapacity ||
		c.Unknown < 0 || c.Unknown > ScopedOutcomeEvidenceCapacity || c.Censored < 0 || c.Censored > ScopedOutcomeEvidenceCapacity ||
		c.Held > ScopedOutcomeEvidenceCapacity-c.Revoked || c.N != c.Held+c.Revoked ||
		c.PriorAlpha != 1 || c.PriorBeta != 1 || c.Calibrated {
		return fmt.Errorf("invalid scoped outcome counts, prior, or calibration claim")
	}
	wantMean := float64(1+c.Held) / float64(2+c.N)
	if !finiteScoped(c.PosteriorMean) || math.Abs(c.PosteriorMean-wantMean) > 1e-12 {
		return fmt.Errorf("posterior mean does not match Beta(1,1) formula")
	}
	if c.N == 0 {
		if c.RawHeldInterval != nil {
			return fmt.Errorf("n=0 must not report a Wilson interval")
		}
		return nil
	}
	lower, upper := Wilson95(c.Held, c.N)
	if c.RawHeldInterval == nil || c.RawHeldInterval.Method != ScopedOutcomeIntervalWilson95 ||
		!finiteScoped(c.RawHeldInterval.Lower) || !finiteScoped(c.RawHeldInterval.Upper) ||
		c.RawHeldInterval.Lower < 0 || c.RawHeldInterval.Upper > 1 || c.RawHeldInterval.Lower > c.RawHeldInterval.Upper ||
		math.Abs(c.RawHeldInterval.Lower-lower) > 1e-12 || math.Abs(c.RawHeldInterval.Upper-upper) > 1e-12 {
		return fmt.Errorf("raw held interval does not match Wilson 95%%")
	}
	return nil
}

func Wilson95(held, n int) (float64, float64) {
	if n <= 0 || held < 0 || held > n {
		return 0, 0
	}
	z := ScopedOutcomeWilson95Z
	nf := float64(n)
	p := float64(held) / nf
	z2 := z * z
	denom := 1 + z2/nf
	center := (p + z2/(2*nf)) / denom
	half := z * math.Sqrt((p*(1-p)+z2/(4*nf))/nf) / denom
	return center - half, center + half
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validPersistenceOutcome(value string) bool {
	switch value {
	case PersistenceHeld, PersistenceRevoked, PersistenceUnknown, PersistenceCensored:
		return true
	default:
		return false
	}
}

func finiteScoped(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
