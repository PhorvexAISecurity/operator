package core

import (
	"github.com/phorvex/metricvalidity"
)

// validity.go binds this package to the SHARED measurement-validity contract in
// metricvalidity. The contract itself — the wire types, the supported version
// and the one validated interpretation — lives there so the harness and every
// downstream reader share a single implementation instead of each mirroring the
// wire format by hand. Hand-mirrored readers omitted the very fields the
// producer had begun checking and silently certified rows the producer refused;
// there is now nothing to keep in sync.
//
// Everything below is an alias or a thin delegation, so existing core code and
// tests keep referring to the familiar names.

// The contract version this build stamps and understands.
const MeasurementValidityVersion = metricvalidity.Version

// Wire types. These are ALIASES, not copies: a core.MeasurementValidity IS a
// metricvalidity.Validity, so a reader in another module reasons about exactly
// the bytes this package writes.
type (
	MeasurementValidity  = metricvalidity.Validity
	BaselineRef          = metricvalidity.BaselineRef
	CleanupStep          = metricvalidity.CleanupStep
	CleanupRecord        = metricvalidity.CleanupRecord
	TrialKind            = metricvalidity.TrialKind
	MeasurementStatus    = metricvalidity.Status
	TrialPhase           = metricvalidity.Phase
	ValidatedMeasurement = metricvalidity.Verdict
	Observations         = metricvalidity.Observations
)

// Trial kinds.
const (
	TrialOrdinary        = metricvalidity.TrialOrdinary
	TrialNegativeControl = metricvalidity.TrialNegativeControl
	TrialAdaptive        = metricvalidity.TrialAdaptive
)

// Measurement statuses.
const (
	MeasurementValid   = metricvalidity.StatusValid
	MeasurementInvalid = metricvalidity.StatusInvalid
	MeasurementSkipped = metricvalidity.StatusSkipped
	MeasurementLegacy  = metricvalidity.StatusLegacy
)

// Lifecycle phases.
const (
	PhaseEnvFactory     = metricvalidity.PhaseEnvFactory
	PhaseCapabilityGate = metricvalidity.PhaseCapabilityGate
	PhaseDefenderSetup  = metricvalidity.PhaseDefenderSetup
	PhaseScenarioSetup  = metricvalidity.PhaseScenarioSetup
	PhaseDefenderStart  = metricvalidity.PhaseDefenderStart
	PhaseAttackExecute  = metricvalidity.PhaseAttackExecute
	PhaseOracle         = metricvalidity.PhaseOracle
	PhaseObserver       = metricvalidity.PhaseObserver
	PhaseCleanup        = metricvalidity.PhaseCleanup
	PhaseComplete       = metricvalidity.PhaseComplete
)

// MeasurementState returns the row's validity block as WRITTEN (the claim), or
// the LEGACY/UNVERIFIED block for a pre-contract row. It is the raw decoded
// evidence and is NOT a verdict: `scored: true` here is only an assertion by
// whatever produced the row. Every consumer that decides whether a number may be
// used must go through Validated().
func (m Metric) MeasurementState() MeasurementValidity {
	if m.Validity == nil {
		return metricvalidity.Legacy()
	}
	return *m.Validity
}

// IsLegacy reports whether the row predates the validity contract.
func (m Metric) IsLegacy() bool { return m.Validity == nil }

// observations are the cross-field values the contract corroborates the claim
// against. Keeping this in one place means a reader that decodes a subset of the
// schema still supplies exactly what the producer checks.
func (m Metric) observations() Observations {
	return Observations{
		Trial:                 m.Trial,
		Disruption:            m.DisruptionVsOracle,
		DefensiveActions:      m.DefensiveActions,
		FalseDefensiveActions: m.FalseDefensiveActions,
		TimeToActionSeconds:   m.TimeToActionSeconds,
		AttackerDwellSeconds:  m.AttackerDwellSeconds,
	}
}

// Validated checks the row's claims against this build's contract and against
// each other. It is the single authority behind IsScored, CostObserved, Kind,
// every aggregator, every reader and the provenance map.
func (m Metric) Validated() ValidatedMeasurement {
	return metricvalidity.Evaluate(m.Validity, m.observations())
}

// IsScored reports whether this row's disruption comparison may enter a
// certified score. It is the VALIDATED verdict, never the row's own claim.
func (m Metric) IsScored() bool { return m.Validated().Scorable }

// Kind returns the validated trial kind, falling back to the legacy markers for
// a pre-contract row (which never recorded the adaptive pass at all).
func (m Metric) Kind() TrialKind {
	if m.Validity == nil {
		if m.NegativeControl {
			return TrialNegativeControl
		}
		return TrialOrdinary
	}
	return m.Validated().Kind()
}

// CostObserved reports whether the defensive-action count and timing on this row
// may be used as observations. It is the VALIDATED verdict.
func (m Metric) CostObserved() bool { return m.Validated().CostUsable }

// CleanupFailed reports whether any owed cleanup step failed, was not attempted,
// is unresolved or was blocked. Legacy rows never recorded cleanup, so they
// report false and are excluded from certified scores on the legacy ground.
func (m Metric) CleanupFailed() bool {
	return m.Validity != nil && !m.Validity.Cleanup.Sound()
}
