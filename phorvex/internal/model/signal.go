/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package model

import "time"

// State is the observation state of one telemetry Signal (T1-C, SENSING->ECONOMICS).
//
// It makes the four distinguishable conditions of property P-SENSING type-level: a
// consumer cannot read an absent, stale, or errored signal as a measured zero, because
// the zero Value only carries meaning when Usable() (State == Present). This is the
// structural fix for M-142/M-113/M-130 — "absence read as measurement" is no longer
// expressible without going through the state.
//
// Lives in internal/model (not internal/ingest as the T1-C ticket snippet suggested):
// model.Telemetry embeds Signal, and model cannot import ingest (ingest imports model),
// so the type must live at or below model. Recorded as a scope-forced deviation in 03.
type State uint8

const (
	// Absent — no series was returned for this pod+signal this scrape (honest "unknown",
	// NOT a measured zero). The zero value of State, so a never-populated Signal is Absent.
	Absent State = iota
	// Present — a fresh, finite sample within maxAge. Value is meaningful.
	Present
	// Stale — a last-good sample older than maxAge (3x scrape interval). Value retained in
	// the record for forensics but treated as absent by every consumer.
	Stale
	// Error — the query failed for this signal's source, or the sample was non-finite
	// (NaN/Inf). Value is meaningless and must never become a weight or cost.
	Error
)

// String renders the state for the decision record (present.<signal> / state).
func (s State) String() string {
	switch s {
	case Present:
		return "present"
	case Stale:
		return "stale"
	case Error:
		return "error"
	default:
		return "absent"
	}
}

// Signal is one observed telemetry value with its observation state, sample age, and
// source exporter/job. Value is meaningful ONLY when Usable() (State == Present); every
// other state means "unknown to consumers" and the per-consumer fallback table (T1-C)
// decides what happens — never a silent collapse to the zero Value.
type Signal struct {
	Value float64       // meaningful only when State == Present
	State State         // Absent | Present | Stale | Error
	Age   time.Duration // since the last successful sample; 0 when Present
	Src   string        // exporter/job name, for the record
	// Reason says WHY a signal is not a fresh measurement (PHORVEXSEC-200 / M-113). Two
	// non-measurements are different facts: the query FAILED (transport/HTTP/timeout —
	// "query-failed") versus the query SUCCEEDED and no series exists for this pod
	// ("no-series"). "" when Present.
	Reason string
}

// Signal reasons (M-113). A measured 0 is none of these.
const (
	ReasonQueryFailed       = "query-failed"       // transport / HTTP / timeout on the signal's query
	ReasonNoSeries          = "no-series"          // query succeeded; this pod has no series
	ReasonNonFinite         = "non-finite"         // saw the pod, NaN/Inf sample
	ReasonStale             = "stale"              // last-good reused within maxAge (State=Stale)
	ReasonSourceUnreachable = "source-unreachable" // every query of the source failed this tick
)

// Usable reports whether a consumer may read Value as a measured quantity. Stale, Error,
// and Absent are all "unknown" to consumers.
func (s Signal) Usable() bool { return s.State == Present }

// PresentSignal is a convenience constructor for a fresh, finite reading.
func PresentSignal(v float64, src string) Signal {
	return Signal{Value: v, State: Present, Src: src}
}
