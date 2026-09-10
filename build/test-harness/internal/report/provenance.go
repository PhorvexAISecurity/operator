package report

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ProvenanceEntry ties one reported result to the EXACT commands + raw log + seed
// that produced it, so every table cell is reproducible from the fixed seed. It
// also carries the measurement-validity verdict for the row, so a provenance
// consumer can tell a measured comparison from a failed, abstained, unanchored
// or legacy/unverified one without re-reading metrics.jsonl.
type ProvenanceEntry struct {
	Scenario        string   `json:"scenario"`
	Defender        string   `json:"defender"`
	Trial           int      `json:"trial"`
	Seed            int64    `json:"seed"`
	RawLogPath      string   `json:"rawLogPath"`
	Commands        []string `json:"commands"`
	OracleAchieved  bool     `json:"oracleAchieved"`
	Disruption      float64  `json:"disruptionVsOracle"`
	ObservedState   string   `json:"observedState"`
	NegativeControl bool     `json:"negativeControl"`

	// TrialKind / Status / Scored describe HOW MUCH of this row is a measurement.
	// Disruption is only a measurement when Scored is true.
	TrialKind core.TrialKind         `json:"trialKind"`
	Status    core.MeasurementStatus `json:"measurementStatus"`
	Scored    bool                   `json:"scored"`
	// OracleObserved says whether OracleAchieved is an observation at all.
	OracleObserved bool `json:"oracleObserved"`
	// ControlDefender / ControlUsable identify the positive control this row was
	// anchored to; UnscoredReason explains an unscored row.
	ControlDefender string `json:"controlDefender,omitempty"`
	ControlUsable   bool   `json:"controlUsable"`
	UnscoredReason  string `json:"unscoredReason,omitempty"`
	// CleanupComplete is false when owed cleanup did not verify;
	// CleanupUnresolved is true when a cleanup call outlived its bound and may
	// still be running.
	CleanupComplete   bool `json:"cleanupComplete"`
	CleanupUnresolved bool `json:"cleanupUnresolved,omitempty"`
	// Unverified is true when this build could not interpret the row's validity
	// claims or found them self-contradictory.
	Unverified bool `json:"unverified,omitempty"`
}

// unscoredReason prefers the producer's own explanation and falls back to this
// build's first rejection, so a row refused on decode still says why.
func unscoredReason(val core.ValidatedMeasurement) string {
	if val.Scorable {
		return ""
	}
	if r := val.Claim.UnscoredReason; r != "" {
		return r
	}
	return firstNonEmpty(val.Rejections)
}

// ProvenanceMap is the whole map plus the run-level reproduction recipe.
type ProvenanceMap struct {
	MasterSeed   int64             `json:"masterSeed"`
	TrialsPerArm int               `json:"trialsPerArm"`
	Context      string            `json:"context"`
	Namespace    string            `json:"namespace"`
	MetricsFile  string            `json:"metricsFile"`
	Entries      []ProvenanceEntry `json:"entries"`
	// HowToReproduce is the exact command to re-run the identical benchmark.
	HowToReproduce string `json:"howToReproduce"`
}

// BuildProvenance constructs the provenance map from the metric stream.
func BuildProvenance(metrics []core.Metric, masterSeed int64, trialsPerArm int, kubeContext, namespace, metricsFile, reproduceCmd string) ProvenanceMap {
	pm := ProvenanceMap{
		MasterSeed:     masterSeed,
		TrialsPerArm:   trialsPerArm,
		Context:        kubeContext,
		Namespace:      namespace,
		MetricsFile:    metricsFile,
		HowToReproduce: reproduceCmd,
	}
	for _, m := range metrics {
		// The provenance entry carries the VALIDATED verdict, not the row's own
		// claim, so a provenance consumer sees exactly what the reports scored.
		val := m.Validated()
		v := val.Claim
		pm.Entries = append(pm.Entries, ProvenanceEntry{
			Scenario:          m.Scenario,
			Defender:          m.Defender,
			Trial:             m.Trial,
			Seed:              m.Seed,
			RawLogPath:        m.RawLogPath,
			Commands:          m.Commands,
			OracleAchieved:    m.OracleAchieved,
			Disruption:        m.DisruptionVsOracle,
			ObservedState:     m.ObservedState,
			NegativeControl:   m.NegativeControl,
			TrialKind:         m.Kind(),
			Status:            val.Status(),
			Scored:            val.Scorable,
			OracleObserved:    val.OracleUsable,
			ControlDefender:   v.Baseline.Defender,
			ControlUsable:     v.Baseline.Usable && val.Scorable,
			UnscoredReason:    unscoredReason(val),
			CleanupComplete:   v.Cleanup.Complete,
			CleanupUnresolved: v.Cleanup.Unresolved,
			Unverified:        val.Unverified,
		})
	}
	return pm
}

// WriteProvenance writes provenance.json into outDir.
func WriteProvenance(outDir string, pm ProvenanceMap) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(outDir, "provenance.json")
	b, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
