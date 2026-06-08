package report

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ProvenanceEntry ties one reported result to the EXACT commands + raw log + seed
// that produced it, so every table cell is reproducible from the fixed seed.
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
		pm.Entries = append(pm.Entries, ProvenanceEntry{
			Scenario:        m.Scenario,
			Defender:        m.Defender,
			Trial:           m.Trial,
			Seed:            m.Seed,
			RawLogPath:      m.RawLogPath,
			Commands:        m.Commands,
			OracleAchieved:  m.OracleAchieved,
			Disruption:      m.DisruptionVsOracle,
			ObservedState:   m.ObservedState,
			NegativeControl: m.NegativeControl,
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
