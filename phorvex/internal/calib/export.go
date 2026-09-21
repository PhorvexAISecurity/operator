/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type coResidencyRow struct {
	Node                string  `json:"node"`
	Namespaces          int     `json:"namespaceCount"`
	X                   float64 `json:"xNode"`
	Pods                int     `json:"podCount"`
	Eligible            bool    `json:"eligible"`
	CandidateScale      float64 `json:"candidateScale"`
	CandidateMultiplier float64 `json:"candidateMultiplier"`
	ShippedMultiplier   float64 `json:"shippedMultiplier"`
}

type dispersionRow struct {
	Asset           string  `json:"asset"`
	ImageRarity     float64 `json:"imageRarity"`
	EPSS            float64 `json:"epss"`
	CoResidency     float64 `json:"coResidency"`
	ModelRarity     float64 `json:"modelRarity"`
	GPUOrModel      bool    `json:"gpuOrModel"`
	NamespaceCount  int     `json:"namespaceCount"`
	UncappedProduct float64 `json:"uncappedProduct"`
	CandidateCapped float64 `json:"candidateCapped"`
	ShippedCapped   float64 `json:"shippedCapped"`
}

type readyDelayRow struct {
	ID               string    `json:"id"`
	Tenant           string    `json:"tenant"`
	Namespace        string    `json:"namespace"`
	Pod              string    `json:"pod"`
	Action           string    `json:"action"`
	StartedAt        time.Time `json:"startedAt"`
	RecordedAt       time.Time `json:"recordedAt"`
	ReadyAt          time.Time `json:"readyAt,omitempty"`
	ElapsedSeconds   float64   `json:"elapsedSeconds"`
	Outcome          Outcome   `json:"outcome"`
	InvalidReason    string    `json:"invalidReason,omitempty"`
	ReferenceSeconds float64   `json:"referenceAtStartSeconds"`
	CensorDeadline   time.Time `json:"censorDeadline"`
	Normalized       float64   `json:"normalized"`
}

func coRow(result RefreshResult, index int) coResidencyRow {
	node := result.Nodes[index]
	return coResidencyRow{
		Node: node.Name, Namespaces: node.Namespaces, X: node.X(), Pods: node.Pods,
		Eligible: node.Schedulable, CandidateScale: result.Joint.CoResidency.Value,
		CandidateMultiplier: CoResidencyMultiplier(node.X(), result.Joint.CoResidency.Value),
		ShippedMultiplier:   CoResidencyMultiplier(node.X(), ShippedCoResidencyCap),
	}
}

func dispersionRowAt(result RefreshResult, index int) dispersionRow {
	asset := result.Assets[index]
	co := CoResidencyMultiplier(float64(max(asset.Namespaces-1, 0)), result.Joint.CoResidency.Value)
	u := asset.Uncapped(result.Joint.CoResidency.Value)
	return dispersionRow{
		Asset: asset.Key, ImageRarity: asset.ImageRarity, EPSS: asset.EPSS,
		CoResidency: co, ModelRarity: asset.ModelRarity, GPUOrModel: asset.AIFactEligible,
		NamespaceCount: asset.Namespaces, UncappedProduct: u,
		CandidateCapped: Capped(u, result.Joint.Dispersion.Value),
		ShippedCapped:   Capped(asset.Uncapped(ShippedCoResidencyCap), ShippedMaxDispersionMult),
	}
}

func readyRow(result RefreshResult, index int) readyDelayRow {
	record := result.Rotations[index]
	ref := record.ReferenceAtStart
	if ref <= 0 {
		ref = ShippedReadyDelayReference
	}
	return readyDelayRow{
		ID: record.ID, Tenant: record.Tenant, Namespace: record.Namespace, Pod: record.Pod,
		Action: record.Action, StartedAt: record.StartedAt, RecordedAt: record.RecordedAt,
		ReadyAt: record.ReadyAt, ElapsedSeconds: record.Elapsed.Seconds(), Outcome: record.Outcome,
		InvalidReason: record.InvalidReason, ReferenceSeconds: ref.Seconds(),
		CensorDeadline: record.CensorDeadline, Normalized: record.Normalized(),
	}
}

type calibrationTemp interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Close() error
}

func writeAtomic(path string, write func(io.Writer) error) (err error) {
	return writeAtomicWith(path, write, func(dir, pattern string) (calibrationTemp, error) {
		return os.CreateTemp(dir, pattern)
	}, os.Rename)
}

func writeAtomicWith(
	path string,
	write func(io.Writer) error,
	createTemp func(string, string) (calibrationTemp, error),
	rename func(string, string) error,
) (err error) {
	tmp, err := createTemp(filepath.Dir(path), ".calib-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpName)
	}()
	if err = write(tmp); err == nil {
		err = tmp.Chmod(0o644)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	closed = true
	if err != nil {
		return err
	}
	return rename(tmpName, path)
}

func writeAtomicBytes(path string, data []byte) error {
	return writeAtomic(path, func(dst io.Writer) error {
		return writeBytes(dst, data)
	})
}

type rowStream struct {
	null  bool
	count int
	at    func(int) any
}

func computedRows(count int, at func(int) any) rowStream {
	return rowStream{count: count, at: at}
}

func sliceRows[T any](rows []T) rowStream {
	return rowStream{
		null: rows == nil, count: len(rows),
		at: func(index int) any { return rows[index] },
	}
}

func writeString(dst io.Writer, value string) error {
	n, err := io.WriteString(dst, value)
	if err == nil && n != len(value) {
		return io.ErrShortWrite
	}
	return err
}

func writeBytes(dst io.Writer, value []byte) error {
	n, err := dst.Write(value)
	if err == nil && n != len(value) {
		return io.ErrShortWrite
	}
	return err
}

func writeJSON(path string, result RefreshResult, scale any, rows rowStream) error {
	metadata := struct {
		GeneratedAt    time.Time `json:"generatedAt"`
		EvidenceSource string    `json:"evidenceSource"`
		EvidenceNote   string    `json:"evidenceNote,omitempty"`
		Scale          any       `json:"scale,omitempty"`
	}{result.GeneratedAt, result.EvidenceSource, result.EvidenceNote, scale}
	prefix, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	if len(prefix) == 0 || prefix[len(prefix)-1] != '}' {
		return fmt.Errorf("calibration JSON metadata has no object boundary")
	}
	boundary := len(prefix) - 1
	for boundary > 0 && (prefix[boundary-1] == ' ' || prefix[boundary-1] == '\t' || prefix[boundary-1] == '\r' || prefix[boundary-1] == '\n') {
		boundary--
	}
	prefix = append(prefix[:boundary], []byte(",\n  \"rows\": ")...)
	return writeAtomic(path, func(dst io.Writer) error {
		if err := writeBytes(dst, prefix); err != nil {
			return err
		}
		switch {
		case rows.null:
			if err := writeString(dst, "null"); err != nil {
				return err
			}
		case rows.count == 0:
			if err := writeString(dst, "[]"); err != nil {
				return err
			}
		default:
			if err := writeString(dst, "["); err != nil {
				return err
			}
			for index := 0; index < rows.count; index++ {
				raw, err := json.Marshal(rows.at(index))
				if err != nil {
					return err
				}
				var indented bytes.Buffer
				if err := json.Indent(&indented, raw, "    ", "  "); err != nil {
					return err
				}
				separator := "\n    "
				if index > 0 {
					separator = ",\n    "
				}
				if err := writeString(dst, separator); err != nil {
					return err
				}
				if _, err := indented.WriteTo(dst); err != nil {
					return err
				}
			}
			if err := writeString(dst, "\n  ]"); err != nil {
				return err
			}
		}
		if err := writeString(dst, "\n}"); err != nil {
			return err
		}
		return writeString(dst, "\n")
	})
}

func writeCSV(path, source string, header []string, count int, row func(int) []string) error {
	return writeAtomic(path, func(dst io.Writer) error {
		writer := csv.NewWriter(dst)
		if err := writer.Write(append([]string{"evidence_source"}, header...)); err != nil {
			return err
		}
		for index := 0; index < count; index++ {
			if err := writer.Write(append([]string{source}, row(index)...)); err != nil {
				return err
			}
		}
		writer.Flush()
		return writer.Error()
	})
}

func f(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func jsonCell(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Export writes both JSON and CSV for every raw distribution and sweep.
func Export(dir string, result RefreshResult) error {
	if dir == "" {
		return fmt.Errorf("calibration export directory is empty")
	}
	if result.EvidenceSource == "" {
		result.EvidenceSource = "unspecified"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	manifest := struct {
		GeneratedAt    time.Time `json:"generatedAt"`
		EvidenceSource string    `json:"evidenceSource"`
		EvidenceNote   string    `json:"evidenceNote,omitempty"`
	}{result.GeneratedAt, result.EvidenceSource, result.EvidenceNote}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomicBytes(filepath.Join(dir, "evidence-manifest.json"), append(manifestBytes, '\n')); err != nil {
		return err
	}
	co := computedRows(len(result.Nodes), func(index int) any { return coRow(result, index) })
	dispersion := computedRows(len(result.Assets), func(index int) any { return dispersionRowAt(result, index) })
	ready := computedRows(len(result.Rotations), func(index int) any { return readyRow(result, index) })
	if err := writeJSON(filepath.Join(dir, "co-residency.json"), result, result.Joint.CoResidency, co); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "dispersion.json"), result, result.Joint.Dispersion, dispersion); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "ready-delay.json"), result, result.ReadyDelay.Reference, ready); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "joint-percentile-sweep.json"), result, nil, sliceRows(result.JointSweep)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "cadence-sweep.json"), result, nil, sliceRows(result.Cadence)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "optimizer-comparisons.json"), result, nil, sliceRows(result.Comparisons)); err != nil {
		return err
	}

	if err := writeCSV(filepath.Join(dir, "co-residency.csv"), result.EvidenceSource, []string{"node", "namespace_count", "x_node", "pod_count", "eligible", "candidate_scale", "candidate_multiplier", "shipped_multiplier"}, len(result.Nodes), func(index int) []string {
		row := coRow(result, index)
		return []string{row.Node, strconv.Itoa(row.Namespaces), f(row.X), strconv.Itoa(row.Pods), strconv.FormatBool(row.Eligible), f(row.CandidateScale), f(row.CandidateMultiplier), f(row.ShippedMultiplier)}
	}); err != nil {
		return err
	}
	if err := writeCSV(filepath.Join(dir, "dispersion.csv"), result.EvidenceSource, []string{"asset", "image_rarity", "epss", "co_residency", "model_rarity", "gpu_or_model", "namespace_count", "uncapped_product", "candidate_capped", "shipped_capped"}, len(result.Assets), func(index int) []string {
		row := dispersionRowAt(result, index)
		return []string{row.Asset, f(row.ImageRarity), f(row.EPSS), f(row.CoResidency), f(row.ModelRarity), strconv.FormatBool(row.GPUOrModel), strconv.Itoa(row.NamespaceCount), f(row.UncappedProduct), f(row.CandidateCapped), f(row.ShippedCapped)}
	}); err != nil {
		return err
	}
	if err := writeCSV(filepath.Join(dir, "ready-delay.csv"), result.EvidenceSource, []string{"id", "tenant", "namespace", "pod", "action", "started_at", "recorded_at", "ready_at", "elapsed_seconds", "outcome", "invalid_reason", "reference_at_start_seconds", "censor_deadline", "normalized"}, len(result.Rotations), func(index int) []string {
		row := readyRow(result, index)
		return []string{row.ID, row.Tenant, row.Namespace, row.Pod, row.Action, row.StartedAt.Format(time.RFC3339Nano), row.RecordedAt.Format(time.RFC3339Nano), row.ReadyAt.Format(time.RFC3339Nano), f(row.ElapsedSeconds), string(row.Outcome), row.InvalidReason, f(row.ReferenceSeconds), row.CensorDeadline.Format(time.RFC3339Nano), f(row.Normalized)}
	}); err != nil {
		return err
	}
	if err := writeCSV(filepath.Join(dir, "joint-percentile-sweep.csv"), result.EvidenceSource, []string{"co_percentile", "dispersion_percentile", "co_scale", "dispersion_cap", "co_at_ceiling_ratio", "dispersion_at_ceiling_ratio", "dispersion_strictly_clipped_ratio", "distinct_capped", "clears_saturation_limit"}, len(result.JointSweep), func(index int) []string {
		row := result.JointSweep[index]
		return []string{f(row.CoPercentile), f(row.DispersionPercentile), f(row.CoScale), f(row.DispersionCap), f(row.CoAtCeilingRatio), f(row.DispAtCeilingRatio), f(row.DispStrictlyClipped), strconv.Itoa(row.DistinctCapped), strconv.FormatBool(row.ClearsSaturationLimit)}
	}); err != nil {
		return err
	}
	if err := writeCSV(filepath.Join(dir, "cadence-sweep.csv"), result.EvidenceSource, []string{"interval", "windows", "skipped", "max_at_ceiling", "mean_at_ceiling", "max_scale_drift", "ready_comparisons", "max_ready_hard_saturation", "optimizer_comparisons", "max_optimizer_change_ratio", "availability_violations", "slo_violations", "optimizer_stable", "clears_threshold"}, len(result.Cadence), func(index int) []string {
		row := result.Cadence[index]
		return []string{row.Interval.String(), strconv.Itoa(row.Windows), strconv.Itoa(row.Skipped), f(row.MaxAtCeiling), f(row.MeanAtCeiling), f(row.MaxScaleDrift), strconv.Itoa(row.ReadyComparisons), f(row.MaxReadyHardSaturation), strconv.Itoa(row.OptimizerComparisons), f(row.MaxOptimizerChangeRatio), strconv.Itoa(row.AvailabilityViolations), strconv.Itoa(row.SLOViolations), strconv.FormatBool(row.OptimizerStable), strconv.FormatBool(row.ClearsThreshold)}
	}); err != nil {
		return err
	}
	return writeCSV(filepath.Join(dir, "optimizer-comparisons.csv"), result.EvidenceSource, []string{"at", "tenant", "production_selected_json", "shadow_selected_json", "production_scores_json", "shadow_scores_json", "availability_violations", "slo_violations"}, len(result.Comparisons), func(index int) []string {
		comparison := result.Comparisons[index]
		return []string{
			comparison.At.Format(time.RFC3339Nano), comparison.Tenant,
			jsonCell(comparison.Production), jsonCell(comparison.Shadow),
			jsonCell(comparison.ProductionScores), jsonCell(comparison.ShadowScores),
			strconv.Itoa(comparison.AvailabilityViolations), strconv.Itoa(comparison.SLOViolations),
		}
	})
}
