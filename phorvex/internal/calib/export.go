/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
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

func coRows(result RefreshResult) []coResidencyRow {
	rows := make([]coResidencyRow, 0, len(result.Nodes))
	for _, node := range result.Nodes {
		rows = append(rows, coResidencyRow{
			Node: node.Name, Namespaces: node.Namespaces, X: node.X(), Pods: node.Pods,
			Eligible: node.Schedulable, CandidateScale: result.Joint.CoResidency.Value,
			CandidateMultiplier: CoResidencyMultiplier(node.X(), result.Joint.CoResidency.Value),
			ShippedMultiplier:   CoResidencyMultiplier(node.X(), ShippedCoResidencyCap),
		})
	}
	return rows
}

func dispersionRows(result RefreshResult) []dispersionRow {
	rows := make([]dispersionRow, 0, len(result.Assets))
	for _, asset := range result.Assets {
		co := CoResidencyMultiplier(float64(max(asset.Namespaces-1, 0)), result.Joint.CoResidency.Value)
		u := asset.Uncapped(result.Joint.CoResidency.Value)
		rows = append(rows, dispersionRow{
			Asset: asset.Key, ImageRarity: asset.ImageRarity, EPSS: asset.EPSS,
			CoResidency: co, ModelRarity: asset.ModelRarity, GPUOrModel: asset.AIFactEligible,
			NamespaceCount: asset.Namespaces, UncappedProduct: u,
			CandidateCapped: Capped(u, result.Joint.Dispersion.Value),
			ShippedCapped:   Capped(asset.Uncapped(ShippedCoResidencyCap), ShippedMaxDispersionMult),
		})
	}
	return rows
}

func readyRows(result RefreshResult) []readyDelayRow {
	rows := make([]readyDelayRow, 0, len(result.Rotations))
	for _, record := range result.Rotations {
		ref := record.ReferenceAtStart
		if ref <= 0 {
			ref = ShippedReadyDelayReference
		}
		rows = append(rows, readyDelayRow{
			ID: record.ID, Tenant: record.Tenant, Namespace: record.Namespace, Pod: record.Pod,
			Action: record.Action, StartedAt: record.StartedAt, RecordedAt: record.RecordedAt,
			ReadyAt: record.ReadyAt, ElapsedSeconds: record.Elapsed.Seconds(), Outcome: record.Outcome,
			InvalidReason: record.InvalidReason, ReferenceSeconds: ref.Seconds(),
			CensorDeadline: record.CensorDeadline, Normalized: record.Normalized(),
		})
	}
	return rows
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".calib-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Chmod(0o644)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func writeJSON(path string, result RefreshResult, scale any, rows any) error {
	payload := struct {
		GeneratedAt    time.Time `json:"generatedAt"`
		EvidenceSource string    `json:"evidenceSource"`
		EvidenceNote   string    `json:"evidenceNote,omitempty"`
		Scale          any       `json:"scale,omitempty"`
		Rows           any       `json:"rows"`
	}{result.GeneratedAt, result.EvidenceSource, result.EvidenceNote, scale, rows}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'))
}

func csvBytes(header []string, rows [][]string) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write(header); err != nil {
		return nil, err
	}
	w.WriteAll(rows)
	w.Flush()
	return b.Bytes(), w.Error()
}

func f(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func sourceCSV(source string, header []string, rows [][]string) ([]string, [][]string) {
	header = append([]string{"evidence_source"}, header...)
	for i := range rows {
		rows[i] = append([]string{source}, rows[i]...)
	}
	return header, rows
}

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
	co := coRows(result)
	disp := dispersionRows(result)
	ready := readyRows(result)
	manifest := struct {
		GeneratedAt    time.Time `json:"generatedAt"`
		EvidenceSource string    `json:"evidenceSource"`
		EvidenceNote   string    `json:"evidenceNote,omitempty"`
	}{result.GeneratedAt, result.EvidenceSource, result.EvidenceNote}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "evidence-manifest.json"), append(manifestBytes, '\n')); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "co-residency.json"), result, result.Joint.CoResidency, co); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "dispersion.json"), result, result.Joint.Dispersion, disp); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "ready-delay.json"), result, result.ReadyDelay.Reference, ready); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "joint-percentile-sweep.json"), result, nil, result.JointSweep); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "cadence-sweep.json"), result, nil, result.Cadence); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "optimizer-comparisons.json"), result, nil, result.Comparisons); err != nil {
		return err
	}

	var coCSV [][]string
	for _, row := range co {
		coCSV = append(coCSV, []string{row.Node, strconv.Itoa(row.Namespaces), f(row.X), strconv.Itoa(row.Pods), strconv.FormatBool(row.Eligible), f(row.CandidateScale), f(row.CandidateMultiplier), f(row.ShippedMultiplier)})
	}
	header, rows := sourceCSV(result.EvidenceSource, []string{"node", "namespace_count", "x_node", "pod_count", "eligible", "candidate_scale", "candidate_multiplier", "shipped_multiplier"}, coCSV)
	b, _ := csvBytes(header, rows)
	if err := writeAtomic(filepath.Join(dir, "co-residency.csv"), b); err != nil {
		return err
	}
	var dispCSV [][]string
	for _, row := range disp {
		dispCSV = append(dispCSV, []string{row.Asset, f(row.ImageRarity), f(row.EPSS), f(row.CoResidency), f(row.ModelRarity), strconv.FormatBool(row.GPUOrModel), strconv.Itoa(row.NamespaceCount), f(row.UncappedProduct), f(row.CandidateCapped), f(row.ShippedCapped)})
	}
	header, rows = sourceCSV(result.EvidenceSource, []string{"asset", "image_rarity", "epss", "co_residency", "model_rarity", "gpu_or_model", "namespace_count", "uncapped_product", "candidate_capped", "shipped_capped"}, dispCSV)
	b, _ = csvBytes(header, rows)
	if err := writeAtomic(filepath.Join(dir, "dispersion.csv"), b); err != nil {
		return err
	}
	var readyCSV [][]string
	for _, row := range ready {
		readyCSV = append(readyCSV, []string{row.ID, row.Tenant, row.Namespace, row.Pod, row.Action, row.StartedAt.Format(time.RFC3339Nano), row.RecordedAt.Format(time.RFC3339Nano), row.ReadyAt.Format(time.RFC3339Nano), f(row.ElapsedSeconds), string(row.Outcome), row.InvalidReason, f(row.ReferenceSeconds), row.CensorDeadline.Format(time.RFC3339Nano), f(row.Normalized)})
	}
	header, rows = sourceCSV(result.EvidenceSource, []string{"id", "tenant", "namespace", "pod", "action", "started_at", "recorded_at", "ready_at", "elapsed_seconds", "outcome", "invalid_reason", "reference_at_start_seconds", "censor_deadline", "normalized"}, readyCSV)
	b, _ = csvBytes(header, rows)
	if err := writeAtomic(filepath.Join(dir, "ready-delay.csv"), b); err != nil {
		return err
	}
	var jointCSV [][]string
	for _, row := range result.JointSweep {
		jointCSV = append(jointCSV, []string{f(row.CoPercentile), f(row.DispersionPercentile), f(row.CoScale), f(row.DispersionCap), f(row.CoAtCeilingRatio), f(row.DispAtCeilingRatio), f(row.DispStrictlyClipped), strconv.Itoa(row.DistinctCapped), strconv.FormatBool(row.ClearsSaturationLimit)})
	}
	header, rows = sourceCSV(result.EvidenceSource, []string{"co_percentile", "dispersion_percentile", "co_scale", "dispersion_cap", "co_at_ceiling_ratio", "dispersion_at_ceiling_ratio", "dispersion_strictly_clipped_ratio", "distinct_capped", "clears_saturation_limit"}, jointCSV)
	b, _ = csvBytes(header, rows)
	if err := writeAtomic(filepath.Join(dir, "joint-percentile-sweep.csv"), b); err != nil {
		return err
	}
	var cadenceCSV [][]string
	for _, row := range result.Cadence {
		cadenceCSV = append(cadenceCSV, []string{row.Interval.String(), strconv.Itoa(row.Windows), strconv.Itoa(row.Skipped), f(row.MaxAtCeiling), f(row.MeanAtCeiling), f(row.MaxScaleDrift), strconv.Itoa(row.ReadyComparisons), f(row.MaxReadyHardSaturation), strconv.Itoa(row.OptimizerComparisons), f(row.MaxOptimizerChangeRatio), strconv.Itoa(row.AvailabilityViolations), strconv.Itoa(row.SLOViolations), strconv.FormatBool(row.OptimizerStable), strconv.FormatBool(row.ClearsThreshold)})
	}
	header, rows = sourceCSV(result.EvidenceSource, []string{"interval", "windows", "skipped", "max_at_ceiling", "mean_at_ceiling", "max_scale_drift", "ready_comparisons", "max_ready_hard_saturation", "optimizer_comparisons", "max_optimizer_change_ratio", "availability_violations", "slo_violations", "optimizer_stable", "clears_threshold"}, cadenceCSV)
	b, _ = csvBytes(header, rows)
	if err := writeAtomic(filepath.Join(dir, "cadence-sweep.csv"), b); err != nil {
		return err
	}
	var comparisonCSV [][]string
	for _, comparison := range result.Comparisons {
		comparisonCSV = append(comparisonCSV, []string{
			comparison.At.Format(time.RFC3339Nano), comparison.Tenant,
			jsonCell(comparison.Production), jsonCell(comparison.Shadow),
			jsonCell(comparison.ProductionScores), jsonCell(comparison.ShadowScores),
			strconv.Itoa(comparison.AvailabilityViolations), strconv.Itoa(comparison.SLOViolations),
		})
	}
	header, rows = sourceCSV(result.EvidenceSource, []string{"at", "tenant", "production_selected_json", "shadow_selected_json", "production_scores_json", "shadow_scores_json", "availability_violations", "slo_violations"}, comparisonCSV)
	b, _ = csvBytes(header, rows)
	return writeAtomic(filepath.Join(dir, "optimizer-comparisons.csv"), b)
}
