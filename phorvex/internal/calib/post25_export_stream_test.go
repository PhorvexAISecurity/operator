package calib

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

func legacyCoRows(result RefreshResult) []coResidencyRow {
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

func legacyDispersionRows(result RefreshResult) []dispersionRow {
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

func legacyReadyRows(result RefreshResult) []readyDelayRow {
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

func legacyAtomic(path string, data []byte) error {
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

func legacyJSON(path string, result RefreshResult, scale, rows any) error {
	payload := struct {
		GeneratedAt    time.Time `json:"generatedAt"`
		EvidenceSource string    `json:"evidenceSource"`
		EvidenceNote   string    `json:"evidenceNote,omitempty"`
		Scale          any       `json:"scale,omitempty"`
		Rows           any       `json:"rows"`
	}{result.GeneratedAt, result.EvidenceSource, result.EvidenceNote, scale, rows}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return legacyAtomic(path, append(data, '\n'))
}

func legacyCSVBytes(header []string, rows [][]string) ([]byte, error) {
	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	if err := writer.Write(header); err != nil {
		return nil, err
	}
	writer.WriteAll(rows)
	writer.Flush()
	return out.Bytes(), writer.Error()
}

func legacySourceCSV(source string, header []string, rows [][]string) ([]string, [][]string) {
	header = append([]string{"evidence_source"}, header...)
	for index := range rows {
		rows[index] = append([]string{source}, rows[index]...)
	}
	return header, rows
}

func legacyExport(dir string, result RefreshResult) error {
	if dir == "" {
		return fmt.Errorf("calibration export directory is empty")
	}
	if result.EvidenceSource == "" {
		result.EvidenceSource = "unspecified"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	co := legacyCoRows(result)
	dispersion := legacyDispersionRows(result)
	ready := legacyReadyRows(result)
	manifest := struct {
		GeneratedAt    time.Time `json:"generatedAt"`
		EvidenceSource string    `json:"evidenceSource"`
		EvidenceNote   string    `json:"evidenceNote,omitempty"`
	}{result.GeneratedAt, result.EvidenceSource, result.EvidenceNote}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := legacyAtomic(filepath.Join(dir, "evidence-manifest.json"), append(manifestBytes, '\n')); err != nil {
		return err
	}
	for _, output := range []struct {
		name  string
		scale any
		rows  any
	}{
		{"co-residency.json", result.Joint.CoResidency, co},
		{"dispersion.json", result.Joint.Dispersion, dispersion},
		{"ready-delay.json", result.ReadyDelay.Reference, ready},
		{"joint-percentile-sweep.json", nil, result.JointSweep},
		{"cadence-sweep.json", nil, result.Cadence},
		{"optimizer-comparisons.json", nil, result.Comparisons},
	} {
		if err := legacyJSON(filepath.Join(dir, output.name), result, output.scale, output.rows); err != nil {
			return err
		}
	}
	writeCSV := func(name string, header []string, rows [][]string) error {
		header, rows = legacySourceCSV(result.EvidenceSource, header, rows)
		data, err := legacyCSVBytes(header, rows)
		if err != nil {
			return err
		}
		return legacyAtomic(filepath.Join(dir, name), data)
	}
	coCSV := make([][]string, 0, len(co))
	for _, row := range co {
		coCSV = append(coCSV, []string{row.Node, strconv.Itoa(row.Namespaces), f(row.X), strconv.Itoa(row.Pods), strconv.FormatBool(row.Eligible), f(row.CandidateScale), f(row.CandidateMultiplier), f(row.ShippedMultiplier)})
	}
	if err := writeCSV("co-residency.csv", []string{"node", "namespace_count", "x_node", "pod_count", "eligible", "candidate_scale", "candidate_multiplier", "shipped_multiplier"}, coCSV); err != nil {
		return err
	}
	dispersionCSV := make([][]string, 0, len(dispersion))
	for _, row := range dispersion {
		dispersionCSV = append(dispersionCSV, []string{row.Asset, f(row.ImageRarity), f(row.EPSS), f(row.CoResidency), f(row.ModelRarity), strconv.FormatBool(row.GPUOrModel), strconv.Itoa(row.NamespaceCount), f(row.UncappedProduct), f(row.CandidateCapped), f(row.ShippedCapped)})
	}
	if err := writeCSV("dispersion.csv", []string{"asset", "image_rarity", "epss", "co_residency", "model_rarity", "gpu_or_model", "namespace_count", "uncapped_product", "candidate_capped", "shipped_capped"}, dispersionCSV); err != nil {
		return err
	}
	readyCSV := make([][]string, 0, len(ready))
	for _, row := range ready {
		readyCSV = append(readyCSV, []string{row.ID, row.Tenant, row.Namespace, row.Pod, row.Action, row.StartedAt.Format(time.RFC3339Nano), row.RecordedAt.Format(time.RFC3339Nano), row.ReadyAt.Format(time.RFC3339Nano), f(row.ElapsedSeconds), string(row.Outcome), row.InvalidReason, f(row.ReferenceSeconds), row.CensorDeadline.Format(time.RFC3339Nano), f(row.Normalized)})
	}
	if err := writeCSV("ready-delay.csv", []string{"id", "tenant", "namespace", "pod", "action", "started_at", "recorded_at", "ready_at", "elapsed_seconds", "outcome", "invalid_reason", "reference_at_start_seconds", "censor_deadline", "normalized"}, readyCSV); err != nil {
		return err
	}
	jointCSV := make([][]string, 0, len(result.JointSweep))
	for _, row := range result.JointSweep {
		jointCSV = append(jointCSV, []string{f(row.CoPercentile), f(row.DispersionPercentile), f(row.CoScale), f(row.DispersionCap), f(row.CoAtCeilingRatio), f(row.DispAtCeilingRatio), f(row.DispStrictlyClipped), strconv.Itoa(row.DistinctCapped), strconv.FormatBool(row.ClearsSaturationLimit)})
	}
	if err := writeCSV("joint-percentile-sweep.csv", []string{"co_percentile", "dispersion_percentile", "co_scale", "dispersion_cap", "co_at_ceiling_ratio", "dispersion_at_ceiling_ratio", "dispersion_strictly_clipped_ratio", "distinct_capped", "clears_saturation_limit"}, jointCSV); err != nil {
		return err
	}
	cadenceCSV := make([][]string, 0, len(result.Cadence))
	for _, row := range result.Cadence {
		cadenceCSV = append(cadenceCSV, []string{row.Interval.String(), strconv.Itoa(row.Windows), strconv.Itoa(row.Skipped), f(row.MaxAtCeiling), f(row.MeanAtCeiling), f(row.MaxScaleDrift), strconv.Itoa(row.ReadyComparisons), f(row.MaxReadyHardSaturation), strconv.Itoa(row.OptimizerComparisons), f(row.MaxOptimizerChangeRatio), strconv.Itoa(row.AvailabilityViolations), strconv.Itoa(row.SLOViolations), strconv.FormatBool(row.OptimizerStable), strconv.FormatBool(row.ClearsThreshold)})
	}
	if err := writeCSV("cadence-sweep.csv", []string{"interval", "windows", "skipped", "max_at_ceiling", "mean_at_ceiling", "max_scale_drift", "ready_comparisons", "max_ready_hard_saturation", "optimizer_comparisons", "max_optimizer_change_ratio", "availability_violations", "slo_violations", "optimizer_stable", "clears_threshold"}, cadenceCSV); err != nil {
		return err
	}
	comparisonCSV := make([][]string, 0, len(result.Comparisons))
	for _, comparison := range result.Comparisons {
		comparisonCSV = append(comparisonCSV, []string{
			comparison.At.Format(time.RFC3339Nano), comparison.Tenant,
			jsonCell(comparison.Production), jsonCell(comparison.Shadow),
			jsonCell(comparison.ProductionScores), jsonCell(comparison.ShadowScores),
			strconv.Itoa(comparison.AvailabilityViolations), strconv.Itoa(comparison.SLOViolations),
		})
	}
	return writeCSV("optimizer-comparisons.csv", []string{"at", "tenant", "production_selected_json", "shadow_selected_json", "production_scores_json", "shadow_scores_json", "availability_violations", "slo_violations"}, comparisonCSV)
}

func runtimeExportResult(t *testing.T) RefreshResult {
	t.Helper()
	base := at0()
	runtime := NewRuntime(RuntimeConfig{MinObservations: 1}, logr.Discard())
	runtime.ObserveRotation(RotationRecord{
		ID: "rotation-\u003cα\u003e", Tenant: "tenant,one", Namespace: "line\nbreak", Pod: "quoted \"pod\"", Action: "replace",
		StartedAt: base.Add(-10 * time.Minute), RecordedAt: base.Add(-5 * time.Minute), ReadyAt: base.Add(-5 * time.Minute),
		Elapsed: 5 * time.Minute, Outcome: OutcomeObserved, ReferenceAtStart: 400 * time.Second,
		CensorDeadline: base.Add(-3 * time.Minute),
	})
	comparison := SelectionComparison{
		At: base.Add(-time.Second), Tenant: "tenant <α>,\n\"quoted\"",
		Production: []string{"prod<&>", "line\nbreak"}, Shadow: []string{},
		ProductionScores: []DecisionScore{{Key: "asset\nα", Action: "move,\"x\"", Selected: true, CoverageValue: math.MaxFloat64, Cost: math.SmallestNonzeroFloat64, Net: -123.5}},
		ShadowScores:     []DecisionScore{{Key: "shadow", Action: "hold", CoverageValue: 1.25, Cost: 0.5, Net: 0.75}},
	}
	runtime.ObserveValidation(comparison, 2, 3)
	snapshot, witness := runtimeSnapshot(base)
	result, refreshed, err := runtime.ObserveSnapshot(snapshot, witness)
	if err != nil || !refreshed {
		t.Fatalf("runtime refresh: refreshed=%v err=%v", refreshed, err)
	}
	if len(result.Comparisons) != 1 || len(result.Nodes) == 0 || len(result.Assets) == 0 || len(result.Rotations) != 1 {
		t.Fatalf("runtime result missing representative rows: %+v", result)
	}
	return result
}

func directoryFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

func TestStreamingExportExactlyMatchesLegacyBytes(t *testing.T) {
	actualRuntime := runtimeExportResult(t)
	const formerMarker = "__phorvex_streamed_rows_marker__"
	markerValues := actualRuntime
	markerValues.EvidenceSource = formerMarker
	markerValues.EvidenceNote = formerMarker
	markerValues.Comparisons = append([]SelectionComparison(nil), actualRuntime.Comparisons...)
	markerValues.Comparisons[0].Tenant = formerMarker
	markerValues.Comparisons[0].Production = []string{formerMarker}
	cases := []struct {
		name   string
		result RefreshResult
	}{
		{name: "actual-runtime", result: actualRuntime},
		{name: "former-marker-in-metadata-and-row", result: markerValues},
		{name: "nil-slices", result: RefreshResult{GeneratedAt: at0(), EvidenceNote: "nil <&> \"note\"\nnext"}},
		{name: "empty-slices", result: RefreshResult{GeneratedAt: at0(), EvidenceSource: "", Nodes: []NodeObservation{}, Assets: []AssetObservation{}, Rotations: []RotationRecord{}, Comparisons: []SelectionComparison{}, JointSweep: []JointSweepRow{}, Cadence: []CadenceRow{}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			legacyDir, streamingDir := t.TempDir(), t.TempDir()
			if err := legacyExport(legacyDir, testCase.result); err != nil {
				t.Fatalf("legacy export: %v", err)
			}
			if err := Export(streamingDir, testCase.result); err != nil {
				t.Fatalf("streaming export: %v", err)
			}
			legacyNames, streamingNames := directoryFiles(t, legacyDir), directoryFiles(t, streamingDir)
			if len(streamingNames) != 13 || !reflect.DeepEqual(streamingNames, legacyNames) {
				t.Fatalf("exported names differ: streaming=%v legacy=%v", streamingNames, legacyNames)
			}
			for _, name := range legacyNames {
				legacyBytes, err := os.ReadFile(filepath.Join(legacyDir, name))
				if err != nil {
					t.Fatal(err)
				}
				streamingBytes, err := os.ReadFile(filepath.Join(streamingDir, name))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(streamingBytes, legacyBytes) {
					t.Fatalf("%s differs\nstreaming:\n%s\nlegacy:\n%s", name, streamingBytes, legacyBytes)
				}
				info, err := os.Stat(filepath.Join(streamingDir, name))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o644 {
					t.Fatalf("%s mode=%o want=644", name, info.Mode().Perm())
				}
			}
		})
	}
}

func TestStreamingComparisonOutputsPreserveEveryRuntimeRowInOrder(t *testing.T) {
	result := runtimeExportResult(t)
	base := result.Comparisons[0]
	for index := 1; index < 5; index++ {
		row := base
		row.At = row.At.Add(time.Duration(index) * time.Second)
		row.Tenant = fmt.Sprintf("tenant-%d,\nα", index)
		result.Comparisons = append(result.Comparisons, row)
	}
	dir := t.TempDir()
	if err := Export(dir, result); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Rows []SelectionComparison `json:"rows"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "optimizer-comparisons.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload.Rows, result.Comparisons) {
		t.Fatalf("JSON comparisons changed or reordered: got=%+v want=%+v", payload.Rows, result.Comparisons)
	}
	file, err := os.Open(filepath.Join(dir, "optimizer-comparisons.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(result.Comparisons)+1 {
		t.Fatalf("CSV records=%d want=%d", len(records), len(result.Comparisons)+1)
	}
	for index, want := range result.Comparisons {
		got := records[index+1]
		if got[1] != want.At.Format(time.RFC3339Nano) || got[2] != want.Tenant {
			t.Fatalf("CSV comparison %d identity/order=%q want at=%q tenant=%q", index, got, want.At.Format(time.RFC3339Nano), want.Tenant)
		}
		var production, shadow []string
		var productionScores, shadowScores []DecisionScore
		for _, target := range []struct {
			cell string
			out  any
		}{{got[3], &production}, {got[4], &shadow}, {got[5], &productionScores}, {got[6], &shadowScores}} {
			if err := json.Unmarshal([]byte(target.cell), target.out); err != nil {
				t.Fatalf("CSV comparison %d nested JSON: %v", index, err)
			}
		}
		if !reflect.DeepEqual(production, want.Production) || !reflect.DeepEqual(shadow, want.Shadow) || !reflect.DeepEqual(productionScores, want.ProductionScores) || !reflect.DeepEqual(shadowScores, want.ShadowScores) {
			t.Fatalf("CSV comparison %d nested values changed", index)
		}
	}
}

type closeErrorTemp struct {
	calibrationTemp
	err error
}

func (temp closeErrorTemp) Close() error {
	_ = temp.calibrationTemp.Close()
	return temp.err
}

func assertOriginalAndNoTemps(t *testing.T, path string, original []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("destination changed after failure: got=%q want=%q", got, original)
	}
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".calib-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary files survived failure: %v", temps)
	}
}

func TestStreamingAtomicFailuresPreserveOriginalAndRemoveTemporary(t *testing.T) {
	sentinel := errors.New("injected export failure")
	create := func(dir, pattern string) (calibrationTemp, error) {
		return os.CreateTemp(dir, pattern)
	}
	rename := os.Rename
	for _, testCase := range []struct {
		name   string
		create func(string, string) (calibrationTemp, error)
		rename func(string, string) error
		write  func(io.Writer) error
	}{
		{
			name: "write",
			write: func(dst io.Writer) error {
				if err := writeString(dst, "partial"); err != nil {
					return err
				}
				return sentinel
			},
		},
		{
			name: "close",
			create: func(dir, pattern string) (calibrationTemp, error) {
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return closeErrorTemp{calibrationTemp: file, err: sentinel}, nil
			},
			write: func(dst io.Writer) error { return writeString(dst, "complete") },
		},
		{
			name:   "rename",
			rename: func(_, _ string) error { return sentinel },
			write:  func(dst io.Writer) error { return writeString(dst, "complete") },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			createForCase, renameForCase := testCase.create, testCase.rename
			if createForCase == nil {
				createForCase = create
			}
			if renameForCase == nil {
				renameForCase = rename
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "evidence.json")
			original := []byte("retained original\n")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := writeAtomicWith(path, testCase.write, createForCase, renameForCase); !errors.Is(err, sentinel) {
				t.Fatalf("error=%v want sentinel", err)
			}
			assertOriginalAndNoTemps(t, path, original)
		})
	}
}

func TestStreamingInvalidRowDoesNotReportSuccessOrReplaceOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "optimizer-comparisons.json")
	original := []byte("original valid evidence\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	result := RefreshResult{GeneratedAt: at0(), EvidenceSource: "invalid-row-control"}
	err := writeJSON(path, result, nil, computedRows(1, func(int) any {
		return struct {
			Invalid float64 `json:"invalid"`
		}{Invalid: math.NaN()}
	}))
	if err == nil {
		t.Fatal("invalid JSON row unexpectedly succeeded")
	}
	assertOriginalAndNoTemps(t, path, original)
}
