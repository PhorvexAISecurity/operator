/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package decision

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

const exactRuntimeTimeout = 500 * time.Millisecond

type exactRuntimeCase struct {
	Name            string  `json:"name"`
	Assets          int     `json:"assets"`
	ActionsPerAsset int     `json:"actionsPerAsset"`
	Budget          int     `json:"budget"`
	Overlap         string  `json:"overlap"`
	InfeasibleEvery int     `json:"infeasibleEvery"`
	Lambda          float64 `json:"lambda"`
	Unguarded       bool    `json:"unguarded"`
	ExpectedStatus  string  `json:"expectedStatus"`
}

type exactRuntimeRecord struct {
	Case                   string   `json:"case"`
	Status                 string   `json:"status"`
	Reason                 string   `json:"reason,omitempty"`
	Assets                 int      `json:"assetCount"`
	FeasibleAssets         int      `json:"feasibleAssetCount"`
	InfeasibleAssets       int      `json:"infeasibleAssetCount"`
	ActionsPerAsset        int      `json:"actionsPerAsset"`
	CandidateCount         int      `json:"candidateCount"`
	Budget                 int      `json:"moveBudget"`
	Overlap                string   `json:"overlapShape"`
	ActiveWorkCap          int      `json:"activeWorkCap"`
	EstimatedWork          float64  `json:"estimatedWork"`
	TimeoutMilliseconds    int64    `json:"timeoutMilliseconds"`
	Seed                   int64    `json:"seed"`
	Repetition             int      `json:"repetition"`
	RuntimeNanoseconds     int64    `json:"runtimeNanoseconds"`
	ExactObjective         *float64 `json:"exactObjective,omitempty"`
	GreedyObjective        *float64 `json:"greedyObjective,omitempty"`
	OptimalityRatio        *float64 `json:"optimalityRatio,omitempty"`
	OptimalityGap          *float64 `json:"optimalityGap,omitempty"`
	CoversDisjoint         bool     `json:"coversDisjoint"`
	StructuralRejection    bool     `json:"structuralRejection"`
	ProductionGuardApplied bool     `json:"productionGuardApplied"`
}

type exactRuntimeSummary struct {
	Case            string   `json:"case"`
	Assets          int      `json:"assetCount"`
	ActionsPerAsset int      `json:"actionsPerAsset"`
	Budget          int      `json:"moveBudget"`
	Overlap         string   `json:"overlapShape"`
	InfeasibleEvery int      `json:"infeasibleEvery"`
	Completed       int      `json:"completed"`
	Timeout         int      `json:"timeout"`
	Failed          int      `json:"failed"`
	Skipped         int      `json:"skipped"`
	P50RuntimeNanos *int64   `json:"p50RuntimeNanoseconds,omitempty"`
	P95RuntimeNanos *int64   `json:"p95RuntimeNanoseconds,omitempty"`
	MaxRuntimeNanos *int64   `json:"maxRuntimeNanoseconds,omitempty"`
	MaxCompletedGap *float64 `json:"maxCompletedOptimalityGap,omitempty"`
}

func exactRuntimeCases() []exactRuntimeCase {
	return []exactRuntimeCase{
		{Name: "production-76-b1", Assets: 76, ActionsPerAsset: 2, Budget: 1, Overlap: "disjoint", Lambda: 0.3, ExpectedStatus: "completed"},
		{Name: "production-76-b2", Assets: 76, ActionsPerAsset: 2, Budget: 2, Overlap: "disjoint", Lambda: 0.3, ExpectedStatus: "completed"},
		{Name: "actions-24-k3", Assets: 24, ActionsPerAsset: 3, Budget: 2, Overlap: "disjoint", Lambda: 0.3, ExpectedStatus: "completed"},
		{Name: "within-asset-overlap", Assets: 24, ActionsPerAsset: 3, Budget: 2, Overlap: "within_asset_shared", Lambda: 0.3, ExpectedStatus: "completed"},
		{Name: "partially-infeasible", Assets: 30, ActionsPerAsset: 3, Budget: 2, Overlap: "within_asset_shared", InfeasibleEvery: 4, Lambda: 0.3, ExpectedStatus: "completed"},
		{Name: "fully-infeasible", Assets: 30, ActionsPerAsset: 3, Budget: 2, Overlap: "disjoint", InfeasibleEvery: 1, Lambda: 0.3, ExpectedStatus: "completed"},
		{Name: "cross-block-rejected", Assets: 20, ActionsPerAsset: 2, Budget: 2, Overlap: "cross_asset_shared", Lambda: 0.3, ExpectedStatus: "skipped"},
		{Name: "guard-skipped", Assets: 80, ActionsPerAsset: 4, Budget: 4, Overlap: "disjoint", Lambda: 0.3, ExpectedStatus: "skipped"},
		{Name: "unguarded-timeout", Assets: 80, ActionsPerAsset: 4, Budget: 4, Overlap: "disjoint", Lambda: 0.3, Unguarded: true, ExpectedStatus: "timeout"},
	}
}

func runtimeAction(j int) model.Action { return model.Action(fmt.Sprintf("benchmark-action-%d", j)) }

func makeExactRuntimeSet(tc exactRuntimeCase, seed int64) actionset.ActionSet {
	rng := rand.New(rand.NewSource(seed))
	set := actionset.ActionSet{FactWeights: map[string]float64{}}
	for i := 0; i < tc.Assets; i++ {
		asset := fmt.Sprintf("bench/asset-%04d", i)
		if tc.InfeasibleEvery > 0 && i%tc.InfeasibleEvery == 0 {
			for j := 0; j < tc.ActionsPerAsset; j++ {
				set.Excluded = append(set.Excluded, actionset.Exclusion{
					Key: asset, Action: runtimeAction(j), Reason: "benchmark hard-feasibility exclusion",
				})
			}
			continue
		}
		for j := 0; j < tc.ActionsPerAsset; j++ {
			unique := fmt.Sprintf("%s|fact-%d", asset, j)
			keys := []string{unique}
			switch tc.Overlap {
			case "within_asset_shared":
				keys = append(keys, asset+"|shared")
			case "cross_asset_shared":
				keys = append(keys, fmt.Sprintf("cross-block|%d", i/2))
			}
			for _, key := range keys {
				if _, exists := set.FactWeights[key]; !exists {
					set.FactWeights[key] = 0.5 + rng.Float64()*2
				}
			}
			set.Candidates = append(set.Candidates, actionset.Candidate{
				Key: asset, Action: runtimeAction(j), CoverKeys: keys,
				ECost: 0.05 + rng.Float64()*0.2,
			})
		}
	}
	if tc.Overlap == "cross_asset_shared" {
		set.Rejected = true
		set.CrossBlockCollisions = append(set.CrossBlockCollisions, actionset.CrossBlockCollision{
			Key: "cross-block|0", ExistingBlock: "bench/asset-0000", ConflictingBlock: "bench/asset-0001",
		})
	}
	return set
}

func baseRuntimeRecord(tc exactRuntimeCase, seed int64, repetition int, set actionset.ActionSet) exactRuntimeRecord {
	feasible := map[string]bool{}
	for _, candidate := range set.Candidates {
		feasible[candidate.Key] = true
	}
	return exactRuntimeRecord{
		Case: tc.Name, Assets: tc.Assets, FeasibleAssets: len(feasible),
		InfeasibleAssets: tc.Assets - len(feasible), ActionsPerAsset: tc.ActionsPerAsset,
		CandidateCount: len(set.Candidates), Budget: tc.Budget, Overlap: tc.Overlap,
		ActiveWorkCap: exactWorkBudget, EstimatedWork: exactWorkEstimate(len(feasible), tc.Budget, tc.ActionsPerAsset),
		TimeoutMilliseconds: exactRuntimeTimeout.Milliseconds(), Seed: seed, Repetition: repetition,
		ProductionGuardApplied: !tc.Unguarded,
	}
}

func runExactRuntimeWorker(tc exactRuntimeCase, seed int64, repetition int) exactRuntimeRecord {
	set := makeExactRuntimeSet(tc, seed)
	record := baseRuntimeRecord(tc, seed, repetition, set)
	if err := set.CollisionError(); err != nil {
		record.Status = "skipped"
		record.Reason = "production rejects cross-block overlap before optimization: " + err.Error()
		record.StructuralRejection = true
		return record
	}
	prov1 := func(string) float64 { return 1 }
	start := time.Now()
	var exact float64
	var skipped bool
	if tc.Unguarded {
		exact, skipped = exactObjectiveWithBudget(set, tc.Budget, prov1, tc.Lambda, math.MaxFloat64)
	} else {
		exact, skipped = exactObjective(set, tc.Budget, prov1, tc.Lambda)
	}
	record.RuntimeNanoseconds = time.Since(start).Nanoseconds()
	if skipped {
		record.Status = "skipped"
		record.Reason = fmt.Sprintf("estimated work %.0f exceeds active cap %d", record.EstimatedWork, exactWorkBudget)
		return record
	}
	greedy := setObjective(greedyPicksOnSet(set, tc.Budget, prov1, tc.Lambda), set.FactWeights, prov1, tc.Lambda)
	ratio := 1.0
	if exact > 1e-12 {
		ratio = greedy / exact
	}
	gap := exact - greedy
	record.Status = "completed"
	record.ExactObjective, record.GreedyObjective = &exact, &greedy
	record.OptimalityRatio, record.OptimalityGap = &ratio, &gap
	record.CoversDisjoint, _ = coversDisjoint(set)
	return record
}

// TestExactRuntimeWorker is re-executed in a subprocess so a timed-out exact enumeration can be
// killed. A goroutine timeout would leave the solver consuming CPU after the benchmark reported it
// stopped, making both the status and subsequent timings false.
func TestExactRuntimeWorker(t *testing.T) {
	if os.Getenv("PHVX_EXACT_RUNTIME_WORKER") != "1" {
		return
	}
	var input struct {
		Case       exactRuntimeCase `json:"case"`
		Seed       int64            `json:"seed"`
		Repetition int              `json:"repetition"`
	}
	if err := json.Unmarshal([]byte(os.Getenv("PHVX_EXACT_RUNTIME_INPUT")), &input); err != nil {
		t.Fatal(err)
	}
	record := runExactRuntimeWorker(input.Case, input.Seed, input.Repetition)
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PHVX_EXACT_RUNTIME_RESULT=%s\n", b)
}

func runExactRuntimeSubprocess(t *testing.T, tc exactRuntimeCase, seed int64, repetition int) exactRuntimeRecord {
	t.Helper()
	input, err := json.Marshal(struct {
		Case       exactRuntimeCase `json:"case"`
		Seed       int64            `json:"seed"`
		Repetition int              `json:"repetition"`
	}{tc, seed, repetition})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), exactRuntimeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestExactRuntimeWorker$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PHVX_EXACT_RUNTIME_WORKER=1", "PHVX_EXACT_RUNTIME_INPUT="+string(input))
	started := time.Now()
	output, runErr := cmd.CombinedOutput()
	wall := time.Since(started)
	if ctx.Err() == context.DeadlineExceeded {
		set := makeExactRuntimeSet(tc, seed)
		record := baseRuntimeRecord(tc, seed, repetition, set)
		record.Status = "timeout"
		record.Reason = fmt.Sprintf("subprocess exceeded the %s exact-check budget", exactRuntimeTimeout)
		record.RuntimeNanoseconds = wall.Nanoseconds()
		return record
	}
	if runErr != nil {
		set := makeExactRuntimeSet(tc, seed)
		record := baseRuntimeRecord(tc, seed, repetition, set)
		record.Status = "failed"
		record.Reason = fmt.Sprintf("worker failed: %v: %s", runErr, strings.TrimSpace(string(output)))
		record.RuntimeNanoseconds = wall.Nanoseconds()
		return record
	}
	const prefix = "PHVX_EXACT_RUNTIME_RESULT="
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), prefix) {
			continue
		}
		var record exactRuntimeRecord
		if err := json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), prefix)), &record); err != nil {
			t.Fatal(err)
		}
		return record
	}
	set := makeExactRuntimeSet(tc, seed)
	record := baseRuntimeRecord(tc, seed, repetition, set)
	record.Status = "failed"
	record.Reason = "worker exited without a result record"
	record.RuntimeNanoseconds = wall.Nanoseconds()
	return record
}

func nearestRuntimePercentile(values []int64, p float64) *int64 {
	if len(values) == 0 {
		return nil
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	v := sorted[idx]
	return &v
}

func summarizeExactRuntime(cases []exactRuntimeCase, records []exactRuntimeRecord) []exactRuntimeSummary {
	byCase := map[string][]exactRuntimeRecord{}
	for _, record := range records {
		byCase[record.Case] = append(byCase[record.Case], record)
	}
	summaries := make([]exactRuntimeSummary, 0, len(cases))
	for _, tc := range cases {
		summary := exactRuntimeSummary{
			Case: tc.Name, Assets: tc.Assets, ActionsPerAsset: tc.ActionsPerAsset,
			Budget: tc.Budget, Overlap: tc.Overlap, InfeasibleEvery: tc.InfeasibleEvery,
		}
		var runtimes []int64
		maxGap := 0.0
		for _, record := range byCase[tc.Name] {
			runtimes = append(runtimes, record.RuntimeNanoseconds)
			switch record.Status {
			case "completed":
				summary.Completed++
				if record.OptimalityGap != nil && *record.OptimalityGap > maxGap {
					maxGap = *record.OptimalityGap
				}
			case "timeout":
				summary.Timeout++
			case "failed":
				summary.Failed++
			case "skipped":
				summary.Skipped++
			}
		}
		summary.P50RuntimeNanos = nearestRuntimePercentile(runtimes, 0.50)
		summary.P95RuntimeNanos = nearestRuntimePercentile(runtimes, 0.95)
		summary.MaxRuntimeNanos = nearestRuntimePercentile(runtimes, 1.0)
		if summary.Completed > 0 {
			summary.MaxCompletedGap = &maxGap
		}
		summaries = append(summaries, summary)
	}
	return summaries
}

func writeJSONLines(path string, records []exactRuntimeRecord) error {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func pointerCell[T int64 | float64](value *T) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(*value)
}

func writeRuntimeCSV(path string, records []exactRuntimeRecord) error {
	var out bytes.Buffer
	w := csv.NewWriter(&out)
	_ = w.Write([]string{"case", "status", "reason", "asset_count", "feasible_assets", "infeasible_assets", "actions_per_asset", "candidate_count", "move_budget", "overlap_shape", "active_work_cap", "estimated_work", "timeout_ms", "seed", "repetition", "runtime_ns", "exact_objective", "greedy_objective", "optimality_ratio", "optimality_gap", "covers_disjoint", "structural_rejection", "production_guard_applied"})
	for _, r := range records {
		_ = w.Write([]string{r.Case, r.Status, r.Reason, strconv.Itoa(r.Assets), strconv.Itoa(r.FeasibleAssets), strconv.Itoa(r.InfeasibleAssets), strconv.Itoa(r.ActionsPerAsset), strconv.Itoa(r.CandidateCount), strconv.Itoa(r.Budget), r.Overlap, strconv.Itoa(r.ActiveWorkCap), strconv.FormatFloat(r.EstimatedWork, 'g', -1, 64), strconv.FormatInt(r.TimeoutMilliseconds, 10), strconv.FormatInt(r.Seed, 10), strconv.Itoa(r.Repetition), strconv.FormatInt(r.RuntimeNanoseconds, 10), pointerCell(r.ExactObjective), pointerCell(r.GreedyObjective), pointerCell(r.OptimalityRatio), pointerCell(r.OptimalityGap), strconv.FormatBool(r.CoversDisjoint), strconv.FormatBool(r.StructuralRejection), strconv.FormatBool(r.ProductionGuardApplied)})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func writeSummaryCSV(path string, summaries []exactRuntimeSummary) error {
	var out bytes.Buffer
	w := csv.NewWriter(&out)
	_ = w.Write([]string{"case", "asset_count", "actions_per_asset", "move_budget", "overlap_shape", "infeasible_every", "completed", "timeout", "failed", "skipped", "p50_runtime_ns", "p95_runtime_ns", "max_runtime_ns", "max_completed_optimality_gap"})
	for _, s := range summaries {
		_ = w.Write([]string{s.Case, strconv.Itoa(s.Assets), strconv.Itoa(s.ActionsPerAsset), strconv.Itoa(s.Budget), s.Overlap, strconv.Itoa(s.InfeasibleEvery), strconv.Itoa(s.Completed), strconv.Itoa(s.Timeout), strconv.Itoa(s.Failed), strconv.Itoa(s.Skipped), pointerCell(s.P50RuntimeNanos), pointerCell(s.P95RuntimeNanos), pointerCell(s.MaxRuntimeNanos), pointerCell(s.MaxCompletedGap)})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func TestExactRuntimeMatrix(t *testing.T) {
	if os.Getenv("PHVX_EXACT_RUNTIME_WORKER") == "1" {
		return
	}
	if raceEnabled {
		t.Skip("wall-clock subprocess matrix is verified in the normal build; race startup alone can exceed the 500ms solver budget")
	}
	cases := exactRuntimeCases()
	seeds := []int64{23001, 23002}
	const repetitions = 3
	var records []exactRuntimeRecord
	for _, tc := range cases {
		for _, seed := range seeds {
			for repetition := 1; repetition <= repetitions; repetition++ {
				record := runExactRuntimeSubprocess(t, tc, seed, repetition)
				if record.Status != tc.ExpectedStatus {
					t.Fatalf("%s seed=%d repetition=%d: status=%s reason=%q, want %s",
						tc.Name, seed, repetition, record.Status, record.Reason, tc.ExpectedStatus)
				}
				if record.Status != "completed" && record.OptimalityGap != nil {
					t.Fatalf("%s status=%s exposed numeric gap %v", record.Case, record.Status, *record.OptimalityGap)
				}
				records = append(records, record)
			}
		}
	}

	statusSeen := map[string]bool{}
	for _, record := range records {
		statusSeen[record.Status] = true
	}
	for _, required := range []string{"completed", "timeout", "skipped"} {
		if !statusSeen[required] {
			t.Fatalf("runtime matrix produced no %s row", required)
		}
	}

	dir := os.Getenv("PHVX_EXACT_RESULTS_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	summaries := summarizeExactRuntime(cases, records)
	if err := writeJSONLines(filepath.Join(dir, "exact-runtime-raw.jsonl"), records); err != nil {
		t.Fatal(err)
	}
	if err := writeRuntimeCSV(filepath.Join(dir, "exact-runtime-raw.csv"), records); err != nil {
		t.Fatal(err)
	}
	summaryJSON, err := json.MarshalIndent(summaries, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exact-runtime-summary.json"), append(summaryJSON, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSummaryCSV(filepath.Join(dir, "exact-runtime-summary.csv"), summaries); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"generatedAt":   time.Now().UTC().Format(time.RFC3339Nano),
		"activeWorkCap": exactWorkBudget, "timeout": exactRuntimeTimeout.String(),
		"seeds": seeds, "repetitionsPerSeed": repetitions,
		"goVersion": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"cpuCount": runtime.NumCPU(),
		"command":  "PHVX_EXACT_RESULTS_DIR=<dir> go test ./internal/decision -run TestExactRuntimeMatrix -count=1 -v",
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exact-runtime-manifest.json"), append(manifestJSON, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
