/*
 * Phorvex Console (P-DASHBOARD) — RUN ATTACK AGENTS (on-demand harness trigger).
 *
 * Safely os/exec's the EXISTING harness binary (harness.exe -config <yaml>) against a
 * whitelisted config, into a unique per-run out dir, and streams status + the resulting
 * metric rows back. It never edits the harness/brain/actuator — it only invokes the
 * existing entrypoint and reads its output.
 */

package console

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// envBase is the inherited process environment (so KUBECONFIG etc. reach the harness).
func envBase() []string { return os.Environ() }

// suite is a triggerable attack-agent run: its config file + the out dir that config writes
// to (parsed from the yaml's outDir at author time; the console reads the metrics from there).
type suite struct{ File, OutDir, Desc string }

// allowedConfigs is the whitelist of attack-agent suites the console may trigger.
var allowedConfigs = map[string]suite{
	"p3-v3":        {"config.p3.v3.yaml", "out-p3-v3", "P3 zero-day dwell (held-out CVE): PX vs blind vs no-MTD"},
	"pactuator":    {"config.pactuator.yaml", "out-pactuator", "Lead demo: native actuator preserves the stateful job"},
	"p3-verify":    {"config.p3.verify.yaml", "out-p3-verify", "P3 verification suite"},
	"fpprobe":      {"config.fpprobe.yaml", "out-fpprobe", "False-positive / controls probe"},
	"p3deep-smoke": {"config.p3deep.smoke.yaml", "out-p3deep-smoke", "Structural zero-day smoke (recon-validity)"},
}

// RunStatus is the live state of a triggered attack-agent run.
type RunStatus struct {
	ID        string      `json:"id"`
	Config    string      `json:"config"`
	State     string      `json:"state"` // running | done | error
	Started   string      `json:"started"`
	Trials    int         `json:"trials"`
	Arms      []ArmResult `json:"arms,omitempty"`
	Error     string      `json:"error,omitempty"`
	NativeActuator bool   `json:"nativeActuator"`
}

// ArmResult is a per-defender live summary as the run streams in.
type ArmResult struct {
	Defender   string  `json:"defender"`
	Trials     int     `json:"trials"`
	Disruption float64 `json:"disruption"`
	DwellMean  float64 `json:"dwellMean"`
}

// RunManager tracks triggered runs (in-memory; the console is single-user until P-VCLUSTER).
type RunManager struct {
	cfg       Config
	mu        sync.Mutex
	runs      map[string]*RunStatus
	runOut    map[string]string // run id -> the out dir its config writes to
	seq       int
	active    int       // currently-running exec count
	lastStart time.Time // for the min-interval rate limit
}

func NewRunManager(cfg Config) *RunManager {
	return &RunManager{cfg: cfg, runs: map[string]*RunStatus{}, runOut: map[string]string{}}
}

const (
	maxConcurrentRuns = 2               // concurrency cap on exec-spawning runs
	minStartInterval  = 3 * time.Second // rate limit between launches
)

// guard enforces the concurrency cap + rate limit on exec endpoints (DoS hardening; the lens
// is demo-trust until real authn [PENDING-P-VCLUSTER]). Caller must hold rm.mu.
func (rm *RunManager) guard(nowMonotonic time.Time) error {
	if rm.active >= maxConcurrentRuns {
		return fmt.Errorf("too many concurrent runs (%d); wait for one to finish", rm.active)
	}
	if !rm.lastStart.IsZero() && nowMonotonic.Sub(rm.lastStart) < minStartInterval {
		return fmt.Errorf("rate limited: wait a moment between launches")
	}
	return nil
}

// validScenario allows only the harness scenario-name charset (defense against injection into
// the generated config / exec args).
var scenarioRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,60}$`)

// AllowedConfigs returns the triggerable suite names (for the UI).
func (rm *RunManager) AllowedConfigs() []string {
	out := make([]string, 0, len(allowedConfigs))
	for k := range allowedConfigs {
		out = append(out, k)
	}
	return out
}

// Start triggers a harness run for a whitelisted config. nativeActuator selects Phorvex's
// own hands (PHORVEX_ACTUATOR=native). Returns the run id.
func (rm *RunManager) Start(name string, nativeActuator bool, startedAt string) (string, error) {
	su, ok := allowedConfigs[name]
	if !ok {
		return "", fmt.Errorf("config %q not in the allowed attack-agent suites", name)
	}
	rm.mu.Lock()
	if err := rm.guard(time.Now()); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	rm.seq++
	rm.active++
	rm.lastStart = time.Now()
	id := fmt.Sprintf("run-%d", rm.seq)
	st := &RunStatus{ID: id, Config: name, State: "running", Started: startedAt, NativeActuator: nativeActuator}
	rm.runs[id] = st
	rm.runOut[id] = su.OutDir
	rm.mu.Unlock()

	go rm.run(id, su, nativeActuator)
	return id, nil
}

// ClusterTargets returns the selectable run targets. kind is executable now; real clusters
// are wired into the selector but execution is [PENDING-P4a] (guarded by the harness
// safety check). NOT hardcoded to kind — the binary is cluster-agnostic.
type ClusterTarget struct {
	ID       string `json:"id"`
	Context  string `json:"context"`
	Label    string `json:"label"`
	Runnable bool   `json:"runnable"`
	Note     string `json:"note"`
}

func (rm *RunManager) ClusterTargets() []ClusterTarget {
	return []ClusterTarget{
		{ID: "kind", Context: "kind-amtd-test", Label: "kind (local)", Runnable: true, Note: "kind-scale, reproducible at seed 1337"},
		{ID: "eks", Context: "", Label: "AWS EKS (GPU)", Runnable: false, Note: "[PENDING-P4a] — real-cluster execution validated at P4a/P4"},
		{ID: "coreweave", Context: "", Label: "CoreWeave (GPU)", Runnable: false, Note: "[PENDING-P4] — GPU magnitudes calibrated at P4"},
	}
}

// StartScenario runs a SINGLE scenario (generated one-scenario config) against the chosen
// arms, on the chosen cluster target. withPX selects d-phorvex; otherwise the non-PX arms.
func (rm *RunManager) StartScenario(scenario string, withPX bool, targetID, startedAt string) (string, error) {
	if !scenarioRe.MatchString(scenario) {
		return "", fmt.Errorf("invalid scenario name")
	}
	target := "kind-amtd-test"
	for _, t := range rm.ClusterTargets() {
		if t.ID == targetID {
			if !t.Runnable {
				return "", fmt.Errorf("cluster target %q execution is %s", t.Label, t.Note)
			}
			target = t.Context
		}
	}
	arms := "[d-nomtd, d-r6blindtimer]"
	if withPX {
		arms = "[d-phorvex, d-nomtd]"
	}
	rm.mu.Lock()
	if err := rm.guard(time.Now()); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	rm.seq++
	rm.active++
	rm.lastStart = time.Now()
	id := fmt.Sprintf("scn-%d", rm.seq)
	outDir := "out-console-" + id
	rm.mu.Unlock()
	cfg := fmt.Sprintf("kubeconfig: \"\"\ncontext: %q\nnamespace: amtd-attack-test\nownedAck: true\ntrialsPerArm: 3\nmasterSeed: 1337\nphoenixSrcDir: %q\noutDir: %q\ndefenderFilter: %s\nscenarioFilter: [%s]\n",
		target, filepath.Join(rm.cfg.Root, "build", "phoenix-extended"), filepath.Join(rm.cfg.HarnessDir, outDir), arms, scenario)
	cfgPath := filepath.Join(rm.cfg.HarnessDir, "config.console-"+id+".yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return "", err
	}
	rm.mu.Lock()
	st := &RunStatus{ID: id, Config: scenario, State: "running", Started: startedAt, NativeActuator: withPX}
	rm.runs[id] = st
	rm.runOut[id] = outDir
	rm.mu.Unlock()
	go rm.run(id, suite{File: "config.console-" + id + ".yaml", OutDir: outDir}, withPX)
	return id, nil
}

// Status returns a snapshot of a run (with the latest parsed metrics).
func (rm *RunManager) Status(id string) (*RunStatus, bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	st, ok := rm.runs[id]
	if !ok {
		return nil, false
	}
	// refresh the live arm summary from the streaming metrics.jsonl (the config's out dir).
	out := filepath.Join(rm.cfg.HarnessDir, rm.runOut[id], "metrics.jsonl")
	if rows, ok := readMetrics(out); ok {
		st.Arms, st.Trials = summarizeArms(rows)
	}
	cp := *st
	return &cp, true
}

func (rm *RunManager) run(id string, su suite, native bool) {
	// 5-minute cap so a triggered run can never hang the console.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, rm.cfg.HarnessBin,
		"-config", filepath.Join(rm.cfg.HarnessDir, su.File),
		"-negative-control=false", "-adaptive=false")
	cmd.Dir = rm.cfg.HarnessDir
	cmd.Env = append(envBase(), "NO_COLOR=1")
	if native {
		cmd.Env = append(cmd.Env, "PHORVEX_ACTUATOR=native")
	}
	err := cmd.Run()
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.active > 0 {
		rm.active--
	}
	st := rm.runs[id]
	if st == nil {
		return
	}
	if err != nil && ctx.Err() == nil {
		// non-timeout error; still surface any partial rows.
		st.State = "error"
		st.Error = err.Error()
		return
	}
	st.State = "done"
}

func summarizeArms(rows []metricRow) ([]ArmResult, int) {
	byDef := map[string][]metricRow{}
	total := 0
	for _, r := range rows {
		if r.NegativeControl || r.Skipped {
			continue
		}
		byDef[r.Defender] = append(byDef[r.Defender], r)
		total++
	}
	var out []ArmResult
	for def, rs := range byDef {
		var dis, dw []float64
		for _, r := range rs {
			dis = append(dis, r.DisruptionVsOracle)
			if v, ok := markers(r.ObservedState)["survival"]; ok {
				dw = append(dw, atof(v))
			} else if r.AttackerDwellSeconds > 0 {
				dw = append(dw, r.AttackerDwellSeconds)
			}
		}
		out = append(out, ArmResult{Defender: def, Trials: len(rs), Disruption: meanf(dis), DwellMean: meanf(dw)})
	}
	return out, total
}
