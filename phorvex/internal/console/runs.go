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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
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
	Date      string      `json:"date"`     // server-side full timestamp the run started (UTC)
	Finished  string      `json:"finished"` // server-side full timestamp the run finished (UTC)
	Trials    int         `json:"trials"`
	Arms      []ArmResult `json:"arms,omitempty"`
	Error     string      `json:"error,omitempty"`
	NativeActuator bool   `json:"nativeActuator"`
	Compare3       bool   `json:"compare3,omitempty"` // a 3-strategy (no-defense/blind/Phorvex) live comparison run
	Namespace string      `json:"namespace,omitempty"` // the sandbox the scenario ran in
	Target    string      `json:"target,omitempty"`    // the kubeconfig context targeted
	Provider    string    `json:"provider,omitempty"`    // which provider this attack ran on: "AWS EKS" | "vCluster" | ...
	TargetLabel string    `json:"targetLabel,omitempty"` // human label of the target cluster
	ExpectedTrials int    `json:"expectedTrials"`      // trialsPerArm × arms — drives the progress bar
}

// tsNow is the canonical run timestamp format (UTC) used for the report history.
func tsNow() string { return time.Now().UTC().Format("2006-01-02 15:04:05 MST") }

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
	runOut    map[string]string   // run id -> the out dir its config writes to
	procs     map[string]*exec.Cmd // run id -> the live harness process (for Stop)
	stopping  map[string]bool     // run id -> a user Stop was requested
	seq       int
	active    int       // currently-running exec count
	lastStart time.Time // for the min-interval rate limit
}

func NewRunManager(cfg Config) *RunManager {
	return &RunManager{cfg: cfg, runs: map[string]*RunStatus{}, runOut: map[string]string{}, procs: map[string]*exec.Cmd{}, stopping: map[string]bool{}}
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

// nsRe is the K8s namespace charset (RFC-1123 label) — guards the generated config's namespace.
var nsRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

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
	st := &RunStatus{ID: id, Config: name, State: "running", Started: startedAt, Date: tsNow(), NativeActuator: nativeActuator}
	rm.runs[id] = st
	rm.runOut[id] = su.OutDir
	rm.mu.Unlock()

	go rm.run(id, su, nativeActuator)
	return id, nil
}

// Stop terminates a running attack: it kills the harness AND the operator children it spawned
// (one signal to the whole process group), and marks the run "stopped". No-op-with-error if the
// run isn't running.
func (rm *RunManager) Stop(id string) error {
	rm.mu.Lock()
	st, ok := rm.runs[id]
	if !ok {
		rm.mu.Unlock()
		return fmt.Errorf("run %q not found", id)
	}
	if st.State != "running" {
		rm.mu.Unlock()
		return fmt.Errorf("run %q is not running (state=%s)", id, st.State)
	}
	rm.stopping[id] = true
	cmd := rm.procs[id]
	rm.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // negative pid = the whole process group
	}
	return nil
}

// ClusterTargets returns the selectable run targets. kind is executable now; real clusters
// are wired into the selector but execution is [PENDING-P4a] (guarded by the harness
// safety check). NOT hardcoded to kind — the binary is cluster-agnostic.
type ClusterTarget struct {
	ID       string `json:"id"`
	Context  string `json:"context"`
	Label    string `json:"label"`
	Provider string `json:"provider"` // short provider name: "AWS EKS" | "vCluster" | "kind" | "CoreWeave" | "Kubernetes"
	Runnable bool   `json:"runnable"`
	Note     string `json:"note"`
}

// ClusterTargets DERIVES the selectable targets from the operator's live kubeconfig contexts
// (P4a — never a hardcoded context string). Each real context becomes a runnable read-only
// scan target; EKS/CoreWeave are recognized for labeling but their GPU magnitudes stay
// [SP-0-PENDING-P4]. If no kubeconfig resolves, the list is honestly empty (the UI shows a
// "no clusters found — point KUBECONFIG at a cluster" state).
func (rm *RunManager) ClusterTargets() []ClusterTarget {
	ctxs := kubeContexts()
	out := make([]ClusterTarget, 0, len(ctxs))
	for _, c := range ctxs {
		out = append(out, classifyContext(c))
	}
	// In-cluster (Deployment) fallback: no kubeconfig contexts resolve, but the pod has a mounted
	// ServiceAccount — surface THIS cluster as a runnable read-only target so the live workload
	// view works at the public console URL without any kubeconfig.
	if len(out) == 0 {
		if _, err := rest.InClusterConfig(); err == nil {
			out = append(out, ClusterTarget{
				ID: "in-cluster", Context: "in-cluster", Runnable: true,
				Label: "This cluster (in-cluster)",
				Note:  "DERIVED from the pod ServiceAccount — read-only live view",
			})
		}
	}
	return out
}

// StartScenario runs a SINGLE scenario (generated one-scenario config) against the chosen
// arms, on the chosen cluster target, confined to the chosen sandbox namespace. withPX selects
// d-phorvex (compared against no-MTD); otherwise the non-PX baselines. The harness deploys its
// own synthetic attacker + victim into `namespace` and confines every object there — it does
// not touch pre-existing workloads in other namespaces.
func (rm *RunManager) StartScenario(scenario string, withPX, compare3 bool, targetID, namespace, startedAt string) (string, error) {
	if !scenarioRe.MatchString(scenario) {
		return "", fmt.Errorf("invalid scenario name")
	}
	// SAFETY (load-bearing): the harness DELETES its run namespace at final teardown
	// (core.Env.CleanupOwned deleteNamespace=true). So an attack MUST run only in a dedicated,
	// disposable sandbox — NEVER a real workload namespace, or that namespace + its app get
	// destroyed. We therefore IGNORE any caller-supplied namespace and always use the sandbox.
	namespace = "amtd-attack-test"
	target := "kind-amtd-test"
	provider, targetLabel := "Kubernetes", target
	for _, t := range rm.ClusterTargets() {
		if t.ID == targetID {
			if !t.Runnable {
				return "", fmt.Errorf("cluster target %q execution is %s", t.Label, t.Note)
			}
			target = t.Context
			provider = t.Provider
			targetLabel = t.Label
		}
	}
	// THREE-WAY (compare3): one run measures all three strategies the dashboard contrasts —
	// No defense (d-nomtd), Blind R6 timer (d-r6blindtimer), Phorvex (d-phorvex) — so cost/uptime
	// reflect THIS live run, not the static benchmark.
	arms, expectedTrials := "[d-nomtd, d-r6blindtimer]", 4
	switch {
	case compare3:
		arms, expectedTrials = "[d-nomtd, d-r6blindtimer, d-phorvex]", 6
	case withPX:
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
	cfg := fmt.Sprintf("kubeconfig: \"\"\ncontext: %q\nnamespace: %q\nownedAck: true\ntrialsPerArm: 2\nmasterSeed: 1337\nphoenixSrcDir: %q\noutDir: %q\ndefenderFilter: %s\nscenarioFilter: [%s]\n",
		target, namespace, filepath.Join(rm.cfg.Root, "build", "phoenix-extended"), filepath.Join(rm.cfg.HarnessDir, outDir), arms, scenario)
	cfgPath := filepath.Join(rm.cfg.HarnessDir, "config.console-"+id+".yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return "", err
	}
	rm.mu.Lock()
	st := &RunStatus{ID: id, Config: scenario, State: "running", Started: startedAt, Date: tsNow(), NativeActuator: withPX, Compare3: compare3, Namespace: namespace, Target: target, Provider: provider, TargetLabel: targetLabel, ExpectedTrials: expectedTrials}
	rm.runs[id] = st
	rm.runOut[id] = outDir
	rm.mu.Unlock()
	// A 3-way (compare3) run uses the NATIVE actuator so the Phorvex arm actually rotates the
	// sandbox victim (direct client-go pod delete) — reliable + fast, so it visibly disrupts the
	// attack. Plain 2-arm scenario runs stay on Seam-1 (matches the benchmark).
	go rm.run(id, suite{File: "config.console-" + id + ".yaml", OutDir: outDir}, compare3)
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

// List returns every triggered run (newest first), each with its date + refreshed per-arm
// metrics — the post-attack report history the dashboard shows after live attacks.
func (rm *RunManager) List() []RunStatus {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	out := make([]RunStatus, 0, len(rm.runs))
	for id, st := range rm.runs {
		if rows, ok := readMetrics(filepath.Join(rm.cfg.HarnessDir, rm.runOut[id], "metrics.jsonl")); ok {
			st.Arms, st.Trials = summarizeArms(rows)
		}
		out = append(out, *st)
	}
	// newest first (run ids are run-N / scn-N; sort by the trailing sequence number desc).
	sort.Slice(out, func(i, j int) bool { return seqOf(out[i].ID) > seqOf(out[j].ID) })
	return out
}

// seqOf extracts the trailing integer of a run id ("scn-12" -> 12) for recency sorting.
func seqOf(id string) int {
	n := 0
	if k := strings.LastIndexByte(id, '-'); k >= 0 {
		for _, c := range id[k+1:] {
			if c < '0' || c > '9' {
				return n
			}
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func (rm *RunManager) run(id string, su suite, native bool) {
	// Cap so a triggered run can never hang the console. A 3-strategy (compare3) run executes
	// 3 arms × trials and needs more headroom than a 2-arm scenario, so give it longer.
	cap := 5 * time.Minute
	rm.mu.Lock()
	if st := rm.runs[id]; st != nil && st.Compare3 {
		cap = 12 * time.Minute
	}
	rm.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), cap)
	defer cancel()
	cmd := exec.CommandContext(ctx, rm.cfg.HarnessBin,
		"-config", filepath.Join(rm.cfg.HarnessDir, su.File),
		"-negative-control=false", "-adaptive=false")
	cmd.Dir = rm.cfg.HarnessDir
	cmd.Env = append(envBase(), "NO_COLOR=1")
	if native {
		cmd.Env = append(cmd.Env, "PHORVEX_ACTUATOR=native")
	}
	// Own process group so Stop can kill the WHOLE tree (the harness + the operator children it
	// spawns, which inherit this pgid) in one signal.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Capture the harness's live stdout/stderr to a per-run log the timeline SSE tails (the
	// "=== scenario=… defender=… trial=N ===" stage headers stream from here in real time).
	outAbs := filepath.Join(rm.cfg.HarnessDir, su.OutDir)
	_ = os.MkdirAll(outAbs, 0o755)
	if lf, lerr := os.Create(filepath.Join(outAbs, "console-run.log")); lerr == nil {
		cmd.Stdout, cmd.Stderr = lf, lf
		defer lf.Close()
	}
	var err error
	if serr := cmd.Start(); serr != nil {
		err = serr
	} else {
		rm.mu.Lock()
		rm.procs[id] = cmd
		rm.mu.Unlock()
		err = cmd.Wait()
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.procs, id)
	if rm.active > 0 {
		rm.active--
	}
	st := rm.runs[id]
	if st == nil {
		return
	}
	if rm.stopping[id] {
		delete(rm.stopping, id)
		st.State = "stopped"
		st.Finished = tsNow()
		st.Error = "stopped by user"
		return
	}
	if err != nil && ctx.Err() == nil {
		// non-timeout error; still surface any partial rows.
		st.State = "error"
		st.Finished = tsNow()
		st.Error = err.Error()
		return
	}
	st.State = "done"
	st.Finished = tsNow()
	// A completed 3-strategy run becomes the LIVE source for the cost/uptime comparison: drop a
	// pointer the cost/uptime readers pick up, so those panels reflect THIS attack, not the static
	// benchmark. (Plain 2-arm scenario runs do NOT claim the comparison — they'd leave it half-filled.)
	if st.Compare3 {
		_ = os.WriteFile(filepath.Join(rm.cfg.HarnessDir, "latest-compare-out.txt"), []byte(su.OutDir), 0o644)
	}
	// Regenerate the cost/ROI report for THIS run so the Report tab updates after an attack
	// finishes (no cluster, no re-run — pure post-processing of the run's metrics.jsonl).
	go func(out string) {
		metrics := filepath.Join(rm.cfg.HarnessDir, out, "metrics.jsonl")
		if _, e := os.Stat(metrics); e != nil {
			return
		}
		rc, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dc := exec.CommandContext(rc, rm.cfg.HarnessBin, "-dollars-from", metrics)
		dc.Dir = rm.cfg.HarnessDir
		dc.Env = envBase()
		_ = dc.Run()
	}(su.OutDir)
}

// streamRef returns the run's out dir (relative to HarnessDir) for tailing its metrics.jsonl +
// console-run.log. ok=false for an unknown id.
func (rm *RunManager) streamRef(id string) (string, bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	out, ok := rm.runOut[id]
	return out, ok
}

// expectedTrials returns the total trial count the run will produce (drives the progress bar).
func (rm *RunManager) expectedTrials(id string) int {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if st, ok := rm.runs[id]; ok {
		return st.ExpectedTrials
	}
	return 0
}

// runMeta returns the provider + human target label for a run (so the live timeline can show
// WHICH provider — EKS vs vCluster — the attack is running against).
func (rm *RunManager) runMeta(id string) (provider, label string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if st, ok := rm.runs[id]; ok {
		return st.Provider, st.TargetLabel
	}
	return "", ""
}

// runState returns the current run state (running|done|error|"") — the timeline SSE's end signal.
func (rm *RunManager) runState(id string) string {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if st, ok := rm.runs[id]; ok {
		return st.State
	}
	return ""
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
