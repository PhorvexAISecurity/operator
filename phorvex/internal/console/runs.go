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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

	"sigs.k8s.io/yaml"
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
	ID             string      `json:"id"`
	Config         string      `json:"config"`
	State          string      `json:"state"` // queued | running | done | error | stopped
	Started        string      `json:"started"`
	Date           string      `json:"date"`     // server-side full timestamp the run started (UTC)
	Finished       string      `json:"finished"` // server-side full timestamp the run finished (UTC)
	Trials         int         `json:"trials"`
	Arms           []ArmResult `json:"arms,omitempty"`
	Error          string      `json:"error,omitempty"`
	NativeActuator bool        `json:"nativeActuator"`
	Compare3       bool        `json:"compare3,omitempty"`    // a 3-strategy (no-defense/blind/Phorvex) live comparison run
	Namespace      string      `json:"namespace,omitempty"`   // the sandbox the scenario ran in
	Target         string      `json:"target,omitempty"`      // the kubeconfig context targeted
	Provider       string      `json:"provider,omitempty"`    // which provider this attack ran on: "AWS EKS" | "vCluster" | ...
	TargetLabel    string      `json:"targetLabel,omitempty"` // human label of the target cluster
	ExpectedTrials int         `json:"expectedTrials"`        // trialsPerArm × arms — drives the progress bar
	QueuePos       int         `json:"queuePos,omitempty"`    // 1-based slot in the pending queue while state=="queued" (0 once running)
	// Owner is the VERIFIED identity that started the run ("<issuer>#<subject>"), recorded so a
	// run id can be authorized rather than guessed at. It is never read from a request body.
	Owner string `json:"owner,omitempty"`
	// ScopeTarget is the cluster TARGET ID the run was authorized against. Target above is the
	// kubeconfig context handed to the harness, which is a different string for most clusters;
	// authorization has to compare the same identifier the grant is written in.
	ScopeTarget string `json:"scopeTarget,omitempty"`
	// ScopeTenant is the namespace the run actually drives, resolved from the producer (the
	// suite's own config, or the forced scenario sandbox). Sharing a cluster does not make one
	// tenant's run readable by another, so run-id authorization compares this too. Empty means
	// the namespace could not be determined; that fails closed short of a cross-tenant grant.
	ScopeTenant string `json:"scopeTenant,omitempty"`
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

// pendingRun holds what's needed to start a QUEUED run once a slot frees up (the harness shares
// one sandbox ns + fixed operator ports, so only maxConcurrentRuns execute at once; the rest wait).
type pendingRun struct {
	su     suite
	native bool
}

// RunManager tracks triggered runs (in-memory; the console is single-user until P-VCLUSTER).
type RunManager struct {
	cfg       Config
	mu        sync.Mutex
	runs      map[string]*RunStatus
	runOut    map[string]string     // run id -> the out dir its config writes to
	procs     map[string]*exec.Cmd  // run id -> the live harness process (for Stop)
	stopping  map[string]bool       // run id -> a user Stop was requested
	pending   map[string]pendingRun // run id -> queued launch args (state=="queued")
	queue     []string              // FIFO of queued run ids (auto-started as slots free)
	seq       int
	active    int       // currently-running exec count
	lastStart time.Time // for the min-interval rate limit
	loadErr   error
}

func NewRunManager(cfg Config) *RunManager {
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{}, runOut: map[string]string{}, procs: map[string]*exec.Cmd{}, stopping: map[string]bool{}, pending: map[string]pendingRun{}}
	rm.loadErr = rm.loadStatuses()
	return rm
}

type persistedRunStatus struct {
	Kind  string    `json:"kind"`
	Phase string    `json:"phase"`
	Out   string    `json:"out"`
	Run   RunStatus `json:"run"`
}

func (rm *RunManager) persistStatus(st *RunStatus, out string) error {
	b, err := json.Marshal(persistedRunStatus{Kind: "phorvex.console.run", Phase: "status", Out: out, Run: *st})
	if err != nil {
		return err
	}
	return rm.cfg.appendState(rm.cfg.statePath("run-events.jsonl"), b)
}

func (rm *RunManager) loadStatuses() error {
	path := rm.cfg.statePath("run-events.jsonl")
	if path == "" {
		return nil
	}
	b, err := readStateLedgerHistory(path)
	if err != nil {
		return fmt.Errorf("read retained runs: %w", err)
	}
	if len(b) == 0 {
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 4096), consoleStateRecordLimit)
	for sc.Scan() {
		var p persistedRunStatus
		if err = json.Unmarshal(sc.Bytes(), &p); err != nil {
			return fmt.Errorf("malformed retained run status: %w", err)
		}
		if p.Phase != "status" {
			continue
		}
		cp := p.Run
		if cp.State == "running" || cp.State == "queued" {
			cp.State = "error"
			cp.Error = "run interrupted by console restart"
			cp.Finished = tsNow()
		}
		rm.runs[cp.ID], rm.runOut[cp.ID] = &cp, p.Out
		if n := seqOf(cp.ID); n > rm.seq {
			rm.seq = n
		}
	}
	if err = sc.Err(); err != nil {
		return fmt.Errorf("read retained runs: %w", err)
	}
	return nil
}

const (
	maxConcurrentRuns = 1               // serialize: runs share one sandbox ns + fixed operator ports (:18090/:18091), so concurrent runs collide (port-bind fail -> dead brain -> false "attack landed")
	minStartInterval  = 3 * time.Second // rate limit between launches
	// scenarioSandboxNamespace and scenarioFallbackContext are StartScenario's OWN substitutions.
	// They are named so the destination the auth boundary authorizes and the destination the
	// launcher uses cannot drift apart.
	scenarioSandboxNamespace = "amtd-attack-test"
	scenarioFallbackContext  = "kind-amtd-test"
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

// dequeueNextLocked starts as many queued runs as free slots allow (FIFO). Caller MUST hold rm.mu.
// Called from a finishing run's completion path so the next queued attack auto-starts. A queued run
// that was Stopped while waiting is skipped (its state is no longer "queued").
func (rm *RunManager) dequeueNextLocked() {
	for rm.active < maxConcurrentRuns && len(rm.queue) > 0 {
		nid := rm.queue[0]
		rm.queue = rm.queue[1:]
		pr, ok := rm.pending[nid]
		delete(rm.pending, nid)
		st := rm.runs[nid]
		if !ok || st == nil || st.State != "queued" {
			continue // dropped/stopped while queued
		}
		st.State = "running"
		st.Date = tsNow()
		rm.active++
		rm.lastStart = time.Now()
		go rm.run(nid, pr.su, pr.native)
	}
}

// queuePosLocked returns the 1-based position of a queued run id in the FIFO (0 if not queued).
// Caller MUST hold rm.mu.
func (rm *RunManager) queuePosLocked(id string) int {
	for i, q := range rm.queue {
		if q == id {
			return i + 1
		}
	}
	return 0
}

// removeFromQueueLocked drops a run id from the FIFO (used when a queued run is Stopped). Caller MUST hold rm.mu.
func (rm *RunManager) removeFromQueueLocked(id string) {
	for i, q := range rm.queue {
		if q == id {
			rm.queue = append(rm.queue[:i], rm.queue[i+1:]...)
			return
		}
	}
}

// queuePos exposes the queued position of a run (0 if running/done) for the timeline SSE.
func (rm *RunManager) queuePos(id string) int {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.queuePosLocked(id)
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
// own hands (PHORVEX_ACTUATOR=native). owner is the verified identity that requested it.
// Returns the run id.
func (rm *RunManager) Start(name string, nativeActuator bool, startedAt, owner string, dest runDestination) (string, error) {
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
	runtimeSuite, err := rm.prepareSuite(id, su)
	if err != nil {
		rm.active--
		rm.mu.Unlock()
		return "", fmt.Errorf("prepare durable run: %w", err)
	}
	su = runtimeSuite
	// dest is what SuiteDestination read out of the suite's own config — never a stamped default.
	// Both halves are recorded so a later run-id lookup is authorized against the cluster AND the
	// namespace this run actually drives.
	st := &RunStatus{ID: id, Config: name, State: "running", Started: startedAt, Date: tsNow(), NativeActuator: nativeActuator, Owner: owner, ScopeTarget: normalizeTargetID(dest.ScopeTarget), ScopeTenant: dest.ScopeTenant}
	rm.runs[id] = st
	rm.runOut[id] = su.OutDir
	if err := rm.persistStatus(st, su.OutDir); err != nil {
		delete(rm.runs, id)
		delete(rm.runOut, id)
		rm.active--
		rm.mu.Unlock()
		return "", fmt.Errorf("persist run status before effect: %w", err)
	}
	rm.mu.Unlock()

	go rm.run(id, su, nativeActuator)
	return id, nil
}

func (rm *RunManager) prepareSuite(id string, su suite) (suite, error) {
	if rm.cfg.runsDir() == "" {
		return suite{}, fmt.Errorf("console state directory is not configured")
	}
	raw, err := os.ReadFile(filepath.Join(rm.cfg.HarnessDir, su.File))
	if err != nil {
		return suite{}, err
	}
	var doc map[string]any
	if err = yaml.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &doc); err != nil {
		return suite{}, err
	}
	out := id
	doc["outDir"] = rm.cfg.runOutputPath(out)
	raw, err = yaml.Marshal(doc)
	if err != nil {
		return suite{}, err
	}
	configPath := filepath.Join(rm.cfg.runsDir(), "configs", id+".yaml")
	if err = atomicWriteState(configPath, raw); err != nil {
		return suite{}, err
	}
	intent, _ := json.Marshal(map[string]any{"kind": "phorvex.console.run", "phase": "intent", "time": time.Now().UTC(), "id": id, "config": su.File})
	if err = rm.cfg.appendState(rm.cfg.statePath("run-events.jsonl"), intent); err != nil {
		return suite{}, err
	}
	return suite{File: configPath, OutDir: out, Desc: su.Desc}, nil
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
	if st.State == "queued" {
		// cancel a not-yet-started run: drop it from the FIFO so it never executes.
		rm.removeFromQueueLocked(id)
		delete(rm.pending, id)
		st.State = "stopped"
		st.Finished = tsNow()
		st.Error = "cancelled while queued"
		if err := rm.persistStatus(st, rm.runOut[id]); err != nil {
			rm.mu.Unlock()
			return fmt.Errorf("stop recorded in memory but persistence failed: %w", err)
		}
		rm.mu.Unlock()
		return nil
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
// are wired into the selector but execution remains tracked by PHORVEXSEC-151 (guarded by the harness
// safety check). NOT hardcoded to kind — the binary is cluster-agnostic.
type ClusterTarget struct {
	ID                    string `json:"id"`
	Context               string `json:"context"`
	Label                 string `json:"label"`
	Provider              string `json:"provider"` // short provider name: "AWS EKS" | "vCluster" | "kind" | "CoreWeave" | "Kubernetes"
	Runnable              bool   `json:"runnable"`
	Note                  string `json:"note"`
	DefaultMutationTarget bool   `json:"defaultMutationTarget,omitempty"`
}

// ClusterTargets DERIVES the selectable targets from the operator's live kubeconfig contexts
// (P4a — never a hardcoded context string). Each real context becomes a runnable read-only
// scan target; EKS/CoreWeave are recognized for labeling but their GPU magnitudes stay
// GPU validation is tracked by PHORVEXSEC-87. If no kubeconfig resolves, the list is
// honestly empty (the UI shows a
// "no clusters found — point KUBECONFIG at a cluster" state).
func (rm *RunManager) ClusterTargets() []ClusterTarget {
	ctxs, defaultContext, inClusterDefault := kubeTargetResolution()
	out := make([]ClusterTarget, 0, len(ctxs))
	for _, c := range ctxs {
		target := classifyContext(c)
		target.DefaultMutationTarget = c == defaultContext
		out = append(out, target)
	}
	// In-cluster (Deployment) fallback: no kubeconfig contexts resolve, but the pod has a mounted
	// ServiceAccount — surface THIS cluster as a runnable read-only target so the live workload
	// view works at the public console URL without any kubeconfig.
	if len(out) == 0 && inClusterDefault {
		out = append(out, ClusterTarget{
			ID: "in-cluster", Context: "in-cluster", Runnable: true,
			DefaultMutationTarget: true,
			Label:                 "This cluster (in-cluster)",
			// The label used to say "read-only live view", which understated it: behind the
			// Cognito auth gate the console fires real attacks AND edits PhorvexPolicy live
			// (mode, budget, actuators) via the operator ServiceAccount. It is a control
			// plane for an authenticated operator, not a read-only viewer.
			Note: "DERIVED from the pod ServiceAccount — live control (authenticated operator)",
		})
	}
	return out
}

// StartScenario runs a SINGLE scenario (generated one-scenario config) against the chosen
// arms, on the chosen cluster target, confined to the chosen sandbox namespace. withPX selects
// d-phorvex (compared against no-MTD); otherwise the non-PX baselines. The harness deploys its
// own synthetic attacker + victim into `namespace` and confines every object there — it does
// not touch pre-existing workloads in other namespaces.
func (rm *RunManager) StartScenario(scenarios []string, withPX, compare3 bool, targetID, namespace, startedAt, owner string) (string, error) {
	if rm.cfg.runsDir() == "" {
		return "", fmt.Errorf("console state directory is not configured")
	}
	if len(scenarios) == 0 {
		return "", fmt.Errorf("no scenario selected")
	}
	if len(scenarios) > 16 {
		return "", fmt.Errorf("too many scenarios (max 16 per batch)")
	}
	for _, s := range scenarios {
		if !scenarioRe.MatchString(s) {
			return "", fmt.Errorf("invalid scenario name %q", s)
		}
	}
	// SAFETY (load-bearing): the harness DELETES its run namespace at final teardown
	// (core.Env.CleanupOwned deleteNamespace=true). So an attack MUST run only in a dedicated,
	// disposable sandbox — NEVER a real workload namespace, or that namespace + its app get
	// destroyed. We therefore IGNORE any caller-supplied namespace and always use the sandbox.
	// ScenarioDestination mirrors both of these substitutions so the auth boundary authorizes
	// the destination this function actually uses.
	namespace = scenarioSandboxNamespace
	target := scenarioFallbackContext
	provider, targetLabel := "Kubernetes", target
	for _, t := range rm.ClusterTargets() {
		if normalizeTargetID(t.ID) == normalizeTargetID(targetID) {
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
	armsPerScenario := 2
	arms := "[d-nomtd, d-r6blindtimer]"
	switch {
	case compare3:
		arms, armsPerScenario = "[d-nomtd, d-r6blindtimer, d-phorvex]", 3
	case withPX:
		arms = "[d-phorvex, d-nomtd]"
	}
	// BATCH: the harness scenarioFilter is a list — one run sweeps every selected scenario.
	expectedTrials := armsPerScenario * 2 * len(scenarios) // arms × trialsPerArm(2) × #scenarios
	scenList := strings.Join(scenarios, ", ")
	scenLabel := scenarios[0]
	if len(scenarios) > 1 {
		scenLabel = fmt.Sprintf("%s +%d more", scenarios[0], len(scenarios)-1)
	}
	rm.mu.Lock()
	// Rate-limit rapid double-launches; the concurrency cap is handled by QUEUEING (below), not rejecting.
	if !rm.lastStart.IsZero() && time.Since(rm.lastStart) < minStartInterval {
		rm.mu.Unlock()
		return "", fmt.Errorf("rate limited: wait a moment between launches")
	}
	rm.seq++
	rm.lastStart = time.Now()
	id := fmt.Sprintf("scn-%d", rm.seq)
	outDir := "out-console-" + id
	rm.mu.Unlock()
	cfg := fmt.Sprintf("kubeconfig: \"\"\ncontext: %q\nnamespace: %q\nownedAck: true\ntrialsPerArm: 2\nmasterSeed: 1337\nphoenixSrcDir: %q\noutDir: %q\ndefenderFilter: %s\nscenarioFilter: [%s]\n",
		target, namespace, filepath.Join(rm.cfg.Root, "build", "phoenix-extended"), rm.cfg.runOutputPath(outDir), arms, scenList)
	cfgPath := filepath.Join(rm.cfg.runsDir(), "configs", "config.console-"+id+".yaml")
	if err := atomicWriteState(cfgPath, []byte(cfg)); err != nil {
		return "", err
	}
	intent, _ := json.Marshal(map[string]any{"kind": "phorvex.console.run", "phase": "intent", "time": time.Now().UTC(), "id": id, "scenarios": scenarios, "namespace": namespace, "target": target})
	if err := rm.cfg.appendState(rm.cfg.statePath("run-events.jsonl"), intent); err != nil {
		return "", err
	}
	// A 3-way (compare3) run uses the NATIVE actuator so the Phorvex arm actually rotates the
	// sandbox victim (direct client-go pod delete) — reliable + fast, so it visibly disrupts the attack.
	su := suite{File: cfgPath, OutDir: outDir}
	rm.mu.Lock()
	// QUEUE rather than reject: when a slot is busy the run waits in FIFO and auto-starts on completion
	// (the harness shares one sandbox ns + fixed operator ports, so concurrent runs would collide).
	queued := rm.active >= maxConcurrentRuns
	state := "running"
	if queued {
		state = "queued"
	} else {
		rm.active++
	}
	st := &RunStatus{ID: id, Config: scenLabel, State: state, Started: startedAt, Date: tsNow(), NativeActuator: withPX, Compare3: compare3, Namespace: namespace, Target: target, Provider: provider, TargetLabel: targetLabel, ExpectedTrials: expectedTrials, Owner: owner, ScopeTarget: normalizeTargetID(target), ScopeTenant: namespace}
	rm.runs[id] = st
	rm.runOut[id] = outDir
	if err := rm.persistStatus(st, outDir); err != nil {
		delete(rm.runs, id)
		delete(rm.runOut, id)
		if !queued && rm.active > 0 {
			rm.active--
		}
		rm.mu.Unlock()
		return "", fmt.Errorf("persist run status before effect: %w", err)
	}
	if queued {
		rm.pending[id] = pendingRun{su: su, native: compare3}
		rm.queue = append(rm.queue, id)
		rm.mu.Unlock()
		return id, nil
	}
	rm.mu.Unlock()
	go rm.run(id, su, compare3)
	return id, nil
}

// runDestination is what a triggered run will ACTUALLY touch, after every default and fallback
// the launcher applies. Authorization has to be decided against this, not against the target the
// request named — a request can omit the target entirely and still reach a concrete cluster.
type runDestination struct {
	// Targets always includes hostTargetID: launching the harness is itself a privileged act on
	// the machine this console runs on. It additionally includes the cluster context the run's
	// config selects, when one can be determined.
	Targets []string
	// Tenants is the namespace the run confines itself to, when the config declares one.
	Tenants []string
	// ScopeTarget and ScopeTenant are recorded on the RunStatus for later run-id authorization.
	ScopeTarget string
	ScopeTenant string
	// RequireTenantWildcard is set when the destination's namespace could NOT be determined. An
	// undetermined namespace is not "no tenant effect": the harness still runs somewhere, so the
	// request needs a cross-tenant grant rather than passing an empty tenant check.
	RequireTenantWildcard bool
}

// hostTargetID is the target identifier for "the machine this console runs on" — the console's
// own cluster and the host that executes harness subprocesses. It is the same sentinel a request
// selects by omitting ?target=/?context=.
const hostTargetID = defaultTargetID

// suiteConfig is the subset of a harness config that decides WHERE a suite runs.
type suiteConfig struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
}

// SuiteDestination reads the whitelisted suite's OWN config to find the cluster context and
// namespace it will drive. It never assumes: an unreadable or context-less config yields only
// the host target, because without a usable config the harness reaches no cluster at all — the
// subprocess launch on this host remains the effect that must still be authorized.
func (rm *RunManager) SuiteDestination(name string) (runDestination, error) {
	su, ok := allowedConfigs[name]
	if !ok {
		return runDestination{}, fmt.Errorf("config %q not in the allowed attack-agent suites", name)
	}
	// An undetermined namespace requires a cross-tenant grant. Reading a config that names none —
	// or failing to read one at all — does not mean the run touches no tenant; it means we cannot
	// say which, and that is not something to resolve in the caller's favour.
	dest := runDestination{Targets: []string{hostTargetID}, ScopeTarget: hostTargetID, RequireTenantWildcard: true}
	raw, err := os.ReadFile(filepath.Join(rm.cfg.HarnessDir, su.File))
	if err != nil {
		return dest, nil
	}
	var cfg suiteConfig
	// The shipped configs carry a UTF-8 BOM; strip it so the destination is actually parsed
	// rather than silently falling back to "host only".
	if yaml.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &cfg) != nil {
		return dest, nil
	}
	if ctx := strings.TrimSpace(cfg.Context); ctx != "" {
		dest.Targets = append(dest.Targets, ctx)
		dest.ScopeTarget = ctx
	}
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		dest.Tenants = append(dest.Tenants, ns)
		dest.ScopeTenant = ns
		dest.RequireTenantWildcard = false
	}
	return dest, nil
}

// ScenarioDestination mirrors StartScenario's OWN resolution: an unknown or omitted target falls
// back to the kind sandbox context, and the namespace is forced to the disposable sandbox
// whatever the caller asked for. Authorizing the requested target instead of this one would let
// an omitted parameter reach a cluster the grant never covered.
func (rm *RunManager) ScenarioDestination(targetID string) runDestination {
	target := scenarioFallbackContext
	for _, t := range rm.ClusterTargets() {
		// Alias-aware: the selector may send "in-cluster" for the same cluster a grant spells
		// "default", and an omitted target means that cluster too.
		if normalizeTargetID(t.ID) == normalizeTargetID(targetID) {
			target = t.Context
		}
	}
	return runDestination{
		Targets:     []string{hostTargetID, target},
		Tenants:     []string{scenarioSandboxNamespace},
		ScopeTarget: target,
		ScopeTenant: scenarioSandboxNamespace,
	}
}

// runOwnership is what a run id resolves to for authorization: the destination it actually
// drives, plus the verified identity that created it.
type runOwnership struct {
	Owner  string
	Target string
	Tenant string
}

// Ownership reports the destination and creator recorded for a run id. The auth boundary uses it
// to decide whether this caller may read, stream or stop the run; an unknown id returns ok=false
// so probing ids discloses nothing about another operator's runs.
func (rm *RunManager) Ownership(id string) (runOwnership, bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	st, found := rm.runs[id]
	if !found {
		return runOwnership{}, false
	}
	return runOwnership{Owner: st.Owner, Target: st.ScopeTarget, Tenant: st.ScopeTenant}, true
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
	out := filepath.Join(rm.cfg.runOutputPath(rm.runOut[id]), "metrics.jsonl")
	if rows, ok := readMetrics(out); ok {
		st.Arms, st.Trials = summarizeArms(rows)
	}
	cp := *st
	cp.QueuePos = rm.queuePosLocked(id) // 0 unless still queued
	return &cp, true
}

// List returns every triggered run (newest first), each with its date + refreshed per-arm
// metrics — the post-attack report history the dashboard shows after live attacks.
func (rm *RunManager) List() []RunStatus {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	out := make([]RunStatus, 0, len(rm.runs))
	for id, st := range rm.runs {
		if rows, ok := readMetrics(filepath.Join(rm.cfg.runOutputPath(rm.runOut[id]), "metrics.jsonl")); ok {
			st.Arms, st.Trials = summarizeArms(rows)
		}
		cp := *st
		cp.QueuePos = rm.queuePosLocked(id) // 0 unless still queued
		out = append(out, cp)
	}
	// newest first (run ids are run-N / scn-N; sort by the trailing sequence number desc).
	sort.Slice(out, func(i, j int) bool { return seqOf(out[i].ID) > seqOf(out[j].ID) })
	return out
}

// ListMetadata snapshots every run without touching its metrics file. Paged callers use this to
// authorize, filter and select a page before doing any filesystem work.
func (rm *RunManager) ListMetadata() ([]RunStatus, int, []string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	out := make([]RunStatus, 0, len(rm.runs))
	maxSeq := 0
	ids := make([]string, 0, len(rm.runs))
	for id, st := range rm.runs {
		cp := *st
		cp.Arms = nil
		cp.QueuePos = rm.queuePosLocked(id)
		out = append(out, cp)
		ids = append(ids, id)
		if n := seqOf(id); n > maxSeq {
			maxSeq = n
		}
	}
	sort.Strings(ids)
	sort.Slice(out, func(i, j int) bool {
		si, sj := seqOf(out[i].ID), seqOf(out[j].ID)
		if si != sj {
			return si > sj
		}
		return out[i].ID > out[j].ID
	})
	return out, maxSeq, ids
}

// HydrateList refreshes metrics only for the already-selected run ids. No manager lock is held
// during file I/O; live status fields are re-snapshotted after each read.
func (rm *RunManager) HydrateList(selected []RunStatus) []RunStatus {
	out := make([]RunStatus, 0, len(selected))
	for _, meta := range selected {
		rm.mu.Lock()
		st := rm.runs[meta.ID]
		if st == nil {
			rm.mu.Unlock()
			continue
		}
		path := filepath.Join(rm.cfg.runOutputPath(rm.runOut[meta.ID]), "metrics.jsonl")
		rm.mu.Unlock()

		var arms []ArmResult
		var trials int
		if rows, ok := readMetrics(path); ok {
			arms, trials = summarizeArms(rows)
		}

		rm.mu.Lock()
		st = rm.runs[meta.ID]
		if st != nil {
			cp := *st
			if arms != nil {
				cp.Arms, cp.Trials = arms, trials
				st.Arms, st.Trials = arms, trials
			}
			cp.QueuePos = rm.queuePosLocked(meta.ID)
			out = append(out, cp)
		}
		rm.mu.Unlock()
	}
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
		"-config", su.File,
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
	outAbs := rm.cfg.runOutputPath(su.OutDir)
	if mkErr := os.MkdirAll(outAbs, 0o750); mkErr != nil {
		rm.failRunBeforeStart(id, mkErr)
		return
	}
	lf, lerr := os.OpenFile(filepath.Join(outAbs, "console-run.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if lerr != nil {
		rm.failRunBeforeStart(id, lerr)
		return
	}
	cmd.Stdout, cmd.Stderr = lf, lf
	defer lf.Close()
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
	defer rm.dequeueNextLocked() // LIFO: runs BEFORE the unlock, so the next queued attack auto-starts
	delete(rm.procs, id)
	if rm.active > 0 {
		rm.active--
	}
	st := rm.runs[id]
	if st == nil {
		return
	}
	defer func() {
		if e := rm.persistStatus(st, rm.runOut[id]); e != nil {
			st.State = "partial"
			st.Error = "run outcome persistence failed; unsafe to retry: " + e.Error()
		}
	}()
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
		// per-provider pointer (st.Target is the kubeconfig context) so a vCluster 3-way doesn't
		// overwrite the EKS comparison and vice-versa.
		if e := atomicWriteState(rm.cfg.statePath(comparePointerFile(st.Target)), []byte(su.OutDir)); e != nil {
			st.State = "partial"
			st.Error = "run completed but comparison pointer is unavailable: " + e.Error()
			return
		}
	}
	// Regenerate the cost/ROI report for THIS run so the Report tab updates after an attack
	// finishes (no cluster, no re-run — pure post-processing of the run's metrics.jsonl).
	go func(out string) {
		metrics := filepath.Join(rm.cfg.runOutputPath(out), "metrics.jsonl")
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

func (rm *RunManager) failRunBeforeStart(id string, err error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.active > 0 {
		rm.active--
	}
	if st := rm.runs[id]; st != nil {
		st.State = "error"
		st.Finished = tsNow()
		st.Error = "run refused before process start: " + err.Error()
		if persistErr := rm.persistStatus(st, rm.runOut[id]); persistErr != nil {
			st.State = "partial"
			st.Error += "; status persistence failed: " + persistErr.Error()
		}
	}
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
		if r.NegativeControl || !r.securityScorable() {
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
