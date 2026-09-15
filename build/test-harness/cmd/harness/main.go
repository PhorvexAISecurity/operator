// Command harness is the durable, plugin-based Kubernetes attack/benchmark
// harness entrypoint. It loads a per-target config, asserts containment (owned
// ack + live-context + apiserver-host match), detects cluster capabilities, runs
// the generic scenario x defender x trial matrix (with negative + positive
// controls and an adaptive-attacker arm), and writes metrics + a report + a
// provenance map. EVERYTHING is reproducible from the fixed master seed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"math/rand"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/r6security/phoenix-test-harness/internal/capability"
	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/kube"
	"github.com/r6security/phoenix-test-harness/internal/report"
	"github.com/r6security/phoenix-test-harness/internal/safety"

	// Side-effect imports: every scenario/defender self-registers via init().
	// Adding a future plugin = one new file in these packages, ZERO changes here.
	_ "github.com/r6security/phoenix-test-harness/defenders"
	_ "github.com/r6security/phoenix-test-harness/scenarios"
)

// cleanupBudget bounds the owned cleanup this command performs per trial and at
// final teardown. It matches core.DefaultCleanupTimeout so the closer cannot
// outlive the bound the runner is already enforcing on it.
const cleanupBudget = core.DefaultCleanupTimeout

func main() {
	cfgPath := flag.String("config", "", "path to the per-target config (YAML/JSON). REQUIRED.")
	dryRun := flag.Bool("dry-run", false, "validate config + safety guard + capabilities and list the plugin matrix WITHOUT mutating the cluster")
	listOnly := flag.Bool("list", false, "list registered scenarios + defenders and exit")
	negControl := flag.Bool("negative-control", true, "run the no-attack negative control per arm")
	adaptive := flag.Bool("adaptive", true, "run the adaptive-attacker arm per (scenario,defender)")
	dollarsFrom := flag.String("dollars-from", "", "PASS-A-WITH-DOLLARS view: read this existing metrics.jsonl, recompute ROI($)/Schwartau/reusability + H1/H2/H3, write report-dollars.md NEXT TO it, and exit (no cluster, no re-run)")
	resume := flag.Bool("resume", false, "ACCUMULATE: append this run's metrics to outDir/metrics.jsonl instead of truncating it, and regenerate the report/dollars over the running total (for batched benchmarks sharing one out-dir + masterSeed; keep batch scenarioFilters disjoint)")
	flag.Parse()

	if *listOnly {
		listPlugins()
		return
	}

	if *dollarsFrom != "" {
		if err := dollarsOnly(*dollarsFrom); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -config is required (the per-target config naming the authorized context + namespace + owned ack)")
		os.Exit(2)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(2)
	}

	ctx := context.Background()
	if err := run(ctx, cfg, *dryRun, *negControl, *adaptive, *resume); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func listPlugins() {
	fmt.Println("Registered scenarios:")
	for _, s := range core.Scenarios() {
		m := s.Metadata()
		fmt.Printf("  - %-26s [%s] R6=%s realism=%s declared=%v exercised=%v caps=%v limits=%q\n", m.Name, m.Category, m.R6ResponseTag, m.EffectiveRealism(), m.AttackTechniqueIDs, m.ExercisedTechniqueIDs, m.CapabilityRequirements, m.ClaimLimits)
	}
	fmt.Println("Registered defenders:")
	for _, d := range core.Defenders() {
		m := d.Metadata()
		fmt.Printf("  - %-18s baseline=%v rate=%.0fs  %s\n", m.Name, m.IsNegativeControlBaseline, m.MeanRotationIntervalSeconds, m.Description)
	}
}

func run(ctx context.Context, cfg config.TargetConfig, dryRun, negControl, adaptive, resume bool) error {
	// 1) Build clients PINNED to the configured context.
	clients, err := kube.Build(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		return err
	}

	// 2) Safety guard: assert owned-ack + live-context + apiserver-host match BEFORE
	// any mutation. A refusal aborts the whole run.
	guard, err := safety.NewGuard(cfg, clients.LiveContext, clients.LiveHost)
	if err != nil {
		return fmt.Errorf("safety guard: %w", err)
	}
	fmt.Printf("Safety guard OK: context=%s host=%s namespace=%s ownedAck=%v\n", clients.LiveContext, clients.LiveHost, cfg.Namespace, cfg.OwnedAck)

	// 3) Capability detection at runtime.
	caps, capNotes, err := capability.Detect(ctx, clients.Kube)
	if err != nil {
		return fmt.Errorf("capability detect: %w", err)
	}
	fmt.Printf("Detected capabilities: GPU=%v MultiNode=%v MIG=%v Nodes=%d\n", caps.GPU, caps.MultiNode, caps.MIG, caps.NodeCount)

	// Install the in-pod exec primitive (core stays decoupled from internal/safety).
	core.SetExecer(func(c context.Context, restCfg *rest.Config, kc kubernetes.Interface, ns, pod, container string, command []string) core.ExecResult {
		r := safety.ExecInPod(c, restCfg, kc, ns, pod, container, command)
		return core.ExecResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode, Err: r.Err}
	})

	if dryRun {
		fmt.Println("\n--- DRY RUN: no cluster mutation. Plugin matrix ---")
		listPlugins()
		fmt.Println("\nCapability notes:")
		for k, v := range capNotes {
			fmt.Printf("  %s: %s\n", k, v)
		}
		return nil
	}

	// 4) Prepare output dirs + metrics writer.
	outDir := cfg.OutDir
	_ = os.MkdirAll(filepath.Join(outDir, "raw"), 0o755)
	metricsPath := filepath.Join(outDir, "metrics.jsonl")
	var mw *core.MetricWriter
	if resume {
		// ACCUMULATE into the same out-dir: preload prior batches' rows + append.
		// The read is STRICT: a file that cannot be fully parsed is never appended
		// to, and prior rows written before the measurement-validity contract are
		// reported as legacy/unverified rather than silently re-scored.
		read, lerr := report.ReadMetricsFile(metricsPath)
		if lerr != nil && !os.IsNotExist(lerr) {
			return fmt.Errorf("resume: read prior metrics %s: %w", metricsPath, lerr)
		}
		if n := len(read.Undecodable); n > 0 {
			return fmt.Errorf("resume: %s has %d undecodable line(s) (first at line %d: %s); refusing to append to a file that cannot be fully read",
				metricsPath, n, read.Undecodable[0].Line, read.Undecodable[0].Error)
		}
		prior := read.Metrics
		mw, err = core.NewMetricWriterResume(metricsPath, prior)
		if err != nil {
			return err
		}
		fmt.Printf("RESUME: preloaded %d prior metric rows from %s (%d LEGACY/UNVERIFIED, excluded from certified scores); appending this batch (masterSeed=%d)\n",
			len(prior), metricsPath, read.Legacy, cfg.MasterSeed)
	} else {
		mw, err = core.NewMetricWriter(metricsPath)
		if err != nil {
			return err
		}
	}
	defer mw.Close()

	// 5) Build the EnvFactory: a fresh Env per trial with a deterministic RNG and a
	// per-trial raw logger. The whole loop is generic; the factory is the only
	// place clients/loggers are wired.
	factory := func(scenarioName, defenderName string, trial int, seed int64, rawLogPath string) (*core.Env, func() error, error) {
		tl, err := core.NewTrialLogger(rawLogPath, func(line string) { /* raw-log only; stdout stays terse */ })
		if err != nil {
			return nil, nil, err
		}
		env := &core.Env{
			Ctrl:           clients.Ctrl,
			Kube:           clients.Kube,
			Rest:           clients.Rest,
			Config:         cfg,
			Caps:           caps,
			Rand:           newRand(seed),
			Log:            tl,
			Guard:          guard,
			Trial:          trial,
			ScenarioName:   scenarioName,
			DefenderName:   defenderName,
			RestConfigHost: clients.LiveHost,
		}
		// Ensure the sandbox namespace exists once per trial (idempotent).
		if err := env.EnsureNamespace(ctx); err != nil {
			_ = closeLogger(tl)
			return nil, nil, err
		}
		closer := func() error {
			// Per-trial owned cleanup (idempotent), then close the logger.
			//
			// The cleanup runs on a DETACHED, BOUNDED context: detached so the
			// cleanup owed by this trial is still attempted when the run context
			// has been cancelled, bounded so an unresponsive apiserver cannot make
			// the closer hang past the runner's own cleanup bound. Both the
			// cleanup error and the logger-close error are PROPAGATED and
			// aggregated — a swallowed cleanup failure here is exactly how a dirty
			// namespace used to be reported as clean.
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
			defer cancel()
			cleanupErr := env.CleanupOwned(cctx, false)
			logErr := closeLogger(tl)
			return errors.Join(cleanupErr, logErr)
		}
		return env, closer, nil
	}

	// 6) Run the generic matrix.
	opts := core.RunnerOptions{
		TrialsPerArm:       cfg.TrialsPerArm,
		MasterSeed:         cfg.MasterSeed,
		OutDir:             outDir,
		CILevel:            0.95,
		RunNegativeControl: negControl,
		AdaptiveArm:        adaptive,
		ScenarioFilter:     toSet(cfg.ScenarioFilter),
		DefenderFilter:     toSet(cfg.DefenderFilter),
	}
	runner := core.NewRunner(opts, factory, mw, func(line string) { fmt.Println(line) })
	fmt.Printf("\nRunning matrix: %d scenarios x %d defenders x %d trials/arm (seed=%d)\n", len(selScenarios(opts)), len(selDefenders(opts)), cfg.TrialsPerArm, cfg.MasterSeed)
	metrics, runErr := runner.Run(ctx)
	outcome := runner.Outcome()
	if runErr != nil {
		// The run stopped early (e.g. unverified cleanup, or a metric write
		// failure). The rows produced before the stop are real evidence, so the
		// reports are still written — labelled INCOMPLETE — and the command then
		// exits non-zero. Nothing here claims a complete matrix.
		fmt.Fprintf(os.Stderr, "RUN INCOMPLETE: %v\n", runErr)
	}

	// 6b) Do not abandon cleanup the runner still owns. A call that outlived its
	// bound may still be mutating the namespace; drain it (bounded) and report
	// whatever it eventually returned. Draining does NOT make an unresolved trial
	// clean — the row and the run outcome keep saying it is unresolved.
	if late := runner.WaitForPendingCleanup(cleanupBudget); late > 0 {
		outcome = runner.Outcome()
		fmt.Fprintf(os.Stderr, "WARN: %d cleanup call(s) outlived their bound; their trials remain UNRESOLVED:\n", late)
		for _, l := range outcome.LateCleanups {
			// Report truthfully: a call that has NOT returned is still running and
			// still owns its resources. Printing "returned" for it would claim the
			// opposite of what is known.
			if !l.Returned {
				fmt.Fprintf(os.Stderr, "  %s/%s trial %d %s STILL RUNNING after %.1fs (has not returned; its resources are still owned)\n",
					l.Scenario, l.Defender, l.Trial, l.Step, l.Seconds)
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s/%s trial %d %s returned late after %.1fs (err=%q)\n",
				l.Scenario, l.Defender, l.Trial, l.Step, l.Seconds, l.Error)
		}
	}

	// 7) Final teardown: remove the sandbox namespace + all owned objects — but
	// ONLY if no cleanup this run still owns is still running. Its failures are
	// part of the RUN RESULT, not a warning: an unverified (or refused) final
	// teardown leaves the cluster dirty for the NEXT run, so it makes this run
	// INCOMPLETE, lands in the provenance and exits non-zero.
	finalErr, attempted := finalizeRun(ctx, runner.UnreturnedCleanups(), factory, outDir)
	if attempted {
		runner.RecordFinalTeardown(finalErr)
		if finalErr != nil {
			fmt.Fprintf(os.Stderr, "FINAL TEARDOWN NOT VERIFIED: %v\n", finalErr)
		}
	} else {
		runner.RecordFinalTeardownBlocked(finalErr.Error())
		fmt.Fprintf(os.Stderr, "FINAL TEARDOWN NOT ATTEMPTED: %v\n", finalErr)
	}
	outcome = runner.Outcome()

	// 8) Reports + provenance.
	reproduce := fmt.Sprintf("go run ./cmd/harness -config <config.yaml>   # masterSeed=%d + the fixed per-trial seeds reproduce this run exactly", cfg.MasterSeed)
	repPath, err := report.WriteReportRun(outDir, metrics, opts.CILevel, capNotes, &outcome)
	if err != nil {
		return err
	}
	pm := report.BuildProvenance(metrics, cfg.MasterSeed, cfg.TrialsPerArm, cfg.Context, cfg.Namespace, metricsPath, reproduce, &outcome)
	provPath, err := report.WriteProvenance(outDir, pm)
	if err != nil {
		return err
	}
	mitre := report.RenderMitreMatrix(core.Scenarios())
	mitrePath := filepath.Join(outDir, "mitre_matrix.md")
	if err := os.WriteFile(mitrePath, []byte(mitre), 0o644); err != nil {
		return fmt.Errorf("write MITRE mapping inventory: %w", err)
	}
	inventoryPath := filepath.Join(outDir, "scenario_inventory.md")
	if err := os.WriteFile(inventoryPath, []byte(report.RenderScenarioInventory(core.Scenarios())), 0o644); err != nil {
		return fmt.Errorf("write scenario mechanism inventory: %w", err)
	}

	// Pass-B dollars / Schwartau / reusability + H1/H2/H3 view (uses the live config
	// $ knobs and the per-arm rotation intervals from defender metadata).
	dollarsPath, derr := report.WriteDollarsReport(outDir, "report-dollars.md", report.ExcludeMarkerSimulations(metrics), dollarInputsFromConfig(cfg), opts.CILevel)
	if derr != nil {
		fmt.Fprintf(os.Stderr, "WARN: dollars report: %v\n", derr)
	}

	state := "COMPLETE"
	if !outcome.Complete {
		state = "INCOMPLETE"
	}
	fmt.Printf("\nDone (%s: planned %d / executed %d / written %d). %d metric records.\n  metrics:    %s\n  report:     %s\n  provenance: %s\n  mitre:      %s\n  inventory:  %s\n  dollars:    %s\n",
		state, outcome.PlannedTrials, outcome.ExecutedTrials, outcome.WrittenTrials, len(metrics), metricsPath, repPath, provPath, mitrePath, inventoryPath, dollarsPath)
	// Both failures matter and neither masks the other.
	return errors.Join(runErr, finalErr)
}

// finalizeRun performs the run-level teardown, honouring the SAME ownership
// barrier the per-trial cleanup enforces.
//
// If cleanup this run still owns has not returned, that call is still operating
// on this namespace and these objects. Deleting the namespace underneath it
// would race it, and a teardown that merely collided with a live callback is not
// a verified teardown. So the teardown is refused, and the caller records it as
// NOT ATTEMPTED — never as verified.
//
// It returns (result, attempted). When attempted is false the error explains the
// refusal; the run stays INCOMPLETE either way.
//
// The `Returned` predicate is applied HERE rather than trusted from the caller:
// a barrier that depends on someone else having filtered the list correctly is
// one refactor away from being no barrier at all.
func finalizeRun(ctx context.Context, late []core.LateCleanup, factory core.EnvFactory, outDir string) (error, bool) {
	var steps []string
	for _, l := range late {
		if l.Returned {
			continue // it finished; it no longer owns anything
		}
		steps = append(steps, fmt.Sprintf("%s/%s trial %d %s (still running after %.1fs)",
			l.Scenario, l.Defender, l.Trial, l.Step, l.Seconds))
	}
	if len(steps) > 0 {
		return fmt.Errorf("%d cleanup call(s) this run owns have not returned and still hold the sandbox namespace, "+
			"so deleting it now would race them: %s", len(steps), strings.Join(steps, "; ")), false
	}
	return finalTeardown(ctx, factory, outDir), true
}

// finalTeardown removes the sandbox namespace and every owned object after the
// matrix, and returns whether that VERIFIED. Every link of the real chain —
// building the environment, the cleanup helper and the closer — is a failure
// worth returning, because any of them leaves state the next run would inherit.
func finalTeardown(ctx context.Context, factory core.EnvFactory, outDir string) error {
	env, closer, ferr := factory("final", "teardown", -1, 0, filepath.Join(outDir, "raw", "final_teardown.log"))
	if ferr != nil {
		return fmt.Errorf("final teardown could not build an environment: %w", ferr)
	}
	fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBudget)
	defer fcancel()
	cleanupErr := env.CleanupOwned(fctx, true)
	closeErr := boundedClose(closer)
	return errors.Join(cleanupErr, closeErr)
}

// boundedClose waits on the context-free closer under the shared cleanup budget.
func boundedClose(closer func() error) error {
	return boundedCloseWithin(closer, cleanupBudget)
}

// boundedCloseWithin waits on the context-free closer under a wall-clock bound.
// The closer receives no context, so the only way to stop it outlasting the run
// is to stop WAITING on it — and to say plainly that it never returned, rather
// than hang the command forever.
func boundedCloseWithin(closer func() error, bound time.Duration) error {
	if closer == nil {
		return nil
	}
	done := make(chan error, 1) // buffered: a late send never blocks or leaks
	go func() { done <- closer() }()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("final teardown closer did not return within %s: UNRESOLVED, it may still be running", bound)
	}
}

// dollarInputsFromConfig assembles the DollarInputs from the live config $ knobs
// plus the per-arm rotation intervals read from the REGISTERED defenders (so
// Schwartau's P is the genuine interval each arm advertises).
func dollarInputsFromConfig(cfg config.TargetConfig) report.DollarInputs {
	gpuCount, dphr, ovhd, breach, horizon := cfg.ROIInputs()
	intervals := map[string]float64{}
	baseline := ""
	for _, d := range core.Defenders() {
		md := d.Metadata()
		intervals[md.Name] = md.MeanRotationIntervalSeconds
		if md.IsNegativeControlBaseline {
			baseline = md.Name
		}
	}
	return report.DollarInputs{
		ROI:               core.ROIInputs{GpuCount: gpuCount, DollarsPerGpuHour: dphr, GpuOverheadPercent: ovhd, AvoidedBreachValue: breach, HorizonYears: horizon},
		RotationIntervals: intervals,
		BaselineDefender:  baseline,
	}
}

// dollarsOnly is the PASS-A-WITH-DOLLARS post-processor: it reads an existing
// metrics.jsonl, recomputes ROI($)/Schwartau/reusability + H1/H2/H3 over the SAME
// extended schema, and writes report-dollars.md next to it. ZERO cluster access,
// ZERO re-execution — so the 1980-row Pass-A matrix becomes comparable to Pass B.
func dollarsOnly(metricsFile string) error {
	// Read TOLERANTLY here: this is a reporting view over a historical file, so an
	// undecodable line is disclosed as a known unknown rather than discarding the
	// rows that did decode. Legacy rows (written before the measurement-validity
	// contract) are counted and excluded from certified scores, never rewritten.
	read, err := report.ReadMetricsFile(metricsFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", metricsFile, err)
	}
	metrics := read.Metrics
	for _, bad := range read.Undecodable {
		fmt.Fprintf(os.Stderr, "WARN: %s line %d could not be decoded and is EXCLUDED: %s\n", metricsFile, bad.Line, bad.Error)
	}
	// Use clearly-labeled DEFAULTS for the $ knobs (a config blob may not be at
	// hand for a historical metrics file) and the known per-arm rotation intervals.
	var defaults config.TargetConfig
	defaults.OwnedAck = true
	defaults.Context = "n/a"
	defaults.Namespace = "n/a"
	// Apply the same ROI defaults the config loader would (exported via a tiny round-trip).
	cfg := config.WithDollarDefaults(defaults)
	gpuCount, dphr, ovhd, breach, horizon := cfg.ROIInputs()
	in := report.DollarInputs{
		ROI:               core.ROIInputs{GpuCount: gpuCount, DollarsPerGpuHour: dphr, GpuOverheadPercent: ovhd, AvoidedBreachValue: breach, HorizonYears: horizon},
		RotationIntervals: report.DefaultRotationIntervals(),
		BaselineDefender:  "d-nomtd",
	}
	outDir := filepath.Dir(metricsFile)
	path, werr := report.WriteDollarsReport(outDir, "report-dollars.md", metrics, in, 0.95)
	if werr != nil {
		return werr
	}
	fmt.Printf("Pass-A-with-dollars view written: %s (%d metric rows decoded, %d LEGACY/UNVERIFIED and excluded from certified scores, %d undecodable line(s); no re-run)\n",
		path, len(metrics), read.Legacy, len(read.Undecodable))
	return nil
}

// newRand builds the deterministic per-trial RNG from a derived seed.
func newRand(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}

// closeLogger flushes/closes a trial logger if it supports io.Closer.
func closeLogger(l core.Logger) error {
	if c, ok := l.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func toSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := map[string]bool{}
	for _, x := range xs {
		if s := strings.TrimSpace(x); s != "" {
			m[s] = true
		}
	}
	return m
}

func selScenarios(o core.RunnerOptions) []core.Scenario {
	all := core.Scenarios()
	if len(o.ScenarioFilter) == 0 {
		return all
	}
	var out []core.Scenario
	for _, s := range all {
		if o.ScenarioFilter[s.Metadata().Name] {
			out = append(out, s)
		}
	}
	return out
}

func selDefenders(o core.RunnerOptions) []core.Defender {
	all := core.Defenders()
	if len(o.DefenderFilter) == 0 {
		return all
	}
	var out []core.Defender
	for _, d := range all {
		if o.DefenderFilter[d.Metadata().Name] {
			out = append(out, d)
		}
	}
	return out
}
