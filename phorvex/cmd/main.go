/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 *
 * The brain on top of UNMODIFIED extended Phoenix: ingest -> graph -> physics/
 * context/belief/cost/feasibility -> decision -> audit/metrics, actuating (active
 * mode only) by emitting SecurityEvent + AMTD CRs that Phoenix executes (Seam 1).
 */

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/controller"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/runner"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	// Register the Phoenix types so Phorvex can construct/emit SecurityEvent + AMTD
	// CRs over Seam 1 (the ONLY reason Phorvex depends on the Phoenix module).
	utilruntime.Must(amtdv1beta1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr      string
		probeAddr        string
		enableLeader     bool
		baseInterval     time.Duration
		promURL          string
		killSwitch       bool
		auditJSON        string
		operatorNS       string
		integrationEmit  bool
		emitNamespace    string
		emitPod          string
		emitAction       string
		emitTenant       string
		emitMatchLabels  string
		engineName       string
		ablation         bool
		ablationNS       string
		ablationSelector string
		ablationBudget   int
		ablationSeeds    int
		scan             bool
		scanNS           string
		nativeDemo       bool
		nativeDemoNS     string
	)
	flag.BoolVar(&nativeDemo, "native-demo", false, "One-shot (P-ACTUATOR): drive the native actuator's full action set live against a demo namespace, verify cluster state + safety, print a table, then exit.")
	flag.StringVar(&nativeDemoNS, "native-demo-namespace", "phorvex-actuator-demo", "[native-demo] namespace for the live actuation proof.")
	flag.BoolVar(&scan, "scan", false, "One-shot (P-PHYSICS): scan the live cluster, print the DISCOVERED both-products PhysicsWitness per pod + the scarcity ablation, then exit.")
	flag.StringVar(&scanNS, "scan-namespace", "", "[scan] restrict the scan/ablation to this namespace.")
	flag.StringVar(&engineName, "engine", "p1", "Decision brain: p1 (submodular recon-coverage) | p0 (greedy baseline).")
	flag.BoolVar(&ablation, "ablation", false, "One-shot: run the STEP-3 IP ablation (P1 vs random per-dollar) live, print, exit.")
	flag.StringVar(&ablationNS, "ablation-namespace", "", "[ablation] namespace to evaluate.")
	flag.StringVar(&ablationSelector, "ablation-selector", "", "[ablation] label selector, e.g. app=demo.")
	flag.IntVar(&ablationBudget, "ablation-budget", 2, "[ablation] move budget B per arm.")
	flag.IntVar(&ablationSeeds, "ablation-seeds", 40, "[ablation] number of random-arm seeds.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address the health probe binds to.")
	flag.BoolVar(&enableLeader, "leader-elect", false, "Enable leader election (single active controller).")
	flag.DurationVar(&baseInterval, "base-interval", 10*time.Second, "Base tick interval for the decision loop.")
	flag.StringVar(&promURL, "prometheus-url", "", "Prometheus base URL for telemetry ingest (empty = no telemetry, K8s-only signals).")
	flag.BoolVar(&killSwitch, "global-kill-switch", false, "Engage the global actuation kill-switch at startup.")
	flag.StringVar(&auditJSON, "audit-json", "", "Optional path to append the JSON-Lines decision audit trail.")
	flag.StringVar(&operatorNS, "operator-namespace", os.Getenv("POD_NAMESPACE"), "Namespace holding the kill-switch ConfigMap.")
	// One-shot Seam-1 integration proof (emit a single SecurityEvent + ensure AMTD, then exit).
	flag.BoolVar(&integrationEmit, "integration-emit", false, "One-shot: emit one Phorvex SecurityEvent + ensure the AMTD, then exit (Seam-1 proof).")
	flag.StringVar(&emitNamespace, "emit-namespace", "", "[integration-emit] target pod namespace.")
	flag.StringVar(&emitPod, "emit-pod", "", "[integration-emit] target pod name.")
	flag.StringVar(&emitAction, "emit-action", "rotate", "[integration-emit] rotate|quarantine.")
	flag.StringVar(&emitTenant, "emit-tenant", "", "[integration-emit] tenant id (defaults to emit-namespace).")
	flag.StringVar(&emitMatchLabels, "emit-matchlabels", "", "[integration-emit] AMTD guest-list matchLabels, e.g. app=demo,tier=web.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if integrationEmit {
		if err := runIntegrationEmit(emitTenant, emitNamespace, emitPod, emitAction, emitMatchLabels); err != nil {
			setupLog.Error(err, "integration-emit failed")
			os.Exit(1)
		}
		return
	}

	if ablation {
		if err := runAblation(ablationNS, ablationSelector, ablationBudget, ablationSeeds); err != nil {
			setupLog.Error(err, "ablation failed")
			os.Exit(1)
		}
		return
	}

	if nativeDemo {
		if err := runNativeActuatorDemo(nativeDemoNS); err != nil {
			setupLog.Error(err, "native-demo failed")
			os.Exit(1)
		}
		return
	}

	if scan {
		if err := runScan(scanNS); err != nil {
			setupLog.Error(err, "scan failed")
			os.Exit(1)
		}
		return
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeader,
		LeaderElectionID:       "phorvex.phorvex.ai",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	rmgr := runner.NewManager(mgr.GetClient(), ctrl.Log)
	rmgr.BaseInterval = baseInterval
	if engineName == "p0" {
		rmgr.Optimizer = decision.NewEngine()
	} else {
		rmgr.Optimizer = decision.NewCoverageEngine()
	}
	setupLog.Info("decision brain", "engine", rmgr.Optimizer.Name())
	rmgr.KillSwitch = &runner.KillSwitch{Static: killSwitch, Client: mgr.GetClient(), Namespace: operatorNS}

	// Telemetry source: real Prometheus client if a URL is set, else honest nil source.
	if promURL != "" {
		rmgr.MetricsSource = ingest.NewPromHTTP(promURL, nil)
		setupLog.Info("telemetry: prometheus", "url", promURL)
	} else {
		setupLog.Info("telemetry: none (K8s-only signals; metrics not fabricated)")
	}

	// Optional JSON audit sink.
	if auditJSON != "" {
		f, ferr := os.OpenFile(auditJSON, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if ferr != nil {
			setupLog.Error(ferr, "cannot open audit-json; continuing with logger-only audit")
		} else {
			rmgr.Audit = audit.New(ctrl.Log, f)
			setupLog.Info("audit JSON sink", "path", auditJSON)
		}
	}

	if err = (&controller.PhorvexPolicyReconciler{Client: mgr.GetClient(), Manager: rmgr}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PhorvexPolicy")
		os.Exit(1)
	}
	if err = mgr.Add(rmgr); err != nil {
		setupLog.Error(err, "unable to add the phorvex tick loop")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting phorvex", "baseInterval", baseInterval.String())
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// runIntegrationEmit proves Seam 1 without the full operator: it ensures the tenant
// AMTD and emits one controlled SecurityEvent for the target pod, then prints what
// it created so an operator can confirm Phoenix consumes it.
func runIntegrationEmit(tenant, namespace, pod, action, matchLabels string) error {
	if namespace == "" || pod == "" {
		return fmt.Errorf("emit-namespace and emit-pod are required")
	}
	if tenant == "" {
		tenant = namespace
	}
	act := model.Action(action)
	if act != model.ActionRotate && act != model.ActionQuarantine {
		return fmt.Errorf("emit-action must be rotate or quarantine, got %q", action)
	}
	ml := parseMatchLabels(matchLabels)
	if len(ml) == 0 {
		return fmt.Errorf("emit-matchlabels is required (the AMTD guest list), e.g. app=demo")
	}

	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ph := actuator.NewPhoenixActuator(c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ph.EnsurePolicy(ctx, actuator.TenantTarget{
		Tenant:      tenant,
		Namespace:   namespace,
		MatchLabels: ml,
		EnabledActions: map[model.Action]bool{
			model.ActionRotate:     true,
			model.ActionQuarantine: true,
		},
	}); err != nil {
		return fmt.Errorf("ensure AMTD: %w", err)
	}
	res, err := ph.Actuate(ctx, actuator.Request{
		Tenant:    tenant,
		Namespace: namespace,
		Pod:       pod,
		Action:    act,
		Reason:    "phorvex P0 Seam-1 integration proof",
		Score:     0.99,
	})
	if err != nil {
		return fmt.Errorf("emit SecurityEvent: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	setupLog.Info("Seam-1 emit complete", "amtd", res.AMTDName, "securityEvent", res.EventName, "rule", res.RuleType+"/"+res.RuleThreatLevel+"/"+res.RuleSource)
	return nil
}

// runScan is the P-PHYSICS proof: scan the live cluster, derive the both-products
// PhysicsWitness per pod (K8s values live; AI/GPU honestly [SP-0-PENDING] until a DCGM
// adapter answers), and run the separately-ablated scarcity A/B. Read-only.
func runScan(namespace string) error {
	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	snap, err := ingest.CollectSnapshot(ctx, c, time.Now(), nil)
	if err != nil {
		return err
	}
	platformName, phys := platform.Derive(snap)
	fmt.Printf("=== P-PHYSICS live scan ===\nplatform-adapter: %s\nnodes: %d   pods: %d   PDBs: %d\n",
		platformName, len(snap.Nodes), len(snap.Pods), len(snap.PDBs))
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		fmt.Printf("  node %-28s allocCPU=%dm allocMem=%dMi allocGPU=%d migKinds=%d\n",
			n.Name, n.AllocatableCPUMilli, n.AllocatableMemBytes/(1024*1024), n.AllocatableGPU, len(n.MIGResources))
	}
	gpuPresent := false
	shown := 0
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if namespace != "" && p.Namespace != namespace {
			continue
		}
		w := phys[p.Namespace+"/"+p.Name]
		ai := "AI:[SP-0-PENDING] (no GPU/DCGM scan)"
		if w.GPUPresent {
			gpuPresent = true
			ai = fmt.Sprintf("AI: VRAMfrac=%.2f SM=%.2f link=%.2f modelRarity=%.2f", w.VRAMFraction, w.SMOccupancy, w.LinkBandwidth, w.ModelRarity)
		}
		fmt.Printf("  %-34s K8s: imgRarity=%.2f coRes=%.2f slack=%.2f pdbMinAvail=%d migValid=%v epss=%.2f | %s\n",
			p.Namespace+"/"+p.Name, w.ImageRarity, w.CoResidency, w.SchedulerSlack, w.PDBMinAvailable, w.MIGGeometryValid, w.EPSS, ai)
		shown++
	}
	fmt.Printf("(%d pods shown; GPU/AI values measured: %v — honest [SP-0-PENDING] on a CPU-only cluster)\n", shown, gpuPresent)

	if namespace != "" {
		rmgr := runner.NewManager(c, ctrl.Log)

		// P-CONTEXT: live kill-chain context (AI-stage classification + predictive horizon).
		rows, cerr := rmgr.ContextScan(ctx, namespace, labels.Everything())
		if cerr != nil {
			return cerr
		}
		fmt.Printf("\n=== P-CONTEXT live kill-chain (stage + moved-before-next-stage horizon) ===\n")
		for _, r := range rows {
			tag := "generic"
			if r.AIClassified {
				tag = "**AI**"
			}
			fmt.Printf("  %-34s stage=%-20s [%s] PHold=%.2f PreemptMargin=%.2f ProjNextStage=%.0fs infectionFrontier=%.1f\n",
				r.Pod, r.Stage, tag, r.PHold, r.PreemptMargin, r.ProjectedNextStageSec, r.InfectionFrontier)
		}

		seeds := make([]int64, 40)
		for i := range seeds {
			seeds[i] = int64(i + 1)
		}
		ab, pname, aerr := rmgr.AblateScarcity(ctx, namespace, labels.Everything(), seeds, 2)
		if aerr != nil {
			return aerr
		}
		fmt.Printf("\n=== Layer-C EMR scarcity ablation (separately ablated; platform=%s) ===\n", pname)
		fmt.Printf("baseline (standard-recon)  per-dollar ratio = %.3f\n", ab.Baseline.Ratio)
		fmt.Printf("scarcity (ucw-recon)       per-dollar ratio = %.3f\n", ab.Scarcity.Ratio)
		fmt.Printf("scarcity lift              = %.3fx  %s\n", ab.ScarcityLift, scarcityVerdict(ab.ScarcityLift))
	}
	return nil
}

func scarcityVerdict(lift float64) string {
	switch {
	case lift > 1.0001:
		return "(BEAT: heavy-tailed measured dispersion the greedy exploits)"
	case lift > 0.9999:
		return "(TIE: uniform fleet -> exact baseline, never regressed)"
	default:
		return "(below baseline: fleet dispersion not heavy-tailed enough to help; needs a crown-jewel tail / real GPU-multi-tenant data)"
	}
}

// runAblation runs the STEP-3 IP ablation live and prints the per-dollar comparison.
func runAblation(namespace, selector string, budget, nseeds int) error {
	if namespace == "" {
		return fmt.Errorf("ablation-namespace is required")
	}
	sel := labels.Everything()
	if selector != "" {
		s, err := labels.Parse(selector)
		if err != nil {
			return fmt.Errorf("invalid ablation-selector: %w", err)
		}
		sel = s
	}
	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	rmgr := runner.NewManager(c, ctrl.Log)
	if nseeds <= 0 {
		nseeds = 40
	}
	seeds := make([]int64, nseeds)
	for i := range seeds {
		seeds[i] = int64(i + 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := rmgr.Ablate(ctx, namespace, sel, seeds, budget)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	verdict := "FAIL (P1 did NOT beat random per-dollar)"
	if res.Ratio > 1.0 {
		verdict = "PASS (P1 invalidates more recon per dollar than random)"
	}
	setupLog.Info("ablation verdict", "ratio", res.Ratio, "verdict", verdict)
	return nil
}

func parseMatchLabels(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return out
}
