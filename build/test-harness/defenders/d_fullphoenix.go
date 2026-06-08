package defenders

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterDefender(&fullPhoenix{}) }

// EmitterSource is the canonical Source name the harness uses when it stands in
// for a Falco/Prometheus integrator and emits a normalized SecurityEvent, so the
// exact-match path (matcher.go) fires.
const EmitterSource = "R6THHarnessEmitter"

// fullPhoenix is the genuine extended-Phoenix operator arm. It is the ONLY arm
// that exercises the real matcher.go reactive path:
//   - Setup builds bin/manager.exe from phoenix-extended ./cmd (verified
//     `go build ./...` exits 0), installs the CRDs from config/crd, and applies
//     an AdaptiveMovingTargetDefense (PodSelector + a {timed,TimeBasedTrigger} ->
//     Rotate strategy AND a {panic,...} -> Delete strategy).
//   - Start runs the operator process for the trial and, where the scenario
//     warrants, the harness wires an EMITTER (creates a normalized SecurityEvent
//     {Type,ThreatLevel,Source}) so the reactive exact-match drives the action.
//   - Stop/Teardown idempotently remove operator + AMTD + CRDs.
//
// If the Phoenix source dir is not configured or the toolchain is unavailable,
// the arm SKIPS-with-note (portable default) rather than failing the run.
type fullPhoenix struct {
	mu        sync.Mutex
	proc      *exec.Cmd
	crdsApplied bool
	amtdName  string
	skip      bool
	skipMsg   string
	actions   []float64
	logFile   *os.File
	// pinnedKcfg is the path to the per-run minified kubeconfig the operator is
	// pinned to (embeds flattened creds; removed on Stop).
	pinnedKcfg string
}

func (f *fullPhoenix) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:                        "d-fullphoenix",
		Description:                 "FullPhoenix: the actual extended Phoenix operator. Builds bin/manager from ./cmd, installs CRDs, applies an AMTD, wires an emitter so the genuine matcher.go reactive exact-match path drives rotate/delete/quarantine.",
		MeanRotationIntervalSeconds: BlindRotationInterval.Seconds(),
	}
}

func (f *fullPhoenix) Setup(ctx context.Context, env *core.Env) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.skip = false
	f.skipMsg = ""
	f.actions = nil

	src := env.Config.PhoenixSrcDir
	if src == "" {
		f.skip = true
		f.skipMsg = "phoenixSrcDir not configured — FullPhoenix arm skips-with-note (set it to ../phoenix-extended to exercise the genuine operator)"
		return nil
	}
	abs, err := filepath.Abs(src)
	if err != nil {
		f.skip = true
		f.skipMsg = "cannot resolve phoenixSrcDir: " + err.Error()
		return nil
	}
	if _, err := os.Stat(filepath.Join(abs, "cmd", "main.go")); err != nil {
		f.skip = true
		f.skipMsg = "phoenix cmd/main.go not found under " + abs + " — skipping FullPhoenix"
		return nil
	}

	// 1) Build the operator binary (go build -o bin/manager.exe ./cmd).
	binDir := filepath.Join(abs, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	binPath := filepath.Join(binDir, managerBinName())
	if _, err := os.Stat(binPath); err != nil {
		env.Log.Command(fmt.Sprintf("go build -o %s ./cmd   (cwd=%s)", binPath, abs))
		build := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd")
		build.Dir = abs
		out, berr := build.CombinedOutput()
		if berr != nil {
			f.skip = true
			f.skipMsg = "phoenix operator build failed: " + berr.Error() + " :: " + string(out)
			env.Log.Logf("FullPhoenix build failed: %v\n%s", berr, string(out))
			return nil
		}
		env.Log.Logf("FullPhoenix: built operator at %s", binPath)
	} else {
		env.Log.Logf("FullPhoenix: reusing existing operator binary %s", binPath)
	}

	// 2) Install CRDs from config/crd/bases. Use SERVER-SIDE apply: the extended
	// Phoenix CRDs (e.g. warminferencesets) carry large schemas that overflow the
	// 256KB client-side last-applied-configuration annotation a plain `kubectl
	// apply` writes ("metadata.annotations: Too long"). Server-side apply stores
	// no such annotation, so it installs the genuine CRDs cleanly and idempotently.
	crdDir := filepath.Join(abs, "config", "crd", "bases")
	if _, err := os.Stat(crdDir); err == nil {
		env.Log.Command(fmt.Sprintf("kubectl apply --server-side --force-conflicts -f %s --context %s", crdDir, env.Config.Context))
		apply := exec.CommandContext(ctx, "kubectl", "apply", "--server-side", "--force-conflicts", "-f", crdDir, "--context", env.Config.Context)
		out, aerr := apply.CombinedOutput()
		if aerr != nil {
			f.skip = true
			f.skipMsg = "kubectl apply CRDs failed: " + aerr.Error() + " :: " + string(out)
			env.Log.Logf("FullPhoenix CRD apply failed: %v\n%s", aerr, string(out))
			return nil
		}
		f.crdsApplied = true
		env.Log.Logf("FullPhoenix: CRDs installed (server-side) from %s", crdDir)
	}

	// 3) Apply an AMTD targeting the rotation-target workload with BOTH a timed
	// rotate strategy and a panic->delete strategy (the reactive exact-match path).
	if err := f.applyAMTD(ctx, env); err != nil {
		f.skip = true
		f.skipMsg = "apply AMTD failed: " + err.Error()
		env.Log.Logf("FullPhoenix AMTD apply failed: %v", err)
		return nil
	}
	return nil
}

func (f *fullPhoenix) applyAMTD(ctx context.Context, env *core.Env) error {
	if env.Ctrl == nil {
		return fmt.Errorf("no controller-runtime client (non-live env)")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	name := "harness-amtd"
	f.amtdName = name
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: env.Config.Namespace,
			Labels:    env.OwnedLabels(nil),
		},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{RotationTargetLabel: "true"},
			MatcherMode: amtdv1beta1.MatcherModeExact,
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					// Scheduled/timed rotation (caps dwell) — the {timed,TimeBasedTrigger}
					// exact path -> Rotate (Phase-0 cold reschedule).
					Rule: amtdv1beta1.Rule{
						Type:        amtdv1beta1.TypeTimed,
						Source:      "TimeBasedTrigger",
						ThreatLevel: amtdv1beta1.ThreatLevelInfo,
					},
					Action: amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{}},
				},
				{
					// Reactive panic eviction — a Falco-class {panic,high,emitter} event
					// exact-matches and DELETES the compromised pod.
					Rule: amtdv1beta1.Rule{
						Type:        amtdv1beta1.TypePanic,
						Source:      EmitterSource,
						ThreatLevel: amtdv1beta1.ThreatLevelHigh,
					},
					Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
				},
				{
					// Policy-violation eviction (KubeArmor-class).
					Rule: amtdv1beta1.Rule{
						Type:        amtdv1beta1.TypePolicyViolation,
						Source:      EmitterSource,
						ThreatLevel: amtdv1beta1.ThreatLevelHigh,
					},
					Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
				},
			},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl apply AdaptiveMovingTargetDefense/%s -n %s (PodSelector r6th.io/rotation-target=true; timed->Rotate, panic->Delete)", name, env.Config.Namespace))
	err := env.Ctrl.Create(ctx, amtd)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (f *fullPhoenix) Start(ctx context.Context, env *core.Env) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.skip {
		return nil
	}
	abs, _ := filepath.Abs(env.Config.PhoenixSrcDir)
	binPath := filepath.Join(abs, "bin", managerBinName())

	logPath := filepath.Join(env.Config.OutDir, "raw", fmt.Sprintf("operator_%s_%s_t%d.log", env.ScenarioName, env.DefenderName, env.Trial))
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	lf, _ := os.Create(logPath)
	f.logFile = lf

	// PIN the operator to the AUTHORIZED context. client-go / controller-runtime
	// resolve their config from KUBECONFIG + the kubeconfig's current-context — they
	// do NOT read KUBECONTEXT. So we generate a minified, flattened kubeconfig whose
	// current-context IS the configured target and point the operator at it via
	// KUBECONFIG. This is portable (kind / EKS / CoreWeave / vcluster) and prevents
	// the operator from wandering onto the ambient current-context.
	env.Log.Command(fmt.Sprintf("%s --leader-elect=false   # phoenix operator (pinned to context %s)", binPath, env.Config.Context))
	cmd := exec.CommandContext(ctx, binPath, "--leader-elect=false")
	cmd.Dir = abs
	cmd.Env = os.Environ()
	if pinned, perr := f.pinnedKubeconfig(ctx, env); perr == nil {
		f.pinnedKcfg = pinned
		cmd.Env = append(cmd.Env, "KUBECONFIG="+pinned)
		env.Log.Logf("FullPhoenix: pinned operator to context %s via minified KUBECONFIG %s", env.Config.Context, pinned)
	} else if env.Config.Kubeconfig != "" {
		cmd.Env = append(cmd.Env, "KUBECONFIG="+env.Config.Kubeconfig)
		env.Log.Logf("FullPhoenix: minify-pin failed (%v); scoped operator to configured KUBECONFIG %s", perr, env.Config.Kubeconfig)
	} else {
		env.Log.Logf("FullPhoenix: minify-pin failed (%v) and no kubeconfig configured; operator falls back to ambient current-context", perr)
	}
	if lf != nil {
		cmd.Stdout = lf
		cmd.Stderr = lf
	}
	if err := cmd.Start(); err != nil {
		f.skip = true
		f.skipMsg = "operator start failed: " + err.Error()
		env.Log.Logf("FullPhoenix operator start failed: %v", err)
		return nil
	}
	f.proc = cmd
	env.Log.Logf("FullPhoenix: operator running (pid %d), logs -> %s", cmd.Process.Pid, logPath)
	// Give the manager a moment to elect/lease and start reconciling.
	time.Sleep(2 * time.Second)
	return nil
}

// EmitSecurityEvent is the harness standing in for a Falco/Prometheus integrator:
// it creates a normalized SecurityEvent {Type,ThreatLevel,Source} targeting the
// given pod so the operator's exact-match path fires the matching action. The
// scenario calls this through the Env when it wants to exercise the reactive
// detection path; it records the rotation/delete as a defensive action.
func (f *fullPhoenix) EmitSecurityEvent(ctx context.Context, env *core.Env, targetPod, eventType, threatLevel string) error {
	if f.skip || env.Ctrl == nil {
		return fmt.Errorf("fullphoenix not active")
	}
	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "harness-evt-",
			Labels:       env.OwnedLabels(nil),
		},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{env.Config.Namespace + "/" + targetPod},
			Description: "harness-emitted normalized event (Falco/Prometheus stand-in)",
			Rule: amtdv1beta1.Rule{
				Type:        eventType,
				ThreatLevel: threatLevel,
				Source:      EmitterSource,
			},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl create SecurityEvent {type:%s,level:%s,source:%s} targets %s/%s", eventType, threatLevel, EmitterSource, env.Config.Namespace, targetPod))
	if err := env.Ctrl.Create(ctx, ev); err != nil {
		return err
	}
	f.mu.Lock()
	f.actions = append(f.actions, float64(time.Now().Unix()))
	f.mu.Unlock()
	return nil
}

func (f *fullPhoenix) Stop(ctx context.Context, env *core.Env) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.proc != nil && f.proc.Process != nil {
		env.Log.Command("kill phoenix operator process")
		_ = f.proc.Process.Kill()
		_, _ = f.proc.Process.Wait()
		f.proc = nil
	}
	if f.logFile != nil {
		_ = f.logFile.Close()
		f.logFile = nil
	}
	if f.pinnedKcfg != "" {
		_ = os.Remove(f.pinnedKcfg) // it embeds flattened creds — do not leave it lying around
		f.pinnedKcfg = ""
	}
	return nil
}

func (f *fullPhoenix) Teardown(ctx context.Context, env *core.Env) error {
	_ = f.Stop(ctx, env)
	f.mu.Lock()
	defer f.mu.Unlock()
	// Remove the AMTD (idempotent). Leave CRDs installed (cheap to reuse; a full
	// uninstall is the cmd's final teardown responsibility).
	if env.Ctrl != nil && f.amtdName != "" {
		amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
			ObjectMeta: metav1.ObjectMeta{Name: f.amtdName, Namespace: env.Config.Namespace},
		}
		env.Log.Command(fmt.Sprintf("kubectl delete AdaptiveMovingTargetDefense/%s -n %s", f.amtdName, env.Config.Namespace))
		_ = env.Ctrl.Delete(ctx, amtd, &client.DeleteOptions{})
	}
	// SecurityEvents are CLUSTER-SCOPED, so the namespaced owned-cleanup cannot
	// reach them. Sweep the harness-emitted ones here so a run leaves ZERO leftover
	// CRs (idempotent: only deletes objects carrying the owned label).
	if env.Ctrl != nil {
		var list amtdv1beta1.SecurityEventList
		if err := env.Ctrl.List(ctx, &list); err == nil {
			for i := range list.Items {
				it := list.Items[i]
				if it.Labels[core.OwnedLabelKey] == core.OwnedLabelValue {
					env.Log.Command("kubectl delete securityevent " + it.Name + "  # cluster-scoped owned sweep")
					_ = env.Ctrl.Delete(ctx, &it, &client.DeleteOptions{})
				}
			}
		}
	}
	return nil
}

func (f *fullPhoenix) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]float64, len(f.actions))
	copy(out, f.actions)
	return len(out), out, nil
}

// SkipReason implements core.SkipReporter: when the Phoenix toolchain/source is
// unavailable, this arm is skipped-with-note instead of failing the run.
func (f *fullPhoenix) SkipReason() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.skip, f.skipMsg
}

func managerBinName() string {
	if isWindows() {
		return "manager.exe"
	}
	return "manager"
}

// pinnedKubeconfig writes a minified, flattened kubeconfig that contains ONLY the
// configured context (set as current-context) and returns its path. Because
// client-go / controller-runtime honor KUBECONFIG + current-context (and NOT
// KUBECONTEXT), pointing the operator at this file pins it to the authorized
// target portably, with no dependency on the ambient kube-context.
func (f *fullPhoenix) pinnedKubeconfig(ctx context.Context, env *core.Env) (string, error) {
	if env.Config.Context == "" {
		return "", fmt.Errorf("no target context configured")
	}
	var args []string
	if env.Config.Kubeconfig != "" {
		args = append(args, "--kubeconfig", env.Config.Kubeconfig)
	}
	args = append(args, "config", "view", "--minify", "--flatten", "--context", env.Config.Context)
	out, err := exec.CommandContext(ctx, "kubectl", args...).Output()
	if err != nil {
		return "", fmt.Errorf("kubectl config view --minify --context %s: %w", env.Config.Context, err)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("empty minified kubeconfig for context %s", env.Config.Context)
	}
	outDir := env.Config.OutDir
	if outDir == "" {
		outDir = "out"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(outDir, "kubeconfig-pinned-"+safeFileName(env.Config.Context)+".yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// safeFileName makes a context name (which may contain '/', ':' on EKS/GKE) safe
// as a file name component.
func safeFileName(s string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(s)
}
