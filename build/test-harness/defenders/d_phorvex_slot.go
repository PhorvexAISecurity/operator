package defenders

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() {
	core.RegisterDefender(&phorvexArm{}) // d-phorvex: the SHIPPED brain (both fixes on)
	// d-phorvex-vuln-steer: the SAME shipped binary but a policy with proactiveFloor=0, which (by
	// coverage.go: floorSec<=0 => prov=1) DISABLES the dispersion-steer provenance discount — the
	// pre-fix state, used to confirm the RL's decoy crowd-out WOULD suppress the actuation.
	core.RegisterDefender(&phorvexArm{armName: "d-phorvex-vuln-steer", floor: "0s"})
}

// phorvexArm is the PX arm: the Phorvex P1/P2 stack (the DETERMINISTIC submodular
// recon-coverage brain) driving UNMODIFIED extended Phoenix over Seam 1. It runs TWO
// real processes against the authorized context:
//   - the genuine extended-Phoenix operator (the hands: delete|quarantine), and
//   - the Phorvex operator in ACTIVE mode (the brain): it ingests the cluster graph,
//     scores per-pod recon-coverage-per-dollar under hard SLO/feasibility + budget,
//     and EMITS SecurityEvents + maintains an AMTD strategy that Phoenix actuates.
//
// PX never writes pods directly. Its defensive actions are the Phorvex-driven
// actuations (SecurityEvents authored by PhorvexController). If the Phoenix OR Phorvex
// source/toolchain is unavailable, the arm SKIPS-with-note (portable default).
//
// This is the file that FILLS the reserved d-phorvex-slot: it drops in as one
// self-registering arm with ZERO harness-core / extended-Phoenix changes.
type phorvexArm struct {
	armName     string // "" => "d-phorvex"; the vuln variant overrides this
	floor       string // proactiveFloor override; "" => "6s". "0s" disables the steer-prov fix
	auditPath   string // where this arm's --audit-json decision trail is written
	mu          sync.Mutex
	phoenixProc *exec.Cmd
	phorvexProc *exec.Cmd
	phoenixLog  *os.File
	phorvexLog  *os.File
	phoenixPin  string
	phorvexPin  string
	policyFile  string
	skip        bool
	skipMsg     string
}

func (p *phorvexArm) name() string {
	if p.armName != "" {
		return p.armName
	}
	return "d-phorvex"
}
func (p *phorvexArm) proactiveFloor() string {
	if p.floor != "" {
		return p.floor
	}
	return "6s"
}

func (p *phorvexArm) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:        p.name(),
		Description: "PX: the Phorvex deterministic submodular recon-coverage brain (P1/P2) driving UNMODIFIED extended Phoenix over Seam 1. Runs the real Phoenix operator + the Phorvex operator (active); Phorvex decides which/when/which-action under hard SLO+budget and emits SecurityEvents Phoenix actuates. NOT a fixed cadence — the rotation rate is a solved decision variable.",
		// 0 = no fixed nominal interval: PX's rate is an emergent decision variable
		// (the adaptive learner reads its OBSERVED gaps, which carry no fixed period).
		MeanRotationIntervalSeconds: 0,
	}
}

// phorvexDir derives the Phorvex repo from the configured phoenix-extended source:
// phoenix-extended is build/phoenix-extended; phorvex is the repo-root sibling
// (../../phorvex from build/phoenix-extended).
func phorvexDir(phoenixAbs string) string {
	return filepath.Join(phoenixAbs, "..", "..", "phorvex")
}

func (p *phorvexArm) Setup(ctx context.Context, env *core.Env) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.skip, p.skipMsg = false, ""

	src := env.Config.PhoenixSrcDir
	if src == "" {
		p.skip, p.skipMsg = true, "phoenixSrcDir not configured — PX arm skips-with-note (set it to ../phoenix-extended to exercise the genuine operator + Phorvex)"
		return nil
	}
	phoenixAbs, err := filepath.Abs(src)
	if err != nil {
		p.skip, p.skipMsg = true, "cannot resolve phoenixSrcDir: "+err.Error()
		return nil
	}
	pxDir := phorvexDir(phoenixAbs)
	if _, err := os.Stat(filepath.Join(pxDir, "cmd", "main.go")); err != nil {
		p.skip, p.skipMsg = true, "phorvex cmd/main.go not found under "+pxDir+" — PX arm skips-with-note"
		return nil
	}

	// 1) Build both operators.
	if _, msg := buildPhoenixOperator(ctx, env, phoenixAbs); msg != "" {
		p.skip, p.skipMsg = true, msg
		return nil
	}
	if _, msg := p.buildPhorvex(ctx, env, pxDir); msg != "" {
		p.skip, p.skipMsg = true, msg
		return nil
	}

	// 2) Install Phoenix CRDs + the Phorvex CRD.
	if msg := installPhoenixCRDs(ctx, env, phoenixAbs); msg != "" {
		p.skip, p.skipMsg = true, msg
		return nil
	}
	pxCRD := filepath.Join(pxDir, "config", "crd", "bases", "phorvex.ai_phorvexpolicies.yaml")
	if _, err := os.Stat(pxCRD); err == nil {
		env.Log.Command(fmt.Sprintf("kubectl apply --server-side --force-conflicts -f %s --context %s", pxCRD, env.Config.Context))
		apply := exec.CommandContext(ctx, "kubectl", "apply", "--server-side", "--force-conflicts", "-f", pxCRD, "--context", env.Config.Context)
		if out, aerr := apply.CombinedOutput(); aerr != nil {
			p.skip, p.skipMsg = true, "kubectl apply phorvex CRD failed: "+aerr.Error()+" :: "+string(out)
			return nil
		}
	}

	// 3) Write + apply the PhorvexPolicy (ACTIVE; selects the rotation-target
	// workload; short proactive floor so the λ-crossing fires within the trial).
	if msg := p.applyPolicy(ctx, env); msg != "" {
		p.skip, p.skipMsg = true, msg
		return nil
	}
	return nil
}

func (p *phorvexArm) buildPhorvex(ctx context.Context, env *core.Env, pxDir string) (string, string) {
	binDir := filepath.Join(pxDir, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	bin := filepath.Join(binDir, phorvexBinName())
	if _, err := os.Stat(bin); err == nil {
		env.Log.Logf("PX: reusing phorvex binary %s", bin)
		return bin, ""
	}
	env.Log.Command(fmt.Sprintf("go build -o %s ./cmd   (cwd=%s)", bin, pxDir))
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd")
	build.Dir = pxDir
	if out, err := build.CombinedOutput(); err != nil {
		return "", "phorvex build failed: " + err.Error() + " :: " + string(out)
	}
	env.Log.Logf("PX: built phorvex at %s", bin)
	return bin, ""
}

func (p *phorvexArm) applyPolicy(ctx context.Context, env *core.Env) string {
	ns := env.Config.Namespace
	policy := fmt.Sprintf(`apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata:
  name: %s
  namespace: %s
spec:
  tenant: %s
  selector:
    matchLabels:
      %s: "true"
  objective:
    lambda: "0.4"
    costWeights: {normSparsity: "0.4", flowDisruption: "0.6"}
  budget:
    maxMovesPerTick: 1
    tickInterval: 3s
    antiOverRotationWindow: 8s
    proactiveFloor: %s
  slo:
    minAvailableReplicas: 1
  assetValue:
    fromLabels:
      data-class: {restricted: "1.0", internal: "0.4", public: "0.1"}
    weightSecrets: "0.8"
    blastRadiusFromGraph: true
  triggers:
    eventDriven: true
  actions:
    enabled: ["rotate"]
  mode: active
`, "harness-"+p.name(), ns, ns, RotationTargetLabel, p.proactiveFloor())
	outDir := env.Config.OutDir
	if outDir == "" {
		outDir = "out"
	}
	_ = os.MkdirAll(outDir, 0o755)
	p.policyFile = filepath.Join(outDir, "phorvexpolicy-"+p.name()+".yaml")
	if err := os.WriteFile(p.policyFile, []byte(policy), 0o644); err != nil {
		return "write PhorvexPolicy: " + err.Error()
	}
	env.Log.Command(fmt.Sprintf("kubectl apply -f %s --context %s   # PhorvexPolicy (active; selects %s=true)", p.policyFile, env.Config.Context, RotationTargetLabel))
	apply := exec.CommandContext(ctx, "kubectl", "apply", "-f", p.policyFile, "--context", env.Config.Context)
	if out, err := apply.CombinedOutput(); err != nil {
		return "kubectl apply PhorvexPolicy failed: " + err.Error() + " :: " + string(out)
	}
	return ""
}

func (p *phorvexArm) Start(ctx context.Context, env *core.Env) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.skip {
		return nil
	}
	phoenixAbs, _ := filepath.Abs(env.Config.PhoenixSrcDir)
	pxDir := phorvexDir(phoenixAbs)
	phoenixBin := filepath.Join(phoenixAbs, "bin", managerBinName())
	phorvexBin := filepath.Join(pxDir, "bin", phorvexBinName())

	// Start the genuine Phoenix operator (the hands).
	if cmd, lf, pin, err := startPinnedProc(ctx, env, phoenixBin, phoenixAbs,
		[]string{"--leader-elect=false"}, "operator", "px-phoenix"); err == nil {
		p.phoenixProc, p.phoenixLog, p.phoenixPin = cmd, lf, pin
	} else {
		p.skip, p.skipMsg = true, "phoenix operator start failed: "+err.Error()
		return nil
	}
	// Start the Phorvex operator (the brain) in ACTIVE mode. Distinct metrics/health
	// ports so it never collides with the Phoenix operator's :8080/:8081. --audit-json captures
	// the JSON-Lines decision trail (selected/actuated/objectsTouched/perDollar/λ) as ground truth.
	outDir := env.Config.OutDir
	if outDir == "" {
		outDir = "out"
	}
	p.auditPath = filepath.Join(outDir, "phorvex-audit-"+p.name()+".jsonl")
	if cmd, lf, pin, err := startPinnedProc(ctx, env, phorvexBin, pxDir,
		// base-interval 1s (was 4s): the in-request/dwell attacks land in ~2-3s, so a 4s tick + 3s
		// warm-up meant the first actuation fired ~10s in — after the attacker already won. A 1s tick
		// lets the brain decide+actuate within ~2s, which is the difference between catching a dwelling
		// foothold and arriving too late.
		[]string{"--engine=p1", "--base-interval=1s",
			"--operator-namespace=" + env.Config.Namespace,
			"--audit-json=" + p.auditPath,
			// ports :18090/:18091 (was :18080/:18081) — a live jump-server phorvex-operator now binds
			// :18080/:18081, so the arm's brain collided and CRASHED on startup ("address already in
			// use") → it never decided/actuated → 0 disruption. Distinct ports fix it.
			"--metrics-bind-address=:18090", "--health-probe-bind-address=:18091"},
		"phorvex", "px-phorvex"); err == nil {
		p.phorvexProc, p.phorvexLog, p.phorvexPin = cmd, lf, pin
	} else {
		env.Log.Logf("PX: phorvex operator start failed: %v", err)
	}
	// Let both managers lease + the Phorvex AMTD stamp the guest list before the first decision tick
	// actuates — 1s (was 3s) so the defender is armed before the fast attacks complete.
	time.Sleep(1 * time.Second)
	return nil
}

func (p *phorvexArm) Stop(ctx context.Context, env *core.Env) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	killProc(&p.phorvexProc)
	killProc(&p.phoenixProc)
	forceKillOperators(ctx) // guarantee no lingering operator stalls the next arm's pod
	closeFile(&p.phorvexLog)
	closeFile(&p.phoenixLog)
	removeFile(&p.phorvexPin)
	removeFile(&p.phoenixPin)
	return nil
}

func (p *phorvexArm) Teardown(ctx context.Context, env *core.Env) error {
	_ = p.Stop(ctx, env)
	// Delete the PhorvexPolicy + the Phorvex-maintained AMTD + sweep emitted events.
	if p.policyFile != "" {
		env.Log.Command(fmt.Sprintf("kubectl delete -f %s --context %s --ignore-not-found", p.policyFile, env.Config.Context))
		_ = exec.CommandContext(ctx, "kubectl", "delete", "-f", p.policyFile, "--context", env.Config.Context, "--ignore-not-found").Run()
	}
	// Delete ONLY the Phorvex-maintained AMTD(s) in the sandbox namespace (scoped by
	// the phorvex managed-by label) — never a blanket delete.
	env.Log.Command(fmt.Sprintf("kubectl delete adaptivemovingtargetdefense -l app.kubernetes.io/managed-by=phorvex -n %s --context %s --ignore-not-found", env.Config.Namespace, env.Config.Context))
	_ = exec.CommandContext(ctx, "kubectl", "delete", "adaptivemovingtargetdefense",
		"-l", "app.kubernetes.io/managed-by=phorvex", "-n", env.Config.Namespace,
		"--context", env.Config.Context, "--ignore-not-found").Run()
	sweepOwnedSecurityEvents(ctx, env)
	sweepNamespaceNetworkPolicies(ctx, env) // remove the deny-all NP a PX quarantine leaves
	return nil
}

// DefensiveActions returns the count + timestamps of Phorvex-DRIVEN actuations: the
// SecurityEvents authored by PhorvexController (the moves the brain decided and
// emitted for Phoenix to run). This is PX's real, observable defensive cost.
func (p *phorvexArm) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	if env.Ctrl == nil {
		return 0, nil, nil
	}
	var list amtdv1beta1.SecurityEventList
	if err := env.Ctrl.List(ctx, &list); err != nil {
		return 0, nil, err
	}
	var at []float64
	for i := range list.Items {
		it := list.Items[i]
		if it.Spec.Rule.Source == "PhorvexController" || it.Labels["app.kubernetes.io/managed-by"] == "phorvex" {
			at = append(at, float64(it.CreationTimestamp.Unix()))
		}
	}
	return len(at), at, nil
}

// SkipReason: PX degrades to skip-with-note when the Phoenix/Phorvex toolchain or
// source is unavailable (never a hard failure).
func (p *phorvexArm) SkipReason() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.skip, p.skipMsg
}

func phorvexBinName() string {
	if isWindows() {
		return "phorvex.exe"
	}
	return "phorvex"
}

func killProc(c **exec.Cmd) {
	if *c != nil && (*c).Process != nil {
		_ = (*c).Process.Kill()
		_, _ = (*c).Process.Wait()
	}
	*c = nil
}

func closeFile(f **os.File) {
	if *f != nil {
		_ = (*f).Close()
		*f = nil
	}
}

func removeFile(p *string) {
	if *p != "" {
		_ = os.Remove(*p)
		*p = ""
	}
}
