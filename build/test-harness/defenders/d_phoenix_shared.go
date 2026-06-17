package defenders

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// forceKillOperators is a belt-and-suspenders guarantee that NO operator process from
// this arm survives into the NEXT arm's trial (a lingering active Phorvex/Phoenix
// operator would keep deleting the next arm's fresh rotation-target pod, stalling its
// Setup). Trials are sequential, so at Stop time the only manager/phorvex processes
// alive are THIS arm's. Portable across the Windows harness host and Linux CI.
func forceKillOperators(ctx context.Context) {
	if isWindows() {
		_ = exec.CommandContext(ctx, "taskkill", "/F", "/T", "/IM", "phorvex.exe").Run()
		_ = exec.CommandContext(ctx, "taskkill", "/F", "/T", "/IM", "manager.exe").Run()
	} else {
		_ = exec.CommandContext(ctx, "pkill", "-f", "bin/phorvex").Run()
		_ = exec.CommandContext(ctx, "pkill", "-f", "bin/manager").Run()
	}
}

// sweepNamespaceNetworkPolicies deletes ALL NetworkPolicies in the sandbox namespace.
// Phoenix's QUARANTINE action creates a deny-all NetworkPolicy that is NOT harness-
// owned-labeled, so the runner's owned-cleanup cannot reach it; left behind it stalls
// the NEXT arm's fresh target pod. Operator arms call this in Teardown so each trial
// starts from a clean network policy state. The harness itself creates no
// NetworkPolicies, so this is safe (idempotent).
func sweepNamespaceNetworkPolicies(ctx context.Context, env *core.Env) {
	if env.Kube == nil {
		return
	}
	_ = env.Kube.NetworkingV1().NetworkPolicies(env.Config.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
}

// d_phoenix_shared.go provides the SHARED, additive helpers the reactive-only and
// Phorvex (PX) arms reuse to build + run the genuine extended-Phoenix operator and
// (for PX) the Phorvex operator. It is a NEW plugin-support file: it does NOT edit
// d_fullphoenix.go or any harness core. All three Phoenix-class arms run real,
// unmodified extended Phoenix; only the DECISION layer differs (blind timer vs
// reactive matcher vs the Phorvex brain).

// buildPhoenixOperator builds (or reuses) bin/manager from the phoenix-extended
// source. Returns the binary path and a non-empty skip message on failure.
func buildPhoenixOperator(ctx context.Context, env *core.Env, phoenixAbs string) (string, string) {
	if _, err := os.Stat(filepath.Join(phoenixAbs, "cmd", "main.go")); err != nil {
		return "", "phoenix cmd/main.go not found under " + phoenixAbs
	}
	binDir := filepath.Join(phoenixAbs, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	binPath := filepath.Join(binDir, managerBinName())
	if _, err := os.Stat(binPath); err == nil {
		env.Log.Logf("phoenix: reusing operator binary %s", binPath)
		return binPath, ""
	}
	env.Log.Command(fmt.Sprintf("go build -o %s ./cmd   (cwd=%s)", binPath, phoenixAbs))
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd")
	build.Dir = phoenixAbs
	if out, err := build.CombinedOutput(); err != nil {
		return "", "phoenix operator build failed: " + err.Error() + " :: " + string(out)
	}
	env.Log.Logf("phoenix: built operator at %s", binPath)
	return binPath, ""
}

// installPhoenixCRDs server-side applies the genuine Phoenix CRDs (idempotent).
// Returns a non-empty error message on failure.
func installPhoenixCRDs(ctx context.Context, env *core.Env, phoenixAbs string) string {
	crdDir := filepath.Join(phoenixAbs, "config", "crd", "bases")
	if _, err := os.Stat(crdDir); err != nil {
		return "" // no CRD dir — assume already installed (cheap to reuse)
	}
	env.Log.Command(fmt.Sprintf("kubectl apply --server-side --force-conflicts -f %s --context %s", crdDir, env.Config.Context))
	apply := exec.CommandContext(ctx, "kubectl", "apply", "--server-side", "--force-conflicts", "-f", crdDir, "--context", env.Config.Context)
	if out, err := apply.CombinedOutput(); err != nil {
		return "kubectl apply phoenix CRDs failed: " + err.Error() + " :: " + string(out)
	}
	env.Log.Logf("phoenix: CRDs installed (server-side) from %s", crdDir)
	return ""
}

// pinnedKubeconfigShared writes a minified, flattened kubeconfig pinned to the
// configured context (current-context) and returns its path. client-go honors
// KUBECONFIG + current-context (NOT KUBECONTEXT), so this pins any operator process
// to the authorized target portably (the same approach FullPhoenix uses).
func pinnedKubeconfigShared(ctx context.Context, env *core.Env, tag string) (string, error) {
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
	_ = os.MkdirAll(outDir, 0o755)
	path := filepath.Join(outDir, "kubeconfig-pinned-"+safeFileName(env.Config.Context+"-"+tag)+".yaml")
	// The operator process runs with cmd.Dir = the operator's repo dir (NOT the harness CWD),
	// so a RELATIVE KUBECONFIG would not resolve from there. On kind, client-go silently fell
	// back to ~/.kube/config (current-context matched); on EKS that fallback yields "no
	// configuration provided" and the operator never connects. Pin an ABSOLUTE path so the
	// operator loads exactly this minified kubeconfig regardless of its working directory.
	if abs, aerr := filepath.Abs(path); aerr == nil {
		path = abs
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// startPinnedProc starts a binary (the operator) in workDir with args, pinned to the
// authorized context via a minified KUBECONFIG, redirecting stdout/stderr to a per-
// trial log. Returns the process, the log file, and the pinned kubeconfig path.
func startPinnedProc(ctx context.Context, env *core.Env, binPath, workDir string, args []string, logName, pinTag string) (*exec.Cmd, *os.File, string, error) {
	logPath := filepath.Join(env.Config.OutDir, "raw", fmt.Sprintf("%s_%s_%s_t%d.log", logName, env.ScenarioName, env.DefenderName, env.Trial))
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	lf, _ := os.Create(logPath)

	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	pinned, perr := pinnedKubeconfigShared(ctx, env, pinTag)
	if perr == nil {
		cmd.Env = append(cmd.Env, "KUBECONFIG="+pinned)
		env.Log.Logf("%s: pinned to context %s via %s", pinTag, env.Config.Context, pinned)
	} else if env.Config.Kubeconfig != "" {
		cmd.Env = append(cmd.Env, "KUBECONFIG="+env.Config.Kubeconfig)
	}
	if lf != nil {
		cmd.Stdout = lf
		cmd.Stderr = lf
	}
	env.Log.Command(fmt.Sprintf("%s %v   # pinned to %s", binPath, args, env.Config.Context))
	if err := cmd.Start(); err != nil {
		if lf != nil {
			_ = lf.Close()
		}
		if pinned != "" {
			_ = os.Remove(pinned)
		}
		return nil, nil, "", err
	}
	env.Log.Logf("%s: process running (pid %d), logs -> %s", pinTag, cmd.Process.Pid, logPath)
	return cmd, lf, pinned, nil
}

// sweepOwnedSecurityEvents deletes all harness/phorvex owned cluster-scoped
// SecurityEvents (idempotent cleanup; they are cluster-scoped so namespaced owned-
// cleanup cannot reach them).
func sweepOwnedSecurityEvents(ctx context.Context, env *core.Env) {
	if env.Ctrl == nil {
		return
	}
	var list amtdv1beta1.SecurityEventList
	if err := env.Ctrl.List(ctx, &list); err != nil {
		return
	}
	for i := range list.Items {
		it := list.Items[i]
		if it.Labels[core.OwnedLabelKey] == core.OwnedLabelValue ||
			it.Labels["app.kubernetes.io/managed-by"] == "phorvex" ||
			it.Spec.Rule.Source == "PhorvexController" {
			_ = env.Ctrl.Delete(ctx, &it, &client.DeleteOptions{})
		}
	}
}
