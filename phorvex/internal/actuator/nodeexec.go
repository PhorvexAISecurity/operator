/*
 * Phorvex — MIG node-exec transport (closes the mig-rebind gap). Implements the REAL privileged
 * node-exec behind execInPodFunc: a SPDY `pods/exec` (remotecommand) into the privileged MIG node-agent
 * DaemonSet pod resolved on the target node, so the nvidia-smi MIG sequence actually runs instead of the
 * default fail-closed path. Wire it once at startup with the cluster REST config + clientset.
 *
 * [PENDING-GPU-VALIDATION] — real transport code; the exec syscall + the nvidia-smi MIG result are
 * validated against a real GPU node + a deployed node-agent DaemonSet by the dev team. CI mocks the exec
 * (asserts the command sequence/ordering + the fail-closed-without-agent path).
 *
 * PREMORTEM (persona panel: GPU-expert / Physics-informed-AI / distributed-systems / Cloud-engineer):
 *   - agent unreachable / not scheduled on the node  → Prepare() fail-closes BEFORE any eviction;
 *   - exec transport not wired (pkgNodeRunner nil)    → Prepare() fail-closes (never fabricate);
 *   - partial repartition (a step errors mid-sequence)→ Repartition returns the failing step (caller aborts);
 *   - CUDA contexts not drained                        → drain is the CALLER's responsibility, ordered BEFORE
 *                                                         Repartition (mig-rebind drains, then repartitions);
 *   - wrong GPU                                         → every nvidia-smi carries explicit `-i <gpuID>`.
 */

package actuator

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// RemoteExecConfig carries what the SPDY exec needs (no hardcoded endpoints — supplied by the deployment).
type RemoteExecConfig struct {
	Config    *rest.Config         // the cluster REST config (in-cluster or kubeconfig)
	Clientset kubernetes.Interface // for the pods/exec subresource request
	Agent     MIGAgentPolicy       // explicit trusted agent identity; there are no production defaults
	// newExecutor is overridable in tests; nil => the real remotecommand.NewSPDYExecutor.
	newExecutor func(cfg *rest.Config, method string, u *url.URL) (remotecommand.Executor, error)
}

// MIGAgentPolicy names the administrative trust boundary and immutable identity attributes used to
// select a privileged node agent. Deployments must supply it explicitly before M-79 wires transport.
type MIGAgentPolicy struct {
	Namespace       string
	ServiceAccounts []string
	DaemonSet       string
	Container       string
	ExecTimeout     time.Duration
}

const maxMIGExecTimeout = 5 * time.Minute

func (p MIGAgentPolicy) validate() error {
	if errs := validation.IsDNS1123Label(p.Namespace); len(errs) > 0 {
		return fmt.Errorf("MIG agent namespace %q is invalid: %s", p.Namespace, strings.Join(errs, ", "))
	}
	if errs := validation.IsDNS1123Subdomain(p.DaemonSet); len(errs) > 0 {
		return fmt.Errorf("MIG agent DaemonSet %q is invalid: %s", p.DaemonSet, strings.Join(errs, ", "))
	}
	if errs := validation.IsDNS1123Label(p.Container); len(errs) > 0 {
		return fmt.Errorf("MIG agent container %q is invalid: %s", p.Container, strings.Join(errs, ", "))
	}
	if len(p.ServiceAccounts) == 0 {
		return fmt.Errorf("MIG agent ServiceAccount allowlist must not be empty")
	}
	seen := make(map[string]struct{}, len(p.ServiceAccounts))
	for _, sa := range p.ServiceAccounts {
		if errs := validation.IsDNS1123Subdomain(sa); len(errs) > 0 {
			return fmt.Errorf("MIG agent ServiceAccount %q is invalid: %s", sa, strings.Join(errs, ", "))
		}
		if _, duplicate := seen[sa]; duplicate {
			return fmt.Errorf("MIG agent ServiceAccount %q is duplicated", sa)
		}
		seen[sa] = struct{}{}
	}
	if p.ExecTimeout <= 0 || p.ExecTimeout > maxMIGExecTimeout {
		return fmt.Errorf("MIG agent exec timeout must be positive and at most %s", maxMIGExecTimeout)
	}
	return nil
}

// newRemoteNodeExec returns the real execInPodFunc: a streamed `pods/exec` capturing stdout/stderr.
func newRemoteNodeExec(cfg RemoteExecConfig) execInPodFunc {
	return func(ctx context.Context, ns, pod, container string, argv []string) (string, error) {
		if cfg.Clientset == nil || cfg.Config == nil {
			return "", fmt.Errorf("remote node-exec: nil clientset/config [PENDING-GPU-VALIDATION]")
		}
		req := cfg.Clientset.CoreV1().RESTClient().Post().
			Resource("pods").Name(pod).Namespace(ns).SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: container, Command: argv, Stdout: true, Stderr: true,
			}, scheme.ParameterCodec)

		newExec := cfg.newExecutor
		if newExec == nil {
			newExec = remotecommand.NewSPDYExecutor
		}
		exec, err := newExec(cfg.Config, "POST", req.URL())
		if err != nil {
			return "", fmt.Errorf("remote node-exec build %v on %s/%s: %w", argv, ns, pod, err)
		}
		var stdout, stderr bytes.Buffer
		if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
			return stdout.String(), fmt.Errorf("remote node-exec %v on %s/%s: %w (stderr: %s)", argv, ns, pod, err, stderr.String())
		}
		return stdout.String(), nil
	}
}

// WireRemoteNodeExec installs the real transport into the package seam so MIG ops execute. Call once at
// startup (deployment has the REST config + clientset). Absent this call, MIG ops stay fail-closed.
func WireRemoteNodeExec(cfg RemoteExecConfig) error {
	if cfg.Config == nil || cfg.Clientset == nil {
		return fmt.Errorf("remote node-exec: nil clientset/config")
	}
	if err := cfg.Agent.validate(); err != nil {
		return err
	}
	policy := cfg.Agent
	policy.ServiceAccounts = append([]string(nil), cfg.Agent.ServiceAccounts...)
	pkgNodeRunner = &execNodeRunner{client: cfg.Clientset, exec: newRemoteNodeExec(cfg), policy: policy}
	return nil
}

// NodeExecWired reports whether the real MIG node-exec transport has been installed (UI/diagnostics).
func NodeExecWired() bool { return pkgNodeRunner != nil }
