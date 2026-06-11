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
 *   - agent unreachable / not scheduled on the node  → Available() fail-closes BEFORE any eviction;
 *   - exec transport not wired (pkgNodeExec nil)      → Available() fail-closes (never fabricate);
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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// RemoteExecConfig carries what the SPDY exec needs (no hardcoded endpoints — supplied by the deployment).
type RemoteExecConfig struct {
	Config    *rest.Config         // the cluster REST config (in-cluster or kubeconfig)
	Clientset kubernetes.Interface // for the pods/exec subresource request
	// newExecutor is overridable in tests; nil => the real remotecommand.NewSPDYExecutor.
	newExecutor func(cfg *rest.Config, method string, u *url.URL) (remotecommand.Executor, error)
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
func WireRemoteNodeExec(cfg RemoteExecConfig) { pkgNodeExec = newRemoteNodeExec(cfg) }

// NodeExecWired reports whether the real MIG node-exec transport has been installed (UI/diagnostics).
func NodeExecWired() bool { return pkgNodeExec != nil }
