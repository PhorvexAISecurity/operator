package safety

import (
	"bytes"
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecTimeout bounds every in-pod exec. A SPDY exec's StreamWithContext does not
// return until ALL output streams close, so a faithfully-detached attacker
// process that keeps the stream open (a backgrounded sleeper / nohup'd backdoor)
// would otherwise block the call forever. Bounding the exec models real tradecraft
// (the attacker's interactive exec returns while the detached process persists)
// and guarantees the harness never hangs. A caller that reaches this deadline
// receives an error and nonzero disposition; partial bytes remain available for
// diagnosis. Properly detached fixtures redirect inherited streams and return
// before this bound, then prove persistence independently via their marker.
const (
	ExecTimeout    = 20 * time.Second
	MaxExecTimeout = 30 * time.Second
)

// ExecResult is the captured output of an in-pod command exec.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// ExecInPod runs a command inside a pod container via the SPDY exec subresource
// and captures stdout/stderr. This is the harness's primary attacker tradecraft
// primitive (T1059.013 Container CLI/API exec). It does NOT mutate cluster state
// and so does not go through the namespace guard, but the pod it targets was
// itself created in the sandbox namespace.
//
// restCfg is the live rest.Config; kube is the clientset; ns/pod/container name
// the target; command is the argv.
func ExecInPod(ctx context.Context, restCfg *rest.Config, kube kubernetes.Interface, ns, pod, container string, command []string) ExecResult {
	return ExecInPodWithTimeout(ctx, restCfg, kube, ns, pod, container, ExecTimeout, command)
}

// ExecInPodWithTimeout runs an in-pod command with an explicit bounded timeout.
// It exists for foreground producers whose valid runtime is longer than the
// default detached-process bound. Callers cannot disable the bound or extend it
// past MaxExecTimeout.
func ExecInPodWithTimeout(ctx context.Context, restCfg *rest.Config, kube kubernetes.Interface, ns, pod, container string, timeout time.Duration, command []string) ExecResult {
	if timeout <= 0 || timeout > MaxExecTimeout {
		return ExecResult{ExitCode: -1, Err: fmt.Errorf("exec timeout %s outside (0,%s]", timeout, MaxExecTimeout)}
	}
	req := kube.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(ns).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restCfg, "POST", req.URL())
	if err != nil {
		return ExecResult{ExitCode: -1, Err: fmt.Errorf("new exec: %w", err)}
	}
	return streamWithTimeout(ctx, exec, timeout)
}

type streamExecutor interface {
	StreamWithContext(context.Context, remotecommand.StreamOptions) error
}

func streamWithTimeout(ctx context.Context, exec streamExecutor, timeout time.Duration) ExecResult {
	// Bound the exec: a faithfully-detached attacker process can hold the stream
	// open, and StreamWithContext only returns once every stream closes. The
	// timeout guarantees the call returns. Properly detached fixtures close the
	// inherited streams first and prove the background process independently.
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	err := exec.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	res := ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		// Preserve partial output, but never report a cancelled or expired stream
		// as successful. Callers that intentionally detach a process still inspect
		// their marker separately; they do not receive a fabricated exit status 0.
		if ctxErr := execCtx.Err(); ctxErr != nil {
			res.ExitCode = -1
			res.Err = fmt.Errorf("exec stream: %w", ctxErr)
			return res
		}
		// A non-zero exit surfaces as a CodeExitError.
		if ce, ok := err.(interface{ ExitStatus() int }); ok {
			res.ExitCode = ce.ExitStatus()
		} else {
			res.ExitCode = -1
			res.Err = err
		}
	}
	return res
}

// AssertObjectInSandbox is a defensive check a builder can call: it refuses to
// hand back an object whose namespace is not the sandbox. Used by manifest
// builders so a mis-targeted object never even reaches the API.
func AssertObjectInSandbox(meta metav1.Object, sandboxNS string) error {
	if meta.GetNamespace() != sandboxNS {
		return &RefuseError{Reason: fmt.Sprintf("object %q namespace %q != sandbox %q — refusing", meta.GetName(), meta.GetNamespace(), sandboxNS)}
	}
	return nil
}
