// Package scenarios contains the self-registering Scenario plugins. Each scenario
// is ONE file with a func init(){ core.RegisterScenario(...) }. Adding a future
// attack is one new file + one register call, ZERO core changes.
//
// Every scenario defines its attack-success ORACLE as a concrete OBSERVABLE
// state and measures disruption strictly against it. ALL behavior is confined to
// the sandbox namespace; category-3 scenarios use the in-cluster MOCK endpoints
// from internal/mocks and never touch real cloud/registry/credentials.
package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

// useStolenToken clones the live rest.Config but swaps in the stolen bearer token
// (clearing other auth), builds a fresh clientset, and exercises the RBAC-
// permitted call (list pods in the sandbox). It returns whether the call was
// AUTHORIZED and a short detail. This is the concrete cred-theft oracle: a stolen
// token used SUCCESSFULLY against the API from a fresh client (outside the pod).
func useStolenToken(ctx context.Context, env *core.Env, token string) (bool, string) {
	if env.Rest == nil {
		return false, "no live rest config (non-live env)"
	}
	cfg := rest.CopyConfig(env.Rest)
	cfg.BearerToken = token
	cfg.BearerTokenFile = ""
	cfg.Username = ""
	cfg.Password = ""
	cfg.CertData = nil
	cfg.KeyData = nil
	cfg.CertFile = ""
	cfg.KeyFile = ""
	cfg.AuthProvider = nil
	cfg.ExecProvider = nil
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, "build client: " + err.Error()
	}
	env.Log.Command(fmt.Sprintf("kubectl --token=<stolen> get pods -n %s  # replay exfiltrated token", env.Config.Namespace))
	pods, err := cs.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, "list pods denied/error: " + err.Error()
	}
	return true, fmt.Sprintf("HTTP 200, listed %d pods with stolen identity", len(pods.Items))
}

// ensureSAWithRBAC creates a ServiceAccount + a (namespaced) Role granting
// list/get on pods + a RoleBinding, all in the sandbox. It models the misconfigured
// RBAC the cred-theft scenario exploits. Idempotent.
func ensureSAWithRBAC(ctx context.Context, env *core.Env, saName string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: saName, Namespace: ns, Labels: env.OwnedLabels(nil)}}
	env.Log.Command(fmt.Sprintf("kubectl create serviceaccount %s -n %s", saName, ns))
	if _, err := env.Kube.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: saName + "-role", Namespace: ns, Labels: env.OwnedLabels(nil)},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods", "secrets"},
			Verbs:     []string{"get", "list"},
		}},
	}
	env.Log.Command(fmt.Sprintf("kubectl create role %s-role --verb=get,list --resource=pods,secrets -n %s", saName, ns))
	if _, err := env.Kube.RbacV1().Roles(ns).Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: saName + "-rb", Namespace: ns, Labels: env.OwnedLabels(nil)},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: saName + "-role"},
	}
	env.Log.Command(fmt.Sprintf("kubectl create rolebinding %s-rb --role=%s-role --serviceaccount=%s:%s -n %s", saName, saName, ns, saName, ns))
	if _, err := env.Kube.RbacV1().RoleBindings(ns).Create(ctx, rb, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// BackdoorMarkerPath is the on-pod path an attacker writes its persistence marker
// to; the persistence oracle reads it.
const BackdoorMarkerPath = "/tmp/.r6th_backdoor"

// BackdoorMarker is the unique sleeper-process marker string.
const BackdoorMarker = "R6TH-BACKDOOR-SLEEPER"

// deployTarget stands up a benign target workload pod in the sandbox, labeled as
// a rotation target so the MTD arms know what to rotate. It is the shared
// "victim" every scenario compromises. saName, if non-empty, mounts that SA.
func deployTarget(ctx context.Context, env *core.Env, name, saName string, extraLabels map[string]string) (*corev1.Pod, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	labels := mocks.LabelMap(map[string]string{defenders.RotationTargetLabel: "true", "app": name}, extraLabels)
	pb := mocks.NewPod(env, name, labels).
		WithBusyboxLoop("app", nil, 100, 32)
	if saName != "" {
		pb = pb.WithServiceAccount(saName)
	}
	pod := pb.Build()
	// The runner reuses pod names across trials; ensure any prior same-named pod has
	// fully terminated before creating, so WaitForPodRunning cannot latch onto a
	// terminating pod (which then vanishes before Execute = a false "evicted" read).
	waitPodGone(ctx, env, name)
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s -l %s=true  # target workload", name, mocks.BusyboxImage, env.Config.Namespace, defenders.RotationTargetLabel))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	// Wait for a FRESH running, non-terminating pod (polls; tolerant of slow start).
	running, err := runningPodByApp(ctx, env, name)
	if err != nil {
		return nil, err
	}
	return running, nil
}

// waitPodGone FORCE-removes any lingering same-named pod so a fresh deploy is not
// blocked by a prior arm's slow-terminating pod. A Phoenix rotation Deletes with the
// default 30s grace, so the rotated pod is often STILL terminating when the next arm
// starts — a plain wait would time out and the same-named Create returns AlreadyExists.
// This grace-0 deletes it and strips any finalizer, then polls until it is gone.
func waitPodGone(ctx context.Context, env *core.Env, name string) {
	ns := env.Config.Namespace
	grace := int64(0)
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		p, err := env.Kube.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err == nil {
			if len(p.Finalizers) > 0 {
				_, _ = env.Kube.CoreV1().Pods(ns).Patch(ctx, name, types.MergePatchType,
					[]byte(`{"metadata":{"finalizers":null}}`), metav1.PatchOptions{})
			}
			_ = env.Kube.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &grace})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(400 * time.Millisecond):
		}
	}
}

// deployPlain stands up a benign pod that is NOT a rotation target (e.g. a
// lateral-movement victim B). Confined to the sandbox.
func deployPlain(ctx context.Context, env *core.Env, name string) (*corev1.Pod, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	pod := mocks.NewPod(env, name, map[string]string{"app": name}).
		WithBusyboxLoop("app", nil, 100, 32).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # plain workload", name, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	if err := env.WaitForPodRunning(ctx, name, 60*time.Second); err != nil {
		return nil, err
	}
	return pod, nil
}

// firstContainerName looks up a pod by name and returns its first container name
// (or "app" as a safe default for harness-built pods).
func firstContainerName(podName string, env *core.Env) string {
	p, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil || len(p.Spec.Containers) == 0 {
		return "app"
	}
	return p.Spec.Containers[0].Name
}

// plantBackdoor writes a persistence backdoor inside the target pod: a marker
// file plus a long-lived sleeper "process" recorded by writing its marker. It
// FAITHFULLY models a runc-overwrite file-clobber persistence (T1543.005) within
// the sandbox container. Returns the commands issued.
func plantBackdoor(ctx context.Context, env *core.Env, pod, container string) []string {
	// Write the marker (the clobbered file the attacker drops) and spawn a
	// DETACHED sleeper that re-touches the marker, so a liveness probe of the
	// process succeeds. Real backdoor tradecraft detaches from the controlling
	// stream (nohup-style: redirect stdin/stdout/stderr away) so the operator's
	// interactive exec returns immediately while the sleeper persists. We model
	// the live process by the marker file's presence + a background sleep whose
	// pid we record. The redirects are LOAD-BEARING: without them the backgrounded
	// loop inherits the exec's stdout stream and the SPDY exec would block until
	// it closes (i.e. never).
	script := fmt.Sprintf(
		"echo %s > %s; (while true; do echo %s > %s; sleep 5; done) </dev/null >/dev/null 2>&1 & echo backdoor-pid=$!",
		BackdoorMarker, BackdoorMarkerPath, BackdoorMarker, BackdoorMarkerPath)
	res := env.Exec(ctx, pod, container, []string{"sh", "-c", script})
	env.Log.Logf("plantBackdoor stdout=%q stderr=%q exit=%d", strings.TrimSpace(res.Stdout), strings.TrimSpace(res.Stderr), res.ExitCode)
	return []string{"sh -c '" + script + "'"}
}

// backdoorAlive checks whether the backdoor marker is still present in ANY pod
// matching the app label (so a rotation that replaced the pod with a fresh
// identity correctly reports the backdoor as gone). Returns (alive, observedPod).
func backdoorAlive(ctx context.Context, env *core.Env, appLabel string) (bool, string, error) {
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=" + appLabel,
	})
	if err != nil {
		return false, "", err
	}
	for i := range pods.Items {
		p := pods.Items[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		res := env.Exec(ctx, p.Name, firstContainer(&p), []string{"sh", "-c", "cat " + BackdoorMarkerPath + " 2>/dev/null"})
		if strings.Contains(res.Stdout, BackdoorMarker) {
			return true, p.Name, nil
		}
	}
	return false, "", nil
}

// firstContainer returns the first container name of a pod (the attacker target).
func firstContainer(p *corev1.Pod) string {
	if len(p.Spec.Containers) > 0 {
		return p.Spec.Containers[0].Name
	}
	return ""
}

// runningPodByApp returns the first Running, NON-terminating pod matching app=<label>.
// It POLLS for up to ~25s: a fresh target may still be coming up, or a prior trial's
// same-named pod may still be terminating (the runner reuses pod names across trials).
// Without this poll the attack Execute can spuriously fail with "no running pod",
// which then falsely reads as an eviction (a measurement-validity bug). Polling makes
// the foothold reliably plant so disruption reflects REAL eviction, not a race.
func runningPodByApp(ctx context.Context, env *core.Env, appLabel string) (*corev1.Pod, error) {
	deadline := time.Now().Add(40 * time.Second)
	for {
		pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app=" + appLabel,
		})
		if err == nil {
			for i := range pods.Items {
				if pods.Items[i].Status.Phase == corev1.PodRunning && pods.Items[i].DeletionTimestamp == nil {
					return &pods.Items[i], nil
				}
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no running pod for app=%s after polling", appLabel)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// teardownByApp deletes every owned object for the scenario's app label. The
// runner also does a global owned-cleanup, but a scenario Teardown that is
// idempotent and scoped keeps trials isolated.
func teardownByApp(ctx context.Context, env *core.Env, appLabels ...string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	grace := int64(0)
	dp := metav1.DeletePropagationBackground
	for _, app := range appLabels {
		lo := metav1.ListOptions{LabelSelector: "app=" + app}
		env.Log.Command(fmt.Sprintf("kubectl delete pods -n %s -l app=%s --grace-period=0", env.Config.Namespace, app))
		_ = env.Kube.CoreV1().Pods(env.Config.Namespace).DeleteCollection(ctx,
			metav1.DeleteOptions{GracePeriodSeconds: &grace, PropagationPolicy: &dp}, lo)
	}
	return nil
}

// measureSurvival POLLS until the foothold is evicted (the backdoor marker is gone
// from every app-labeled running pod) or maxWindow elapses, returning the REAL
// foothold-survival seconds and whether it was still alive at the end. This is the
// genuine dwell-to-eviction metric the report LEADS with (the runner's
// AttackerDwellSeconds is merely trial-elapsed time, not survival). A fast-evicting
// arm (PX on a high-risk pod) yields a small survival; a slow periodic timer yields a
// survival near its interval; an arm that never evicts yields the full window.
func measureSurvival(ctx context.Context, env *core.Env, appLabel string, maxWindow time.Duration) (float64, bool) {
	start := time.Now()
	deadline := start.Add(maxWindow)
	for {
		alive, _, _ := backdoorAlive(ctx, env, appLabel)
		if !alive {
			return time.Since(start).Seconds(), false
		}
		if time.Now().After(deadline) {
			return time.Since(start).Seconds(), true
		}
		select {
		case <-ctx.Done():
			return time.Since(start).Seconds(), true
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// survivalMarker formats the parseable ObservedState markers the post-processor reads
// for the dwell-led, feasibility and harm metrics. Keep keys stable.
func survivalMarker(survivalSec float64, stillAlive bool) string {
	return fmt.Sprintf("[survival=%.1fs] [evicted=%v]", survivalSec, !stillAlive)
}

// dwellCheck waits dwell seconds (bounded for smoke) then reports whether the
// backdoor survived. It is the shared persistence-dwell measurement.
func dwellCheck(ctx context.Context, env *core.Env, appLabel string, dwell time.Duration) (bool, string) {
	// Bound the actual wait so smoke trials stay fast.
	const maxWait = 10 * time.Second
	w := dwell
	if w > maxWait {
		w = maxWait
	}
	select {
	case <-ctx.Done():
	case <-time.After(w):
	}
	alive, pod, err := backdoorAlive(ctx, env, appLabel)
	if err != nil {
		env.Log.Logf("dwellCheck error: %v", err)
	}
	return alive, pod
}
