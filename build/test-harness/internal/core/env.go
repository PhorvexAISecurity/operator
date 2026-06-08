package core

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// OwnedLabelKey/OwnedLabelValue mark every object the harness creates, so
// teardown is an idempotent label-selector delete and nothing is orphaned.
const (
	OwnedLabelKey   = "r6th.io/owned"
	OwnedLabelValue = "true"
	// TrialLabelKey records the per-trial id on created objects (provenance).
	TrialLabelKey = "r6th.io/trial"
	// ScenarioLabelKey records the owning scenario on created objects.
	ScenarioLabelKey = "r6th.io/scenario"
)

// Capabilities is the detected, environment-agnostic cluster capability set. The
// runner skips scenarios whose CapabilityRequirements are unmet (skip-with-note)
// so the SAME plugin set runs unchanged on any cluster.
type Capabilities struct {
	GPU       bool
	MultiNode bool
	MIG       bool
	NodeCount int
}

// Has reports whether a required capability is present.
func (c Capabilities) Has(cap Capability) bool {
	switch cap {
	case CapGPU:
		return c.GPU
	case CapMultiNode:
		return c.MultiNode
	case CapMIG:
		return c.MIG
	}
	return false
}

// Missing returns the subset of required capabilities that are NOT satisfied.
func (c Capabilities) Missing(reqs []Capability) []Capability {
	var miss []Capability
	for _, r := range reqs {
		if !c.Has(r) {
			miss = append(miss, r)
		}
	}
	return miss
}

// SafetyGuard is the pre-mutation gate. It is an interface so internal/safety
// owns the concrete implementation while core stays import-cycle-free; the Env
// calls AssertMutationAllowed before any create.
type SafetyGuard interface {
	// AssertMutationAllowed verifies live-context == cfg.Context AND live
	// apiserver host == the named context host AND ownedAck AND that targetNS ==
	// cfg.Namespace. Returns a non-nil error (REFUSAL) otherwise.
	AssertMutationAllowed(targetNS string) error
}

// Logger is the structured, per-trial logger. It writes both to the run log and
// the per-trial raw log file (provenance).
type Logger interface {
	Logf(format string, args ...any)
	// Command records a provenance command line (also written to the raw log).
	Command(cmd string)
	// Commands returns the recorded command lines (for the metric schema).
	Commands() []string
	// RawLogPath returns the path of the per-trial raw log file.
	RawLogPath() string
}

// Env is the per-run context handed to EVERY plugin method. It carries the two
// clients, the resolved config, detected capabilities, the deterministic RNG,
// the per-trial logger, and the sandbox create/cleanup helpers.
type Env struct {
	// Ctrl is the controller-runtime client (typed CRD access: AMTD/SecurityEvent).
	Ctrl ctrlclient.Client
	// Kube is the client-go kubernetes.Interface (pods/exec/services).
	Kube kubernetes.Interface
	// Rest is the live *rest.Config (nil in unit tests with a fake clientset);
	// used by exec-based helpers. It is the SAME connection the guard validated.
	Rest *rest.Config
	// Config is the resolved per-target config.
	Config config.TargetConfig
	// Caps is the detected cluster capability set.
	Caps Capabilities
	// Rand is the deterministic per-trial RNG (seeded from masterSeed+scenario+
	// defender+trial). Use it for ALL randomness so trials are reproducible.
	Rand *rand.Rand
	// Log is the per-trial structured logger / raw-log writer.
	Log Logger
	// Guard is the pre-mutation safety gate.
	Guard SafetyGuard
	// Trial is the current trial id (for labels/provenance).
	Trial int
	// ScenarioName is the current scenario (for labels/provenance).
	ScenarioName string
	// DefenderName is the current defender arm (for labels/provenance).
	DefenderName string
	// RestConfigHost is the live apiserver host (provenance/debug).
	RestConfigHost string
}

// OwnedLabels returns the standard owner labels for a created object, including
// the scenario/trial provenance labels. Extra labels are merged in.
func (e *Env) OwnedLabels(extra map[string]string) map[string]string {
	m := map[string]string{
		OwnedLabelKey:    OwnedLabelValue,
		ScenarioLabelKey: sanitizeLabel(e.ScenarioName),
		TrialLabelKey:    fmt.Sprintf("%d", e.Trial),
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// OwnedSelector is the label selector that matches EVERY harness-owned object.
func OwnedSelector() string {
	return fmt.Sprintf("%s=%s", OwnedLabelKey, OwnedLabelValue)
}

// sanitizeLabel makes a string safe as a label value (<=63 chars, [a-z0-9.-]).
func sanitizeLabel(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 63 {
		out = out[:63]
	}
	return strings.Trim(out, "-.")
}

// EnsureNamespace creates the sandbox namespace (labeled owned) if missing. It
// goes through the safety guard so a misconfigured namespace cannot be created.
func (e *Env) EnsureNamespace(ctx context.Context) error {
	if err := e.Guard.AssertMutationAllowed(e.Config.Namespace); err != nil {
		return err
	}
	_, err := e.Kube.CoreV1().Namespaces().Get(ctx, e.Config.Namespace, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   e.Config.Namespace,
			Labels: map[string]string{OwnedLabelKey: OwnedLabelValue},
		},
	}
	e.Log.Command(fmt.Sprintf("kubectl create namespace %s", e.Config.Namespace))
	_, err = e.Kube.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// CleanupOwned deletes every harness-owned object of the common kinds in the
// sandbox namespace by label selector. Idempotent and safe to re-run. It does
// NOT delete the namespace itself (so a re-run can reuse it cheaply); pass
// deleteNamespace=true at final teardown to remove it.
func (e *Env) CleanupOwned(ctx context.Context, deleteNamespace bool) error {
	if err := e.Guard.AssertMutationAllowed(e.Config.Namespace); err != nil {
		return err
	}
	ns := e.Config.Namespace
	sel := OwnedSelector()
	lo := metav1.ListOptions{LabelSelector: sel}
	delColl := func(kind string, fn func() error) {
		e.Log.Command(fmt.Sprintf("kubectl delete %s -n %s -l %s", kind, ns, sel))
		if err := fn(); err != nil && !apierrors.IsNotFound(err) {
			e.Log.Logf("cleanup %s: %v", kind, err)
		}
	}
	dp := metav1.DeletePropagationBackground
	dopts := metav1.DeleteOptions{PropagationPolicy: &dp}

	delColl("pods", func() error {
		return e.Kube.CoreV1().Pods(ns).DeleteCollection(ctx, dopts, lo)
	})
	delColl("deployments", func() error {
		return e.Kube.AppsV1().Deployments(ns).DeleteCollection(ctx, dopts, lo)
	})
	// Services do not support DeleteCollection; list+delete.
	if svcs, err := e.Kube.CoreV1().Services(ns).List(ctx, lo); err == nil {
		for i := range svcs.Items {
			e.Log.Command(fmt.Sprintf("kubectl delete service %s -n %s", svcs.Items[i].Name, ns))
			_ = e.Kube.CoreV1().Services(ns).Delete(ctx, svcs.Items[i].Name, dopts)
		}
	}
	delColl("configmaps", func() error {
		return e.Kube.CoreV1().ConfigMaps(ns).DeleteCollection(ctx, dopts, lo)
	})
	delColl("secrets", func() error {
		return e.Kube.CoreV1().Secrets(ns).DeleteCollection(ctx, dopts, lo)
	})
	delColl("serviceaccounts", func() error {
		return e.Kube.CoreV1().ServiceAccounts(ns).DeleteCollection(ctx, dopts, lo)
	})
	// RBAC (namespaced) — Roles/RoleBindings.
	delColl("rolebindings", func() error {
		return e.Kube.RbacV1().RoleBindings(ns).DeleteCollection(ctx, dopts, lo)
	})
	delColl("roles", func() error {
		return e.Kube.RbacV1().Roles(ns).DeleteCollection(ctx, dopts, lo)
	})

	if deleteNamespace {
		e.Log.Command(fmt.Sprintf("kubectl delete namespace %s", ns))
		if err := e.Kube.CoreV1().Namespaces().Delete(ctx, ns, dopts); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// ExecResult mirrors safety.ExecResult so callers can use it without importing
// internal/safety. The Env.Exec helper returns this.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Execer is the in-pod exec primitive, injected by the cmd wiring so core does
// not import internal/safety (which would create a cycle through the guard).
type Execer func(ctx context.Context, restCfg *rest.Config, kube kubernetes.Interface, ns, pod, container string, command []string) ExecResult

// exec is the injected exec implementation (set by SetExecer at startup).
var execFn Execer

// SetExecer installs the in-pod exec implementation. Called once at startup by
// the cmd wiring; kept as a package var so the unit tests can stub it.
func SetExecer(fn Execer) { execFn = fn }

// Exec runs a command in a sandbox pod container and returns its captured output.
// It records the command for provenance. Returns an error result if no execer is
// installed (unit-test environments without a live apiserver).
func (e *Env) Exec(ctx context.Context, pod, container string, command []string) ExecResult {
	e.Log.Command(fmt.Sprintf("kubectl exec -n %s %s -c %s -- %v", e.Config.Namespace, pod, container, command))
	if execFn == nil || e.Rest == nil {
		return ExecResult{ExitCode: -1, Err: fmt.Errorf("no execer/rest config available (non-live env)")}
	}
	return execFn(ctx, e.Rest, e.Kube, e.Config.Namespace, pod, container, command)
}

// WaitForPodRunning polls until the named pod is Running (or ctx/timeout). It is
// a convenience used widely by scenarios; it issues no mutation.
func (e *Env) WaitForPodRunning(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pod, err := e.Kube.CoreV1().Pods(e.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil && pod.Status.Phase == corev1.PodRunning {
			ready := true
			for _, cs := range pod.Status.ContainerStatuses {
				if !cs.Ready {
					ready = false
					break
				}
			}
			if ready {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pod %s not running within %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
