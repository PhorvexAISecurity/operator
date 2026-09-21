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
	// EffectAttemptID is set by scenarios after observing the initial attacker
	// outcome and before delivering a response trigger. Defender-owned receipts
	// must match this attempt to avoid credit from a previous trial.
	EffectAttemptID string
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

// CleanupResidue names owned objects still present after the deletes were
// accepted. Background deletion is asynchronous, and a finalizer can hold an
// object indefinitely, so "the API accepted my delete" is NOT proof of absence.
type CleanupResidue struct {
	Kind string
	Name string
	// Terminating is true when the object has a deletion timestamp but is still
	// held (typically by a finalizer).
	Terminating bool
}

func (r CleanupResidue) String() string {
	state := "present"
	if r.Terminating {
		state = "terminating (held, likely by a finalizer)"
	}
	return fmt.Sprintf("%s/%s %s", r.Kind, r.Name, state)
}

// CleanupOwned deletes every harness-owned object of the common kinds in the
// sandbox namespace by label selector, then VERIFIES they are gone. Idempotent
// and safe to re-run. It does NOT delete the namespace itself (so a re-run can
// reuse it cheaply); pass deleteNamespace=true at final teardown to remove it.
//
// It never returns nil on a failure it observed. Every API error across every
// kind is aggregated (one failing kind does not mask the others), and residue
// that survives the deletes is reported as an error too, because a later trial
// must not reuse a namespace whose previous contents are still there. It only
// ever touches objects carrying this harness's owned label in the configured
// sandbox namespace.
func (e *Env) CleanupOwned(ctx context.Context, deleteNamespace bool) error {
	if err := e.Guard.AssertMutationAllowed(e.Config.Namespace); err != nil {
		return err
	}
	ns := e.Config.Namespace
	sel := OwnedSelector()
	lo := metav1.ListOptions{LabelSelector: sel}
	var problems []string
	record := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		e.Log.Logf("cleanup: %s", msg)
		problems = append(problems, msg)
	}
	delColl := func(kind string, fn func() error) {
		e.Log.Command(fmt.Sprintf("kubectl delete %s -n %s -l %s", kind, ns, sel))
		if err := fn(); err != nil && !apierrors.IsNotFound(err) {
			record("delete %s: %v", kind, err)
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
	delColl("replicasets", func() error {
		return e.Kube.AppsV1().ReplicaSets(ns).DeleteCollection(ctx, dopts, lo)
	})
	delColl("persistentvolumeclaims", func() error {
		return e.Kube.CoreV1().PersistentVolumeClaims(ns).DeleteCollection(ctx, dopts, lo)
	})
	// Services do not support DeleteCollection; list+delete. BOTH the list and
	// each delete are failures worth reporting: a list error means we do not even
	// know what is left.
	if svcs, err := e.Kube.CoreV1().Services(ns).List(ctx, lo); err != nil {
		if !apierrors.IsNotFound(err) {
			record("list services: %v", err)
		}
	} else {
		for i := range svcs.Items {
			e.Log.Command(fmt.Sprintf("kubectl delete service %s -n %s", svcs.Items[i].Name, ns))
			if err := e.Kube.CoreV1().Services(ns).Delete(ctx, svcs.Items[i].Name, dopts); err != nil && !apierrors.IsNotFound(err) {
				record("delete service %s: %v", svcs.Items[i].Name, err)
			}
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

	// Verify absence rather than trusting the accepted deletes — but WAIT for it.
	// Kubernetes deletion is asynchronous by design: a Pod that the API accepted
	// a delete for is normally still listed, terminating, for a short grace
	// period. A one-shot check right after the delete would call that ordinary,
	// successful deletion a failure. So poll until the residue clears or the
	// budget runs out; only what is STILL there at the deadline is a problem, and
	// its terminating/finalizer state is reported rather than guessed at.
	residue, verifyErrs := e.awaitOwnedResidueGone(ctx, lo)
	problems = append(problems, verifyErrs...)
	for _, r := range residue {
		record("owned object still present when the cleanup budget expired: %s", r)
	}

	if deleteNamespace {
		e.Log.Command(fmt.Sprintf("kubectl delete namespace %s", ns))
		if err := e.Kube.CoreV1().Namespaces().Delete(ctx, ns, dopts); err != nil && !apierrors.IsNotFound(err) {
			record("delete namespace %s: %v", ns, err)
		} else if gone, state, err := e.awaitNamespaceGone(ctx, ns); err != nil {
			// Absence that cannot be observed must not be claimed.
			record("verify namespace %s: %v", ns, err)
		} else if !gone {
			record("namespace %s still present when the cleanup budget expired: %s", ns, state)
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("cleanup of owned objects in namespace %s did not verify (%d problem(s)): %s",
			ns, len(problems), strings.Join(problems, "; "))
	}
	return nil
}

// residuePollInterval is how often the verification re-lists while waiting for
// an accepted deletion to actually complete.
const residuePollInterval = 25 * time.Millisecond

// DefaultResidueWait bounds the wait for accepted deletions to complete when the
// caller supplied a context with no deadline of its own.
const DefaultResidueWait = 30 * time.Second

// residueDeadline is the instant the verification stops waiting: the caller's
// deadline when it has one, otherwise DefaultResidueWait from now. Either way it
// is BOUNDED — the harness never waits forever for a finalizer to release.
func residueDeadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(DefaultResidueWait)
}

// awaitOwnedResidueGone polls until no owned object remains, the budget expires
// or the context ends. It returns whatever is still there at that point, plus
// any error that prevented the check.
//
// This preserves the asynchronous-deletion and finalizer uncertainty the review
// asked for: a normal terminating Pod that disappears well within the budget is
// a SUCCESS, while an object a finalizer still holds at the deadline is reported
// with that state and never treated as absent.
func (e *Env) awaitOwnedResidueGone(ctx context.Context, lo metav1.ListOptions) ([]CleanupResidue, []string) {
	deadline := residueDeadline(ctx)
	for {
		residue, errs := e.ownedResidue(ctx, lo)
		if len(errs) > 0 {
			// The check itself failed; retrying cannot turn an unreadable kind
			// into an observation of absence.
			return residue, errs
		}
		if len(residue) == 0 {
			return nil, nil
		}
		if !time.Now().Before(deadline) {
			return residue, nil
		}
		select {
		case <-ctx.Done():
			return residue, nil
		case <-time.After(residuePollInterval):
		}
	}
}

// awaitNamespaceGone polls until the sandbox namespace is actually gone, the
// budget expires or the context ends. An accepted namespace delete is not
// absence: a namespace routinely sits in Terminating while its contents drain,
// and a finalizer can hold it indefinitely.
func (e *Env) awaitNamespaceGone(ctx context.Context, ns string) (bool, string, error) {
	deadline := residueDeadline(ctx)
	for {
		got, err := e.Kube.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return true, "", nil
		case err != nil:
			return false, "", err
		}
		state := "present"
		if got.DeletionTimestamp != nil {
			state = fmt.Sprintf("terminating since %s (held, likely by a finalizer: %v)",
				got.DeletionTimestamp.Time.UTC().Format(time.RFC3339), got.Finalizers)
		}
		if !time.Now().Before(deadline) {
			return false, state, nil
		}
		select {
		case <-ctx.Done():
			return false, state, nil
		case <-time.After(residuePollInterval):
		}
	}
}

// ownedResidue lists the owned objects that are still present, and any error
// that prevented the check. An unreadable kind is itself a problem: absence that
// cannot be observed must not be claimed.
func (e *Env) ownedResidue(ctx context.Context, lo metav1.ListOptions) ([]CleanupResidue, []string) {
	ns := e.Config.Namespace
	var out []CleanupResidue
	var errs []string
	add := func(kind, name string, deletionTS *metav1.Time) {
		out = append(out, CleanupResidue{Kind: kind, Name: name, Terminating: deletionTS != nil})
	}
	check := func(kind string, fn func() error) {
		if err := fn(); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Sprintf("verify %s: %v", kind, err))
		}
	}
	check("pods", func() error {
		l, err := e.Kube.CoreV1().Pods(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("pod", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("deployments", func() error {
		l, err := e.Kube.AppsV1().Deployments(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("deployment", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("replicasets", func() error {
		l, err := e.Kube.AppsV1().ReplicaSets(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("replicaset", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("services", func() error {
		l, err := e.Kube.CoreV1().Services(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("service", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("persistentvolumeclaims", func() error {
		l, err := e.Kube.CoreV1().PersistentVolumeClaims(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("persistentvolumeclaim", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("configmaps", func() error {
		l, err := e.Kube.CoreV1().ConfigMaps(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("configmap", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("secrets", func() error {
		l, err := e.Kube.CoreV1().Secrets(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("secret", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("serviceaccounts", func() error {
		l, err := e.Kube.CoreV1().ServiceAccounts(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("serviceaccount", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("rolebindings", func() error {
		l, err := e.Kube.RbacV1().RoleBindings(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("rolebinding", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	check("roles", func() error {
		l, err := e.Kube.RbacV1().Roles(ns).List(ctx, lo)
		if err != nil {
			return err
		}
		for i := range l.Items {
			add("role", l.Items[i].Name, l.Items[i].DeletionTimestamp)
		}
		return nil
	})
	return out, errs
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
