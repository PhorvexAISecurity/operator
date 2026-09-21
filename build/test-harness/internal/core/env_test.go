package core

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// refusingGuard refuses any namespace except the allowed one (mirrors the real
// safety guard's sandbox assertion without importing internal/safety here).
type refusingGuard struct{ allow string }

func (g refusingGuard) AssertMutationAllowed(ns string) error {
	if ns != g.allow {
		return errors.New("REFUSED: namespace " + ns + " != sandbox " + g.allow)
	}
	return nil
}

type nopLogger struct{ cmds []string }

func (l *nopLogger) Logf(string, ...any) {}
func (l *nopLogger) Command(c string)    { l.cmds = append(l.cmds, c) }
func (l *nopLogger) Commands() []string  { return l.cmds }
func (l *nopLogger) RawLogPath() string  { return "" }

func newTestEnv(ns string, guardNS string) *Env {
	nsUID := types.UID("namespace-" + ns)
	return &Env{
		Kube: fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: ns, UID: nsUID,
		}}),
		Config:       config.TargetConfig{Namespace: ns, Context: "kind-amtd-test", OwnedAck: true},
		Log:          &nopLogger{},
		Guard:        refusingGuard{allow: guardNS},
		namespaceUID: nsUID,
	}
}

func TestEnsureNamespaceBindsExistingSandbox(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatalf("EnsureNamespace failed: %v", err)
	}
	_, err := env.Kube.CoreV1().Namespaces().Get(context.Background(), "sandbox", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("sandbox namespace not found: %v", err)
	}
	if env.namespaceUID != types.UID("namespace-sandbox") {
		t.Fatalf("captured namespace UID = %q", env.namespaceUID)
	}
}

func TestEnsureNamespaceRefusedOutsideSandbox(t *testing.T) {
	// Env targets "evil" but the guard only allows "sandbox" => refused.
	env := newTestEnv("evil", "sandbox")
	if err := env.EnsureNamespace(context.Background()); err == nil {
		t.Fatalf("expected refusal creating a namespace outside the sandbox")
	}
}

func TestCleanupOwnedGoesThroughGuard(t *testing.T) {
	env := newTestEnv("evil", "sandbox")
	if err := env.CleanupOwned(context.Background(), false); err == nil {
		t.Fatalf("expected refusal cleaning outside the sandbox")
	}
	env2 := newTestEnv("sandbox", "sandbox")
	if err := env2.CleanupOwned(context.Background(), false); err != nil {
		t.Fatalf("cleanup in sandbox should be allowed: %v", err)
	}
}

func TestOwnedLabelsAndSelector(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	env.ScenarioName = "c1-escape-persist"
	env.Trial = 3
	labels := env.OwnedLabels(map[string]string{"app": "x"})
	if labels[OwnedLabelKey] != OwnedLabelValue {
		t.Fatalf("owned label missing")
	}
	if labels[ScenarioLabelKey] != "c1-escape-persist" {
		t.Fatalf("scenario label want c1-escape-persist got %q", labels[ScenarioLabelKey])
	}
	if labels[TrialLabelKey] != "3" {
		t.Fatalf("trial label want 3 got %q", labels[TrialLabelKey])
	}
	if labels["app"] != "x" {
		t.Fatalf("extra label not merged")
	}
	if OwnedSelector() != OwnedLabelKey+"="+OwnedLabelValue {
		t.Fatalf("owned selector malformed: %s", OwnedSelector())
	}
}

func TestDefaultAndExplicitTimeoutExecUseSeparateWiring(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	env.Rest = &rest.Config{Host: "https://example.invalid"}
	defaultCalls, timedCalls := 0, 0
	SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) ExecResult {
		defaultCalls++
		return ExecResult{Stdout: "default"}
	})
	SetTimedExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, timeout time.Duration, _ []string) ExecResult {
		timedCalls++
		if timeout != 30*time.Second {
			return ExecResult{ExitCode: -1, Err: errors.New("wrong timeout")}
		}
		return ExecResult{Stdout: "timed"}
	})
	t.Cleanup(func() { SetExecer(nil); SetTimedExecer(nil) })
	if got := env.Exec(t.Context(), "pod", "container", []string{"default"}); got.Stdout != "default" || got.Err != nil {
		t.Fatalf("default result=%+v", got)
	}
	if got := env.ExecWithTimeout(t.Context(), "pod", "container", 30*time.Second, []string{"timed"}); got.Stdout != "timed" || got.Err != nil {
		t.Fatalf("timed result=%+v", got)
	}
	if defaultCalls != 1 || timedCalls != 1 {
		t.Fatalf("default/timed calls=%d/%d", defaultCalls, timedCalls)
	}
}
