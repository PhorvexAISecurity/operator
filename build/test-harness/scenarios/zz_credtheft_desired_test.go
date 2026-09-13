package scenarios

// zz_credtheft_desired_test.go — DISCRIMINATING desired-behavior probe for
// T2-M162. It uses ONLY the stable Scenario interface (Execute + the exec seam +
// a real replay HTTP boundary), so the SAME file compiles and runs against both
// the d296799 baseline and the fix:
//
//   - baseline: Execute ignores a failed theft and never replays the captured
//     bytes (the API call, with a MINTED substitute, happens later in the oracle),
//     so both assertions FAIL (RED).
//   - fix: Execute fails a failed theft and replays the CAPTURED bytes against the
//     API before returning, so both assertions PASS (GREEN).
//
// No window seam, config field or fix-only symbol is referenced, precisely so the
// probe is runnable at the baseline pin.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

const dpStolenToken = "STOLEN-FROM-POD-abcdefghijklmnop"

type dpLogger struct {
	mu   sync.Mutex
	cmds []string
}

func (l *dpLogger) Logf(string, ...any) {}
func (l *dpLogger) Command(c string)    { l.mu.Lock(); defer l.mu.Unlock(); l.cmds = append(l.cmds, c) }
func (l *dpLogger) Commands() []string  { l.mu.Lock(); defer l.mu.Unlock(); return l.cmds }
func (l *dpLogger) RawLogPath() string  { return "" }

type dpGuard struct{}

func (dpGuard) AssertMutationAllowed(string) error { return nil }

func dpEnv(t *testing.T, srvURL string) *core.Env {
	t.Helper()
	kube := fake.NewSimpleClientset()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "c1ct-target", Namespace: "sandbox", UID: "pod-uid-123", Labels: map[string]string{"app": "c1ct-target"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if _, err := kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	env := &core.Env{
		Kube:   kube,
		Rest:   &rest.Config{Host: srvURL},
		Config: config.TargetConfig{Namespace: "sandbox", Context: "rv", OwnedAck: true},
		Log:    &dpLogger{},
		Guard:  dpGuard{},
	}
	return env
}

func dpExecer(t *testing.T, stdout string, exit int) {
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Stdout: stdout, ExitCode: exit}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
}

// DESIRED: a failed in-pod theft must make Execute return an error. RED on the
// baseline (Execute ignores exit code), GREEN on the fix.
func TestDesiredFailedTheftMakesExecuteError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: []corev1.Pod{}})
	}))
	defer api.Close()
	env := dpEnv(t, api.URL)
	dpExecer(t, "" /* empty */, 1 /* failed */)

	s := &c1CredTheftRBAC{app: "c1ct-target", sa: "c1ct-sa"}
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("DESIRED-RED-AT-BASELINE: Execute ignored a failed theft (want an error)")
	}
}

// DESIRED: Execute must replay the CAPTURED bytes against the API before
// returning, and never a minted substitute. RED on the baseline (Execute makes no
// API call; the oracle later replays a MINTED token), GREEN on the fix.
func TestDesiredExecuteReplaysCapturedCredential(t *testing.T) {
	var mu sync.Mutex
	var auths []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: []corev1.Pod{}})
	}))
	defer api.Close()
	env := dpEnv(t, api.URL)
	dpExecer(t, dpStolenToken, 0)

	s := &c1CredTheftRBAC{app: "c1ct-target", sa: "c1ct-sa"}
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	mu.Lock()
	got := append([]string(nil), auths...)
	mu.Unlock()
	if len(got) == 0 {
		t.Fatal("DESIRED-RED-AT-BASELINE: Execute performed no credential replay against the API")
	}
	for _, a := range got {
		if a != "Bearer "+dpStolenToken {
			t.Fatalf("DESIRED-RED-AT-BASELINE: replay used %q, not the captured credential", a)
		}
	}
	if strings.Contains(strings.Join(got, ","), "MINTED") {
		t.Fatal("DESIRED-RED-AT-BASELINE: a minted substitute token was replayed")
	}
}
