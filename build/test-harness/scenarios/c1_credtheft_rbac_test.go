package scenarios

// c1_credtheft_rbac_test.go — PERMANENT regressions for the actual per-trial
// credential-replay scenario (T2-M162). Every case drives the REAL scenario
// methods (and, for the L2 cases, the REAL Runner) across a REAL replay REST/HTTP
// boundary; only the in-pod exec, the API server and the observation-window wait
// are deterministic local fixtures. NO real credential is ever used: the fake
// exec mints synthetic token strings.
//
// The desired assertions here FAIL against the d296799 baseline (which minted an
// unrelated unbound token, discarded the stolen bytes and scored a failed theft
// as success) and PASS against the fix.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ---------------------------------------------------------------- fixtures

// ctLogger records every log line and provenance command so a test can assert
// the captured credential never leaks into either.
type ctLogger struct {
	mu    sync.Mutex
	lines []string
	cmds  []string
}

func (l *ctLogger) Logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
}
func (l *ctLogger) Command(c string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cmds = append(l.cmds, c)
}
func (l *ctLogger) Commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.cmds...)
}
func (l *ctLogger) RawLogPath() string { return "" }
func (l *ctLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n") + "\n" + strings.Join(l.cmds, "\n")
}

type ctGuard struct{}

func (ctGuard) AssertMutationAllowed(string) error { return nil }

// ctAPI is a programmable stand-in API server. It records every Authorization
// header it saw and drives its response from a per-call behavior function.
type ctAPI struct {
	mu       sync.Mutex
	auths    []string
	calls    int
	behavior func(w http.ResponseWriter, call int)
}

func (a *ctAPI) handler(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.auths = append(a.auths, r.Header.Get("Authorization"))
	call := a.calls
	a.calls++
	beh := a.behavior
	a.mu.Unlock()
	if beh != nil {
		beh(w, call)
		return
	}
	writePodList(w)
}

func (a *ctAPI) sawAuth() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auths...)
}

func writePodList(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}})
}

func writeStatus(w http.ResponseWriter, code int, reason metav1.StatusReason) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   "Failure", Reason: reason, Code: int32(code),
	})
}

// newCredEnv builds an Env whose Rest points at srv, whose Kube is a fake
// clientset that FAILS the test if a TokenRequest is ever minted, and seeds a
// single running target pod so Execute's runningPodByApp resolves. adminToken, if
// non-empty, is planted as the base client's own bearer so a test can prove it is
// never replayed.
func newCredEnv(t *testing.T, srvURL, adminToken string, window int) (*core.Env, *ctLogger) {
	t.Helper()
	kube := fake.NewSimpleClientset()
	kube.PrependReactor("create", "serviceaccounts", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "token" {
			t.Errorf("oracle minted a TokenRequest; the replay must use ONLY the captured credential")
		}
		return false, nil, nil
	})
	log := &ctLogger{}
	env := &core.Env{
		Kube: kube,
		Rest: &rest.Config{Host: srvURL, BearerToken: adminToken},
		Config: config.TargetConfig{
			Namespace: "sandbox", Context: "rv", OwnedAck: true,
			CredentialObservationWindowSeconds: window,
		},
		Log:   log,
		Guard: ctGuard{},
	}
	seedRunningPod(t, env, "c1ct-target", "c1ct-target")
	return env, log
}

func seedRunningPod(t *testing.T, env *core.Env, name, app string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace, UID: "pod-uid-123", Labels: map[string]string{"app": app}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// installExecer installs a fake in-pod exec returning the given stdout/exit for
// every command.
func installExecer(t *testing.T, stdout string, exit int) {
	t.Helper()
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Stdout: stdout, ExitCode: exit}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
}

// noSleepWindow replaces the observation-window wait with a no-op that records the
// duration it was asked to wait, so tests exercise the real request order without
// actually sleeping. Restores the production seam afterwards.
func noSleepWindow(t *testing.T) *time.Duration {
	t.Helper()
	var got time.Duration
	prev := credObservationSleep
	credObservationSleep = func(_ context.Context, d time.Duration) error { got = d; return nil }
	t.Cleanup(func() { credObservationSleep = prev })
	return &got
}

// mintJWT builds a synthetic (unsigned-in-effect) JWT with the given claims. It is
// never a real credential; the replay boundary treats the whole string opaquely.
func mintJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pj, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	pl := base64.RawURLEncoding.EncodeToString(pj)
	sig := base64.RawURLEncoding.EncodeToString([]byte("synthetic-signature-not-verified"))
	return hdr + "." + pl + "." + sig
}

func podBoundToken(t *testing.T, ttl time.Duration) string {
	return mintJWT(t, map[string]any{
		"exp":           time.Now().Add(ttl).Unix(),
		"sub":           "system:serviceaccount:sandbox:c1ct-sa",
		"kubernetes.io": map[string]any{"pod": map[string]any{"name": "c1ct-target", "uid": "pod-uid-123"}},
	})
}

func newScenario() *c1CredTheftRBAC { return &c1CredTheftRBAC{app: "c1ct-target", sa: "c1ct-sa"} }

// ---------------------------------------------------------------- direct tests

// The captured credential — and ONLY it — is replayed in BOTH the initial and the
// post-window observation, and NO substitute token is ever minted.
func TestCredReplayReplaysTheCapturedCredentialTwice(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()

	tok := podBoundToken(t, time.Hour)
	env, log := newCredEnv(t, srv.URL, "ADMIN-SUPER-SECRET", 2)
	installExecer(t, tok, 0)
	window := noSleepWindow(t)

	s := newScenario()
	ar, err := s.Execute(context.Background(), env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	res, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatalf("SuccessOracle: %v", err)
	}
	if !res.Achieved {
		t.Fatalf("achieved=%v want true (captured pod-bound token accepted before and after window)", res.Achieved)
	}

	auth := api.sawAuth()
	if len(auth) != 2 {
		t.Fatalf("API calls=%d want 2 (initial + post-window), saw %v", len(auth), auth)
	}
	for i, a := range auth {
		if a != "Bearer "+tok {
			t.Fatalf("call %d Authorization=%q want the CAPTURED credential", i, a)
		}
		if strings.Contains(a, "ADMIN-SUPER-SECRET") {
			t.Fatalf("call %d replayed the base client's admin identity: %q", i, a)
		}
	}
	if *window != 2*time.Second {
		t.Fatalf("observation window waited %v want 2s from config", *window)
	}
	if res.Evidence["credentialBinding"] != "pod-bound" {
		t.Fatalf("binding evidence=%q want pod-bound", res.Evidence["credentialBinding"])
	}
	if len(ar.Stages) == 0 {
		t.Fatal("Execute reported no kill-chain stages")
	}
	assertNoTokenLeak(t, tok, log, ar, res)
}

// A demonstrably FAILED theft (empty output, non-zero exit) is an Execute error —
// an INVALID measurement — never a scored success off a minted substitute.
func TestCredReplayFailedTheftIsExecuteError(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, "" /* nothing stolen */, 1 /* exec failed */)
	noSleepWindow(t)

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute returned nil error for a failed in-pod theft; want an attack-stimulus error")
	}
	if len(api.sawAuth()) != 0 {
		t.Fatalf("a failed theft still hit the API: %v", api.sawAuth())
	}
}

// An empty (but exit-0) read is still no credential and must fail the stimulus.
func TestCredReplayEmptyReadIsExecuteError(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, "   \n", 0)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute accepted an empty credential read; want an error")
	}
}

// An initial 401 means the theft's credential is not usable, so there is no
// capability to observe surviving: an Execute error (invalid), not a defense win.
func TestCredReplayUnusableBaselineIsExecuteError(t *testing.T) {
	api := &ctAPI{behavior: func(w http.ResponseWriter, _ int) { writeStatus(w, http.StatusUnauthorized, metav1.StatusReasonUnauthorized) }}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute accepted an initially-denied credential; want an error")
	}
}

// A genuine post-window 401 after an ACCEPTED baseline is an observed denial:
// Achieved=false, a VALID measurement (not an oracle error).
func TestCredReplayPostWindowDenialIsObservedFailure(t *testing.T) {
	api := &ctAPI{behavior: func(w http.ResponseWriter, call int) {
		if call == 0 {
			writePodList(w)
			return
		}
		writeStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden)
	}}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	noSleepWindow(t)

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute (accepted baseline): %v", err)
	}
	res, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatalf("a genuine 403 must be a VALID observed denial, not an oracle error: %v", err)
	}
	if res.Achieved {
		t.Fatalf("post-window 403 scored as achieved=%v want false", res.Achieved)
	}
	if res.Evidence["finalReplayClass"] != "forbidden-403" {
		t.Fatalf("final class=%q want forbidden-403", res.Evidence["finalReplayClass"])
	}
}

// A transport/5xx fault on the FINAL observation is an oracle error (invalid),
// never a false denial credited to the defender.
func TestCredReplayFinalTransportFaultIsOracleError(t *testing.T) {
	api := &ctAPI{behavior: func(w http.ResponseWriter, call int) {
		if call == 0 {
			writePodList(w)
			return
		}
		writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError)
	}}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	noSleepWindow(t)

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := s.SuccessOracle(context.Background(), env); err == nil {
		t.Fatal("a 5xx on the final observation must be an oracle error (invalid), got nil")
	}
}

// A 2xx whose body is not a PodList is malformed, not a usable success.
func TestCredReplayMalformedFinalIsOracleError(t *testing.T) {
	api := &ctAPI{behavior: func(w http.ResponseWriter, call int) {
		if call == 0 {
			writePodList(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not a pod list"))
	}}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	noSleepWindow(t)

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := s.SuccessOracle(context.Background(), env); err == nil {
		t.Fatal("a malformed 2xx on the final observation must be an oracle error, got nil")
	}
}

// A cancelled observation wait is an invalid measurement, not a denial.
func TestCredReplayCancelledWindowIsOracleError(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)

	// A wait seam that blocks until the context ends, exercising real cancellation.
	prev := credObservationSleep
	credObservationSleep = func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	t.Cleanup(func() { credObservationSleep = prev })

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.SuccessOracle(ctx, env); err == nil {
		t.Fatal("a cancelled observation window must be an oracle error, got nil")
	}
}

// If the captured credential's own natural expiry falls within the observation
// window, the measurement is refused rather than crediting the defender for
// natural expiry.
func TestCredReplayNaturalExpiryGuard(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 60) // 60s window
	installExecer(t, podBoundToken(t, 1*time.Second), 0)
	noSleepWindow(t)

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, err := s.SuccessOracle(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "expiry") {
		t.Fatalf("expected a natural-expiry invalidation, got %v", err)
	}
}

// The oracle refuses to score with no captured state from this trial's Execute.
func TestCredReplayNoCaptureIsOracleError(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	s := newScenario()
	if _, err := s.SuccessOracle(context.Background(), env); err == nil {
		t.Fatal("SuccessOracle without a completed Execute must error, got nil")
	}
}

// Teardown clears the captured credential so a following trial cannot replay a
// stale one; an oracle run after that clearing is invalid, not a stale success.
func TestCredReplayTeardownClearsCapturedState(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	noSleepWindow(t)

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := s.SuccessOracle(context.Background(), env); err != nil {
		t.Fatalf("SuccessOracle: %v", err)
	}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if s.captured != "" || s.baselineDone {
		t.Fatal("Teardown did not clear the captured credential state")
	}
	if _, err := s.SuccessOracle(context.Background(), env); err == nil {
		t.Fatal("oracle after teardown reused stale state; want an error")
	}
}

// An opaque credential-injecting transport on the base client is REFUSED, so an
// inherited admin identity can never produce a false success.
func TestCredReplayRefusesOpaqueTransport(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	env.Rest.WrapTransport = func(rt http.RoundTripper) http.RoundTripper { return rt }
	installExecer(t, podBoundToken(t, time.Hour), 0)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute proceeded with an opaque custom transport; want a clear refusal")
	}
	if len(api.sawAuth()) != 0 {
		t.Fatalf("refused replay still reached the API: %v", api.sawAuth())
	}
}

// The captured credential is never forwarded across a redirect to another host.
func TestCredReplayDoesNotFollowRedirectToAnotherHost(t *testing.T) {
	other := &ctAPI{}
	otherSrv := httptest.NewServer(http.HandlerFunc(other.handler))
	defer otherSrv.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, otherSrv.URL+"/api/v1/namespaces/sandbox/pods", http.StatusFound)
	}))
	defer primary.Close()

	env, _ := newCredEnv(t, primary.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute treated a redirect as a usable success; want an error")
	}
	if got := other.sawAuth(); len(got) != 0 {
		t.Fatalf("captured credential was forwarded to the redirect target: %v", got)
	}
}

// Positive control: an accepted pod-bound token that keeps working across the
// window yields Achieved=true — the pipeline can and does produce a real success.
func TestCredReplayPositiveControlSurvives(t *testing.T) {
	api := &ctAPI{} // default: always 200 PodList
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	noSleepWindow(t)

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	res, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatalf("SuccessOracle: %v", err)
	}
	if !res.Achieved {
		t.Fatalf("positive control achieved=%v want true", res.Achieved)
	}
}

// assertNoTokenLeak fails if the captured credential (or its 16-char prefix)
// appears in any log line, provenance command, attack note or oracle evidence.
func assertNoTokenLeak(t *testing.T, tok string, log *ctLogger, ar core.AttackResult, res core.OracleResult) {
	t.Helper()
	prefix := tok
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	haystacks := map[string]string{"log": log.all()}
	for k, v := range ar.Notes {
		haystacks["note:"+k] = v
	}
	for _, c := range ar.Commands {
		haystacks["cmd:"+c] = c
	}
	for k, v := range res.Evidence {
		haystacks["evidence:"+k] = v
	}
	haystacks["observedState"] = res.ObservedState
	for where, hay := range haystacks {
		if strings.Contains(hay, tok) {
			t.Fatalf("captured credential leaked into %s", where)
		}
		if strings.Contains(hay, prefix) {
			t.Fatalf("captured credential PREFIX leaked into %s", where)
		}
	}
}

// ---------------------------------------------------------- binding metadata

func TestParseCapturedCredMeta(t *testing.T) {
	podBound := podBoundToken(t, time.Hour)
	unbound := mintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "sub": "system:serviceaccount:sandbox:c1ct-sa"})

	cases := []struct {
		name        string
		token       string
		wantDecoded bool
		wantBinding string
		wantExp     bool
	}{
		{"pod-bound projected JWT", podBound, true, "pod-bound", true},
		{"unbound JWT (no pod claim)", unbound, true, "unbound", true},
		{"opaque non-JWT credential", "opaque-legacy-token-value", false, "unknown", false},
		{"malformed JWT payload", "aaa.!!!not-base64!!!.bbb", false, "unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := parseCapturedCredMeta(tc.token)
			if m.decoded != tc.wantDecoded {
				t.Fatalf("decoded=%v want %v", m.decoded, tc.wantDecoded)
			}
			if m.binding != tc.wantBinding {
				t.Fatalf("binding=%q want %q", m.binding, tc.wantBinding)
			}
			if (m.expUnix > 0) != tc.wantExp {
				t.Fatalf("expUnix=%d wantExpPresent=%v", m.expUnix, tc.wantExp)
			}
		})
	}
}

// ------------------------------------------------------- L2 real Runner cases

// runCredMatrix drives the REAL Runner for one c1-credtheft-rbac trial under the
// undefended d-nomtd baseline and returns that row. The per-trial Env is wired to
// the given API server and in-pod exec output; created pods are marked Running so
// the real Setup/deployTarget path resolves against the fake clientset.
func runCredMatrix(t *testing.T, api *ctAPI, execToken string, execExit int) core.Metric {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	t.Cleanup(srv.Close)

	installExecer(t, execToken, execExit)
	noSleepWindow(t)

	factory := func(_, _ string, _ int, _ int64, _ string) (*core.Env, func() error, error) {
		kube := fake.NewSimpleClientset()
		kube.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
			if ca, ok := a.(ktesting.CreateAction); ok {
				if pod, ok2 := ca.GetObject().(*corev1.Pod); ok2 {
					pod.Status.Phase = corev1.PodRunning
				}
			}
			return false, nil, nil
		})
		kube.PrependReactor("create", "serviceaccounts", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() == "token" {
				t.Errorf("runner path minted a TokenRequest; replay must use the captured credential only")
			}
			return false, nil, nil
		})
		env := &core.Env{
			Kube: kube,
			Rest: &rest.Config{Host: srv.URL},
			Config: config.TargetConfig{
				Namespace: "sandbox", Context: "rv", OwnedAck: true,
				CredentialObservationWindowSeconds: 2,
			},
			Log:   &ctLogger{},
			Guard: ctGuard{},
		}
		return env, func() error { return nil }, nil
	}

	writer, err := core.NewMetricWriter(filepath.Join(t.TempDir(), "metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	opts := core.RunnerOptions{
		TrialsPerArm:   1,
		MasterSeed:     1,
		OutDir:         t.TempDir(),
		CILevel:        0.95,
		ScenarioFilter: map[string]bool{"c1-credtheft-rbac": true},
		DefenderFilter: map[string]bool{"d-nomtd": true},
	}
	runner := core.NewRunner(opts, factory, writer, func(string) {})
	metrics, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("runner.Run: %v", err)
	}
	for _, m := range metrics {
		if m.Scenario == "c1-credtheft-rbac" && m.Defender == "d-nomtd" {
			return m
		}
	}
	t.Fatalf("no c1-credtheft-rbac/d-nomtd row in %d metrics", len(metrics))
	return core.Metric{}
}

// L2: a good trial through the real Runner is a VALID measurement whose oracle
// records the credential surviving the window under the undefended baseline.
func TestRunnerCredReplaySurvivalIsValid(t *testing.T) {
	api := &ctAPI{} // always 200 PodList
	m := runCredMatrix(t, api, podBoundToken(t, time.Hour), 0)
	if got := m.MeasurementState().Status; got != core.MeasurementValid {
		t.Fatalf("measurement status=%q want valid", got)
	}
	if !m.OracleAchieved {
		t.Fatalf("undefended baseline oracleAchieved=%v want true", m.OracleAchieved)
	}
}

// L2: a failed in-pod theft makes the Runner record an INVALID measurement — the
// M161 contract classifies the attack-stimulus failure, and it is not scored.
func TestRunnerCredReplayFailedTheftIsInvalid(t *testing.T) {
	api := &ctAPI{}
	m := runCredMatrix(t, api, "" /* nothing stolen */, 1 /* exec failed */)
	if got := m.MeasurementState().Status; got != core.MeasurementInvalid {
		t.Fatalf("failed-theft measurement status=%q want invalid", got)
	}
	if m.IsScored() {
		t.Fatal("failed-theft row was scored; an invalid measurement must not enter a score")
	}
}

// L2: a transport fault on the final observation makes the Runner record an
// INVALID measurement (oracle error), not a false denial.
func TestRunnerCredReplayFinalFaultIsInvalid(t *testing.T) {
	api := &ctAPI{behavior: func(w http.ResponseWriter, call int) {
		if call == 0 {
			writePodList(w)
			return
		}
		writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError)
	}}
	m := runCredMatrix(t, api, podBoundToken(t, time.Hour), 0)
	if got := m.MeasurementState().Status; got != core.MeasurementInvalid {
		t.Fatalf("final-fault measurement status=%q want invalid", got)
	}
}
