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
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

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
	// A genuine v1 PodList: kind/apiVersion set and an items ARRAY present (empty
	// is valid). Items must be a non-nil slice so it marshals as [] not null.
	_ = json.NewEncoder(w).Encode(corev1.PodList{
		TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"},
		Items:    []corev1.Pod{},
	})
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

// startTLS starts a trusted local HTTPS fixture for the API stand-in. The replay
// contract requires an explicit https:// endpoint, so every normal replay test
// uses this rather than a cleartext server.
func startTLS(t *testing.T, api *ctAPI) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(api.handler))
	t.Cleanup(srv.Close)
	return srv
}

// credEnvTLS wires an Env at the trusted HTTPS fixture, trusting only that
// fixture's CA — the honest way to exercise a real verified-TLS replay.
func credEnvTLS(t *testing.T, srv *httptest.Server, adminToken string, window int) (*core.Env, *ctLogger) {
	t.Helper()
	env, log := newCredEnv(t, srv.URL, adminToken, window)
	env.Rest.TLSClientConfig.CAData = caPEM(t, srv)
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

// Exercise the actual Setup path: the captured credential needs only the
// namespace Pod-list operation, while the fixture's own admin client creates
// its ServiceAccount, Role, RoleBinding and Pod. The same credential must still
// drive the initial and post-window API observations.
func TestCredReplaySetupGrantsOnlyPodListAndReplaysCapturedToken(t *testing.T) {
	env, kube := ownershipEnv(t)
	assignCreateUIDs(kube)
	kube.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		action.(ktesting.CreateAction).GetObject().(*corev1.ServiceAccount).UID = types.UID("owned-sa")
		return false, nil, nil
	})
	kube.PrependReactor("create", "roles", func(action ktesting.Action) (bool, runtime.Object, error) {
		action.(ktesting.CreateAction).GetObject().(*rbacv1.Role).UID = types.UID("owned-role")
		return false, nil, nil
	})
	kube.PrependReactor("create", "rolebindings", func(action ktesting.Action) (bool, runtime.Object, error) {
		action.(ktesting.CreateAction).GetObject().(*rbacv1.RoleBinding).UID = types.UID("owned-binding")
		return false, nil, nil
	})

	api := &ctAPI{}
	srv := startTLS(t, api)
	env.Rest = &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: caPEM(t, srv)}}
	s := &c1CredTheftRBAC{}
	if err := s.Setup(t.Context(), env); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	role, err := kube.RbacV1().Roles(env.Config.Namespace).Get(t.Context(), s.sa+"-role", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wantRules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}}
	if !reflect.DeepEqual(role.Rules, wantRules) {
		t.Fatalf("fixture Role rules=%#v; want only core/pods/list", role.Rules)
	}
	binding, err := kube.RbacV1().RoleBindings(env.Config.Namespace).Get(t.Context(), s.sa+"-rb", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != role.Name ||
		len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Name != s.sa {
		t.Fatalf("fixture binding points outside the owned ServiceAccount/Role: %#v", binding)
	}
	pod, err := kube.CoreV1().Pods(env.Config.Namespace).Get(t.Context(), s.app, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pod.Spec.ServiceAccountName != s.sa {
		t.Fatalf("source Pod serviceAccount=%q, want %q", pod.Spec.ServiceAccountName, s.sa)
	}
	token := mintJWT(t, map[string]any{
		"exp":           time.Now().Add(time.Hour).Unix(),
		"sub":           "system:serviceaccount:sandbox:" + s.sa,
		"kubernetes.io": map[string]any{"pod": map[string]any{"name": pod.Name, "uid": string(pod.UID)}},
	})
	installExecer(t, token, 0)
	noSleepWindow(t)
	attack, err := s.Execute(t.Context(), env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	result, err := s.SuccessOracle(t.Context(), env)
	if err != nil || !result.Achieved {
		t.Fatalf("SuccessOracle=%#v, %v; want post-window authorization", result, err)
	}
	requests := api.sawAuth()
	if len(requests) != 2 || requests[0] != "Bearer "+token || requests[1] != "Bearer "+token {
		t.Fatalf("initial/final replay did not use only the same captured credential (calls=%d)", len(requests))
	}
	if strings.Contains(strings.Join(env.Log.Commands(), "\n"), token) ||
		strings.Contains(strings.Join(attack.Commands, "\n"), token) {
		t.Fatal("fixture credential leaked into command provenance")
	}
}

// The captured credential — and ONLY it — is replayed in BOTH the initial and the
// post-window observation, and NO substitute token is ever minted.
func TestCredReplayReplaysTheCapturedCredentialTwice(t *testing.T) {
	api := &ctAPI{}
	srv := startTLS(t, api)

	tok := podBoundToken(t, time.Hour)
	env, log := credEnvTLS(t, srv, "ADMIN-SUPER-SECRET", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
	installExecer(t, "   \n", 0)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute accepted an empty credential read; want an error")
	}
}

// An initial 401 means the theft's credential is not usable, so there is no
// capability to observe surviving: an Execute error (invalid), not a defense win.
func TestCredReplayUnusableBaselineIsExecuteError(t *testing.T) {
	api := &ctAPI{behavior: func(w http.ResponseWriter, _ int) {
		writeStatus(w, http.StatusUnauthorized, metav1.StatusReasonUnauthorized)
	}}
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 60) // 60s window
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
	if _, err := env.Kube.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: "cred-teardown-namespace"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	otherSrv := httptest.NewTLSServer(http.HandlerFunc(other.handler))
	defer otherSrv.Close()
	primary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, otherSrv.URL+"/api/v1/namespaces/sandbox/pods", http.StatusFound)
	}))
	defer primary.Close()

	env, _ := newCredEnv(t, primary.URL, "", 2)
	env.Rest.TLSClientConfig.CAData = caPEM(t, primary)
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
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
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
	srv := httptest.NewTLSServer(http.HandlerFunc(api.handler))
	t.Cleanup(srv.Close)
	caData := caPEM(t, srv)

	installExecer(t, execToken, execExit)
	noSleepWindow(t)

	factory := func(_, _ string, _ int, _ int64, _ string) (*core.Env, func() error, error) {
		kube := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: types.UID("cred-test-namespace")}})
		kube.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
			if ca, ok := a.(ktesting.CreateAction); ok {
				if pod, ok2 := ca.GetObject().(*corev1.Pod); ok2 {
					pod.UID = types.UID("cred-test-pod")
					pod.Status.Phase = corev1.PodRunning
				}
			}
			return false, nil, nil
		})
		kube.PrependReactor("create", "serviceaccounts", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() == "token" {
				t.Errorf("runner path minted a TokenRequest; replay must use the captured credential only")
			} else if ca, ok := a.(ktesting.CreateAction); ok {
				ca.GetObject().(*corev1.ServiceAccount).UID = types.UID("cred-test-sa")
			}
			return false, nil, nil
		})
		kube.PrependReactor("create", "roles", func(a ktesting.Action) (bool, runtime.Object, error) {
			a.(ktesting.CreateAction).GetObject().(*rbacv1.Role).UID = types.UID("cred-test-role")
			return false, nil, nil
		})
		kube.PrependReactor("create", "rolebindings", func(a ktesting.Action) (bool, runtime.Object, error) {
			a.(ktesting.CreateAction).GetObject().(*rbacv1.RoleBinding).UID = types.UID("cred-test-rb")
			return false, nil, nil
		})
		env := &core.Env{
			Kube: kube,
			Rest: &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: caData}},
			Config: config.TargetConfig{
				Namespace: "sandbox", Context: "rv", OwnedAck: true,
				CredentialObservationWindowSeconds: 2,
			},
			Log:   &ctLogger{},
			Guard: ctGuard{},
		}
		if err := env.EnsureNamespace(context.Background()); err != nil {
			return nil, nil, err
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

// -------------------------------------------------- R1 review repairs (P3 r1)

// R1.1: only a genuine v1 PodList counts as usable. A generic 200 (empty object,
// null, a success Status, or a different collection kind) is malformed, so the
// initial replay in Execute rejects it as an unusable credential.
func TestCredReplayRejectsNonPodListResponses(t *testing.T) {
	bad := map[string]string{
		"empty-object":     `{}`,
		"null":             `null`,
		"success-status":   `{"kind":"Status","apiVersion":"v1","status":"Success"}`,
		"wrong-kind":       `{"kind":"SecretList","apiVersion":"v1","items":[]}`,
		"podlist-no-items": `{"kind":"PodList","apiVersion":"v1"}`,
	}
	for name, body := range bad {
		t.Run("reject/"+name, func(t *testing.T) {
			b := body
			api := &ctAPI{behavior: func(w http.ResponseWriter, _ int) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(b))
			}}
			srv := startTLS(t, api)
			env, _ := credEnvTLS(t, srv, "", 2)
			installExecer(t, podBoundToken(t, time.Hour), 0)
			s := newScenario()
			if _, err := s.Execute(context.Background(), env); err == nil {
				t.Fatalf("Execute accepted a non-PodList 200 body %q as a usable credential", b)
			}
		})
	}

	// Controls: a valid empty PodList and a populated PodList are both accepted.
	for name, items := range map[string]string{"empty-list": `[]`, "populated-list": `[{"metadata":{"name":"p1"}}]`} {
		t.Run("accept/"+name, func(t *testing.T) {
			body := `{"kind":"PodList","apiVersion":"v1","items":` + items + `}`
			api := &ctAPI{behavior: func(w http.ResponseWriter, _ int) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
			}}
			srv := startTLS(t, api)
			env, _ := credEnvTLS(t, srv, "", 2)
			installExecer(t, podBoundToken(t, time.Hour), 0)
			s := newScenario()
			if _, err := s.Execute(context.Background(), env); err != nil {
				t.Fatalf("Execute rejected a valid PodList control (%s): %v", name, err)
			}
		})
	}
}

// R1.2: natural expiry reached at the ACTUAL final observation invalidates the
// measurement even when the credential's expiry is beyond the PLANNED window, so
// scheduling/transport delay cannot award a defender credit for natural expiry.
func TestCredReplayNaturalExpiryReachedAtFinalObservation(t *testing.T) {
	api := &ctAPI{} // 200 PodList on both calls; the guard, not the API, decides
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 1) // planned window 1s
	// Expiry is 3s out — beyond the planned 1s window, so the pre-wait guard does
	// NOT fire; only the actual-final guard can catch it.
	installExecer(t, podBoundToken(t, 3*time.Second), 0)

	// A wait seam that actually elapses PAST the credential's expiry.
	prev := credObservationSleep
	credObservationSleep = func(_ context.Context, _ time.Duration) error { time.Sleep(4 * time.Second); return nil }
	t.Cleanup(func() { credObservationSleep = prev })

	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute (accepted baseline before expiry): %v", err)
	}
	_, err := s.SuccessOracle(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "expiry") {
		t.Fatalf("expected natural-expiry-at-final invalidation, got %v", err)
	}
}

// R1.2 control: a long-lived credential whose expiry is never reached yields a
// normal valid measurement (no expiry invalidation).
func TestCredReplayNonExpiredSurvivesControl(t *testing.T) {
	api := &ctAPI{}
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 1)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	noSleepWindow(t)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	res, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatalf("non-expired control must be a valid measurement: %v", err)
	}
	if !res.Achieved {
		t.Fatalf("non-expired surviving credential achieved=%v want true", res.Achieved)
	}
}

func caPEM(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("TLS server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// R1.3: replay verifies the server's TLS identity — a trusted fixture CA succeeds,
// a wrong CA refuses before the credential is sent, and insecure (skip-verify) is
// refused outright.
func TestCredReplayVerifiesServerTLS(t *testing.T) {
	api := &ctAPI{}
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(api.handler))
	defer tlsSrv.Close()

	t.Run("trusted-CA-succeeds", func(t *testing.T) {
		env, _ := newCredEnv(t, tlsSrv.URL, "", 2)
		env.Rest.TLSClientConfig.CAData = caPEM(t, tlsSrv)
		installExecer(t, podBoundToken(t, time.Hour), 0)
		s := newScenario()
		if _, err := s.Execute(context.Background(), env); err != nil {
			t.Fatalf("Execute over verified TLS: %v", err)
		}
		if got := api.sawAuth(); len(got) == 0 {
			t.Fatal("verified TLS replay never reached the API")
		}
	})

	t.Run("untrusted-server-refuses", func(t *testing.T) {
		// No trusted CA supplied and Insecure is false, so the fixture's
		// self-signed certificate is not trusted by the system roots: verification
		// must fail before the credential is ever sent.
		env, _ := newCredEnv(t, tlsSrv.URL, "", 2)
		env.Rest.TLSClientConfig.CAData = nil
		installExecer(t, podBoundToken(t, time.Hour), 0)
		before := len(api.sawAuth())
		s := newScenario()
		if _, err := s.Execute(context.Background(), env); err == nil {
			t.Fatal("Execute accepted a server whose certificate was not trusted")
		}
		if len(api.sawAuth()) != before {
			t.Fatal("credential was sent to a server whose identity was not verified")
		}
	})

	t.Run("insecure-refused", func(t *testing.T) {
		env, _ := newCredEnv(t, tlsSrv.URL, "", 2)
		env.Rest.TLSClientConfig.Insecure = true
		installExecer(t, podBoundToken(t, time.Hour), 0)
		before := len(api.sawAuth())
		s := newScenario()
		if _, err := s.Execute(context.Background(), env); err == nil {
			t.Fatal("Execute proceeded with insecure TLS (skip-verify); want a refusal")
		}
		if len(api.sawAuth()) != before {
			t.Fatal("insecure replay still reached the API")
		}
	})
}

// R1.3: an auth/exec credential provider on the base client is OMITTED (not
// invoked) — the replay uses only the captured bearer and never resolves the
// provider (a bogus provider name would fail the build if it were used).
func TestCredReplayOmitsAuthProviderWithoutInvoking(t *testing.T) {
	api := &ctAPI{}
	srv := startTLS(t, api)
	tok := podBoundToken(t, time.Hour)
	env, _ := credEnvTLS(t, srv, "", 2)
	env.Rest.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "nonexistent-oidc-provider"}
	installExecer(t, tok, 0)
	noSleepWindow(t)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err != nil {
		t.Fatalf("Execute failed; an omitted auth provider must not be resolved: %v", err)
	}
	for _, a := range api.sawAuth() {
		if a != "Bearer "+tok {
			t.Fatalf("replay used %q, not the captured bearer", a)
		}
	}
}

// -------------------------------------------------- R2 review repairs (P3 r2)

// R2.1: a cleartext (http) endpoint is refused before any request — the captured
// credential is never sent over an unverified transport.
func TestCredReplayRefusesCleartextEndpoint(t *testing.T) {
	api := &ctAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.handler)) // cleartext http
	defer srv.Close()
	env, _ := newCredEnv(t, srv.URL, "", 2) // http host, no CA
	installExecer(t, podBoundToken(t, time.Hour), 0)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute replayed over a cleartext http endpoint; want a refusal")
	}
	if got := api.sawAuth(); len(got) != 0 {
		t.Fatalf("captured credential was sent to a cleartext endpoint: %v", got)
	}
}

// R2.1: a userinfo-bearing endpoint is refused before any request.
func TestCredReplayRefusesUserinfoEndpoint(t *testing.T) {
	api := &ctAPI{}
	srv := startTLS(t, api)
	env, _ := credEnvTLS(t, srv, "", 2)
	env.Rest.Host = strings.Replace(srv.URL, "https://", "https://user:pass@", 1)
	installExecer(t, podBoundToken(t, time.Hour), 0)
	s := newScenario()
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("Execute replayed to a userinfo-bearing endpoint; want a refusal")
	}
	if got := api.sawAuth(); len(got) != 0 {
		t.Fatalf("captured credential reached a userinfo endpoint: %v", got)
	}
}

// R2.2: a 200 v1 PodList whose members are not Pod objects is malformed, not
// usable capability; valid empty and populated lists remain accepted.
func TestCredReplayRejectsMalformedPodItems(t *testing.T) {
	cases := map[string]struct {
		items string
		valid bool
	}{
		"null-member":     {`[null]`, false},
		"number-member":   {`[1]`, false},
		"string-member":   {`["not-a-pod"]`, false},
		"object-not-list": {`{"foo":"bar"}`, false},
		"empty-list":      {`[]`, true},
		"populated-list":  {`[{"metadata":{"name":"p1"}}]`, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			items := tc.items
			api := &ctAPI{behavior: func(w http.ResponseWriter, _ int) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"kind":"PodList","apiVersion":"v1","items":` + items + `}`))
			}}
			srv := startTLS(t, api)
			env, _ := credEnvTLS(t, srv, "", 2)
			installExecer(t, podBoundToken(t, time.Hour), 0)
			s := newScenario()
			_, err := s.Execute(context.Background(), env)
			switch {
			case tc.valid && err != nil:
				t.Fatalf("valid PodList members (%s) rejected: %v", items, err)
			case !tc.valid && err == nil:
				t.Fatalf("malformed PodList members (%s) accepted as usable credential", items)
			}
		})
	}
}
