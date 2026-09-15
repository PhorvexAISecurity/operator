package scenarios

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// These fixtures invoke registered scenario oracles and the real Pod lookup / in-
// Pod exec seam. They never set a final Achieved flag or contact a cluster.
func TestObservationIntegrityRegisteredOracles(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })
	cases := []struct{ name, app, marker string }{
		{"c1-lateral", "c1lat-dst", lateralMarker},
		{"c2-lateral-disrupt", "c2lat-dst", c2LatMarker},
		{"c2-supplychain-foothold", "c2sc-target", mocks.TamperedMarker},
		{"c2-stealth-foothold", "c2sf-target", StealthFootholdMarker},
		{"c3-admission-bypass", "c3ab-priv", "PRIVILEGED-CONTEXT-RAN"},
		{"c3-cicd", "c3cicd-runner", mocks.InjectedStepMarker},
		{"c3-cryptomining", "c3cm-miner", "5"},
		{"c3-sidecar-inject", "c3si-target", sidecarProofMarker},
		{"c3-supplychain", "c3sc-victim", mocks.TamperedMarker},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scenario := allScenarios()[tc.name]
			setObservationTrial(scenario, tc.app)
			env := fixtureObservationEnv()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			_, err := scenario.SuccessOracle(ctx, env)
			cancel()
			if err == nil {
				t.Fatal("absent target was scored as a defensive result")
			}
			lookupEnv := fixtureObservationEnv()
			lookupEnv.Kube.(*fake.Clientset).PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("fixture lookup transport failed")
			})
			lookupCtx, stopLookup := context.WithTimeout(context.Background(), 20*time.Millisecond)
			if _, err := scenario.SuccessOracle(lookupCtx, lookupEnv); err == nil {
				t.Fatal("failed Pod lookup was scored")
			}
			stopLookup()
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: tc.app, Namespace: "sandbox", UID: "fixture-original", Labels: map[string]string{"app": tc.app}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "runner"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
			if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				return core.ExecResult{Err: context.DeadlineExceeded, ExitCode: -1}
			})
			if _, err := scenario.SuccessOracle(context.Background(), env); err == nil {
				t.Fatal("failed exec was scored")
			}
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				return core.ExecResult{Stdout: "truncated", ExitCode: 0}
			})
			if _, err := scenario.SuccessOracle(context.Background(), env); err == nil {
				t.Fatal("malformed or truncated observation was scored")
			}
			output := tc.marker
			if tc.name == "c2-stealth-foothold" {
				output = tc.marker + "\n" + observationAbsent
			}
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				return core.ExecResult{Stdout: output, ExitCode: 0}
			})
			got, err := scenario.SuccessOracle(context.Background(), env)
			if err != nil || !got.Achieved {
				t.Fatalf("positive marker/counter control: achieved=%v err=%v", got.Achieved, err)
			}
			if got.Evidence["observedPodUID"] != "fixture-original" {
				t.Fatalf("missing concrete observed UID: %v", got.Evidence)
			}
			absence := observationAbsent
			if tc.name == "c2-stealth-foothold" {
				absence = observationAbsent + "\n" + observationAbsent
			}
			if tc.name == "c3-cryptomining" {
				absence = "0"
			}
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				return core.ExecResult{Stdout: absence, ExitCode: 0}
			})
			got, err = scenario.SuccessOracle(context.Background(), env)
			if err != nil || got.Achieved {
				t.Fatalf("measured objective refusal: achieved=%v err=%v", got.Achieved, err)
			}
		})
	}
}

func fixtureObservationEnv() *core.Env {
	return &core.Env{Kube: fake.NewSimpleClientset(), Rest: &rest.Config{Host: "https://fixture.invalid"}, Config: config.TargetConfig{Namespace: "sandbox"}, Log: &dpLogger{}, Guard: dpGuard{}}
}

func setObservationTrial(s core.Scenario, app string) {
	switch v := s.(type) {
	case *c1Lateral:
		v.dstApp = app
		v.targetUID = "fixture-original"
	case *c2LateralDisrupt:
		v.dstApp = app
		v.targetUID = "fixture-original"
	case *c2SupplyChainFoothold:
		v.app = app
		v.targetUID = "fixture-original"
	case *c2StealthFoothold:
		v.app = app
		v.targetUID = "fixture-original"
	case *c3AdmissionBypass:
		v.app = app
		v.targetUID = "fixture-original"
	case *c3CICD:
		v.app = app
		v.targetUID = "fixture-original"
	case *c3CryptoMining:
		v.app = app
		v.targetUID = "fixture-original"
	case *c3SidecarInject:
		v.app = app
		v.targetUID = "fixture-original"
	case *c3SupplyChain:
		v.app = app
		v.targetUID = "fixture-original"
	}
}

func TestMockCredentialObservationUsesCapturedFixtureValue(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })
	cases := []struct {
		name, app, value string
		makeScenario     func() core.Scenario
	}{
		{"c3-imds-theft", "c3imds-target", `{"Token":"` + mocks.FakeIMDSCredential + `"}`, func() core.Scenario {
			return &c3IMDSTheft{app: "c3imds-target", targetUID: "fixture-original", capturedCred: `{"Token":"` + mocks.FakeIMDSCredential + `"}`, cloud: &mocks.MockCloudAPI{MockServer: &mocks.MockServer{ClusterDNS: "mock-cloud-api-svc"}}}
		}},
		{"c3-secrets-sprawl", "c3ss-target", SprawledSecretValue, func() core.Scenario {
			return &c3SecretsSprawl{app: "c3ss-target", targetUID: "fixture-original", capturedSecret: SprawledSecretValue}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.makeScenario()
			env := fixtureObservationEnv()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			if _, err := s.SuccessOracle(ctx, env); err == nil {
				t.Fatal("absent replay Pod yielded a measured denial")
			}
			cancel()
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: tc.app, Namespace: "sandbox", UID: "fixture-replacement", Labels: map[string]string{"app": tc.app}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
			if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			calls := 0
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				calls++
				return core.ExecResult{Stdout: "", ExitCode: 17}
			})
			if _, err := s.SuccessOracle(context.Background(), env); err == nil {
				t.Fatal("lost captured file was treated as credential revocation")
			}
			if calls != 1 {
				t.Fatalf("replay re-read mutable file in %d execs", calls)
			}
			// A file changed to a different fake value before the one local use
			// cannot be attested by an authorized mock body alone.
			calls = 0
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, cmd []string) core.ExecResult {
				calls++
				if strings.Contains(cmd[2], tc.value) {
					t.Fatal("captured fake bytes entered command log")
				}
				return core.ExecResult{Stdout: fixtureReplayOutput("DIFFERENT-FAKE-FIXTURE", `{"authorized":true}`), ExitCode: 0}
			})
			if _, err := s.SuccessOracle(context.Background(), env); err == nil {
				t.Fatal("changed fake value falsely attested as captured replay")
			}
			if calls != 1 {
				t.Fatalf("changed-file replay used %d execs", calls)
			}
			calls = 0
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				calls++
				return core.ExecResult{Stdout: fixtureReplayOutput(tc.value, `{"authorized":true}`), ExitCode: 0}
			})
			got, err := s.SuccessOracle(context.Background(), env)
			if err != nil || !got.Achieved {
				t.Fatalf("same captured fake fixture authorized: achieved=%v err=%v", got.Achieved, err)
			}
			if calls != 1 {
				t.Fatalf("captured replay used %d execs", calls)
			}
			if got.Evidence["originalPodUID"] != "fixture-original" || got.Evidence["observedPodUID"] != "fixture-replacement" {
				t.Fatalf("UID provenance missing: %v", got.Evidence)
			}
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				return core.ExecResult{Stdout: fixtureReplayOutput(tc.value, `{"authorized":false}`), ExitCode: 0}
			})
			got, err = s.SuccessOracle(context.Background(), env)
			if err != nil || got.Achieved {
				t.Fatalf("measured mock denial: achieved=%v err=%v", got.Achieved, err)
			}
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				return core.ExecResult{Stdout: fixtureReplayOutput(tc.value, "truncated"), ExitCode: 0}
			})
			if _, err := s.SuccessOracle(context.Background(), env); err == nil {
				t.Fatal("malformed mock response was scored as denial")
			}

		})
	}
}

func TestObservationStimulusFailuresDoNotReachOracle(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })
	env := fixtureObservationEnv()
	for _, name := range []string{"c1lat-src", "c1lat-dst"} {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sandbox", UID: types.UID("fixture-" + name), Labels: map[string]string{"app": name}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
		if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Err: errors.New("fixture stimulus transport failed"), ExitCode: -1}
	})
	s := &c1Lateral{srcApp: "c1lat-src", dstApp: "c1lat-dst"}
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("failed lateral stimulus was accepted")
	}
	// A created privileged Pod that never reaches Running is a failed stimulus,
	// even if its creation request was accepted by the fake API.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := (&c3AdmissionBypass{app: "c3ab-priv"}).Execute(ctx, fixtureObservationEnv()); err == nil {
		t.Fatal("privileged Pod startup failure was accepted")
	}
}

func fixtureReplayOutput(value, response string) string {
	return fmt.Sprintf("%s%x\n%s", replayDigestPrefix, sha256.Sum256([]byte(value)), response)
}
