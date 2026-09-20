package scenarios

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func TestEphemeralSessionMetadataIsExplicitBenignControl(t *testing.T) {
	md := (&c2EphemeralSessionRotation{}).Metadata()
	if !md.BenignControl || md.EffectiveRealism() != core.RealismExecutable {
		t.Fatalf("classification=%+v", md)
	}
	if len(md.AttackTechniqueIDs) != 0 || len(md.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("benign control claims techniques: declared=%v exercised=%v", md.AttackTechniqueIDs, md.ExercisedTechniqueIDs)
	}
	for _, want := range []string{sessionPythonImage, "serverSourceSHA256=" + sessionServerSourceSHA256(), "20-second cancellable observation window", "zero ATT&CK", "does not establish credential revocation"} {
		if !strings.Contains(md.Mechanism+" "+md.ClaimLimits, want) {
			t.Errorf("metadata omits %q: %+v", want, md)
		}
	}
}

func TestEphemeralSessionSetupBuildsPinnedControllerOwnedCPUFixture(t *testing.T) {
	env := fixtureObservationEnv()
	env.ScenarioName = "c2-ephemeral-session-rotation"
	env.Trial = 2
	createSessionFixturePod(t, env, sessionFixturePod("controller-fixture-pod", sessionApp, "fixture", false, true))
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment).UID = "deployment-owned"
		return false, nil, nil
	})
	client.PrependReactor("create", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*corev1.Service).UID = "service-owned"
		return false, nil, nil
	})
	client.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pod := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		if pod.Name == sessionProducer {
			pod.UID = "producer-owned"
			pod.Status.Phase = corev1.PodRunning
			pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		}
		return false, nil, nil
	})
	scenario := &c2EphemeralSessionRotation{}
	if err := scenario.Setup(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if scenario.deploymentUID != "deployment-owned" || scenario.serviceUID != "service-owned" || scenario.producerUID != "producer-owned" {
		t.Fatalf("successful Create UIDs not retained: %+v", scenario)
	}
	dep, err := env.Kube.AppsV1().Deployments("sandbox").Get(context.Background(), sessionDeployment, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	template := dep.Spec.Template
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || template.Labels["app"] != sessionApp || template.Labels["r6th.io/rotation-target"] != "true" {
		t.Fatalf("deployment ownership/rotation shape=%+v", dep.Spec)
	}
	if template.Spec.AutomountServiceAccountToken == nil || *template.Spec.AutomountServiceAccountToken || len(template.Spec.Containers) != 1 {
		t.Fatalf("deployment token/container shape=%+v", template.Spec)
	}
	container := template.Spec.Containers[0]
	if container.Image != sessionPythonImage || !strings.Contains(strings.Join(container.Command, " "), sessionServerSource) {
		t.Fatalf("fixture image/source drift: image=%q command=%v", container.Image, container.Command)
	}
	for name := range container.Resources.Requests {
		if strings.Contains(string(name), "gpu") {
			t.Fatalf("fixture requested GPU resource %q", name)
		}
	}
	if container.Resources.Requests.Cpu().IsZero() || container.Resources.Requests.Memory().IsZero() || container.Resources.Limits.Cpu().IsZero() || container.Resources.Limits.Memory().IsZero() {
		t.Fatalf("fixture CPU/memory quota missing: %+v", container.Resources)
	}
	svc, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Spec.Selector["app"] != sessionApp || len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != sessionPort {
		t.Fatalf("stable Service shape=%+v", svc.Spec)
	}
	producer, err := env.Kube.CoreV1().Pods("sandbox").Get(context.Background(), sessionProducer, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if producer.Labels["r6th.io/rotation-target"] != "" || producer.Spec.AutomountServiceAccountToken == nil || *producer.Spec.AutomountServiceAccountToken || producer.Spec.Containers[0].Image != sessionPythonImage {
		t.Fatalf("producer isolation/pin drift: labels=%v spec=%+v", producer.Labels, producer.Spec)
	}
}

func TestEphemeralSessionSetupCollisionPreservesForeignResource(t *testing.T) {
	env := fixtureObservationEnv()
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: sessionService, Namespace: "sandbox", UID: "foreign-service"}}
	if _, err := env.Kube.CoreV1().Services("sandbox").Create(context.Background(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment).UID = "deployment-owned"
		return false, nil, nil
	})
	s := &c2EphemeralSessionRotation{deploymentUID: "stale-deployment", serviceUID: "stale-service", producerUID: "stale-producer"}
	if err := s.Setup(context.Background(), env); err == nil {
		t.Fatal("fixed-name Service collision was accepted")
	}
	if s.deploymentUID != "deployment-owned" || s.serviceUID != "" || s.producerUID != "" {
		t.Fatalf("setup did not reset/bind cleanup UIDs: %+v", s)
	}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	got, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
	if err != nil || got.UID != "foreign-service" {
		t.Fatalf("foreign colliding Service was deleted or replaced: service=%+v err=%v", got, err)
	}
}

func TestEphemeralSessionTeardownUsesUIDPrecondition(t *testing.T) {
	env := fixtureObservationEnv()
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: sessionService, Namespace: "sandbox", UID: "replacement-foreign"}}
	if _, err := env.Kube.CoreV1().Services("sandbox").Create(context.Background(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("delete", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		opts := action.(k8stesting.DeleteAction).GetDeleteOptions()
		if opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != "original-owned" {
			t.Fatalf("delete did not carry exact owned UID: %+v", opts)
		}
		return true, nil, errors.New("UID precondition rejected replacement")
	})
	s := &c2EphemeralSessionRotation{serviceUID: "original-owned"}
	if err := s.Teardown(context.Background(), env); err == nil {
		t.Fatal("replacement UID conflict was hidden")
	}
	got, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
	if err != nil || got.UID != "replacement-foreign" {
		t.Fatalf("replacement Service was deleted: service=%+v err=%v", got, err)
	}
}

func TestEphemeralSessionExecuteUsesActualServiceReplyAndClearsState(t *testing.T) {
	env := fixtureObservationEnv()
	env.Rand = rand.New(rand.NewSource(19))
	env.Trial = 4
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	var calls int
	var events []string
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, pod, _ string, command []string) core.ExecResult {
		calls++
		if pod != sessionProducer || len(command) < 3 || command[len(command)-3] != "POST" && command[len(command)-3] != "GET" {
			t.Fatalf("unexpected producer request: pod=%s command=%v", pod, command)
		}
		method := command[len(command)-3]
		events = append(events, method)
		id := command[len(command)-1]
		return sessionExecReply(method, 200+map[string]int{"POST": 1}[method], "original", id, true, method == "POST")
	})
	oldWait := benignSessionObservationWait
	windowStart := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	benignSessionObservationWait = func(_ context.Context, interval time.Duration) (time.Time, time.Time, error) {
		if interval != benignSessionObservationWindow {
			t.Fatalf("observation interval=%s want=%s", interval, benignSessionObservationWindow)
		}
		events = append(events, "WAIT")
		return windowStart, windowStart.Add(interval), nil
	}
	t.Cleanup(func() {
		benignSessionObservationWait = oldWait
		core.SetExecer(nil)
	})

	s := &c2EphemeralSessionRotation{originalName: "stale", originalUID: "stale", sessionID: "stale"}
	result, err := s.Execute(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || s.originalName != "original-pod" || s.originalUID != "original" || !strings.HasPrefix(s.sessionID, "session-4-") {
		t.Fatalf("state/calls not grounded: calls=%d scenario=%+v result=%+v", calls, s, result)
	}
	if strings.Join(events, ",") != "POST,GET,WAIT" {
		t.Fatalf("session establishment/window ordering=%v", events)
	}
	if result.Notes["transport"] != "ordinary HTTP via ClusterIP Service" || result.Notes["sessionID"] != s.sessionID || result.Notes["fixtureImage"] != sessionPythonImage || result.Notes["serverSourceSHA256"] != sessionServerSourceSHA256() {
		t.Fatalf("provenance=%v", result.Notes)
	}
	if result.Notes["observationWindowSeconds"] != "20" || result.Notes["observationWindowStartedAtUTC"] != windowStart.Format(time.RFC3339Nano) || result.Notes["observationWindowEndedAtUTC"] != windowStart.Add(20*time.Second).Format(time.RFC3339Nano) || result.Notes["observationWindowElapsedSeconds"] != "20.000" {
		t.Fatalf("observation timing notes=%v", result.Notes)
	}
}

func TestEphemeralSessionObservationWindowIsContextCancellableAfterEstablishment(t *testing.T) {
	env := fixtureObservationEnv()
	env.Rand = rand.New(rand.NewSource(29))
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	ctx, cancel := context.WithCancel(context.Background())
	var events []string
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
		method := command[len(command)-3]
		events = append(events, method)
		return sessionExecReply(method, 200+map[string]int{"POST": 1}[method], "original", command[len(command)-1], true, method == "POST")
	})
	oldWait := benignSessionObservationWait
	benignSessionObservationWait = func(waitCtx context.Context, interval time.Duration) (time.Time, time.Time, error) {
		events = append(events, "WAIT")
		cancel()
		return waitBenignSessionObservation(waitCtx, interval)
	}
	t.Cleanup(func() {
		cancel()
		benignSessionObservationWait = oldWait
		core.SetExecer(nil)
	})
	started := time.Now()
	_, err := (&c2EphemeralSessionRotation{}).Execute(ctx, env)
	if err == nil || !strings.Contains(err.Error(), "observation window did not complete: context canceled") {
		t.Fatalf("cancelled post-establishment window result=%v", err)
	}
	if strings.Join(events, ",") != "POST,GET,WAIT" || time.Since(started) >= time.Second {
		t.Fatalf("window cancellation was not prompt or ordered: events=%v elapsed=%s", events, time.Since(started))
	}
}

func TestEphemeralSessionExecutePreservesProducerFailure(t *testing.T) {
	env := fixtureObservationEnv()
	env.Rand = rand.New(rand.NewSource(23))
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		return core.ExecResult{Err: errors.New("fixture producer failed"), ExitCode: -1}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := &c2EphemeralSessionRotation{originalName: "stale", originalUID: "stale", sessionID: "stale"}
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("producer failure was accepted")
	}
	if s.originalName != "original-pod" || s.originalUID != "original" || s.sessionID != "" {
		t.Fatalf("failed producer retained stale/success state: %+v", s)
	}
}

func TestEphemeralSessionOracleNoDefenseRetainsSameUIDAndID(t *testing.T) {
	env := fixtureObservationEnv()
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
		return sessionExecReply("GET", 200, "original", command[len(command)-1], true, false)
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedSessionScenario()
	got, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Achieved || got.Evidence["originalUIDAbsent"] != "false" || got.Evidence["oldSessionPresent"] != "true" {
		t.Fatalf("same-identity persistence not observed: %+v", got)
	}
}

func TestEphemeralSessionOracleCreditsOnlyConfirmedReplacementLoss(t *testing.T) {
	env := fixtureObservationEnv()
	createSessionFixturePod(t, env, sessionFixturePod("replacement-pod", sessionApp, "replacement", false, true))
	var call int
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
		call++
		id := command[len(command)-1]
		switch call {
		case 1:
			return sessionExecReply("GET", 404, "replacement", id, false, false)
		case 2:
			return sessionExecReply("POST", 201, "replacement", id, true, true)
		case 3:
			return sessionExecReply("GET", 200, "replacement", id, true, false)
		default:
			t.Fatalf("unexpected request %d", call)
			return core.ExecResult{}
		}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedSessionScenario()
	got, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Achieved || call != 3 || got.Evidence["originalUIDAbsent"] != "true" || got.Evidence["newSessionRetrieved"] != "true" {
		t.Fatalf("replacement loss not fully confirmed: calls=%d result=%+v", call, got)
	}
}

func TestEphemeralSessionOracleRejectsOverlapAndObservationFailures(t *testing.T) {
	newScenario := func() *c2EphemeralSessionRotation {
		return observedSessionScenario()
	}

	t.Run("overlap with original label removed", func(t *testing.T) {
		env := fixtureObservationEnv()
		createSessionFixturePod(t, env, sessionFixturePod("replacement-pod", sessionApp, "replacement", false, true))
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", "detached", "original", false, true))
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
			return sessionExecReply("GET", 404, "replacement", command[len(command)-1], false, false)
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "overlap is ambiguous") {
			t.Fatalf("overlap was credited as mitigation: %v", err)
		}
	})

	t.Run("original terminating", func(t *testing.T) {
		env := fixtureObservationEnv()
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", true, true))
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "not ready and non-terminating") {
			t.Fatalf("terminating original was scored: %v", err)
		}
	})

	t.Run("replacement unavailable", func(t *testing.T) {
		if _, err := newScenario().SuccessOracle(context.Background(), fixtureObservationEnv()); err == nil {
			t.Fatal("absence without replacement was scored")
		}
	})

	t.Run("malformed reply", func(t *testing.T) {
		env := fixtureObservationEnv()
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
		core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
			return core.ExecResult{Stdout: "{", ExitCode: 0}
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("malformed reply was scored: %v", err)
		}
	})

	t.Run("server error", func(t *testing.T) {
		env := fixtureObservationEnv()
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
			return sessionExecReply("GET", 503, "original", command[len(command)-1], false, false)
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "unusable status 503") {
			t.Fatalf("server error was scored: %v", err)
		}
	})

	t.Run("transport timeout", func(t *testing.T) {
		env := fixtureObservationEnv()
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
		core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
			return core.ExecResult{Err: context.DeadlineExceeded, ExitCode: -1}
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
			t.Fatalf("transport timeout was scored: %v", err)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := newScenario().SuccessOracle(ctx, fixtureObservationEnv()); err == nil {
			t.Fatal("cancelled observation was scored")
		}
	})

	t.Run("required presence field integrity", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{name: "omitted", raw: `{"podUID":"original","id":"session-old"}`},
			{name: "null", raw: `{"podUID":"original","id":"session-old","present":null}`},
			{name: "duplicate", raw: `{"podUID":"original","id":"session-old","present":false,"present":true}`},
			{name: "case variant", raw: `{"podUID":"original","id":"session-old","Present":false}`},
			{name: "trailing object", raw: `{"podUID":"original","id":"session-old","present":false} {}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := fixtureObservationEnv()
				core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
					return core.ExecResult{Stdout: sessionEnvelope(404, tc.raw), ExitCode: 0}
				})
				defer core.SetExecer(nil)
				if _, err := performSessionRequest(context.Background(), env, "GET", "session-old"); err == nil {
					t.Fatalf("%s presence reply was accepted", tc.name)
				}
			})
		}
	})

	t.Run("POST requires explicit created field", func(t *testing.T) {
		env := fixtureObservationEnv()
		core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
			return core.ExecResult{Stdout: sessionEnvelope(201, `{"podUID":"original","id":"session-old","present":true}`), ExitCode: 0}
		})
		defer core.SetExecer(nil)
		if _, err := performSessionRequest(context.Background(), env, "POST", "session-old"); err == nil {
			t.Fatal("POST without explicit created field was accepted")
		}
	})

	t.Run("redirect following disabled", func(t *testing.T) {
		if !strings.Contains(sessionClientSource, "HTTPRedirectHandler") || !strings.Contains(sessionClientSource, "return None") {
			t.Fatalf("client source can follow redirects:\n%s", sessionClientSource)
		}
	})
}

func observedSessionScenario() *c2EphemeralSessionRotation {
	started := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	return &c2EphemeralSessionRotation{
		originalName:  "original-pod",
		originalUID:   "original",
		sessionID:     "session-old",
		windowStarted: started,
		windowEnded:   started.Add(benignSessionObservationWindow),
	}
}

func sessionFixturePod(name, app string, uid types.UID, terminating, ready bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sandbox", UID: uid, Labels: map[string]string{"app": app}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "session"}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: map[bool]corev1.ConditionStatus{true: corev1.ConditionTrue, false: corev1.ConditionFalse}[ready]}},
		},
	}
	if terminating {
		now := metav1.Now()
		pod.DeletionTimestamp = &now
	}
	return pod
}

func createSessionFixturePod(t *testing.T, env *core.Env, pod *corev1.Pod) {
	t.Helper()
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func sessionExecReply(method string, status int, uid, id string, present, created bool) core.ExecResult {
	raw := fmt.Sprintf(`{"podUID":%q,"id":%q,"present":%v}`, uid, id, present)
	if method == "POST" {
		raw = fmt.Sprintf(`{"podUID":%q,"id":%q,"present":%v,"created":%v}`, uid, id, present, created)
	}
	return core.ExecResult{Stdout: sessionEnvelope(status, raw), ExitCode: 0}
}

func sessionEnvelope(status int, raw string) string {
	return fmt.Sprintf("%d\n%s", status, base64.StdEncoding.EncodeToString([]byte(raw)))
}
