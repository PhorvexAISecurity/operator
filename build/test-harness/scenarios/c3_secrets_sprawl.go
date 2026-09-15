package scenarios

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3SecretsSprawl{}) }

// SprawledSecretValue is the FAKE secret value mounted over-permissively; it is
// only ever presented to the mock sink in the same namespace.
const SprawledSecretValue = "R6TH-FAKE-SPRAWLED-SECRET-tok-7c1d"

// c3SecretsSprawl: a secret value is read from an over-permissive volume mount/env
// var in the compromised pod AND then presented to the in-namespace mock sink.
// ORACLE: the same captured fake value is presented and the fixed responder
// reports an authorized body; it does not authenticate the header.
// R6 CANNOT respond: a single in-pod read has no runtime signal Phoenix classifies;
// rotation does not un-leak an already-read secret; the over-permissive mount is
// re-created on the rotated pod.
type c3SecretsSprawl struct {
	app            string
	targetUID      types.UID
	capturedSecret string
	secret         string
}

func (s *c3SecretsSprawl) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c3-secrets-sprawl",
		Category:           core.CategoryModernUnsupported,
		Source:             "Cat3 c3-secrets-sprawl; MAESTRO L2/L6 leaked secrets",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1552.001", "T1552.007", "T1528", "T1078"},
		R6Justification:    "Reading a secret from an over-permissive mount/env is a single in-pod read with no runtime signal Phoenix's emitters classify; rotation does not un-leak an already-read value, and the over-permissive mount is re-created on the rotated pod. Cannot respond.",
	}
}

func (s *c3SecretsSprawl) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c3ss-target"
	s.secret = "c3ss-secret"
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	// Create the over-permissively-mounted FAKE secret.
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.secret, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(nil)},
		StringData: map[string]string{"token": SprawledSecretValue},
	}
	env.Log.Command(fmt.Sprintf("kubectl create secret generic %s -n %s  # FAKE sprawled secret", s.secret, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Secrets(env.Config.Namespace).Create(ctx, sec, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	// Target pod mounts the secret as a volume (the over-permissive sprawl).
	secVol := corev1.Volume{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: s.secret}}}
	secMount := corev1.VolumeMount{Name: "sec", MountPath: "/secrets", ReadOnly: true}
	pod := mocks.NewPod(env, s.app, map[string]string{"app": s.app}).
		WithBusyboxLoop("app", nil, 100, 32).
		WithVolume(secVol, secMount).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # pod with over-permissive secret mount", s.app, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	// The fixed in-namespace mock sink returns a response for the fake value.
	if _, err := mocks.DeployMockCloudAPI(ctx, env); err != nil {
		return err
	}
	return env.WaitForPodRunning(ctx, s.app, 60*time.Second)
}

func (s *c3SecretsSprawl) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.targetUID = pod.UID
	stages := []string{
		"cred-access: read the sprawled secret from the over-permissive mount (T1552.001)",
		"use: present the captured fake value to the mock sink (T1078)",
	}
	readCmd := "cat /secrets/token 2>/dev/null"
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", readCmd})
	if err := stimulusExec(ctx, res); err != nil {
		return core.AttackResult{}, err
	}
	got := strings.TrimSpace(res.Stdout) == SprawledSecretValue
	if !got {
		return core.AttackResult{}, fmt.Errorf("mock secret read missing or malformed")
	}
	s.capturedSecret = strings.TrimSpace(res.Stdout)
	env.Log.Logf("c3-secrets-sprawl: secret read from mount=%v", got)
	return core.AttackResult{Stages: stages, Commands: []string{readCmd, "present leaked secret to mock sink"}, Notes: map[string]string{"secretRead": fmt.Sprintf("%v", got)}}, nil
}

func (s *c3SecretsSprawl) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	observationPause(2 * time.Second)
	ev := map[string]string{}
	pod, err := observationTarget(ctx, env, s.app, s.targetUID)
	if err != nil {
		// Source Pod loss cannot establish fake-value revocation or denial.
		return core.OracleResult{}, fmt.Errorf("observation target unavailable: %w", err)
	}
	if s.capturedSecret == "" {
		return core.OracleResult{}, fmt.Errorf("captured mock secret unavailable")
	}
	// One local mock-only exec reads the saved fake value once and uses that same
	// shell variable for both the request and its digest evidence.
	res := env.Exec(ctx, pod.Name, firstContainer(pod), mockReplayCommand("/secrets/token", "mock-cloud-api-svc"))
	out, err := observationExec(ctx, res)
	if err != nil {
		return core.OracleResult{}, err
	}
	response, err := capturedMockReplay(out, s.capturedSecret)
	if err != nil {
		return core.OracleResult{}, err
	}
	authorized, err := mockResponderAuthorization(response)
	if err != nil {
		return core.OracleResult{}, err
	}
	ev["secretUsed"] = fmt.Sprintf("%v", authorized)
	ev["sinkResponse"] = strings.TrimSpace(response)
	ev["mockResponderChecksHeader"] = "false"
	ev["originalPodUID"] = string(s.targetUID)
	ev["observedPodUID"] = string(pod.UID)
	state := fmt.Sprintf("captured FAKE secret presented to in-namespace mock; fixed responder reported authorized=%v (header not authenticated)", authorized)
	return core.OracleResult{Achieved: authorized, ObservedState: state, Evidence: ev}, nil
}

func (s *c3SecretsSprawl) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-cloud-api")
}
