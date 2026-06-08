package scenarios

import (
	"context"
	"fmt"
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
// only ever trusted by the mock sink in the same namespace.
const SprawledSecretValue = "R6TH-FAKE-SPRAWLED-SECRET-tok-7c1d"

// c3SecretsSprawl: a secret value is read from an over-permissive volume mount/env
// var in the compromised pod AND then used successfully (authenticates to the mock
// sink that trusts that secret). ORACLE: the mock sink accepts the leaked secret.
// R6 CANNOT respond: a single in-pod read has no runtime signal Phoenix classifies;
// rotation does not un-leak an already-read secret; the over-permissive mount is
// re-created on the rotated pod.
type c3SecretsSprawl struct {
	app    string
	secret string
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
	// A mock sink that trusts the sprawled secret value (the oracle endpoint).
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
	stages := []string{
		"cred-access: read the sprawled secret from the over-permissive mount (T1552.001)",
		"use: authenticate to the mock sink that trusts the secret (T1078)",
	}
	readCmd := "cat /secrets/token 2>/dev/null"
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", readCmd})
	got := strings.Contains(res.Stdout, SprawledSecretValue)
	env.Log.Logf("c3-secrets-sprawl: secret read from mount=%v", got)
	return core.AttackResult{Stages: stages, Commands: []string{readCmd, "present leaked secret to mock sink"}, Notes: map[string]string{"secretRead": fmt.Sprintf("%v", got)}}, nil
}

func (s *c3SecretsSprawl) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	time.Sleep(2 * time.Second)
	ev := map[string]string{}
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		ev["secretUsed"] = "false"
		return core.OracleResult{Achieved: false, ObservedState: "pod absent for secret replay", Evidence: ev}, nil
	}
	// Use the leaked secret against the mock sink (mock-cloud-api authorizes).
	// Retry the use against the mock sink so a transient Service-endpoint or
	// listener gap does not yield an empty body (which previously failed the
	// positive-control anchor); the mock readiness gate already confirmed it serves.
	useCmd := "TOK=$(cat /secrets/token 2>/dev/null); for i in 1 2 3 4 5; do R=$(wget -T 3 -qO- --header=\"Authorization: $TOK\" http://mock-cloud-api-svc:8082/authorize 2>/dev/null); if [ -n \"$R\" ]; then break; fi; sleep 1; done; printf '%s' \"$R\""
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", useCmd})
	authorized := strings.Contains(res.Stdout, "\"authorized\":true")
	ev["secretUsed"] = fmt.Sprintf("%v", authorized)
	ev["sinkResponse"] = strings.TrimSpace(res.Stdout)
	state := fmt.Sprintf("leaked secret read + used against mock sink authorized=%v", authorized)
	return core.OracleResult{Achieved: authorized, ObservedState: state, Evidence: ev}, nil
}

func (s *c3SecretsSprawl) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-cloud-api")
}
