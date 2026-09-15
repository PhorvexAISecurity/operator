package scenarios

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3SidecarInject{}) }

// c3SidecarInject: an injected malicious sidecar/init container runs with the
// access it was granted. ORACLE: the sidecar reads the shared volume / SA token
// and writes proof. R6 CANNOT respond: admission-time mutation; no webhook
// actuator; a rotation re-creates the pod from its (already-poisoned) spec,
// re-injecting the sidecar.
type c3SidecarInject struct {
	app       string
	targetUID types.UID
}

const sidecarProofMarker = "R6TH-SIDECAR-READ-SHARED-VOLUME"

func (s *c3SidecarInject) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c3-sidecar-inject",
		Category:           core.CategoryModernUnsupported,
		Source:             "Cat3 c3-sidecar-inject; MAESTRO L3 priv-esc via CRDs",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1610", "T1543.005", "T1525", "T1611"},
		R6Justification:    "Injecting a malicious sidecar is an admission-time mutation; Phoenix has no mutating/validating webhook actuator and no emitter for 'unexpected container added'. Rotation re-creates the pod from its poisoned spec, re-injecting the sidecar. Cannot respond.",
	}
}

func (s *c3SidecarInject) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c3si-target"
	return nil
}

func (s *c3SidecarInject) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return core.AttackResult{}, err
	}
	// A pod with an injected malicious sidecar that reads the shared volume and
	// writes proof — the admission-time injection result, confined to the sandbox.
	shared := corev1.Volume{Name: "shared", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}
	mount := corev1.VolumeMount{Name: "shared", MountPath: "/shared"}
	app := corev1.Container{
		Name: "app", Image: mocks.BusyboxImage, ImagePullPolicy: corev1.PullIfNotPresent,
		Command:      []string{"sh", "-c", "echo legit-data > /shared/data; while true; do sleep 3600; done"},
		VolumeMounts: []corev1.VolumeMount{mount},
	}
	// The INJECTED malicious sidecar: reads the shared volume and writes proof.
	sidecar := corev1.Container{
		Name: "injected-sidecar", Image: mocks.BusyboxImage, ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{"sh", "-c",
			"sleep 2; if [ -f /shared/data ]; then echo " + sidecarProofMarker + " > /shared/proof; fi; while true; do sleep 3600; done"},
		VolumeMounts: []corev1.VolumeMount{mount},
	}
	pod := mocks.NewPod(env, s.app, map[string]string{"app": s.app}).
		WithContainer(app).
		WithContainer(sidecar).
		MutateSpec(func(spec *corev1.PodSpec) { spec.Volumes = append(spec.Volumes, shared) }).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # pod with INJECTED malicious sidecar", s.app, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return core.AttackResult{}, err
	}
	if err := env.WaitForPodRunning(ctx, s.app, 60*time.Second); err != nil {
		return core.AttackResult{}, err
	}
	original, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, fmt.Errorf("stimulus target unavailable: %w", err)
	}
	s.targetUID = original.UID
	stages := []string{"admission: pod admitted with injected sidecar (T1610)", "sidecar-exec: reads shared volume with granted access (T1525)"}
	return core.AttackResult{Stages: stages, Commands: []string{"create pod with injected-sidecar container"}}, nil
}

func (s *c3SidecarInject) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	observationPause(3 * time.Second)
	ev := map[string]string{}
	ev["originalPodUID"] = string(s.targetUID)
	pod, err := observationTarget(ctx, env, s.app, s.targetUID)
	if err != nil {
		ev["sidecarRan"] = "false"
		return core.OracleResult{}, fmt.Errorf("observation target unavailable: %w", err)
	}
	res := env.Exec(ctx, pod.Name, "app", markerReadCommand("/shared/proof"))
	ran, err := observedMarker(ctx, res, sidecarProofMarker)
	if err != nil {
		return core.OracleResult{}, err
	}
	ev["sidecarRan"] = fmt.Sprintf("%v", ran)
	ev["observedPod"] = pod.Name
	ev["observedPodUID"] = string(pod.UID)
	state := fmt.Sprintf("injected sidecar read shared volume + wrote proof=%v", ran)
	return core.OracleResult{Achieved: ran, ObservedState: state, Evidence: ev}, nil
}

func (s *c3SidecarInject) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
