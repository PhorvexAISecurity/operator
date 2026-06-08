package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3AdmissionBypass{}) }

// c3AdmissionBypass: a deliberately policy-violating pod (privileged) is admitted
// and reaches Running, and its violating capability is exercised. ORACLE: the
// privileged pod runs AND a marker is written from the privileged context. R6
// CANNOT respond: Phoenix is not an admission controller; a policy-violating pod
// that is admitted simply runs, and rotation would re-admit it.
//
// CONTAINMENT: the privileged pod is created ONLY in the sandbox namespace, does
// NOT mount the host root, and only exercises a privileged-context marker.
type c3AdmissionBypass struct{ app string }

func (s *c3AdmissionBypass) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c3-admission-bypass",
		Category:           core.CategoryModernUnsupported,
		Source:             "Cat3 c3-admission-bypass; MAESTRO L3 protect admission controllers",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1610", "T1611", "T1068", "T1078.001"},
		R6Justification:    "Phoenix is not an admission controller and emits/consumes nothing at admission; a policy-violating pod that is admitted simply runs, and rotation re-admits it. No matcher path applies. Cannot respond.",
	}
}

func (s *c3AdmissionBypass) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c3ab-priv"
	return nil
}

func (s *c3AdmissionBypass) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return core.AttackResult{}, err
	}
	priv := true
	c := corev1.Container{
		Name: "app", Image: mocks.BusyboxImage, ImagePullPolicy: corev1.PullIfNotPresent,
		// Exercise the privileged context: report that we are running privileged.
		Command: []string{"sh", "-c",
			"id > /tmp/.r6th_priv 2>&1; echo PRIVILEGED-CONTEXT-RAN >> /tmp/.r6th_priv; while true; do sleep 3600; done"},
		SecurityContext: &corev1.SecurityContext{Privileged: &priv},
	}
	pod := mocks.NewPod(env, s.app, map[string]string{"app": s.app}).
		WithContainer(c).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s --privileged  # policy-violating pod (sandbox only)", s.app, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return core.AttackResult{}, err
	}
	admitted := true
	if err := env.WaitForPodRunning(ctx, s.app, 60*time.Second); err != nil {
		admitted = false
		env.Log.Logf("c3-admission-bypass: privileged pod did not reach Running: %v", err)
	}
	stages := []string{"admission: privileged/policy-violating pod admitted (T1610)", "exercise: run from the privileged context (T1611/T1068)"}
	return core.AttackResult{Stages: stages, Commands: []string{"create privileged pod (sandbox)"}, Notes: map[string]string{"admitted": fmt.Sprintf("%v", admitted)}}, nil
}

func (s *c3AdmissionBypass) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	time.Sleep(2 * time.Second)
	ev := map[string]string{}
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		ev["privilegedRan"] = "false"
		return core.OracleResult{Achieved: false, ObservedState: "privileged pod absent", Evidence: ev}, nil
	}
	res := env.Exec(ctx, pod.Name, "app", []string{"sh", "-c", "cat /tmp/.r6th_priv 2>/dev/null"})
	ran := strings.Contains(res.Stdout, "PRIVILEGED-CONTEXT-RAN")
	ev["privilegedRan"] = fmt.Sprintf("%v", ran)
	ev["idOutput"] = strings.TrimSpace(res.Stdout)
	state := fmt.Sprintf("policy-violating pod admitted+Running and exercised privileged context=%v", ran)
	return core.OracleResult{Achieved: ran, ObservedState: state, Evidence: ev}, nil
}

func (s *c3AdmissionBypass) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
