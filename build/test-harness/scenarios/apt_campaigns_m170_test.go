package scenarios

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestAPTCampaignInventoryAndExecutedStimulus(t *testing.T) {
	registered := allScenarios()
	for _, spec := range aptTable {
		t.Run(spec.id, func(t *testing.T) {
			scenario, ok := registered[spec.id+"-apt"]
			if !ok {
				t.Fatalf("registered campaign missing")
			}
			campaign, ok := scenario.(*aptCampaign)
			if !ok {
				t.Fatalf("registered type=%T", scenario)
			}
			campaign.app = "apt-" + spec.id
			if len(campaign.app) > 50 {
				campaign.app = campaign.app[:50]
			}
			md := campaign.Metadata()
			if md.EffectiveRealism() != core.RealismMarkerSimulation {
				t.Fatalf("realism=%q", md.EffectiveRealism())
			}
			if len(md.ExercisedTechniqueIDs) != 0 {
				t.Fatalf("marker claims exercised techniques: %v", md.ExercisedTechniqueIDs)
			}
			if len(md.CapabilityRequirements) != 0 {
				t.Fatalf("unused capability gate retained: %v", md.CapabilityRequirements)
			}
			env := fixtureObservationEnv()
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: campaign.app, Namespace: "sandbox", UID: "apt-fixture", Labels: map[string]string{"app": campaign.app}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
			if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			var commands [][]string
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, cmd []string) core.ExecResult {
				commands = append(commands, append([]string(nil), cmd...))
				return core.ExecResult{ExitCode: 0}
			})
			result, err := campaign.Execute(context.Background(), env)
			core.SetExecer(nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Stages) != 1 || strings.Contains(strings.Join(result.Stages, " "), "recon:") {
				t.Fatalf("narrative returned as stages: %v", result.Stages)
			}
			if len(commands) != 1 || !strings.Contains(strings.Join(commands[0], " "), BackdoorMarkerPath) {
				t.Fatalf("unexpected stimulus commands: %v", commands)
			}
			if err := campaign.Teardown(context.Background(), env); err != nil {
				t.Fatal(err)
			}
			actions := env.Kube.(*fake.Clientset).Actions()
			last := actions[len(actions)-1]
			if last.GetVerb() != "delete-collection" || last.GetResource().Resource != "pods" {
				t.Fatalf("teardown did not issue owned pod collection delete: %v", last)
			}
		})
	}
}

func TestAPTCampaignFailedMarkerExecCannotReuseStaleMarker(t *testing.T) {
	campaign := allScenarios()[aptTable[0].id+"-apt"].(*aptCampaign)
	campaign.app = "apt-failed-stimulus"
	env := fixtureObservationEnv()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: campaign.app, Namespace: "sandbox", UID: "stale-marker-pod", Labels: map[string]string{"app": campaign.app}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	_, _ = env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{})
	calls := 0
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		calls++
		return core.ExecResult{Stdout: BackdoorMarker, ExitCode: 19, Err: context.DeadlineExceeded}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	result, err := campaign.Execute(context.Background(), env)
	if err == nil || calls != 1 {
		t.Fatalf("failed producer was not preserved: calls=%d result=%+v err=%v", calls, result, err)
	}
}

func TestAPTCampaignOraclePositiveAndUnavailable(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })
	campaign := &aptCampaign{spec: aptTable[0], app: "apt-oracle", targetUID: "apt-original"}
	env := fixtureObservationEnv()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: campaign.app, Namespace: "sandbox", UID: campaign.targetUID, Labels: map[string]string{"app": campaign.app}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	_, _ = env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{})
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Stdout: BackdoorMarker, ExitCode: 0}
	})
	got, err := campaign.SuccessOracle(context.Background(), env)
	if err != nil || !got.Achieved || got.Evidence["realism"] != string(core.RealismMarkerSimulation) {
		t.Fatalf("positive marker: got=%+v err=%v", got, err)
	}
	_ = env.Kube.CoreV1().Pods("sandbox").Delete(context.Background(), campaign.app, metav1.DeleteOptions{})
	pod.UID = "apt-replacement"
	_, _ = env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{})
	replaced, err := campaign.SuccessOracle(context.Background(), env)
	if err != nil || replaced.Achieved {
		t.Fatalf("replacement inherited marker success: got=%+v err=%v", replaced, err)
	}
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Err: context.DeadlineExceeded, ExitCode: -1}
	})
	if _, err := campaign.SuccessOracle(context.Background(), env); err == nil {
		t.Fatal("unavailable observation was treated as a measured miss")
	}
}
