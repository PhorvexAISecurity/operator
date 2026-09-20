package scenarios

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func TestC2DwellRotationMetadataIsMarkerOnly(t *testing.T) {
	md := (&c2DwellRotation{}).Metadata()
	if md.EffectiveRealism() != core.RealismMarkerSimulation {
		t.Fatalf("realism=%q", md.EffectiveRealism())
	}
	if len(md.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("marker simulation claims exercised techniques: %v", md.ExercisedTechniqueIDs)
	}
	for name, value := range map[string]string{
		"mechanism": md.Mechanism,
		"limits":    md.ClaimLimits,
		"oracle":    md.OracleDescription,
		"cleanup":   md.CleanupDescription,
	} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("%s is empty", name)
		}
	}
	for _, forbidden := range []string{"execute an exploit", "runc overwrite", "no technique is credited as exercised"} {
		if !strings.Contains(md.ClaimLimits, forbidden) {
			t.Errorf("claim limits omit %q: %q", forbidden, md.ClaimLimits)
		}
	}
}

func TestC2DwellRotationExecutePreservesStimulusFailure(t *testing.T) {
	env := fixtureObservationEnv()
	pod := dwellFixturePod("c2dr-target", "original")
	if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Err: errors.New("fixture exec transport failed"), ExitCode: -1}
	})
	t.Cleanup(func() { core.SetExecer(nil) })

	s := &c2DwellRotation{app: "c2dr-target", targetUID: "stale", plantedAt: time.Now().Add(-time.Hour)}
	result, err := s.Execute(context.Background(), env)
	if err == nil {
		t.Fatalf("failed marker producer accepted: %+v", result)
	}
	if s.targetUID != "original" {
		t.Fatalf("selected Pod UID not retained: %q", s.targetUID)
	}
	if !s.plantedAt.IsZero() {
		t.Fatalf("failed stimulus recorded a start time: %s", s.plantedAt)
	}
}

func TestC2DwellRotationExecuteClearsProvenanceBeforeLookup(t *testing.T) {
	env := fixtureObservationEnv()
	s := &c2DwellRotation{app: "c2dr-target", targetUID: "stale", plantedAt: time.Now().Add(-time.Hour)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.Execute(ctx, env); err == nil {
		t.Fatal("missing target was accepted")
	}
	if s.targetUID != "" || !s.plantedAt.IsZero() {
		t.Fatalf("failed lookup retained prior provenance: uid=%q plantedAt=%s", s.targetUID, s.plantedAt)
	}
}

func TestC2DwellRotationExecuteRecordsUIDAndPreciseClock(t *testing.T) {
	env := fixtureObservationEnv()
	pod := dwellFixturePod("c2dr-target", "original")
	if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Stdout: "backdoor-pid=17", ExitCode: 0}
	})
	t.Cleanup(func() { core.SetExecer(nil) })

	s := &c2DwellRotation{app: "c2dr-target"}
	result, err := s.Execute(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if s.targetUID != "original" || s.plantedAt.IsZero() {
		t.Fatalf("stimulus provenance missing: uid=%q plantedAt=%s", s.targetUID, s.plantedAt)
	}
	if result.Notes["originalPodUID"] != "original" || result.Notes["plantedAt"] != s.plantedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("reported provenance=%v", result.Notes)
	}
	if stages := strings.Join(result.Stages, " "); strings.Contains(stages, "T1543") || strings.Contains(strings.ToLower(stages), "exploit") {
		t.Fatalf("marker stages claim a technique or exploit: %q", stages)
	}
}

func TestC2DwellRotationOracleBindsUIDAndMarker(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })

	tests := []struct {
		name         string
		originalUID  types.UID
		observedUID  types.UID
		output       string
		wantAchieved bool
		wantMarker   string
		wantIdentity string
		wantAbsent   string
	}{
		{name: "original marker survives", originalUID: "original", observedUID: "original", output: BackdoorMarker, wantAchieved: true, wantMarker: "true", wantIdentity: "true", wantAbsent: "false"},
		{name: "original marker absent", originalUID: "original", observedUID: "original", output: observationAbsent, wantMarker: "false", wantIdentity: "true", wantAbsent: "false"},
		{name: "fresh replacement has no marker", originalUID: "original", observedUID: "replacement", output: observationAbsent, wantMarker: "false", wantIdentity: "false", wantAbsent: "true"},
		{name: "replacement marker is not original state", originalUID: "original", observedUID: "replacement", output: BackdoorMarker, wantMarker: "true", wantIdentity: "false", wantAbsent: "true"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := fixtureObservationEnv()
			if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), dwellFixturePod("c2dr-target", tc.observedUID), metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
				return core.ExecResult{Stdout: tc.output, ExitCode: 0}
			})
			s := &c2DwellRotation{app: "c2dr-target", targetUID: tc.originalUID, plantedAt: time.Now().Add(-9 * time.Second)}
			got, err := s.SuccessOracle(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if got.Achieved != tc.wantAchieved {
				t.Fatalf("achieved=%v, want %v; evidence=%v", got.Achieved, tc.wantAchieved, got.Evidence)
			}
			if got.Evidence["markerPresent"] != tc.wantMarker || got.Evidence["originalIdentity"] != tc.wantIdentity {
				t.Fatalf("marker/identity evidence=%v", got.Evidence)
			}
			if got.Evidence["originalUIDAbsent"] != tc.wantAbsent {
				t.Fatalf("original-absence evidence=%v", got.Evidence)
			}
			if got.Evidence["originalPodUID"] != string(tc.originalUID) || got.Evidence["observedPodUID"] != string(tc.observedUID) {
				t.Fatalf("UID evidence=%v", got.Evidence)
			}
		})
	}
}

func TestC2DwellRotationOraclePrefersOriginalDuringOverlap(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })

	tests := []struct {
		name        string
		terminating bool
	}{
		{name: "original running"},
		{name: "original terminating", terminating: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := fixtureObservationEnv()
			// Create the replacement first to ensure list order cannot select it.
			if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), dwellFixturePodNamed("replacement-pod", "c2dr-target", "replacement", false), metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), dwellFixturePodNamed("original-pod", "c2dr-target", "original", tc.terminating), metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			observedPod := ""
			core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, pod, _ string, _ []string) core.ExecResult {
				observedPod = pod
				return core.ExecResult{Stdout: BackdoorMarker, ExitCode: 0}
			})
			s := &c2DwellRotation{app: "c2dr-target", targetUID: "original", plantedAt: time.Now().Add(-9 * time.Second)}
			got, err := s.SuccessOracle(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Achieved || observedPod != "original-pod" {
				t.Fatalf("overlap selected %q: achieved=%v evidence=%v", observedPod, got.Achieved, got.Evidence)
			}
			if got.Evidence["originalUIDAbsent"] != "false" || got.Evidence["observedPodUID"] != "original" {
				t.Fatalf("overlap identity evidence=%v", got.Evidence)
			}
		})
	}
}

func TestC2DwellRotationOracleRejectsObservationLoss(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })

	newScenario := func() *c2DwellRotation {
		return &c2DwellRotation{app: "c2dr-target", targetUID: "original", plantedAt: time.Now()}
	}

	t.Run("missing stimulus provenance", func(t *testing.T) {
		if _, err := (&c2DwellRotation{app: "c2dr-target"}).SuccessOracle(context.Background(), fixtureObservationEnv()); err == nil {
			t.Fatal("missing stimulus provenance was scored")
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := newScenario().SuccessOracle(ctx, fixtureObservationEnv()); err == nil {
			t.Fatal("cancelled observation was scored")
		}
	})

	t.Run("pod lookup failure", func(t *testing.T) {
		env := fixtureObservationEnv()
		env.Kube.(*k8sfake.Clientset).PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("fixture pod lookup failed")
		})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := newScenario().SuccessOracle(ctx, env); err == nil {
			t.Fatal("failed Pod lookup was scored as mitigation")
		}
	})

	t.Run("original absent without observable replacement", func(t *testing.T) {
		if _, err := newScenario().SuccessOracle(context.Background(), fixtureObservationEnv()); err == nil {
			t.Fatal("Pod disappearance without an observable replacement was scored as mitigation")
		}
	})

	t.Run("exec failure", func(t *testing.T) {
		env := fixtureObservationEnv()
		if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), dwellFixturePod("c2dr-target", "original"), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
			return core.ExecResult{Err: errors.New("fixture observation failed"), ExitCode: -1}
		})
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil {
			t.Fatal("failed marker observation was scored as mitigation")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		env := fixtureObservationEnv()
		if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), dwellFixturePod("c2dr-target", "original"), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
			return core.ExecResult{Stdout: "truncated", ExitCode: 0}
		})
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil {
			t.Fatal("malformed marker observation was scored as mitigation")
		}
	})
}

func dwellFixturePod(app string, uid types.UID) *corev1.Pod {
	return dwellFixturePodNamed(app, app, uid, false)
}

func dwellFixturePodNamed(name, app string, uid types.UID, terminating bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sandbox", UID: uid, Labels: map[string]string{"app": app}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if terminating {
		now := metav1.Now()
		pod.DeletionTimestamp = &now
	}
	return pod
}
