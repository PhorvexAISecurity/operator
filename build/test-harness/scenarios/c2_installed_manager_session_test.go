package scenarios

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestInstalledSessionMetadataIsBoundedBenignAndSourcePinned(t *testing.T) {
	meta := (&c2InstalledManagerSession{}).Metadata()
	if !meta.BenignControl || len(meta.AttackTechniqueIDs) != 0 || len(meta.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("installed session classification claims attack coverage: %+v", meta)
	}
	for _, want := range []string{"two controller-owned CPU replicas", installedSessionWindow.String(), sessionPythonImage, sessionServerSourceSHA256(), installedSessionAvailabilitySourceSHA256(), "zero ATT&CK/security efficacy"} {
		if !containsInstalled(meta.Mechanism+" "+meta.ClaimLimits, want) {
			t.Errorf("installed session metadata omits %q", want)
		}
	}
}

func TestInstalledSessionActualSamplingLoopRetainsFailuresAfterSixteenAttempts(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		if call%3 == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"warming"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if call%5 == 0 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"podUID":"pod-live","id":"session-live","present":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"podUID":"pod-live","id":"session-live","present":true}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "-c", installedSessionAvailabilitySource, server.URL, "session-live", "2.000", "0.100")
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("actual availability producer: %v", err)
	}
	var receipt installedSessionAvailability
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatalf("decode actual producer receipt: %v\n%s", err, raw)
	}
	if len(receipt.Observations) <= 16 {
		t.Fatalf("actual loop retained %d attempts, want >16", len(receipt.Observations))
	}
	known, unknown := installedAvailabilityCounts(receipt)
	if known == 0 || unknown == 0 || known+unknown != len(receipt.Observations) {
		t.Fatalf("actual loop did not retain both successes and failures: known=%d unknown=%d total=%d", known, unknown, len(receipt.Observations))
	}
	previous := time.Time{}
	knownNotFound := 0
	for i, observation := range receipt.Observations {
		at, parseErr := time.Parse(time.RFC3339Nano, observation.AtUTC)
		if parseErr != nil || !previous.IsZero() && at.Before(previous) {
			t.Fatalf("observation %d timestamp invalid: %q", i, observation.AtUTC)
		}
		previous = at
		if observation.Known && (observation.Category != "application-response" || observation.HTTPStatus != 200 && observation.HTTPStatus != 404 || observation.PodUID != "pod-live") {
			t.Fatalf("known observation %d invalid: %+v", i, observation)
		}
		if observation.Known && observation.HTTPStatus == 404 {
			knownNotFound++
		}
		if !observation.Known && observation.Category != "invalid-response" {
			t.Fatalf("failed observation %d was not retained as typed unknown: %+v", i, observation)
		}
	}
	if knownNotFound == 0 {
		t.Fatal("ordinary HTTP 404 application response was not retained distinctly from transport failure")
	}
}

func TestInstalledSessionWarmupRequiresSameReadyTargetToReachAntiOverAge(t *testing.T) {
	env := fixtureObservationEnv()
	old := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target-old", Namespace: env.Config.Namespace, UID: "target-old-uid", ResourceVersion: "10", CreationTimestamp: metav1.NewTime(time.Now().Add(-installedSessionMinimumPodAge - time.Second)), Labels: map[string]string{installedSessionTargetRoute: "trial-0"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(context.Background(), old, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	got, readyAt, err := waitInstalledSessionTargetAge(context.Background(), env, old.Name, old.UID, installedSessionMinimumPodAge, time.Second)
	if err != nil || got.UID != old.UID || readyAt.Before(old.CreationTimestamp.Time.Add(installedSessionMinimumPodAge)) {
		t.Fatalf("aged exact target refused: pod=%+v readyAt=%v err=%v", got, readyAt, err)
	}

	fresh := old.DeepCopy()
	fresh.Name, fresh.UID, fresh.ResourceVersion, fresh.CreationTimestamp = "target-fresh", "target-fresh-uid", "11", metav1.Now()
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(context.Background(), fresh, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, err := waitInstalledSessionTargetAge(ctx, env, fresh.Name, fresh.UID, installedSessionMinimumPodAge, time.Second); err == nil {
		t.Fatal("fresh target bypassed the configured anti-over-rotation age")
	}
	fresh.Labels[defenders.RotationTargetLabel] = "true"
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Update(context.Background(), fresh, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := waitInstalledSessionTargetAge(context.Background(), env, fresh.Name, fresh.UID, 0, time.Second); err == nil {
		t.Fatal("preselected target accepted during warmup")
	}
}

func TestInstalledSessionBenchmarkEvidenceRetainsEveryTypedAttempt(t *testing.T) {
	created := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	s := &c2InstalledManagerSession{
		deploymentUID: "deployment", pdbUID: "pdb", pdbRV: "pdb-rv", replicaSetUID: "replicaset", originalUID: "original", peerUID: "peer", originalCreatedAt: created.Format(time.RFC3339Nano), originalAgeReadyAt: created.Add(installedSessionMinimumPodAge).Format(time.RFC3339Nano),
		availability: installedSessionAvailability{SegmentCount: 1, StartedAtUTC: created.Add(2 * time.Minute).Format(time.RFC3339Nano), EndedAtUTC: created.Add(2*time.Minute + 10*time.Second).Format(time.RFC3339Nano)},
		effectStatus: "original-state-retained",
	}
	for i := 0; i < 20; i++ {
		known := i%4 != 0
		observation := installedSessionAvailabilityObservation{AtUTC: created.Add(2*time.Minute + time.Duration(i)*100*time.Millisecond).Format(time.RFC3339Nano), Known: known, Category: "transport-unavailable"}
		if known {
			observation.Category, observation.HTTPStatus, observation.PodUID = "application-response", 200, "peer"
		}
		s.availability.Observations = append(s.availability.Observations, observation)
	}
	if err := s.updateInstalledSessionBenchmarkEvidence("oracle-complete", "original-state-retained", true, "", "original", ""); err != nil {
		t.Fatal(err)
	}
	if s.benchmarkEvidence["availability.attempts"] != "20" || s.benchmarkEvidence["availability.known"] != "15" || s.benchmarkEvidence["availability.unknown"] != "5" {
		t.Fatalf("evidence counts differ: attempts=%s known=%s unknown=%s", s.benchmarkEvidence["availability.attempts"], s.benchmarkEvidence["availability.known"], s.benchmarkEvidence["availability.unknown"])
	}
	for i := 0; i < 20; i++ {
		if s.benchmarkEvidence["availability.observation."+leftPadInstalled(i)] == "" {
			t.Fatalf("attempt %d was not retained", i)
		}
	}
}

func leftPadInstalled(value int) string {
	if value < 10 {
		return "00" + strconv.Itoa(value)
	}
	if value < 100 {
		return "0" + strconv.Itoa(value)
	}
	return strconv.Itoa(value)
}

func containsInstalled(value, want string) bool {
	for i := 0; i+len(want) <= len(value); i++ {
		if value[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
