package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "-c", installedSessionAvailabilitySource, server.URL, "session-live", "9.200", "0.500")
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("actual availability producer: %v", err)
	}
	receipt, err := parseInstalledSessionAvailability(raw, server.URL, "session-live", 9200*time.Millisecond)
	if err != nil {
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

func TestInstalledSessionActualSamplerBoundsResolverAndSlowResponse(t *testing.T) {
	validServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"podUID":"pod-live","id":"session-live","present":true}`))
	}))
	defer validServer.Close()

	t.Run("resolver", func(t *testing.T) {
		const delayedResolver = `import socket,time
_installed_real_getaddrinfo=socket.getaddrinfo
def _installed_slow_getaddrinfo(*args,**kwargs):
    time.sleep(2)
    return _installed_real_getaddrinfo(*args,**kwargs)
socket.getaddrinfo=_installed_slow_getaddrinfo
`
		receipt, elapsed := runInstalledSessionPython(t, delayedResolver+installedSessionAvailabilitySource, validServer.URL, 400*time.Millisecond)
		if elapsed >= 1500*time.Millisecond || len(receipt.Observations) != 1 || receipt.Observations[0].Known || receipt.Observations[0].Category != "sampling-deadline" {
			t.Fatalf("resolver was not bounded and retained: elapsed=%s receipt=%+v", elapsed, receipt)
		}
	})

	t.Run("slow-response", func(t *testing.T) {
		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			select {
			case <-request.Context().Done():
			case <-time.After(2 * time.Second):
				_, _ = w.Write([]byte(`{"podUID":"pod-live","id":"session-live","present":true}`))
			}
		}))
		defer slowServer.Close()
		receipt, elapsed := runInstalledSessionPython(t, installedSessionAvailabilitySource, slowServer.URL, 400*time.Millisecond)
		if elapsed >= 1500*time.Millisecond || len(receipt.Observations) != 1 || receipt.Observations[0].Known || receipt.Observations[0].Category != "sampling-deadline" {
			t.Fatalf("slow response was not bounded and retained: elapsed=%s receipt=%+v", elapsed, receipt)
		}
	})
}

func TestInstalledSessionPartialStreamRetainsOnlyValidatedPrefix(t *testing.T) {
	started := time.Now().UTC().Format(time.RFC3339Nano)
	header, _ := json.Marshal(map[string]any{"type": "header", "version": 1, "serviceURL": "http://service", "sessionID": "session-live", "durationMillis": 1000, "cadenceMillis": 500, "startedAtUTC": started})
	observation, _ := json.Marshal(map[string]any{"type": "observation", "observation": installedSessionAvailabilityObservation{AtUTC: started, Known: false, Category: "transport-unavailable"}})
	raw := append(append(append([]byte{}, header...), '\n'), observation...)
	raw = append(raw, '\n')
	raw = append(raw, []byte(`{"type":"observation","observation":`)...)
	receipt, err := parseInstalledSessionAvailability(raw, "http://service", "session-live", time.Second)
	if err == nil || len(receipt.Observations) != 1 || !installedSessionAvailabilityPrefixValid(receipt, "http://service", "session-live", time.Second) {
		t.Fatalf("validated partial prefix lost or accepted as complete: receipt=%+v err=%v", receipt, err)
	}
	segment := installedSessionSegmentReceipt{Segment: 2, Status: "exec-failed", Availability: receipt, AvailabilityPrefixValidated: true, StdoutBytes: len(raw), StdoutSHA256: "full-hash", ExitCode: -1, ExecErrorCategory: "deadline", ParseError: err.Error()}
	installedSessionRetainFailureBytes(&segment, string(raw), "bounded diagnostic")
	encoded := marshalInstalledSessionSegmentReceipts([]installedSessionSegmentReceipt{segment})
	if !json.Valid([]byte(encoded)) || segment.StdoutPrefixBytes != len(raw) || segment.StdoutTruncated || segment.StdoutPrefixBase64 == "" || segment.StderrPrefixBase64 == "" {
		t.Fatalf("partial bytes were not reconstructably retained: segment=%+v encoded=%s", segment, encoded)
	}
}

func TestInstalledSessionFailedSegmentIsRetainedButNotTrustedByAggregate(t *testing.T) {
	env := fixtureObservationEnv()
	env.ScenarioName, env.Trial = installedSessionScenario, 0
	producer := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: sessionProducer, Namespace: env.Config.Namespace, UID: "producer-live-uid", Labels: env.OwnedLabels(map[string]string{"app": sessionProducer})},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "producer", Image: sessionPythonImage, Command: []string{"python3", "-c", "import time; time.sleep(3600)"}}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(context.Background(), producer, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	serviceURL := "http://" + installedSessionSharedService + ":" + strconv.Itoa(sessionPort)
	started := time.Now().UTC().Format(time.RFC3339Nano)
	header, _ := json.Marshal(map[string]any{"type": "header", "version": 1, "serviceURL": serviceURL, "sessionID": "session-live", "durationMillis": int(installedSessionSegment.Milliseconds()), "cadenceMillis": int(installedSessionSamplePeriod.Milliseconds()), "startedAtUTC": started})
	observation, _ := json.Marshal(map[string]any{"type": "observation", "observation": installedSessionAvailabilityObservation{AtUTC: started, Known: false, Category: "request-deadline"}})
	partial := string(header) + "\n" + string(observation) + "\n"
	core.SetTimedExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, time.Duration, []string) core.ExecResult {
		return core.ExecResult{Stdout: partial, Stderr: "bounded producer diagnostic", ExitCode: -1, Err: context.DeadlineExceeded}
	})
	t.Cleanup(func() { core.SetTimedExecer(nil) })
	aggregate, retained, err := runInstalledSessionAvailability(context.Background(), env, producer.UID, "session-live")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || len(aggregate.Observations) != 0 || aggregate.StartedAtUTC != "" || !json.Valid([]byte(retained)) {
		t.Fatalf("failed prefix became trusted aggregate evidence: aggregate=%+v retained=%s err=%v", aggregate, retained, err)
	}
	var evidence struct {
		SchemaVersion string                           `json:"schemaVersion"`
		Segments      []installedSessionSegmentReceipt `json:"segments"`
	}
	if err := json.Unmarshal([]byte(retained), &evidence); err != nil || evidence.SchemaVersion != "phorvex.installed-session-availability.v2" || len(evidence.Segments) != 1 {
		t.Fatalf("decode failed segment evidence: evidence=%+v err=%v", evidence, err)
	}
	segment := evidence.Segments[0]
	decoded, decodeErr := base64.StdEncoding.DecodeString(segment.StdoutPrefixBase64)
	if decodeErr != nil || string(decoded) != partial || segment.Status != "exec-failed" || !segment.AvailabilityPrefixValidated || len(segment.Availability.Observations) != 1 || segment.StderrPrefixBase64 == "" || segment.ExecErrorCategory != "deadline" {
		t.Fatalf("failed segment evidence incomplete: segment=%+v decodeErr=%v", segment, decodeErr)
	}
}

func TestInstalledSessionFailureByteRetentionIsExplicitlyCapped(t *testing.T) {
	stdout, stderr := strings.Repeat("o", installedSessionStdoutPrefixMax+17), strings.Repeat("e", installedSessionStderrPrefixMax+19)
	segment := installedSessionSegmentReceipt{StdoutBytes: len(stdout), StderrBytes: len(stderr), StdoutSHA256: "stdout-full-hash", StderrSHA256: "stderr-full-hash"}
	installedSessionRetainFailureBytes(&segment, stdout, stderr)
	stdoutPrefix, stdoutErr := base64.StdEncoding.DecodeString(segment.StdoutPrefixBase64)
	stderrPrefix, stderrErr := base64.StdEncoding.DecodeString(segment.StderrPrefixBase64)
	if stdoutErr != nil || stderrErr != nil || len(stdoutPrefix) != installedSessionStdoutPrefixMax || len(stderrPrefix) != installedSessionStderrPrefixMax || !segment.StdoutTruncated || !segment.StderrTruncated || segment.StdoutBytes != len(stdout) || segment.StderrBytes != len(stderr) || segment.StdoutSHA256 != "stdout-full-hash" || segment.StderrSHA256 != "stderr-full-hash" {
		t.Fatalf("failure byte cap/hash contract differs: segment=%+v stdoutErr=%v stderrErr=%v", segment, stdoutErr, stderrErr)
	}
}

func runInstalledSessionPython(t *testing.T, source, baseURL string, duration time.Duration) (installedSessionAvailability, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	command := exec.CommandContext(ctx, "python3", "-B", "-c", source, baseURL, "session-live", strconv.FormatFloat(duration.Seconds(), 'f', 3, 64), strconv.FormatFloat(installedSessionSamplePeriod.Seconds(), 'f', 3, 64))
	raw, err := command.Output()
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("actual bounded sampler: elapsed=%s err=%v", elapsed, err)
	}
	receipt, err := parseInstalledSessionAvailability(raw, baseURL, "session-live", duration)
	if err != nil {
		t.Fatalf("decode bounded sampler: elapsed=%s err=%v raw=%s", elapsed, err, raw)
	}
	return receipt, elapsed
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
