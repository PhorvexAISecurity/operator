package scenarios

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/safety"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	remotecommandconsts "k8s.io/apimachinery/pkg/util/remotecommand"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type installedTestExecStream struct {
	httpstream.Stream
	replySent <-chan struct{}
}

type installedTestExecStreams struct {
	conn           io.Closer
	stdout, stderr io.WriteCloser
	writeStatus    func(*apierrors.StatusError) error
}

func upgradeInstalledTestExecStreams(w http.ResponseWriter, req *http.Request) (*installedTestExecStreams, error) {
	if _, err := httpstream.Handshake(req, w, []string{remotecommandconsts.StreamProtocolV4Name}); err != nil {
		return nil, err
	}
	streamCh := make(chan installedTestExecStream)
	conn := spdy.NewResponseUpgrader().UpgradeResponse(w, req, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		streamCh <- installedTestExecStream{Stream: stream, replySent: replySent}
		return nil
	})
	streams := &installedTestExecStreams{conn: conn}
	for received := 0; received < 3; received++ {
		stream := <-streamCh
		switch stream.Headers().Get(corev1.StreamType) {
		case corev1.StreamTypeError:
			streams.writeStatus = func(status *apierrors.StatusError) error { return json.NewEncoder(stream).Encode(status.Status()) }
		case corev1.StreamTypeStdout:
			streams.stdout = stream
		case corev1.StreamTypeStderr:
			streams.stderr = stream
		default:
			_ = conn.Close()
			return nil, errors.New("unexpected exec stream type")
		}
	}
	return streams, nil
}

func TestInstalledSessionActualPythonAcrossRealSPDYAndDeadline(t *testing.T) {
	application := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"podUID":"pod-live","id":"session-live","present":true}`))
	}))
	defer application.Close()

	t.Run("normal-status", func(t *testing.T) {
		env, producerUID, closeServer := installedSessionSPDYEnv(t, func(streams *installedTestExecStreams, req *http.Request) {
			time.Sleep(6 * time.Second)
			argv := req.URL.Query()["command"]
			if len(argv) != 8 || argv[0] != "python3" {
				t.Errorf("unexpected exec argv: %v", argv)
				return
			}
			command := exec.CommandContext(req.Context(), argv[0], argv[1:]...)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			_, _ = streams.stdout.Write(stdout.Bytes())
			_, _ = streams.stderr.Write(stderr.Bytes())
			if err != nil {
				t.Errorf("actual Python sampler through SPDY: %v stderr=%s", err, stderr.String())
				return
			}
			if err := streams.writeStatus(&apierrors.StatusError{ErrStatus: metav1.Status{Status: metav1.StatusSuccess}}); err != nil {
				t.Errorf("write status: %v", err)
			}
		})
		defer closeServer()
		started := time.Now()
		got, receipt, err := runInstalledSessionAvailabilitySegmentAtURL(context.Background(), env, producerUID, "session-live", application.URL, installedSessionSegment, installedSessionExecTimeout, 0)
		elapsed := time.Since(started)
		if err != nil || elapsed <= 23*time.Second || elapsed >= installedSessionExecTimeout || receipt.Status != "complete" || !receipt.AvailabilityPrefixValidated || len(got.Observations) < 30 || got.EndedAtUTC == "" || receipt.StdoutBytes == 0 || receipt.StdoutPrefixBase64 != "" {
			t.Fatalf("real 18s Python/SPDY control differs: elapsed=%s got=%+v receipt=%+v err=%v", elapsed, got, receipt, err)
		}
	})

	t.Run("deadline-partial-output", func(t *testing.T) {
		started := time.Now().UTC().Format(time.RFC3339Nano)
		header, _ := json.Marshal(map[string]any{"type": "header", "version": 1, "serviceURL": application.URL, "sessionID": "session-live", "durationMillis": 400, "cadenceMillis": 500, "startedAtUTC": started})
		observation, _ := json.Marshal(map[string]any{"type": "observation", "observation": installedSessionAvailabilityObservation{AtUTC: started, Known: false, Category: "transport-unavailable"}})
		partial := string(header) + "\n" + string(observation) + "\n"
		env, producerUID, closeServer := installedSessionSPDYEnv(t, func(streams *installedTestExecStreams, req *http.Request) {
			_, _ = streams.stdout.Write([]byte(partial))
			select {
			case <-req.Context().Done():
			case <-time.After(2 * time.Second):
			}
		})
		defer closeServer()
		got, receipt, err := runInstalledSessionAvailabilitySegmentAtURL(context.Background(), env, producerUID, "session-live", application.URL, 400*time.Millisecond, 100*time.Millisecond, 4)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) || receipt.Status != "exec-failed" || receipt.ExecErrorCategory != "deadline" || !receipt.AvailabilityPrefixValidated || len(got.Observations) != 1 || receipt.StdoutPrefixBase64 == "" || receipt.StdoutBytes != len(partial) || receipt.StdoutTruncated || !strings.Contains(receipt.ParseError, "incomplete") {
			t.Fatalf("real SPDY deadline lost partial evidence: got=%+v receipt=%+v err=%v", got, receipt, err)
		}
	})
}

func installedSessionSPDYEnv(t *testing.T, execHandler func(*installedTestExecStreams, *http.Request)) (*core.Env, types.UID, func()) {
	t.Helper()
	producerUID := types.UID("producer-live-uid")
	envTemplate := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, ScenarioName: installedSessionScenario, Trial: 0}
	pod := &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: sessionProducer, Namespace: "owned", UID: producerUID, Labels: envTemplate.OwnedLabels(map[string]string{"app": sessionProducer})},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "producer", Image: sessionPythonImage, Command: []string{"python3", "-c", "import time; time.sleep(3600)"}}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Path == "/api/v1/namespaces/owned/pods/"+sessionProducer {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pod)
			return
		}
		if req.Method == http.MethodPost && req.URL.Path == "/api/v1/namespaces/owned/pods/"+sessionProducer+"/exec" {
			streams, err := upgradeInstalledTestExecStreams(w, req)
			if err != nil {
				t.Errorf("upgrade SPDY: %v", err)
				return
			}
			defer streams.conn.Close()
			execHandler(streams, req)
			return
		}
		http.NotFound(w, req)
	}))
	cfg := &rest.Config{Host: server.URL}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	env := &core.Env{Kube: kube, Rest: cfg, Config: config.TargetConfig{Namespace: "owned"}, ScenarioName: installedSessionScenario, Trial: 0, Log: &ctLogger{}}
	core.SetTimedExecer(func(ctx context.Context, restCfg *rest.Config, kc kubernetes.Interface, ns, podName, container string, timeout time.Duration, command []string) core.ExecResult {
		result := safety.ExecInPodWithTimeout(ctx, restCfg, kc, ns, podName, container, timeout, command)
		return core.ExecResult{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode, Err: result.Err}
	})
	return env, producerUID, func() {
		core.SetTimedExecer(nil)
		server.Close()
	}
}
