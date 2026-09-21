package safety

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	remotecommandconsts "k8s.io/apimachinery/pkg/util/remotecommand"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type streamFunc func(context.Context, remotecommand.StreamOptions) error

func (f streamFunc) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	return f(ctx, options)
}

type exitError int

func (e exitError) Error() string   { return "remote command failed" }
func (e exitError) ExitStatus() int { return int(e) }

type testExecStream struct {
	httpstream.Stream
	replySent <-chan struct{}
}

type testExecStreams struct {
	conn           io.Closer
	stdout, stderr io.WriteCloser
	writeStatus    func(*apierrors.StatusError) error
}

func upgradeExecStreams(w http.ResponseWriter, req *http.Request) (*testExecStreams, error) {
	if _, err := httpstream.Handshake(req, w, []string{remotecommandconsts.StreamProtocolV4Name}); err != nil {
		return nil, err
	}
	streamCh := make(chan testExecStream)
	conn := spdy.NewResponseUpgrader().UpgradeResponse(w, req, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		streamCh <- testExecStream{Stream: stream, replySent: replySent}
		return nil
	})
	streams := &testExecStreams{conn: conn}
	for received := 0; received < 3; received++ {
		stream := <-streamCh
		switch stream.Headers().Get(corev1.StreamType) {
		case corev1.StreamTypeError:
			streams.writeStatus = func(status *apierrors.StatusError) error {
				return json.NewEncoder(stream).Encode(status.Status())
			}
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

func realExecClient(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*rest.Config, kubernetes.Interface, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(handler))
	cfg := &rest.Config{Host: server.URL}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return cfg, kube, server.Close
}

func TestExecInPodRealSPDYDeadlineRetainsPartialOutputAndFailsTruthfully(t *testing.T) {
	wrote := make(chan struct{})
	cfg, kube, closeServer := realExecClient(t, func(w http.ResponseWriter, req *http.Request) {
		streams, err := upgradeExecStreams(w, req)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer streams.conn.Close()
		_, _ = streams.stdout.Write([]byte("partial stdout"))
		_, _ = streams.stderr.Write([]byte("partial stderr"))
		close(wrote)
		select {
		case <-req.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	defer closeServer()
	started := time.Now()
	result := ExecInPodWithTimeout(context.Background(), cfg, kube, "ns", "pod", "container", 100*time.Millisecond, []string{"producer"})
	if time.Since(started) >= time.Second {
		t.Fatalf("real SPDY deadline was not bounded: %s", time.Since(started))
	}
	select {
	case <-wrote:
	default:
		t.Fatal("SPDY server did not write partial output")
	}
	if result.Stdout != "partial stdout" || result.Stderr != "partial stderr" {
		t.Fatalf("real SPDY partial output lost: %+v", result)
	}
	if result.ExitCode == 0 || !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("real SPDY deadline reported as success: %+v", result)
	}
}

func TestExecInPodRealSPDYPreservesNormalStatus(t *testing.T) {
	cfg, kube, closeServer := realExecClient(t, func(w http.ResponseWriter, req *http.Request) {
		streams, err := upgradeExecStreams(w, req)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer streams.conn.Close()
		_, _ = streams.stdout.Write([]byte("complete"))
		if err := streams.writeStatus(&apierrors.StatusError{ErrStatus: metav1.Status{Status: metav1.StatusSuccess}}); err != nil {
			t.Errorf("status: %v", err)
		}
	})
	defer closeServer()
	result := ExecInPodWithTimeout(context.Background(), cfg, kube, "ns", "pod", "container", time.Second, []string{"producer"})
	if result.Stdout != "complete" || result.Stderr != "" || result.ExitCode != 0 || result.Err != nil {
		t.Fatalf("real SPDY success changed: %+v", result)
	}
}

func TestStreamDeadlineRetainsPartialOutputAndFailsTruthfully(t *testing.T) {
	exec := streamFunc(func(ctx context.Context, options remotecommand.StreamOptions) error {
		_, _ = options.Stdout.Write([]byte("partial stdout"))
		_, _ = options.Stderr.Write([]byte("partial stderr"))
		<-ctx.Done()
		return ctx.Err()
	})
	result := streamWithTimeout(context.Background(), exec, 10*time.Millisecond)
	if result.Stdout != "partial stdout" || result.Stderr != "partial stderr" {
		t.Fatalf("partial output lost: %+v", result)
	}
	if result.ExitCode == 0 || !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("deadline reported as success: %+v", result)
	}
}

func TestStreamUsesEarlierParentDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := streamWithTimeout(parent, streamFunc(func(ctx context.Context, _ remotecommand.StreamOptions) error {
		<-ctx.Done()
		return ctx.Err()
	}), MaxExecTimeout)
	if time.Since(started) >= time.Second || result.ExitCode == 0 || !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline did not win: elapsed=%s result=%+v", time.Since(started), result)
	}
}

func TestStreamPreservesSuccessAndRemoteExitStatus(t *testing.T) {
	success := streamWithTimeout(context.Background(), streamFunc(func(_ context.Context, options remotecommand.StreamOptions) error {
		_, _ = options.Stdout.Write([]byte("complete"))
		return nil
	}), ExecTimeout)
	if success.Stdout != "complete" || success.ExitCode != 0 || success.Err != nil {
		t.Fatalf("successful stream changed: %+v", success)
	}
	failed := streamWithTimeout(context.Background(), streamFunc(func(_ context.Context, _ remotecommand.StreamOptions) error {
		return exitError(23)
	}), ExecTimeout)
	if failed.ExitCode != 23 || failed.Err != nil {
		t.Fatalf("remote exit status changed: %+v", failed)
	}
}

func TestExplicitExecTimeoutIsFiniteAndValidatedBeforeClientUse(t *testing.T) {
	if ExecTimeout != 20*time.Second || MaxExecTimeout != 30*time.Second {
		t.Fatalf("default/max timeout=%s/%s", ExecTimeout, MaxExecTimeout)
	}
	for _, timeout := range []time.Duration{0, -time.Second, MaxExecTimeout + time.Nanosecond} {
		result := ExecInPodWithTimeout(context.Background(), nil, nil, "ns", "pod", "container", timeout, []string{"true"})
		if result.ExitCode == 0 || result.Err == nil {
			t.Fatalf("invalid timeout %s accepted: %+v", timeout, result)
		}
	}
}
