package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// voiceAgencyPodPin is one previously admitted serving container incarnation.
// A Pod name alone is never authority for an agency probe or fixture write.
type voiceAgencyPodPin struct {
	Name, UID, ContainerID, ImageID, SourceSHA256 string
	RestartCount                                  int32
}

type voiceAgencyPodGet func(context.Context, string) (*corev1.Pod, error)
type voiceAgencyPodInvoke func(context.Context, string, string, []byte) ([]byte, error)

func voiceAgencyExactPod(p *corev1.Pod, pin voiceAgencyPodPin) bool {
	if p == nil || p.Namespace != "voice" || p.Name != pin.Name || string(p.UID) != pin.UID ||
		p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
		pin.Name == "" || pin.UID == "" || pin.ContainerID == "" || pin.ImageID == "" ||
		pin.SourceSHA256 == "" || p.Annotations["phorvex.ai/voice-refund-source-sha256"] != pin.SourceSHA256 {
		return false
	}
	ready := false
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	container := 0
	for _, item := range p.Spec.Containers {
		if item.Name == "bot" {
			container++
		}
	}
	status := 0
	for _, item := range p.Status.ContainerStatuses {
		if item.Name == "bot" && item.Ready && item.RestartCount == pin.RestartCount &&
			item.ContainerID == pin.ContainerID && item.ImageID == pin.ImageID {
			status++
		}
	}
	return ready && container == 1 && status == 1
}

// The caller supplies only fixed, reviewed script bytes. The inputs travel on
// stdin, while pre/post API reads keep a name-reused or restarted Pod ambiguous.
func voiceAgencyRunExactPod(ctx context.Context, pin voiceAgencyPodPin, script string, input []byte,
	get voiceAgencyPodGet, invoke voiceAgencyPodInvoke) ([]byte, error) {
	if get == nil || invoke == nil || len(script) == 0 || len(script) > 24<<10 ||
		len(input) == 0 || len(input) > 128<<10 {
		return nil, errors.New("Voice agency probe source or input exceeds fixed bound")
	}
	before, err := get(ctx, pin.Name)
	if err != nil || !voiceAgencyExactPod(before, pin) {
		return nil, errors.New("Voice agency Pod identity changed before probe")
	}
	out, invokeErr := invoke(ctx, pin.Name, script, input)
	after, afterErr := get(ctx, pin.Name)
	if afterErr != nil || !voiceAgencyExactPod(after, pin) {
		return nil, errors.New("Voice agency Pod identity changed after ambiguous probe")
	}
	if len(out) > 64<<10 {
		return nil, errors.New("Voice agency Pod reply exceeds fixed bound")
	}
	if invokeErr != nil {
		return nil, errors.New("Voice agency Pod probe result unresolved; inspect exact run receipt")
	}
	return out, nil
}

type voiceAgencyLimitedWriter struct {
	bytes.Buffer
	limit int
	over  bool
}

func (w *voiceAgencyLimitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.Len() {
		w.over = true
		return 0, errors.New("Voice agency Pod stream exceeds bound")
	}
	return w.Buffer.Write(p)
}

// voiceAgencyPodTransport uses the console's existing scoped pods/exec grant.
// No developer SSH transport, broad cluster mutation, or credential argument
// is involved. The target's private credentials remain in the target process.
func voiceAgencyPodTransport(ctx context.Context, pin voiceAgencyPodPin, script string, input []byte) ([]byte, error) {
	config, err := restConfigFor("")
	if err != nil {
		return nil, err
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	get := func(ctx context.Context, name string) (*corev1.Pod, error) {
		return kube.CoreV1().Pods("voice").Get(ctx, name, metav1.GetOptions{})
	}
	invoke := func(ctx context.Context, name, script string, input []byte) ([]byte, error) {
		return voiceAgencySPDYExec(ctx, config, kube, name, script, input)
	}
	return voiceAgencyRunExactPod(bounded, pin, script, input, get, invoke)
}

func voiceAgencySPDYExec(ctx context.Context, config *rest.Config, kube kubernetes.Interface,
	name, script string, input []byte) ([]byte, error) {
	request := kube.CoreV1().RESTClient().Post().Resource("pods").Name(name).Namespace("voice").SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: "bot", Command: []string{"python3", "-B", "-c", script},
			Stdin: true, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, request.URL())
	if err != nil {
		return nil, err
	}
	stdout := &voiceAgencyLimitedWriter{limit: 64 << 10}
	stderr := &voiceAgencyLimitedWriter{limit: 4 << 10}
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: bytes.NewReader(input), Stdout: stdout, Stderr: stderr})
	if err != nil || stdout.over || stderr.over || stderr.Len() != 0 {
		return nil, errors.New("Voice agency Pod exec failed or produced non-receipt output")
	}
	return io.ReadAll(bytes.NewReader(stdout.Bytes()))
}
