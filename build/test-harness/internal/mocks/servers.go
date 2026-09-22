package mocks

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// MockServer describes an in-cluster HTTP stand-in (IMDS / C2 sink / registry /
// pipeline). All are tiny busybox httpd-or-netcat servers, so no custom image is
// pulled. Each is a Pod + a ClusterIP Service in the sandbox namespace.
type MockServer struct {
	Name    string
	PodName string
	SvcName string
	Port    int32
	// ClusterDNS is the in-namespace DNS the attacker pod dials.
	ClusterDNS string
}

// httpdScript builds a busybox `httpd`-free tiny HTTP responder using a netcat
// loop. It answers EVERY request with a fixed body + 200, and (for the C2 sink)
// appends the request body length to a counter file. Kept deliberately minimal
// and CPU-cheap.
//
// We use a `while true | nc -lp` loop: busybox nc serves one connection per
// accept; the outer loop re-listens. The response is a valid minimal HTTP/1.0
// reply so curl/wget clients are satisfied.
func httpResponderScript(body string) string {
	// printf INTERPRETS backslash escapes in its FORMAT string, so the \r\n in
	// `format` become real CRLF on the wire; the body is passed as a %s ARGUMENT so
	// its bytes are emitted verbatim and answer EVERY path (catch-all, as IMDS
	// needs). A prior version pre-escaped the whole reply and fed it through
	// `printf '%s'`, which emitted LITERAL "\r\n" text — an HTTP reply no client
	// could parse, so wget read 0 bytes and the c3-imds-theft / c3-secrets-sprawl
	// positive-control anchors failed. The CRLF-correct form is verified serving on
	// busybox:1.36 (incl. arbitrary paths). -w 30 keeps the listener bound across
	// the short trial window; WaitHTTPReady still confirms readiness actively.
	format := fmt.Sprintf(`HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%%s`, len(body))
	return fmt.Sprintf(`while true; do printf '%s' %s | nc -l -p $PORT -w 30 2>/dev/null || sleep 1; done`, format, shQuote(body))
}

// c2SinkScript is the exfil sink: it accepts a connection, drains the request to
// a per-connection temp file, appends its byte count to /tmp/bytes, and replies
// 200 with the running total. The cumulative byte counter is the exfil oracle.
func c2SinkScript() string {
	return `: > /tmp/bytes_total; ` +
		`while true; do ` +
		`req=$(nc -l -p $PORT -w 2 2>/dev/null | wc -c); ` +
		`prev=$(cat /tmp/bytes_total 2>/dev/null || echo 0); ` +
		`echo $((prev + req)) > /tmp/bytes_total; ` +
		`done`
}

// shQuote single-quotes s for POSIX sh, escaping any embedded single quotes, so a
// JSON/body argument reaches printf as one literal word regardless of its content.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// deployServer creates the Pod+Service for a mock server and waits for Running.
func deployServer(ctx context.Context, env *core.Env, name string, port int32, script string, extraLabels map[string]string) (*MockServer, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	podName := name + "-pod"
	svcName := name + "-svc"
	labels := LabelMap(map[string]string{"app": name}, extraLabels)

	container := corev1.Container{
		Name:            "server",
		Image:           BusyboxImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", script},
		Env:             []corev1.EnvVar{{Name: "PORT", Value: fmt.Sprintf("%d", port)}},
		Ports:           []corev1.ContainerPort{{ContainerPort: port}},
	}
	pb := NewPod(env, podName, LabelMap(labels, map[string]string{"r6th.io/role": "mock"})).
		WithContainer(container).
		WithRestartPolicy(corev1.RestartPolicyAlways)
	pod := pb.Build()

	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # mock %s :%d", podName, BusyboxImage, env.Config.Namespace, name, port))
	createdPod, err := createOwnedPod(ctx, env, pod)
	if err != nil {
		return nil, fmt.Errorf("create mock pod %s: %w", podName, err)
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: env.Config.Namespace,
			Labels:    env.OwnedLabels(labels),
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": name, core.OwnedLabelKey: core.OwnedLabelValue},
			Ports: []corev1.ServicePort{{
				Port:       port,
				TargetPort: intstr.FromInt32(port),
			}},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl expose pod %s --name=%s --port=%d -n %s", podName, svcName, port, env.Config.Namespace))
	if _, err := createOwnedService(ctx, env, svc); err != nil {
		return nil, fmt.Errorf("create mock svc %s: %w", svcName, err)
	}

	ms := &MockServer{
		Name:       name,
		PodName:    podName,
		SvcName:    svcName,
		Port:       port,
		ClusterDNS: fmt.Sprintf("%s.%s.svc.cluster.local", svcName, env.Config.Namespace),
	}
	if err := env.WaitForPodRunning(ctx, podName, waitTimeout); err != nil {
		// Not fatal for the harness contract — return the server; the scenario will
		// surface a dial failure in its oracle. But log it.
		env.Log.Logf("mock %s pod not Ready in time: %v", name, err)
	}
	if err := requireCreatedPodCurrent(ctx, env, podName, createdPod); err != nil {
		return nil, err
	}
	return ms, nil
}

// httpReadyTimeout bounds how long WaitHTTPReady polls for the in-pod responder to
// actually serve (distinct from the pod merely being Running).
const httpReadyTimeout = 30 * time.Second

// WaitHTTPReady closes the mock-endpoint READINESS RACE: it polls the server's
// in-pod listener (an HTTP GET to 127.0.0.1:Port, executed inside the mock pod)
// until it returns a body containing wantMarker (or any non-empty body when
// wantMarker is ""). The pod being Running does NOT mean the `nc` responder has
// bound the port yet; before this gate the attacker's single fetch could hit a
// dead listener and read 0 bytes, sinking the positive-control anchor for
// c3-imds-theft / c3-secrets-sprawl. Callers that deploy an HTTP mock should wait
// on it before the attack executes.
//
// In a non-live env (no rest config / execer) it is a no-op so unit tests do not
// block.
func WaitHTTPReady(ctx context.Context, env *core.Env, ms *MockServer, wantMarker string) error {
	if ms == nil {
		return fmt.Errorf("WaitHTTPReady: nil mock server")
	}
	if env.Rest == nil {
		return nil // non-live env (unit test) — nothing to probe
	}
	probe := []string{"sh", "-c", fmt.Sprintf("wget -T 2 -qO- http://127.0.0.1:%d/ 2>/dev/null", ms.Port)}
	deadline := time.Now().Add(httpReadyTimeout)
	lastLen := -1
	for {
		res := env.Exec(ctx, ms.PodName, "server", probe)
		body := strings.TrimSpace(res.Stdout)
		if body != "" && (wantMarker == "" || strings.Contains(body, wantMarker)) {
			env.Log.Logf("mock %s READY (in-pod probe served %d bytes on :%d)", ms.Name, len(body), ms.Port)
			return nil
		}
		lastLen = len(body)
		if time.Now().After(deadline) {
			return fmt.Errorf("mock %s not serving on :%d within %s (last in-pod probe body len=%d)", ms.Name, ms.Port, httpReadyTimeout, lastLen)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(750 * time.Millisecond):
		}
	}
}
