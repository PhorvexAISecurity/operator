// Package scenarios contains the self-registering Scenario plugins. Each scenario
// is ONE file with a func init(){ core.RegisterScenario(...) }. Adding a future
// attack is one new file + one register call, ZERO core changes.
//
// Every scenario defines its attack-success ORACLE as a concrete OBSERVABLE
// state and measures disruption strictly against it. ALL behavior is confined to
// the sandbox namespace; category-3 scenarios use the in-cluster MOCK endpoints
// from internal/mocks and never touch real cloud/registry/credentials.
package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

// ---- credential-replay boundary (c1-credtheft-rbac) ----
//
// The credential-theft scenario replays the ACTUAL bytes it exfiltrated from the
// pod against the SAME guarded API. These helpers build a replay client that
// carries ONLY the captured bearer (no fallback identity), classify the API's
// response into the arms the oracle must treat differently, and describe the
// captured credential's binding/expiry WITHOUT ever logging or emitting the
// credential itself.

// replayReqTimeout bounds a single replay API call so a hung or slow endpoint
// cannot stall a trial. It is per-call and independent of the observation window.
const replayReqTimeout = 20 * time.Second

// tokenServiceAccountPath is the in-pod path of the projected ServiceAccount
// token the attack exfiltrates.
const tokenServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// replayClass classifies the outcome of replaying a captured bearer against the
// guarded API. It distinguishes an authenticated success and an authenticated
// refusal (401/403 — a real API decision) from every transport/protocol fault
// (which makes the measurement invalid rather than a defensive win).
type replayClass int

const (
	replayAuthorized   replayClass = iota // 2xx with a decodable PodList
	replayUnauthorized                    // 401
	replayForbidden                       // 403
	replayOtherHTTP                       // other API status (5xx, 429, ...)
	replayMalformed                       // 2xx whose body is not a valid PodList
	replayTimeout                         // deadline exceeded
	replayCancelled                       // context cancelled
	replayTransport                       // dial/TLS/connection error
	replayRefused                         // refused to build a clean replay client
)

// authorized reports an authenticated success (a usable credential).
func (c replayClass) authorized() bool { return c == replayAuthorized }

// denied reports an authenticated-but-refused outcome (401/403): a genuine API
// decision, which is a measured failure, NOT an invalid measurement.
func (c replayClass) denied() bool { return c == replayUnauthorized || c == replayForbidden }

// String is a short, safe label for evidence (never a token or a response body).
func (c replayClass) String() string {
	switch c {
	case replayAuthorized:
		return "authorized"
	case replayUnauthorized:
		return "unauthorized-401"
	case replayForbidden:
		return "forbidden-403"
	case replayOtherHTTP:
		return "other-http-error"
	case replayMalformed:
		return "malformed-2xx"
	case replayTimeout:
		return "timeout"
	case replayCancelled:
		return "cancelled"
	case replayTransport:
		return "transport-error"
	case replayRefused:
		return "replay-refused"
	default:
		return "unknown"
	}
}

// replayOutcome is the sanitized result of one replay. It NEVER carries the token
// or a response body; detail is a short, safe reason.
type replayOutcome struct {
	class    replayClass
	podCount int
	detail   string
}

// sanitizedReplayConfig builds a fresh rest.Config carrying ONLY the captured
// bearer plus the NON-AUTH connectivity/trust settings needed to reach the SAME
// endpoint with the SAME verified server trust: host, TLS server verification
// (CA/ServerName/ALPN) and any Proxy/Dial connectivity hooks. Every caller
// identity is simply OMITTED, never invoked: a fresh config carries no bearer
// file, client cert/key, basic auth, auth/exec provider or impersonation, so an
// auth/exec plugin is never executed and a failure to authenticate can never be
// masked by the harness's own admin caller. Two things are hard REFUSALS rather
// than silent proceed: an opaque custom Transport/WrapTransport (which could
// inject a non-captured identity we cannot strip), and insecure TLS (skip-verify),
// because a real credential must only ever reach a server whose identity was
// verified.
func sanitizedReplayConfig(base *rest.Config, token string) (*rest.Config, error) {
	if base == nil {
		return nil, errors.New("no live rest config (non-live env)")
	}
	if base.Transport != nil || base.WrapTransport != nil {
		return nil, errors.New("base client uses an opaque custom transport that may inject a non-captured identity")
	}
	if base.TLSClientConfig.Insecure {
		return nil, errors.New("insecure TLS (skip-verify) is refused for credential replay; the server's identity must be verified")
	}
	// Require an EXPLICIT https:// endpoint before any transport is built: a
	// cleartext (http), scheme-relative/implicit, or userinfo-bearing host would
	// send the captured bearer without a verified TLS peer. Insecure=false only
	// governs verification once TLS is in use; it does not reject a cleartext host.
	u, err := url.Parse(base.Host)
	if err != nil {
		return nil, errors.New("replay endpoint is not a parseable URL")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("replay endpoint must be an explicit https:// URL, not %q; cleartext/implicit transport is refused", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("replay endpoint must not carry userinfo credentials")
	}
	if u.Host == "" {
		return nil, errors.New("replay endpoint has no host")
	}
	cfg := &rest.Config{
		Host:      base.Host,
		APIPath:   base.APIPath,
		UserAgent: base.UserAgent,
		QPS:       base.QPS,
		Burst:     base.Burst,
		Timeout:   replayReqTimeout,
		TLSClientConfig: rest.TLSClientConfig{
			// Insecure is left false: server trust is always verified.
			ServerName: base.TLSClientConfig.ServerName,
			CAFile:     base.TLSClientConfig.CAFile,
			CAData:     base.TLSClientConfig.CAData,
			NextProtos: base.TLSClientConfig.NextProtos,
		},
		// Preserve NON-AUTH connectivity so the replay reaches the same endpoint
		// the operator does (a proxy or custom dialer is connectivity, not identity).
		Proxy:       base.Proxy,
		Dial:        base.Dial,
		BearerToken: token,
	}
	return cfg, nil
}

// replayCapturedCredential replays the captured bearer against the sandbox
// list-pods operation with a freshly built client that follows NO redirects (so
// the credential is never forwarded to another host). It records the operation
// for provenance but never the token or a response body, and returns a sanitized,
// classified outcome.
func replayCapturedCredential(ctx context.Context, env *core.Env, token string) replayOutcome {
	cfg, err := sanitizedReplayConfig(env.Rest, token)
	if err != nil {
		return replayOutcome{class: replayRefused, detail: err.Error()}
	}
	httpClient, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return replayOutcome{class: replayTransport, detail: "could not build replay HTTP client"}
	}
	// Refuse to follow redirects: a 3xx to another host must never carry the
	// captured credential onward.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cs, err := kubernetes.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return replayOutcome{class: replayTransport, detail: "could not build replay client"}
	}
	reqCtx, cancel := context.WithTimeout(ctx, replayReqTimeout)
	defer cancel()
	env.Log.Command(fmt.Sprintf("kubectl --token=<captured> get pods -n %s  # replay the exfiltrated credential", env.Config.Namespace))
	var code int
	raw, err := cs.CoreV1().RESTClient().Get().
		Namespace(env.Config.Namespace).Resource("pods").
		Do(reqCtx).StatusCode(&code).Raw()
	if err != nil {
		return classifyReplayError(ctx, reqCtx, err, code)
	}
	return classifyReplayBody(code, raw)
}

// classifyReplayBody accepts a replay ONLY when the API answered the exact
// list-pods protocol: HTTP 200 with a body that is structurally a v1 PodList
// (kind "PodList", apiVersion "v1", an "items" array present — empty is valid —
// AND every member decodes as an actual Pod object). Any other 2xx status, or a
// body that is empty, null, a bare object, a success Status, a different
// collection kind, or a PodList whose items are not Pod objects (e.g. numbers or
// strings), is a MALFORMED response, not evidence of credential usability: a
// proxy/frontend generic 200 must never be read as attacker capability. This is a
// protocol-shape check, not an attempt to authenticate the (trusted) server's
// claims.
func classifyReplayBody(code int, raw []byte) replayOutcome {
	if code != 200 {
		return replayOutcome{class: replayMalformed, detail: fmt.Sprintf("non-200 success status %d", code)}
	}
	var probe struct {
		Kind       string           `json:"kind"`
		APIVersion string           `json:"apiVersion"`
		Items      *json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return replayOutcome{class: replayMalformed, detail: "200 body did not decode as JSON"}
	}
	if probe.Kind != "PodList" || probe.APIVersion != "v1" {
		return replayOutcome{class: replayMalformed,
			detail: fmt.Sprintf("200 body is not a v1 PodList (kind=%q apiVersion=%q)", probe.Kind, probe.APIVersion)}
	}
	if probe.Items == nil {
		return replayOutcome{class: replayMalformed, detail: "200 PodList body has no items list"}
	}
	// Decode the actual PodList structure so items whose members are not Pod
	// objects (numbers, strings, wrong shape) are rejected rather than counted.
	var pods corev1.PodList
	if err := json.Unmarshal(raw, &pods); err != nil {
		return replayOutcome{class: replayMalformed, detail: "200 v1 PodList had malformed item member(s)"}
	}
	n := len(pods.Items)
	return replayOutcome{class: replayAuthorized, podCount: n, detail: fmt.Sprintf("HTTP 200, listed %d pods", n)}
}

// classifyReplayError maps a failed replay into its sanitized class. It never
// includes the server's message or body in the detail, only the class of fault.
func classifyReplayError(parent, reqCtx context.Context, err error, code int) replayOutcome {
	switch {
	case parent.Err() == context.Canceled, errors.Is(err, context.Canceled):
		return replayOutcome{class: replayCancelled, detail: "replay cancelled"}
	case errors.Is(err, context.DeadlineExceeded), reqCtx.Err() == context.DeadlineExceeded:
		return replayOutcome{class: replayTimeout, detail: "replay timed out"}
	case apierrors.IsUnauthorized(err):
		return replayOutcome{class: replayUnauthorized, detail: "API returned 401 Unauthorized"}
	case apierrors.IsForbidden(err):
		return replayOutcome{class: replayForbidden, detail: "API returned 403 Forbidden"}
	}
	if code >= 400 {
		return replayOutcome{class: replayOtherHTTP, detail: fmt.Sprintf("API returned HTTP %d", code)}
	}
	return replayOutcome{class: replayTransport, detail: "transport/TLS error reaching the API"}
}

// capturedCredMeta is the best-effort, NON-AUTHORITATIVE metadata decoded from a
// captured credential. Decoding a JWT's unverified claims is not cryptographic
// proof of anything; it is used ONLY to describe binding for the report and to
// guard against crediting a defender for a token's own natural expiry. An opaque
// or malformed credential yields decoded=false and binding "unknown".
type capturedCredMeta struct {
	decoded   bool
	binding   string // "pod-bound" | "unbound" | "unknown"
	boundName string
	expUnix   int64 // 0 = no/unknown expiry
}

// parseCapturedCredMeta decodes a projected ServiceAccount JWT's claims WITHOUT
// verifying its signature. A three-segment JWT with a kubernetes.io pod claim is
// reported pod-bound; a JWT without one is unbound; anything that is not a decodable
// JWT (opaque or malformed) stays "unknown". The result is descriptive only and is
// never treated as authority for attack success.
func parseCapturedCredMeta(token string) capturedCredMeta {
	meta := capturedCredMeta{binding: "unknown"}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return meta // opaque, not a JWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return meta // malformed base64url payload
	}
	var claims struct {
		Exp        int64 `json:"exp"`
		Kubernetes struct {
			Pod *struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"pod"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return meta // malformed claims
	}
	meta.decoded = true
	meta.expUnix = claims.Exp
	if claims.Kubernetes.Pod != nil && claims.Kubernetes.Pod.Name != "" {
		meta.binding = "pod-bound"
		meta.boundName = claims.Kubernetes.Pod.Name
	} else {
		meta.binding = "unbound"
	}
	return meta
}

// credObservationSleep is the observation-window wait seam. Production waits the
// real, context-cancellable interval; tests replace it so they exercise the real
// request order without sleeping. It returns a non-nil error only when the context
// ends first (cancellation), which the oracle treats as an invalid measurement.
var credObservationSleep = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ensureSAWithRBAC creates a ServiceAccount + a (namespaced) Role granting
// list/get on pods + a RoleBinding, all in the sandbox. It models the misconfigured
// RBAC the cred-theft scenario exploits. Idempotent.
func ensureSAWithRBAC(ctx context.Context, env *core.Env, saName string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: saName, Namespace: ns, Labels: env.OwnedLabels(nil)}}
	env.Log.Command(fmt.Sprintf("kubectl create serviceaccount %s -n %s", saName, ns))
	if _, err := env.Kube.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: saName + "-role", Namespace: ns, Labels: env.OwnedLabels(nil)},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods", "secrets"},
			Verbs:     []string{"get", "list"},
		}},
	}
	env.Log.Command(fmt.Sprintf("kubectl create role %s-role --verb=get,list --resource=pods,secrets -n %s", saName, ns))
	if _, err := env.Kube.RbacV1().Roles(ns).Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: saName + "-rb", Namespace: ns, Labels: env.OwnedLabels(nil)},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: saName + "-role"},
	}
	env.Log.Command(fmt.Sprintf("kubectl create rolebinding %s-rb --role=%s-role --serviceaccount=%s:%s -n %s", saName, saName, ns, saName, ns))
	if _, err := env.Kube.RbacV1().RoleBindings(ns).Create(ctx, rb, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// BackdoorMarkerPath is the on-pod path an attacker writes its persistence marker
// to; the persistence oracle reads it.
const BackdoorMarkerPath = "/tmp/.r6th_backdoor"

// BackdoorMarker is the unique sleeper-process marker string.
const BackdoorMarker = "R6TH-BACKDOOR-SLEEPER"

// deployTarget stands up a benign target workload pod in the sandbox, labeled as
// a rotation target so the MTD arms know what to rotate. It is the shared
// "victim" every scenario compromises. saName, if non-empty, mounts that SA.
func deployTarget(ctx context.Context, env *core.Env, name, saName string, extraLabels map[string]string) (*corev1.Pod, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	labels := mocks.LabelMap(map[string]string{defenders.RotationTargetLabel: "true", "app": name}, extraLabels)
	pb := mocks.NewPod(env, name, labels).
		WithBusyboxLoop("app", nil, 100, 32)
	if saName != "" {
		pb = pb.WithServiceAccount(saName)
	}
	pod := pb.Build()
	// The runner reuses pod names across trials; ensure any prior same-named pod has
	// fully terminated before creating, so WaitForPodRunning cannot latch onto a
	// terminating pod (which then vanishes before Execute = a false "evicted" read).
	waitPodGone(ctx, env, name)
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s -l %s=true  # target workload", name, mocks.BusyboxImage, env.Config.Namespace, defenders.RotationTargetLabel))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	// Wait for a FRESH running, non-terminating pod (polls; tolerant of slow start).
	running, err := runningPodByApp(ctx, env, name)
	if err != nil {
		return nil, err
	}
	return running, nil
}

// waitPodGone FORCE-removes any lingering same-named pod so a fresh deploy is not
// blocked by a prior arm's slow-terminating pod. A Phoenix rotation Deletes with the
// default 30s grace, so the rotated pod is often STILL terminating when the next arm
// starts — a plain wait would time out and the same-named Create returns AlreadyExists.
// This grace-0 deletes it and strips any finalizer, then polls until it is gone.
func waitPodGone(ctx context.Context, env *core.Env, name string) {
	ns := env.Config.Namespace
	grace := int64(0)
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		p, err := env.Kube.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err == nil {
			if len(p.Finalizers) > 0 {
				_, _ = env.Kube.CoreV1().Pods(ns).Patch(ctx, name, types.MergePatchType,
					[]byte(`{"metadata":{"finalizers":null}}`), metav1.PatchOptions{})
			}
			_ = env.Kube.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &grace})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(400 * time.Millisecond):
		}
	}
}

// deployPlain stands up a benign pod that is NOT a rotation target (e.g. a
// lateral-movement victim B). Confined to the sandbox.
func deployPlain(ctx context.Context, env *core.Env, name string) (*corev1.Pod, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	pod := mocks.NewPod(env, name, map[string]string{"app": name}).
		WithBusyboxLoop("app", nil, 100, 32).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # plain workload", name, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	if err := env.WaitForPodRunning(ctx, name, 60*time.Second); err != nil {
		return nil, err
	}
	return pod, nil
}

// firstContainerName looks up a pod by name and returns its first container name
// (or "app" as a safe default for harness-built pods).
func firstContainerName(podName string, env *core.Env) string {
	p, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil || len(p.Spec.Containers) == 0 {
		return "app"
	}
	return p.Spec.Containers[0].Name
}

// plantBackdoor writes a persistence backdoor inside the target pod: a marker
// file plus a long-lived sleeper "process" recorded by writing its marker. It
// FAITHFULLY models a runc-overwrite file-clobber persistence (T1543.005) within
// the sandbox container. Returns the commands issued.
func plantBackdoor(ctx context.Context, env *core.Env, pod, container string) []string {
	// Write the marker (the clobbered file the attacker drops) and spawn a
	// DETACHED sleeper that re-touches the marker, so a liveness probe of the
	// process succeeds. Real backdoor tradecraft detaches from the controlling
	// stream (nohup-style: redirect stdin/stdout/stderr away) so the operator's
	// interactive exec returns immediately while the sleeper persists. We model
	// the live process by the marker file's presence + a background sleep whose
	// pid we record. The redirects are LOAD-BEARING: without them the backgrounded
	// loop inherits the exec's stdout stream and the SPDY exec would block until
	// it closes (i.e. never).
	script := fmt.Sprintf(
		"echo %s > %s; (while true; do echo %s > %s; sleep 5; done) </dev/null >/dev/null 2>&1 & echo backdoor-pid=$!",
		BackdoorMarker, BackdoorMarkerPath, BackdoorMarker, BackdoorMarkerPath)
	res := env.Exec(ctx, pod, container, []string{"sh", "-c", script})
	env.Log.Logf("plantBackdoor stdout=%q stderr=%q exit=%d", strings.TrimSpace(res.Stdout), strings.TrimSpace(res.Stderr), res.ExitCode)
	return []string{"sh -c '" + script + "'"}
}

// backdoorAlive checks whether the backdoor marker is still present in ANY pod
// matching the app label (so a rotation that replaced the pod with a fresh
// identity correctly reports the backdoor as gone). Returns (alive, observedPod).
func backdoorAlive(ctx context.Context, env *core.Env, appLabel string) (bool, string, error) {
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=" + appLabel,
	})
	if err != nil {
		return false, "", err
	}
	for i := range pods.Items {
		p := pods.Items[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		res := env.Exec(ctx, p.Name, firstContainer(&p), []string{"sh", "-c", "cat " + BackdoorMarkerPath + " 2>/dev/null"})
		if strings.Contains(res.Stdout, BackdoorMarker) {
			return true, p.Name, nil
		}
	}
	return false, "", nil
}

// firstContainer returns the first container name of a pod (the attacker target).
func firstContainer(p *corev1.Pod) string {
	if len(p.Spec.Containers) > 0 {
		return p.Spec.Containers[0].Name
	}
	return ""
}

// runningPodByApp returns the first Running, NON-terminating pod matching app=<label>.
// It POLLS for up to ~25s: a fresh target may still be coming up, or a prior trial's
// same-named pod may still be terminating (the runner reuses pod names across trials).
// Without this poll the attack Execute can spuriously fail with "no running pod",
// which then falsely reads as an eviction (a measurement-validity bug). Polling makes
// the foothold reliably plant so disruption reflects REAL eviction, not a race.
func runningPodByApp(ctx context.Context, env *core.Env, appLabel string) (*corev1.Pod, error) {
	deadline := time.Now().Add(40 * time.Second)
	for {
		pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app=" + appLabel,
		})
		if err == nil {
			for i := range pods.Items {
				if pods.Items[i].Status.Phase == corev1.PodRunning && pods.Items[i].DeletionTimestamp == nil {
					return &pods.Items[i], nil
				}
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no running pod for app=%s after polling", appLabel)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// teardownByApp deletes every owned object for the scenario's app label. The
// runner also does a global owned-cleanup, but a scenario Teardown that is
// idempotent and scoped keeps trials isolated.
func teardownByApp(ctx context.Context, env *core.Env, appLabels ...string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	grace := int64(0)
	dp := metav1.DeletePropagationBackground
	for _, app := range appLabels {
		lo := metav1.ListOptions{LabelSelector: "app=" + app}
		env.Log.Command(fmt.Sprintf("kubectl delete pods -n %s -l app=%s --grace-period=0", env.Config.Namespace, app))
		_ = env.Kube.CoreV1().Pods(env.Config.Namespace).DeleteCollection(ctx,
			metav1.DeleteOptions{GracePeriodSeconds: &grace, PropagationPolicy: &dp}, lo)
	}
	return nil
}

// measureSurvival POLLS until the foothold is evicted (the backdoor marker is gone
// from every app-labeled running pod) or maxWindow elapses, returning the REAL
// foothold-survival seconds and whether it was still alive at the end. This is the
// genuine dwell-to-eviction metric the report LEADS with (the runner's
// AttackerDwellSeconds is merely trial-elapsed time, not survival). A fast-evicting
// arm (PX on a high-risk pod) yields a small survival; a slow periodic timer yields a
// survival near its interval; an arm that never evicts yields the full window.
func measureSurvival(ctx context.Context, env *core.Env, appLabel string, maxWindow time.Duration) (float64, bool) {
	start := time.Now()
	deadline := start.Add(maxWindow)
	for {
		alive, _, _ := backdoorAlive(ctx, env, appLabel)
		if !alive {
			return time.Since(start).Seconds(), false
		}
		if time.Now().After(deadline) {
			return time.Since(start).Seconds(), true
		}
		select {
		case <-ctx.Done():
			return time.Since(start).Seconds(), true
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// survivalMarker formats the parseable ObservedState markers the post-processor reads
// for the dwell-led, feasibility and harm metrics. Keep keys stable.
func survivalMarker(survivalSec float64, stillAlive bool) string {
	return fmt.Sprintf("[survival=%.1fs] [evicted=%v]", survivalSec, !stillAlive)
}

// dwellCheck waits dwell seconds (bounded for smoke) then reports whether the
// backdoor survived. It is the shared persistence-dwell measurement.
func dwellCheck(ctx context.Context, env *core.Env, appLabel string, dwell time.Duration) (bool, string) {
	// Bound the actual wait so smoke trials stay fast.
	const maxWait = 10 * time.Second
	w := dwell
	if w > maxWait {
		w = maxWait
	}
	select {
	case <-ctx.Done():
	case <-time.After(w):
	}
	alive, pod, err := backdoorAlive(ctx, env, appLabel)
	if err != nil {
		env.Log.Logf("dwellCheck error: %v", err)
	}
	return alive, pod
}
