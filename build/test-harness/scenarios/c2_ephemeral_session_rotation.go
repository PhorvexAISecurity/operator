package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func init() { core.RegisterScenario(&c2EphemeralSessionRotation{}) }

const (
	sessionApp         = "c2-session-target"
	sessionDeployment  = "c2-session-target"
	sessionService     = "c2-session-target"
	sessionProducer    = "c2-session-producer"
	sessionPort        = 8080
	sessionPythonImage = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
	// benignSessionObservationWindow is deliberately independent of credential
	// replay configuration. It gives the already-running defender a bounded
	// opportunity to replace the fixture after the original state is confirmed.
	benignSessionObservationWindow = 20 * time.Second
	benignSessionMeasurementWindow = 15 * time.Second
	sessionBatchExecTimeout        = 8 * time.Second
	sessionBatchHTTPBudget         = 5 * time.Second
	sessionMeasurementRetry        = 250 * time.Millisecond
)

var benignSessionObservationWait = waitBenignSessionObservation
var sessionMeasurementLimit = benignSessionMeasurementWindow

// sessionServerSource is the entire fixture application. It retains only
// caller-supplied synthetic identifiers in one process-local set. A replacement
// process necessarily starts empty; no credential, volume, or external store is
// involved.
const sessionServerSource = `import json, os, re, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sessions = set()
lock = threading.Lock()
pod_uid = os.environ["POD_UID"]
valid = re.compile(r"^[A-Za-z0-9-]{1,64}$")

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body):
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def session_id(self):
        values = parse_qs(urlparse(self.path).query).get("id", [])
        return values[0] if len(values) == 1 and valid.fullmatch(values[0]) else None

    def do_GET(self):
        if urlparse(self.path).path == "/healthz":
            self.reply(200, {"podUID": pod_uid, "ready": True})
            return
        if urlparse(self.path).path != "/session":
            self.reply(404, {"podUID": pod_uid, "error": "not-found"})
            return
        sid = self.session_id()
        if sid is None:
            self.reply(400, {"podUID": pod_uid, "error": "invalid-id"})
            return
        with lock:
            present = sid in sessions
        self.reply(200 if present else 404, {"podUID": pod_uid, "id": sid, "present": present})

    def do_POST(self):
        if urlparse(self.path).path != "/session":
            self.reply(404, {"podUID": pod_uid, "error": "not-found"})
            return
        sid = self.session_id()
        if sid is None:
            self.reply(400, {"podUID": pod_uid, "error": "invalid-id"})
            return
        with lock:
            created = sid not in sessions
            sessions.add(sid)
        self.reply(201 if created else 200, {"podUID": pod_uid, "id": sid, "present": True, "created": created})

    def log_message(self, fmt, *args):
        pass

ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
`

// sessionClientSource executes one bounded multi-request protocol inside the
// dedicated producer Pod. It always uses the stable ClusterIP Service, disables
// ambient proxy discovery and redirects, bounds response bytes and preserves
// per-request status, body, timestamps and transport failure.
const sessionClientSource = `import base64, datetime, hashlib, json, signal, sys, time, urllib.error, urllib.parse, urllib.request
base, encoded, budget_text = sys.argv[1:]
def strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise ValueError("duplicate batch input field")
        out[key] = value
    return out
operations = json.loads(base64.b64decode(encoded, validate=True), object_pairs_hook=strict_object)
if type(operations) is not list or not 1 <= len(operations) <= 3: raise ValueError("invalid batch operation count")
for operation in operations:
    if type(operation) is not dict or set(operation) != {"method", "id", "when"}: raise ValueError("invalid batch operation shape")
    if operation["method"] not in ("GET", "POST") or type(operation["id"]) is not str or type(operation["when"]) is not str or operation["when"] not in ("always", "old-absent"): raise ValueError("invalid batch operation")
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
def wall_timeout(signum, frame): raise TimeoutError("batch-wall-deadline-exhausted")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
budget = float(budget_text)
if not 0 < budget <= 5: raise ValueError("invalid batch wall budget")
started = now(); deadline = time.monotonic() + budget; responses = []; old_absent = False
signal.signal(signal.SIGALRM, wall_timeout); signal.setitimer(signal.ITIMER_REAL, budget)
for operation in operations:
    url = base + "/session?" + urllib.parse.urlencode({"id": operation["id"]})
    item = {"method": operation["method"], "id": operation["id"], "destination": url, "startedAtUTC": now()}
    if operation["when"] == "old-absent" and not old_absent:
        item["skipped"] = "old-session-not-explicitly-absent"; item["endedAtUTC"] = now(); responses.append(item); continue
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        item["transportError"] = "batch-deadline-exhausted"; item["endedAtUTC"] = now(); responses.append(item); continue
    request = urllib.request.Request(url, method=operation["method"])
    raw = bytearray(); response = None
    try:
        try: response = opener.open(request, timeout=min(3.0, remaining))
        except urllib.error.HTTPError as error: response = error
        while len(raw) <= 1024:
            if time.monotonic() >= deadline: raise TimeoutError("batch-wall-deadline-exhausted")
            chunk = response.read(1)
            if not chunk: break
            raw.extend(chunk)
        item.update({"httpStatus": response.status, "bodyBase64": base64.b64encode(raw).decode("ascii"), "bodyBytes": len(raw), "bodySHA256": hashlib.sha256(raw).hexdigest()})
        if len(raw) > 1024: item["protocolError"] = "response-too-large"
        if len(responses) == 0:
            try:
                parsed = json.loads(raw, object_pairs_hook=strict_object)
                old_absent = response.status == 404 and type(parsed) is dict and set(parsed) == {"podUID", "id", "present"} and type(parsed["podUID"]) is str and parsed["podUID"] and type(parsed["id"]) is str and parsed["id"] == operation["id"] and type(parsed["present"]) is bool and parsed["present"] is False
            except Exception: old_absent = False
    except Exception as error:
        if response is not None:
            item.update({"httpStatus": response.status, "bodyBase64": base64.b64encode(raw).decode("ascii"), "bodyBytes": len(raw), "bodySHA256": hashlib.sha256(raw).hexdigest()})
        item["transportError"] = type(error).__name__ + ": " + str(error)
    item["endedAtUTC"] = now(); responses.append(item)
signal.setitimer(signal.ITIMER_REAL, 0)
sys.stdout.write(json.dumps({"version": 1, "startedAtUTC": started, "endedAtUTC": now(), "responses": responses}, sort_keys=True, separators=(",", ":")))
`

type c2EphemeralSessionRotation struct {
	originalName        string
	originalUID         types.UID
	sessionID           string
	deploymentUID       types.UID
	serviceUID          types.UID
	producerUID         types.UID
	replicaSetName      string
	replicaSetUID       types.UID
	windowStarted       time.Time
	windowEnded         time.Time
	measurementStarted  time.Time
	measurementEnded    time.Time
	measurementAttempts int
	measurementFailures int
}

func (s *c2EphemeralSessionRotation) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:          "c2-ephemeral-session-rotation",
		Category:      core.CategoryR6Claimed,
		Source:        "Post25 catalogue gap: benign ephemeral application-state replacement control",
		R6ResponseTag: core.R6Partial,
		BenignControl: true,
		Realism:       core.RealismExecutable,
		Mechanism: fmt.Sprintf("actual bounded multi-request HTTP batches through a stable ClusterIP Service to a controller-owned single-replica process-memory session fixture, followed by a fixed %.0f-second observation window and a separately reported at-most %.0f-second measurement convergence interval; image=%s serverSourceSHA256=%s",
			benignSessionObservationWindow.Seconds(), benignSessionMeasurementWindow.Seconds(), sessionPythonImage, sessionServerSourceSHA256()),
		ClaimLimits:        "benign application-state control only; executes no attack or exploit, exercises zero ATT&CK techniques, and does not establish credential revocation, attack prevention, detection, or security coverage",
		OracleDescription:  "one bounded same-UID Service sequence supplies the served Pod UID; API identity then corroborates the exact Deployment/ReplicaSet/Pod, Service and endpoint chain. Original state remains usable only when the original UID serves it; loss requires exact original-UID absence and one replacement UID that reports the old ID absent then creates and retrieves a distinct ID",
		CleanupDescription: "delete the owned Deployment, Service, and producer Pod; runner-owned cleanup independently verifies absence",
		R6Justification:    "Pod replacement can clear process-local state. This control measures that narrow functional effect through real Service traffic and makes no attack-mitigation claim.",
	}
}

func (s *c2EphemeralSessionRotation) Setup(ctx context.Context, env *core.Env) error {
	// Scenario objects are reused across trials. Cleanup authority belongs only
	// to objects whose successful Create response supplied the UID in this setup.
	s.deploymentUID, s.serviceUID, s.producerUID = "", "", ""
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	labels := env.OwnedLabels(map[string]string{"app": sessionApp})
	podLabels := env.OwnedLabels(map[string]string{"app": sessionApp, defenders.RotationTargetLabel: "true"})
	one := int32(1)
	noToken := false
	runAsNonRoot := true
	runAsUser := int64(65532)
	readOnly := true
	noEscalation := false
	targetNodeSelector := cloneStringMap(env.Config.BenignSessionNodeSelector)
	producerNodeSelector := cloneStringMap(env.Config.BenignSessionNodeSelector)
	selectorEvidence := sessionNodeSelectorEvidence(env.Config.BenignSessionNodeSelector)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: sessionDeployment, Namespace: env.Config.Namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": sessionApp}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: map[string]string{"r6th.io/session-source-sha256": sessionServerSourceSHA256()}},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &noToken,
					NodeSelector:                 targetNodeSelector,
					SecurityContext:              &corev1.PodSecurityContext{RunAsNonRoot: &runAsNonRoot, RunAsUser: &runAsUser, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{
						Name:            "session",
						Image:           sessionPythonImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"python3", "-B", "-c", sessionServerSource},
						Env:             []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}},
						Ports:           []corev1.ContainerPort{{Name: "http", ContainerPort: sessionPort}},
						ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("http")}}, InitialDelaySeconds: 1, PeriodSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 5},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("20m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
						},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEscalation, ReadOnlyRootFilesystem: &readOnly, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					}},
				},
			},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl create deployment %s -n %s  # pinned CPU-only in-memory session fixture nodeSelector=%s", sessionDeployment, env.Config.Namespace, selectorEvidence))
	createdDeployment, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Create(ctx, dep, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create session deployment: %w", err)
	}
	if createdDeployment.UID == "" {
		return errors.New("create session deployment returned no UID; refusing unbound cleanup authority")
	}
	s.deploymentUID = createdDeployment.UID
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: sessionService, Namespace: env.Config.Namespace, Labels: labels},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": sessionApp}, Ports: []corev1.ServicePort{{Name: "http", Port: sessionPort, TargetPort: intstr.FromString("http")}}},
	}
	env.Log.Command(fmt.Sprintf("kubectl create service clusterip %s -n %s --tcp=%d:%d", sessionService, env.Config.Namespace, sessionPort, sessionPort))
	createdService, err := env.Kube.CoreV1().Services(env.Config.Namespace).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create session service: %w", err)
	}
	if createdService.UID == "" {
		return errors.New("create session service returned no UID; refusing unbound cleanup authority")
	}
	s.serviceUID = createdService.UID
	producerLabels := env.OwnedLabels(map[string]string{"app": sessionProducer})
	producer := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: sessionProducer, Namespace: env.Config.Namespace, Labels: producerLabels},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &noToken,
			NodeSelector:                 producerNodeSelector,
			SecurityContext:              &corev1.PodSecurityContext{RunAsNonRoot: &runAsNonRoot, RunAsUser: &runAsUser, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Containers: []corev1.Container{{
				Name:            "producer",
				Image:           sessionPythonImage,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"python3", "-c", "import time; time.sleep(3600)"},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
					Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
				},
				SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEscalation, ReadOnlyRootFilesystem: &readOnly, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			}},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl run %s -n %s --image=%s  # HTTP producer nodeSelector=%s", sessionProducer, env.Config.Namespace, sessionPythonImage, selectorEvidence))
	createdProducer, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, producer, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create session producer: %w", err)
	}
	if createdProducer.UID == "" {
		return errors.New("create session producer returned no UID; refusing unbound cleanup authority")
	}
	s.producerUID = createdProducer.UID
	if err := env.WaitForPodRunning(ctx, sessionProducer, 60*time.Second); err != nil {
		return fmt.Errorf("wait for session producer: %w", err)
	}
	if _, err := readySessionPod(ctx, env, sessionApp, 60*time.Second); err != nil {
		return err
	}
	return nil
}

func (s *c2EphemeralSessionRotation) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.originalName, s.originalUID, s.sessionID = "", "", ""
	s.replicaSetName, s.replicaSetUID = "", ""
	s.windowStarted, s.windowEnded = time.Time{}, time.Time{}
	s.measurementStarted, s.measurementEnded = time.Time{}, time.Time{}
	s.measurementAttempts, s.measurementFailures = 0, 0
	if err := ctx.Err(); err != nil {
		return core.AttackResult{}, fmt.Errorf("session producer cancelled: %w", err)
	}
	_, err := readySessionPod(ctx, env, sessionApp, 40*time.Second)
	if err != nil {
		return core.AttackResult{}, err
	}
	if env.Rand == nil {
		return core.AttackResult{}, errors.New("session producer has no deterministic trial RNG")
	}
	sid := fmt.Sprintf("session-%d-%016x", env.Trial, env.Rand.Uint64())
	batch, err := performSessionBatch(ctx, env, []sessionBatchOperation{{Method: "POST", ID: sid, When: "always"}, {Method: "GET", ID: sid, When: "always"}}, s.producerUID)
	if err != nil {
		return core.AttackResult{Stages: []string{"create and retrieve synthetic process-memory session in one bounded Service batch"}}, err
	}
	if len(batch.Responses) != 2 {
		return core.AttackResult{}, fmt.Errorf("session establishment batch returned %d replies", len(batch.Responses))
	}
	created, retained := batch.Responses[0].Reply, batch.Responses[1].Reply
	servedUID := batch.ServedUID
	pod, err := s.corroborateSessionWorkload(ctx, env, servedUID, true)
	if err != nil {
		return core.AttackResult{Stages: []string{"create and retrieve synthetic process-memory session in one bounded Service batch"}}, err
	}
	s.originalName, s.originalUID = pod.Name, pod.UID
	if created.HTTPStatus != 201 || !created.Body.Created || !created.Body.Present || created.Body.PodUID != string(s.originalUID) {
		return core.AttackResult{Stages: []string{"create synthetic process-memory session through stable Service"}}, fmt.Errorf("session create reply did not bind new state to original UID: status=%d created=%v present=%v replyUID=%q originalUID=%q", created.HTTPStatus, created.Body.Created, created.Body.Present, created.Body.PodUID, s.originalUID)
	}
	if retained.HTTPStatus != 200 || !retained.Body.Present || retained.Body.PodUID != string(s.originalUID) {
		return core.AttackResult{Stages: []string{"create synthetic process-memory session through stable Service", "retrieve the same synthetic session ID"}}, fmt.Errorf("session retain reply did not confirm original process state: status=%d present=%v replyUID=%q originalUID=%q", retained.HTTPStatus, retained.Body.Present, retained.Body.PodUID, s.originalUID)
	}
	s.sessionID = sid
	windowStart, windowEnd, err := benignSessionObservationWait(ctx, benignSessionObservationWindow)
	s.windowStarted, s.windowEnded = windowStart, windowEnd
	stages := []string{
		"create and retrieve the same synthetic session ID in one bounded Service batch",
		fmt.Sprintf("hold the established session for a bounded %.0f-second benign observation window", benignSessionObservationWindow.Seconds()),
	}
	if err != nil {
		return core.AttackResult{Stages: stages}, fmt.Errorf("benign session observation window did not complete: %w", err)
	}
	if windowStart.IsZero() || windowEnd.Before(windowStart) || windowEnd.Sub(windowStart) < benignSessionObservationWindow {
		return core.AttackResult{Stages: stages}, fmt.Errorf("benign session observation window was shorter than %.0fs: start=%s end=%s elapsed=%s",
			benignSessionObservationWindow.Seconds(), windowStart.UTC().Format(time.RFC3339Nano), windowEnd.UTC().Format(time.RFC3339Nano), windowEnd.Sub(windowStart))
	}
	return core.AttackResult{
		Stages: stages,
		Notes: map[string]string{
			"originalPod":                     s.originalName,
			"originalPodUID":                  string(s.originalUID),
			"sessionID":                       sid,
			"transport":                       "ordinary HTTP via ClusterIP Service",
			"classification":                  "benign functional-effect control",
			"fixtureImage":                    sessionPythonImage,
			"serverSourceSHA256":              sessionServerSourceSHA256(),
			"benignSessionNodeSelector":       sessionNodeSelectorEvidence(env.Config.BenignSessionNodeSelector),
			"observationWindowSeconds":        fmt.Sprintf("%.0f", benignSessionObservationWindow.Seconds()),
			"observationWindowStartedAtUTC":   windowStart.UTC().Format(time.RFC3339Nano),
			"observationWindowEndedAtUTC":     windowEnd.UTC().Format(time.RFC3339Nano),
			"observationWindowElapsedSeconds": strconv.FormatFloat(windowEnd.Sub(windowStart).Seconds(), 'f', 3, 64),
		},
	}, nil
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func sessionNodeSelectorEvidence(selector map[string]string) string {
	if len(selector) == 0 {
		return "{}"
	}
	raw, err := json.Marshal(selector)
	if err != nil {
		panic(fmt.Sprintf("marshal validated benign session node selector: %v", err))
	}
	return string(raw)
}

func (s *c2EphemeralSessionRotation) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	if s.originalName == "" || s.originalUID == "" || s.sessionID == "" || s.replicaSetUID == "" {
		return core.OracleResult{}, errors.New("session stimulus, workload identity, or synthetic ID missing")
	}
	if s.windowStarted.IsZero() || s.windowEnded.Before(s.windowStarted) || s.windowEnded.Sub(s.windowStarted) < benignSessionObservationWindow {
		return core.OracleResult{}, errors.New("completed benign session observation window missing or shorter than the declared interval")
	}
	measurement, err := s.measureSessionState(ctx, env)
	s.measurementStarted, s.measurementEnded = measurement.Started, measurement.Ended
	s.measurementAttempts, s.measurementFailures = measurement.Attempts, measurement.Failures
	evidence := map[string]string{
		"originalPodUID":                  string(s.originalUID),
		"originalUIDAbsent":               strconv.FormatBool(measurement.OriginalAbsent),
		"transport":                       "ordinary HTTP via ClusterIP Service",
		"classification":                  "benign functional-effect control",
		"fixtureImage":                    sessionPythonImage,
		"serverSourceSHA256":              sessionServerSourceSHA256(),
		"observationWindowSeconds":        fmt.Sprintf("%.0f", benignSessionObservationWindow.Seconds()),
		"observationWindowStartedAtUTC":   s.windowStarted.UTC().Format(time.RFC3339Nano),
		"observationWindowEndedAtUTC":     s.windowEnded.UTC().Format(time.RFC3339Nano),
		"observationWindowElapsedSeconds": strconv.FormatFloat(s.windowEnded.Sub(s.windowStarted).Seconds(), 'f', 3, 64),
		"measurementWindowLimitSeconds":   fmt.Sprintf("%.0f", benignSessionMeasurementWindow.Seconds()),
		"measurementWindowStartedAtUTC":   measurement.Started.UTC().Format(time.RFC3339Nano),
		"measurementWindowEndedAtUTC":     measurement.Ended.UTC().Format(time.RFC3339Nano),
		"measurementWindowElapsedSeconds": strconv.FormatFloat(measurement.Ended.Sub(measurement.Started).Seconds(), 'f', 3, 64),
		"measurementAttempts":             strconv.Itoa(measurement.Attempts),
		"measurementFailures":             strconv.Itoa(measurement.Failures),
	}
	if measurement.Pod != nil {
		evidence["observedPodUID"] = string(measurement.Pod.UID)
	}
	if len(measurement.Batch.Responses) > 0 {
		old := measurement.Batch.Responses[0].Reply
		evidence["serviceReplyPodUID"] = old.Body.PodUID
		evidence["oldSessionPresent"] = strconv.FormatBool(old.Body.Present)
		evidence["oldSessionStatus"] = strconv.Itoa(old.HTTPStatus)
	}
	if err != nil {
		return core.OracleResult{Evidence: evidence}, err
	}
	old := measurement.Batch.Responses[0].Reply
	if !measurement.OriginalAbsent {
		if measurement.Pod.UID != s.originalUID || old.Body.PodUID != string(s.originalUID) {
			return core.OracleResult{Evidence: evidence}, fmt.Errorf("original UID still exists but bounded Service sequence was served by uid=%s", old.Body.PodUID)
		}
		if old.HTTPStatus != 200 || !old.Body.Present {
			return core.OracleResult{Evidence: evidence}, fmt.Errorf("same original UID did not explicitly retain session: status=%d present=%v", old.HTTPStatus, old.Body.Present)
		}
		return core.OracleResult{Achieved: true, ObservedState: "benign control: same Pod UID served the same synthetic process-memory session ID", Evidence: evidence}, nil
	}
	if old.HTTPStatus == 200 && old.Body.Present {
		return core.OracleResult{Achieved: true, ObservedState: "benign control: exact replacement retained the original synthetic session ID", Evidence: evidence}, nil
	}
	if old.HTTPStatus != 404 || old.Body.Present {
		return core.OracleResult{Evidence: evidence}, fmt.Errorf("replacement did not explicitly report old synthetic session absent: status=%d present=%v", old.HTTPStatus, old.Body.Present)
	}
	if len(measurement.Batch.Responses) != 3 {
		return core.OracleResult{Evidence: evidence}, errors.New("replacement loss batch omitted fresh-session proof")
	}
	created, verified := measurement.Batch.Responses[1].Reply, measurement.Batch.Responses[2].Reply
	if created.HTTPStatus != 201 || !created.Body.Created || !created.Body.Present || created.Body.PodUID != string(measurement.Pod.UID) {
		return core.OracleResult{Evidence: evidence}, fmt.Errorf("replacement could not create new process state: status=%d created=%v present=%v replyUID=%q replacementUID=%q", created.HTTPStatus, created.Body.Created, created.Body.Present, created.Body.PodUID, measurement.Pod.UID)
	}
	if verified.HTTPStatus != 200 || !verified.Body.Present || verified.Body.PodUID != string(measurement.Pod.UID) {
		return core.OracleResult{Evidence: evidence}, fmt.Errorf("replacement did not retain newly created process state: status=%d present=%v replyUID=%q replacementUID=%q", verified.HTTPStatus, verified.Body.Present, verified.Body.PodUID, measurement.Pod.UID)
	}
	evidence["newSessionCreated"] = "true"
	evidence["newSessionRetrieved"] = "true"
	return core.OracleResult{Achieved: false, ObservedState: "benign control: exact original UID was absent; one exact replacement served a bounded sequence that lacked the old synthetic ID and retained a new one", Evidence: evidence}, nil
}

type sessionMeasurement struct {
	Started        time.Time
	Ended          time.Time
	Attempts       int
	Failures       int
	OriginalAbsent bool
	Pod            *corev1.Pod
	Batch          sessionBatchResult
}

type sessionIdentityReceipt struct {
	ObservedAtUTC        string            `json:"observedAtUTC"`
	ServedPodUID         string            `json:"servedPodUID"`
	PodName              string            `json:"podName,omitempty"`
	PodUID               string            `json:"podUID,omitempty"`
	PodReady             bool              `json:"podReady"`
	PodDeleting          bool              `json:"podDeleting"`
	PodLabels            map[string]string `json:"podLabels,omitempty"`
	PodSourceSHA256      string            `json:"podSourceSHA256,omitempty"`
	PodImage             string            `json:"podImage,omitempty"`
	ReplicaSetName       string            `json:"replicaSetName,omitempty"`
	ReplicaSetUID        string            `json:"replicaSetUID,omitempty"`
	DeploymentUID        string            `json:"deploymentUID,omitempty"`
	ServiceUID           string            `json:"serviceUID,omitempty"`
	ServiceSelector      map[string]string `json:"serviceSelector,omitempty"`
	ReadyEndpointUIDs    []string          `json:"readyEndpointUIDs,omitempty"`
	ExpectedOriginalUID  string            `json:"expectedOriginalUID,omitempty"`
	OriginalUIDPresent   *bool             `json:"originalUIDPresent,omitempty"`
	PodObject            json.RawMessage   `json:"podObject,omitempty"`
	ReplicaSetObject     json.RawMessage   `json:"replicaSetObject,omitempty"`
	DeploymentObject     json.RawMessage   `json:"deploymentObject,omitempty"`
	ServiceObject        json.RawMessage   `json:"serviceObject,omitempty"`
	EndpointSliceObjects []json.RawMessage `json:"endpointSliceObjects,omitempty"`
	OriginalPodObject    json.RawMessage   `json:"originalPodObject,omitempty"`
	Error                string            `json:"error,omitempty"`
}

const (
	sessionIdentityObjectLimit = 32 * 1024
	sessionIdentityTotalLimit  = 48 * 1024
)

func rawSessionIdentityObject(kind string, object any) (json.RawMessage, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("marshal session %s identity object: %w", kind, err)
	}
	if len(raw) > sessionIdentityObjectLimit {
		return nil, fmt.Errorf("session %s identity object exceeds %d bytes", kind, sessionIdentityObjectLimit)
	}
	return raw, nil
}

func recordSessionIdentityReceipt(env *core.Env, receipt sessionIdentityReceipt) {
	raw, err := json.Marshal(receipt)
	if err != nil {
		env.Log.Logf("c2-ephemeral-session-rotation identity-receipt marshal-error=%q", err)
		return
	}
	env.Log.Logf("c2-ephemeral-session-rotation identity-receipt=%s", raw)
}

func (s *c2EphemeralSessionRotation) measureSessionState(ctx context.Context, env *core.Env) (sessionMeasurement, error) {
	out := sessionMeasurement{Started: time.Now()}
	deadline := out.Started.Add(sessionMeasurementLimit)
	measurementCtx, cancelMeasurement := context.WithDeadline(ctx, deadline)
	defer cancelMeasurement()
	newID := s.sessionID + "-new"
	operations := []sessionBatchOperation{{Method: "GET", ID: s.sessionID, When: "always"}, {Method: "POST", ID: newID, When: "old-absent"}, {Method: "GET", ID: newID, When: "old-absent"}}
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			out.Ended = time.Now()
			return out, fmt.Errorf("session measurement cancelled: %w", err)
		}
		if !time.Now().Before(deadline) {
			out.Ended = time.Now()
			if lastErr == nil {
				lastErr = errors.New("no bounded same-UID session observation completed")
			}
			return out, fmt.Errorf("session replacement did not converge within %.0fs after %d attempts (%d failed): %w", sessionMeasurementLimit.Seconds(), out.Attempts, out.Failures, lastErr)
		}
		out.Attempts++
		batch, err := performSessionBatch(measurementCtx, env, operations, s.producerUID)
		if err == nil {
			pod, corroborateErr := s.corroborateSessionWorkload(measurementCtx, env, batch.ServedUID, false)
			absent, absenceErr := s.originalSessionUIDAbsent(measurementCtx, env)
			if corroborateErr == nil && absenceErr == nil {
				if !absent && pod.UID != s.originalUID {
					err = fmt.Errorf("original UID survives while the bounded batch was served by replacement UID %s", pod.UID)
				} else {
					out.Ended, out.OriginalAbsent, out.Pod, out.Batch = time.Now(), absent, pod, batch
					return out, nil
				}
			} else {
				err = errors.Join(corroborateErr, absenceErr)
			}
		}
		out.Failures++
		lastErr = err
		env.Log.Logf("c2-ephemeral-session-rotation measurement-attempt=%d failed=%q", out.Attempts, err)
		wait := sessionMeasurementRetry
		if remaining := time.Until(deadline); wait > remaining {
			wait = remaining
		}
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-measurementCtx.Done():
			timer.Stop()
			if err := ctx.Err(); err != nil {
				out.Ended = time.Now()
				return out, fmt.Errorf("session measurement cancelled: %w", err)
			}
			continue
		case <-timer.C:
		}
	}
}

func (s *c2EphemeralSessionRotation) Teardown(ctx context.Context, env *core.Env) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	var errs []error
	if s.deploymentUID != "" {
		opts := sessionDeleteOptions(s.deploymentUID)
		env.Log.Command(fmt.Sprintf("kubectl delete deployment %s -n %s --preconditions uid=%s", sessionDeployment, env.Config.Namespace, s.deploymentUID))
		if err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Delete(ctx, sessionDeployment, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete session deployment uid=%s: %w", s.deploymentUID, err))
		}
	}
	if s.serviceUID != "" {
		opts := sessionDeleteOptions(s.serviceUID)
		env.Log.Command(fmt.Sprintf("kubectl delete service %s -n %s --preconditions uid=%s", sessionService, env.Config.Namespace, s.serviceUID))
		if err := env.Kube.CoreV1().Services(env.Config.Namespace).Delete(ctx, sessionService, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete session service uid=%s: %w", s.serviceUID, err))
		}
	}
	if s.producerUID != "" {
		opts := sessionDeleteOptions(s.producerUID)
		env.Log.Command(fmt.Sprintf("kubectl delete pod %s -n %s --grace-period=0 --preconditions uid=%s", sessionProducer, env.Config.Namespace, s.producerUID))
		if err := env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, sessionProducer, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete session producer uid=%s: %w", s.producerUID, err))
		}
	}
	return errors.Join(errs...)
}

func sessionDeleteOptions(uid types.UID) metav1.DeleteOptions {
	grace := int64(0)
	dp := metav1.DeletePropagationBackground
	return metav1.DeleteOptions{GracePeriodSeconds: &grace, PropagationPolicy: &dp, Preconditions: &metav1.Preconditions{UID: &uid}}
}

func waitBenignSessionObservation(ctx context.Context, interval time.Duration) (time.Time, time.Time, error) {
	started := time.Now()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return started, time.Now(), ctx.Err()
	case <-timer.C:
		return started, time.Now(), nil
	}
}

type sessionReply struct {
	HTTPStatus int `json:"httpStatus"`
	Body       struct {
		PodUID  string `json:"podUID"`
		ID      string `json:"id"`
		Present bool   `json:"present"`
		Created bool   `json:"created"`
	} `json:"body"`
}

type sessionBatchOperation struct {
	Method string `json:"method"`
	ID     string `json:"id"`
	When   string `json:"when"`
}

type sessionBatchResponse struct {
	Operation      sessionBatchOperation
	Destination    string
	Started        time.Time
	Ended          time.Time
	Reply          sessionReply
	Skipped        string
	TransportError string
}

type sessionBatchResult struct {
	Started   time.Time
	Ended     time.Time
	Responses []sessionBatchResponse
	ServedUID types.UID
}

const (
	sessionReceiptStdoutLimit = 16384
	sessionReceiptStderrLimit = 2048
)

type sessionHTTPReceipt struct {
	Method                   string                  `json:"method,omitempty"`
	SyntheticSessionID       string                  `json:"syntheticSessionID,omitempty"`
	Operations               []sessionBatchOperation `json:"operations"`
	ServiceURL               string                  `json:"serviceURL"`
	ProducerName             string                  `json:"producerName"`
	ExpectedProducerUID      string                  `json:"expectedProducerUID"`
	ObservedProducerUID      string                  `json:"observedProducerUID,omitempty"`
	ObservedProducerUIDAfter string                  `json:"observedProducerUIDAfter,omitempty"`
	BatchStartedAtUTC        string                  `json:"batchStartedAtUTC"`
	BatchEndedAtUTC          string                  `json:"batchEndedAtUTC"`
	BatchDeadlineSeconds     string                  `json:"batchDeadlineSeconds"`
	IdentityError            string                  `json:"identityError,omitempty"`
	ExitCode                 int                     `json:"exitCode"`
	Stdout                   string                  `json:"stdout"`
	StdoutBytes              int                     `json:"stdoutBytes"`
	StdoutSHA256             string                  `json:"stdoutSHA256"`
	StdoutTruncated          bool                    `json:"stdoutTruncated"`
	Stderr                   string                  `json:"stderr"`
	StderrBytes              int                     `json:"stderrBytes"`
	StderrSHA256             string                  `json:"stderrSHA256"`
	StderrTruncated          bool                    `json:"stderrTruncated"`
	ExecError                string                  `json:"execError,omitempty"`
	ContextError             string                  `json:"contextError,omitempty"`
}

func boundedSessionReceipt(value string, limit int) (captured string, size int, digest string, truncated bool) {
	raw := []byte(value)
	sum := sha256.Sum256(raw)
	if len(raw) > limit {
		raw = raw[:limit]
		truncated = true
	}
	return string(raw), len(value), fmt.Sprintf("%x", sum), truncated
}

func recordSessionHTTPReceipt(env *core.Env, receipt sessionHTTPReceipt) {
	raw, err := json.Marshal(receipt)
	if err != nil {
		env.Log.Logf("c2-ephemeral-session-rotation http-receipt marshal-error=%q", err)
		return
	}
	env.Log.Logf("c2-ephemeral-session-rotation http-receipt=%s", raw)
}

func performSessionRequest(ctx context.Context, env *core.Env, method, id string, expectedProducerUID types.UID) (sessionReply, error) {
	batch, err := performSessionBatch(ctx, env, []sessionBatchOperation{{Method: method, ID: id, When: "always"}}, expectedProducerUID)
	if err != nil {
		return sessionReply{}, err
	}
	if len(batch.Responses) != 1 {
		return sessionReply{}, fmt.Errorf("single session request returned %d replies", len(batch.Responses))
	}
	return batch.Responses[0].Reply, nil
}

func performSessionBatch(ctx context.Context, env *core.Env, operations []sessionBatchOperation, expectedProducerUID types.UID) (sessionBatchResult, error) {
	var out sessionBatchResult
	url := fmt.Sprintf("http://%s:%d", sessionService, sessionPort)
	execTimeout, producerBudget := sessionBatchExecTimeout, sessionBatchHTTPBudget
	if callerDeadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(callerDeadline)
		if remaining < execTimeout {
			execTimeout = remaining
		}
		if bounded := execTimeout - 100*time.Millisecond; bounded < producerBudget {
			producerBudget = bounded
		}
	}
	receipt := sessionHTTPReceipt{Operations: append([]sessionBatchOperation(nil), operations...), ServiceURL: url, ProducerName: sessionProducer, ExpectedProducerUID: string(expectedProducerUID), BatchDeadlineSeconds: strconv.FormatFloat(producerBudget.Seconds(), 'f', 3, 64), ExitCode: -1}
	if len(operations) == 1 {
		receipt.Method, receipt.SyntheticSessionID = operations[0].Method, operations[0].ID
	}
	if err := validateSessionBatchOperations(operations); err != nil {
		receipt.IdentityError = err.Error()
		recordSessionHTTPReceipt(env, receipt)
		return out, err
	}
	if execTimeout <= 100*time.Millisecond || producerBudget <= 0 {
		err := fmt.Errorf("HTTP batch caller deadline leaves no bounded producer interval: remaining=%s", execTimeout)
		receipt.ContextError = err.Error()
		recordSessionHTTPReceipt(env, receipt)
		return out, err
	}
	batchCtx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	if err := batchCtx.Err(); err != nil {
		receipt.ContextError = err.Error()
		recordSessionHTTPReceipt(env, receipt)
		return out, fmt.Errorf("HTTP batch cancelled: %w", err)
	}
	producer, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(batchCtx, sessionProducer, metav1.GetOptions{})
	if err != nil {
		receipt.IdentityError = err.Error()
		recordSessionHTTPReceipt(env, receipt)
		return out, fmt.Errorf("read HTTP producer identity: %w", err)
	}
	receipt.ObservedProducerUID = string(producer.UID)
	if err := validateSessionProducer(env, producer, expectedProducerUID); err != nil {
		receipt.IdentityError = err.Error()
		recordSessionHTTPReceipt(env, receipt)
		return out, err
	}
	rawOperations, err := json.Marshal(operations)
	if err != nil {
		return out, fmt.Errorf("marshal HTTP batch operations: %w", err)
	}
	receipt.BatchStartedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	res := env.Exec(batchCtx, sessionProducer, "producer", []string{"python3", "-B", "-c", sessionClientSource, url, base64.StdEncoding.EncodeToString(rawOperations), strconv.FormatFloat(producerBudget.Seconds(), 'f', 3, 64)})
	receipt.BatchEndedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	receipt.ExitCode = res.ExitCode
	receipt.Stdout, receipt.StdoutBytes, receipt.StdoutSHA256, receipt.StdoutTruncated = boundedSessionReceipt(res.Stdout, sessionReceiptStdoutLimit)
	receipt.Stderr, receipt.StderrBytes, receipt.StderrSHA256, receipt.StderrTruncated = boundedSessionReceipt(res.Stderr, sessionReceiptStderrLimit)
	if res.Err != nil {
		receipt.ExecError = res.Err.Error()
	}
	producerAfter, identityErr := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(batchCtx, sessionProducer, metav1.GetOptions{})
	if identityErr == nil {
		receipt.ObservedProducerUIDAfter = string(producerAfter.UID)
		identityErr = validateSessionProducer(env, producerAfter, expectedProducerUID)
	}
	if identityErr != nil {
		receipt.IdentityError = identityErr.Error()
	}
	if err := batchCtx.Err(); err != nil {
		receipt.ContextError = err.Error()
		recordSessionHTTPReceipt(env, receipt)
		return out, fmt.Errorf("HTTP batch cancelled or exceeded %.3fs: %w", execTimeout.Seconds(), err)
	}
	// Persist exact bounded stdout/stderr and producer identity before parsing.
	recordSessionHTTPReceipt(env, receipt)
	if res.Err != nil {
		return out, fmt.Errorf("HTTP batch transport/exec failed: %w", res.Err)
	}
	if res.ExitCode != 0 {
		return out, fmt.Errorf("HTTP batch producer exited %d: %s", res.ExitCode, truncateSessionDetail(res.Stderr))
	}
	if identityErr != nil {
		return out, fmt.Errorf("HTTP producer identity changed across batch: %w", identityErr)
	}
	if len(res.Stdout) > sessionReceiptStdoutLimit {
		return out, fmt.Errorf("HTTP batch reply exceeded %d bytes", sessionReceiptStdoutLimit)
	}
	out, err = parseSessionBatchReply([]byte(res.Stdout), operations, producerBudget, url)
	if err != nil {
		return out, err
	}
	return out, nil
}

func validateSessionBatchOperations(operations []sessionBatchOperation) error {
	if len(operations) < 1 || len(operations) > 3 {
		return fmt.Errorf("session HTTP batch operation count %d is outside 1..3", len(operations))
	}
	for i, operation := range operations {
		if operation.Method != "GET" && operation.Method != "POST" {
			return fmt.Errorf("session HTTP batch operation %d has unsupported method %q", i, operation.Method)
		}
		if operation.ID == "" || len(operation.ID) > 64 {
			return fmt.Errorf("session HTTP batch operation %d has invalid ID", i)
		}
		for _, r := range operation.ID {
			if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("session HTTP batch operation %d has invalid ID", i)
			}
		}
		if operation.When != "always" && operation.When != "old-absent" {
			return fmt.Errorf("session HTTP batch operation %d has invalid condition %q", i, operation.When)
		}
		if i == 0 && operation.When != "always" {
			return errors.New("first session HTTP batch operation must always execute")
		}
	}
	return nil
}

func validateSessionProducer(env *core.Env, pod *corev1.Pod, expectedUID types.UID) error {
	if pod == nil || expectedUID == "" || pod.UID == "" || pod.UID != expectedUID || pod.DeletionTimestamp != nil || !podReady(pod) {
		return fmt.Errorf("producer UID/readiness mismatch: observed=%q expected=%q", func() types.UID {
			if pod == nil {
				return ""
			}
			return pod.UID
		}(), expectedUID)
	}
	expectedLabels := env.OwnedLabels(map[string]string{"app": sessionProducer})
	for key, value := range expectedLabels {
		if pod.Labels[key] != value {
			return fmt.Errorf("producer label %q differs", key)
		}
	}
	if len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "producer" || pod.Spec.Containers[0].Image != sessionPythonImage || !slices.Equal(pod.Spec.Containers[0].Command, []string{"python3", "-c", "import time; time.sleep(3600)"}) {
		return errors.New("producer container/image identity differs")
	}
	return nil
}

type sessionBatchWire struct {
	Version      *int                       `json:"version"`
	StartedAtUTC *string                    `json:"startedAtUTC"`
	EndedAtUTC   *string                    `json:"endedAtUTC"`
	Responses    []sessionBatchResponseWire `json:"responses"`
}

type sessionBatchResponseWire struct {
	Method         *string `json:"method"`
	ID             *string `json:"id"`
	Destination    *string `json:"destination"`
	StartedAtUTC   *string `json:"startedAtUTC"`
	EndedAtUTC     *string `json:"endedAtUTC"`
	HTTPStatus     *int    `json:"httpStatus,omitempty"`
	BodyBase64     *string `json:"bodyBase64,omitempty"`
	BodyBytes      *int    `json:"bodyBytes,omitempty"`
	BodySHA256     *string `json:"bodySHA256,omitempty"`
	Skipped        *string `json:"skipped,omitempty"`
	TransportError *string `json:"transportError,omitempty"`
	ProtocolError  *string `json:"protocolError,omitempty"`
}

func parseSessionBatchReply(raw []byte, operations []sessionBatchOperation, budget time.Duration, serviceURL string) (sessionBatchResult, error) {
	var out sessionBatchResult
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return out, err
	}
	var wire sessionBatchWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return out, fmt.Errorf("malformed HTTP batch JSON: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return out, err
	}
	if wire.Version == nil || *wire.Version != 1 || wire.StartedAtUTC == nil || wire.EndedAtUTC == nil || len(wire.Responses) != len(operations) {
		return out, errors.New("HTTP batch envelope required fields/version/count differ")
	}
	var err error
	out.Started, err = time.Parse(time.RFC3339Nano, *wire.StartedAtUTC)
	if err != nil {
		return out, fmt.Errorf("HTTP batch start timestamp: %w", err)
	}
	out.Ended, err = time.Parse(time.RFC3339Nano, *wire.EndedAtUTC)
	if budget <= 0 || budget > sessionBatchHTTPBudget || err != nil || out.Ended.Before(out.Started) || out.Ended.Sub(out.Started) > budget+100*time.Millisecond {
		return out, fmt.Errorf("HTTP batch end timestamp/bound differs: start=%s end=%s err=%v", out.Started, out.Ended, err)
	}
	oldAbsent := false
	previousEnd := out.Started
	for i, item := range wire.Responses {
		op := operations[i]
		expectedDestination := serviceURL + "/session?id=" + op.ID
		if item.Method == nil || item.ID == nil || item.Destination == nil || item.StartedAtUTC == nil || item.EndedAtUTC == nil || *item.Method != op.Method || *item.ID != op.ID || *item.Destination != expectedDestination {
			return out, fmt.Errorf("HTTP batch response %d identity/required fields differ", i)
		}
		response := sessionBatchResponse{Operation: op, Destination: *item.Destination}
		response.Started, err = time.Parse(time.RFC3339Nano, *item.StartedAtUTC)
		if err != nil {
			return out, fmt.Errorf("HTTP batch response %d start timestamp: %w", i, err)
		}
		response.Ended, err = time.Parse(time.RFC3339Nano, *item.EndedAtUTC)
		if err != nil || response.Ended.Before(response.Started) || response.Started.Before(previousEnd) || response.Ended.After(out.Ended) {
			return out, fmt.Errorf("HTTP batch response %d timestamp order differs", i)
		}
		previousEnd = response.Ended
		if item.Skipped != nil {
			response.Skipped = *item.Skipped
			if op.When != "old-absent" || oldAbsent || response.Skipped != "old-session-not-explicitly-absent" || item.TransportError != nil || item.ProtocolError != nil || item.HTTPStatus != nil || item.BodyBase64 != nil || item.BodyBytes != nil || item.BodySHA256 != nil {
				return out, fmt.Errorf("HTTP batch response %d invalid skip", i)
			}
			out.Responses = append(out.Responses, response)
			continue
		}
		if op.When == "old-absent" && !oldAbsent {
			return out, fmt.Errorf("HTTP batch response %d executed despite failed old-absence condition", i)
		}
		hasBodyEvidence := item.HTTPStatus != nil || item.BodyBase64 != nil || item.BodyBytes != nil || item.BodySHA256 != nil
		var bodyRaw []byte
		if hasBodyEvidence {
			if item.HTTPStatus == nil || item.BodyBase64 == nil || item.BodyBytes == nil || item.BodySHA256 == nil {
				return out, fmt.Errorf("HTTP batch response %d has partial body evidence", i)
			}
			bodyRaw, err = base64.StdEncoding.Strict().DecodeString(*item.BodyBase64)
			if err != nil || len(bodyRaw) != *item.BodyBytes || fmt.Sprintf("%x", sha256.Sum256(bodyRaw)) != *item.BodySHA256 {
				return out, fmt.Errorf("HTTP batch response %d body bytes/hash differ: %v", i, err)
			}
		}
		if item.TransportError != nil {
			response.TransportError = *item.TransportError
			out.Responses = append(out.Responses, response)
			return out, fmt.Errorf("HTTP batch response %d transport failed after %d retained body bytes: %s", i, len(bodyRaw), response.TransportError)
		}
		if item.ProtocolError != nil {
			out.Responses = append(out.Responses, response)
			return out, fmt.Errorf("HTTP batch response %d protocol failed after %d retained body bytes: %s", i, len(bodyRaw), *item.ProtocolError)
		}
		if !hasBodyEvidence {
			return out, fmt.Errorf("HTTP batch response %d omitted status/body evidence", i)
		}
		if len(bodyRaw) > 1024 {
			return out, fmt.Errorf("HTTP batch response %d body exceeded 1024 bytes without protocol error", i)
		}
		body, parseErr := parseSessionBody(bodyRaw, op.Method)
		if parseErr != nil {
			return out, fmt.Errorf("HTTP batch response %d: %w", i, parseErr)
		}
		if body.PodUID == "" || body.ID != op.ID {
			return out, fmt.Errorf("HTTP batch response %d identity mismatch: podUID=%q id=%q", i, body.PodUID, body.ID)
		}
		response.Reply = sessionReply{HTTPStatus: *item.HTTPStatus, Body: body}
		if response.Reply.HTTPStatus != 200 && response.Reply.HTTPStatus != 201 && response.Reply.HTTPStatus != 404 {
			return out, fmt.Errorf("HTTP batch response %d returned unusable status %d", i, response.Reply.HTTPStatus)
		}
		if out.ServedUID == "" {
			out.ServedUID = types.UID(body.PodUID)
		} else if out.ServedUID != types.UID(body.PodUID) {
			return out, fmt.Errorf("HTTP batch changed serving Pod UID from %s to %s", out.ServedUID, body.PodUID)
		}
		if i == 0 {
			oldAbsent = response.Reply.HTTPStatus == 404 && !response.Reply.Body.Present
		}
		out.Responses = append(out.Responses, response)
	}
	if out.ServedUID == "" {
		return out, errors.New("HTTP batch had no served Pod UID")
	}
	return out, nil
}

func parseSessionBody(raw []byte, method string) (struct {
	PodUID  string `json:"podUID"`
	ID      string `json:"id"`
	Present bool   `json:"present"`
	Created bool   `json:"created"`
}, error) {
	var body struct {
		PodUID  string `json:"podUID"`
		ID      string `json:"id"`
		Present bool   `json:"present"`
		Created bool   `json:"created"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return body, fmt.Errorf("malformed HTTP JSON object: %w", err)
	}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return body, fmt.Errorf("malformed HTTP JSON key: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return body, errors.New("malformed non-string HTTP JSON key")
		}
		if seen[key] {
			return body, fmt.Errorf("duplicate HTTP JSON field %q", key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return body, fmt.Errorf("malformed HTTP JSON field %q: %w", key, err)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return body, fmt.Errorf("HTTP JSON field %q is null", key)
		}
		switch key {
		case "podUID":
			if err := json.Unmarshal(value, &body.PodUID); err != nil {
				return body, fmt.Errorf("HTTP JSON field podUID is not a string: %w", err)
			}
		case "id":
			if err := json.Unmarshal(value, &body.ID); err != nil {
				return body, fmt.Errorf("HTTP JSON field id is not a string: %w", err)
			}
		case "present":
			if err := json.Unmarshal(value, &body.Present); err != nil {
				return body, fmt.Errorf("HTTP JSON field present is not a boolean: %w", err)
			}
		case "created":
			if method != "POST" {
				return body, errors.New("unexpected HTTP JSON field \"created\" for GET")
			}
			if err := json.Unmarshal(value, &body.Created); err != nil {
				return body, fmt.Errorf("HTTP JSON field created is not a boolean: %w", err)
			}
		default:
			return body, fmt.Errorf("unknown or case-variant HTTP JSON field %q", key)
		}
	}
	if _, err := dec.Token(); err != nil {
		return body, fmt.Errorf("malformed HTTP JSON object end: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return body, err
	}
	required := []string{"podUID", "id", "present"}
	if method == "POST" {
		required = append(required, "created")
	} else if method != "GET" {
		return body, fmt.Errorf("unsupported session HTTP method %q", method)
	}
	for _, key := range required {
		if !seen[key] {
			return body, fmt.Errorf("required HTTP JSON field %q is absent", key)
		}
	}
	return body, nil
}

func rejectDuplicateJSONFields(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("HTTP batch JSON object has non-string key")
				}
				if seen[key] {
					return fmt.Errorf("duplicate HTTP batch JSON field %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("malformed HTTP batch JSON object")
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("malformed HTTP batch JSON array")
			}
		default:
			return errors.New("malformed HTTP batch JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return fmt.Errorf("malformed HTTP batch JSON: %w", err)
	}
	if dec.More() {
		return errors.New("malformed trailing HTTP batch JSON")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("malformed trailing HTTP batch JSON")
	}
	return nil
}

func (s *c2EphemeralSessionRotation) originalSessionUIDAbsent(ctx context.Context, env *core.Env) (bool, error) {
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		recordSessionIdentityReceipt(env, sessionIdentityReceipt{ObservedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), ExpectedOriginalUID: string(s.originalUID), Error: err.Error()})
		return false, fmt.Errorf("list namespace for original session UID: %w", err)
	}
	receipt := sessionIdentityReceipt{ObservedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), ExpectedOriginalUID: string(s.originalUID)}
	present := false
	for i := range pods.Items {
		if pods.Items[i].UID == s.originalUID {
			if present {
				receipt.Error = fmt.Sprintf("original session UID %s appeared more than once", s.originalUID)
				recordSessionIdentityReceipt(env, receipt)
				return false, errors.New(receipt.Error)
			}
			present = true
			receipt.OriginalPodObject, err = rawSessionIdentityObject("original Pod", &pods.Items[i])
			if err != nil {
				receipt.Error = err.Error()
				recordSessionIdentityReceipt(env, receipt)
				return false, err
			}
		}
	}
	receipt.OriginalUIDPresent = &present
	recordSessionIdentityReceipt(env, receipt)
	return !present, nil
}

func (s *c2EphemeralSessionRotation) corroborateSessionWorkload(ctx context.Context, env *core.Env, servedUID types.UID, captureReplicaSet bool) (observed *corev1.Pod, observedErr error) {
	receipt := sessionIdentityReceipt{ObservedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), ServedPodUID: string(servedUID), ExpectedOriginalUID: string(s.originalUID)}
	defer func() {
		if observedErr != nil {
			receipt.Error = observedErr.Error()
		}
		recordSessionIdentityReceipt(env, receipt)
	}()
	if servedUID == "" || s.deploymentUID == "" || s.serviceUID == "" {
		return nil, errors.New("session workload identity provenance missing")
	}
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespace for served session UID: %w", err)
	}
	var pod *corev1.Pod
	for i := range pods.Items {
		if pods.Items[i].UID == servedUID {
			if pod != nil {
				return nil, fmt.Errorf("served session UID %s appeared more than once", servedUID)
			}
			pod = pods.Items[i].DeepCopy()
		}
	}
	if pod == nil || !podReady(pod) || pod.DeletionTimestamp != nil {
		return nil, fmt.Errorf("served session Pod uid=%s is absent, terminating, or not Ready", servedUID)
	}
	receipt.PodObject, err = rawSessionIdentityObject("Pod", pod)
	if err != nil {
		return nil, err
	}
	receipt.PodName, receipt.PodUID = pod.Name, string(pod.UID)
	receipt.PodReady, receipt.PodDeleting = podReady(pod), pod.DeletionTimestamp != nil
	receipt.PodLabels = cloneStringMap(pod.Labels)
	receipt.PodSourceSHA256 = pod.Annotations["r6th.io/session-source-sha256"]
	if len(pod.Spec.Containers) == 1 {
		receipt.PodImage = pod.Spec.Containers[0].Image
	}
	expectedLabels := env.OwnedLabels(map[string]string{"app": sessionApp, defenders.RotationTargetLabel: "true"})
	for key, value := range expectedLabels {
		if pod.Labels[key] != value {
			return nil, fmt.Errorf("served session Pod label %q differs", key)
		}
	}
	if pod.Annotations["r6th.io/session-source-sha256"] != sessionServerSourceSHA256() || len(pod.Spec.Containers) != 1 {
		return nil, errors.New("served session Pod source/container provenance differs")
	}
	container := pod.Spec.Containers[0]
	if container.Name != "session" || container.Image != sessionPythonImage || len(container.Command) != 4 || container.Command[0] != "python3" || container.Command[1] != "-B" || container.Command[2] != "-c" || container.Command[3] != sessionServerSource {
		return nil, errors.New("served session Pod image/source command differs")
	}
	var rsName string
	var rsUID types.UID
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "ReplicaSet" && owner.Controller != nil && *owner.Controller {
			if rsUID != "" {
				return nil, errors.New("served session Pod has multiple controller ReplicaSets")
			}
			rsName, rsUID = owner.Name, owner.UID
		}
	}
	if rsName == "" || rsUID == "" {
		return nil, errors.New("served session Pod controller ReplicaSet identity missing")
	}
	receipt.ReplicaSetName, receipt.ReplicaSetUID = rsName, string(rsUID)
	if captureReplicaSet {
		s.replicaSetName, s.replicaSetUID = rsName, rsUID
	} else if rsName != s.replicaSetName || rsUID != s.replicaSetUID {
		return nil, fmt.Errorf("served session Pod ReplicaSet changed: name=%s uid=%s", rsName, rsUID)
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, rsName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read exact session ReplicaSet: %w", err)
	}
	receipt.ReplicaSetObject, err = rawSessionIdentityObject("ReplicaSet", rs)
	if err != nil {
		return nil, err
	}
	if rs.UID != rsUID {
		return nil, fmt.Errorf("exact session ReplicaSet UID differs: observed=%s expected=%s", rs.UID, rsUID)
	}
	owned := false
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" && owner.Name == sessionDeployment && owner.UID == s.deploymentUID && owner.Controller != nil && *owner.Controller {
			owned = true
		}
	}
	if !owned {
		return nil, errors.New("served session ReplicaSet is not owned by exact Deployment UID")
	}
	dep, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Get(ctx, sessionDeployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read exact session Deployment: %w", err)
	}
	receipt.DeploymentObject, err = rawSessionIdentityObject("Deployment", dep)
	if err != nil {
		return nil, err
	}
	if dep.UID != s.deploymentUID {
		return nil, fmt.Errorf("session Deployment UID changed: observed=%s expected=%s", dep.UID, s.deploymentUID)
	}
	receipt.DeploymentUID = string(dep.UID)
	for key, value := range env.OwnedLabels(map[string]string{"app": sessionApp}) {
		if dep.Labels[key] != value {
			return nil, fmt.Errorf("session Deployment label %q differs", key)
		}
	}
	svc, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, sessionService, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read exact session Service: %w", err)
	}
	receipt.ServiceObject, err = rawSessionIdentityObject("Service", svc)
	if err != nil {
		return nil, err
	}
	if svc.UID != s.serviceUID {
		return nil, fmt.Errorf("session Service UID changed: observed=%s expected=%s", svc.UID, s.serviceUID)
	}
	receipt.ServiceUID, receipt.ServiceSelector = string(svc.UID), cloneStringMap(svc.Spec.Selector)
	if len(svc.Spec.Selector) != 1 || svc.Spec.Selector["app"] != sessionApp || len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != sessionPort || svc.Spec.Ports[0].TargetPort != intstr.FromString("http") {
		return nil, errors.New("session Service selector/port differs")
	}
	for key, value := range env.OwnedLabels(map[string]string{"app": sessionApp}) {
		if svc.Labels[key] != value {
			return nil, fmt.Errorf("session Service label %q differs", key)
		}
	}
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + sessionService})
	if err != nil {
		return nil, fmt.Errorf("list session EndpointSlices: %w", err)
	}
	identityBytes := len(receipt.PodObject) + len(receipt.ReplicaSetObject) + len(receipt.DeploymentObject) + len(receipt.ServiceObject)
	if identityBytes > sessionIdentityTotalLimit {
		return nil, fmt.Errorf("session identity objects exceed %d bytes", sessionIdentityTotalLimit)
	}
	readyTargets := 0
	for i := range slices.Items {
		slice := &slices.Items[i]
		rawSlice, marshalErr := rawSessionIdentityObject("EndpointSlice", slice)
		if marshalErr != nil {
			return nil, marshalErr
		}
		identityBytes += len(rawSlice)
		if identityBytes > sessionIdentityTotalLimit {
			return nil, fmt.Errorf("session identity objects exceed %d bytes", sessionIdentityTotalLimit)
		}
		receipt.EndpointSliceObjects = append(receipt.EndpointSliceObjects, rawSlice)
		ownedByService := false
		for _, owner := range slice.OwnerReferences {
			if owner.Kind == "Service" && owner.Name == sessionService && owner.UID == s.serviceUID && owner.Controller != nil && *owner.Controller {
				ownedByService = true
			}
		}
		if !ownedByService {
			return nil, fmt.Errorf("session EndpointSlice %q is not owned by exact Service UID", slice.Name)
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			readyTargets++
			if endpoint.TargetRef != nil {
				receipt.ReadyEndpointUIDs = append(receipt.ReadyEndpointUIDs, string(endpoint.TargetRef.UID))
			}
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != env.Config.Namespace || endpoint.TargetRef.Name != pod.Name || endpoint.TargetRef.UID != pod.UID {
				return nil, fmt.Errorf("session ready endpoint is not exact served Pod UID %s", pod.UID)
			}
		}
	}
	if readyTargets != 1 {
		return nil, fmt.Errorf("session Service has %d ready endpoint targets; require exactly one", readyTargets)
	}
	return pod, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("malformed trailing HTTP producer reply: %w", err)
	}
	return errors.New("malformed HTTP producer reply: multiple JSON values")
}

func truncateSessionDetail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

func sessionServerSourceSHA256() string {
	sum := sha256.Sum256([]byte(sessionServerSource))
	return fmt.Sprintf("%x", sum)
}

func readySessionPod(ctx context.Context, env *core.Env, app string, timeout time.Duration) (*corev1.Pod, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + app})
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			var ready []*corev1.Pod
			for i := range pods.Items {
				if podReady(&pods.Items[i]) {
					ready = append(ready, &pods.Items[i])
				}
			}
			if len(ready) == 1 {
				return ready[0], nil
			}
			if len(ready) > 1 {
				return nil, fmt.Errorf("session target app=%s has %d ready Pods; original identity is ambiguous", app, len(ready))
			}
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return nil, fmt.Errorf("session target lookup failed: %w", lastErr)
			}
			return nil, fmt.Errorf("session target app=%s did not produce exactly one ready Pod", app)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("session target readiness cancelled: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func podReady(pod *corev1.Pod) bool {
	if pod == nil || pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
