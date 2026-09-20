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
	"strconv"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
)

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

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
`

// sessionClientSource executes inside the dedicated producer Pod. It always
// uses the stable ClusterIP Service, disables ambient proxy discovery, bounds
// response bytes, and preserves HTTP status separately from transport failure.
const sessionClientSource = `import base64, sys, urllib.error, urllib.parse, urllib.request
method, base, sid = sys.argv[1:]
url = base + "/session?" + urllib.parse.urlencode({"id": sid})
request = urllib.request.Request(url, method=method)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    response = opener.open(request, timeout=3)
except urllib.error.HTTPError as error:
    response = error
raw = response.read(1025)
if len(raw) > 1024:
    raise RuntimeError("response-too-large")
sys.stdout.write(str(response.status) + "\n" + base64.b64encode(raw).decode("ascii"))
`

type c2EphemeralSessionRotation struct {
	originalName  string
	originalUID   types.UID
	sessionID     string
	deploymentUID types.UID
	serviceUID    types.UID
	producerUID   types.UID
}

func (s *c2EphemeralSessionRotation) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:          "c2-ephemeral-session-rotation",
		Category:      core.CategoryR6Claimed,
		Source:        "Post25 catalogue gap: benign ephemeral application-state replacement control",
		R6ResponseTag: core.R6Partial,
		BenignControl: true,
		Realism:       core.RealismExecutable,
		Mechanism: fmt.Sprintf("actual HTTP through a stable ClusterIP Service to a controller-owned single-replica process-memory session fixture; image=%s serverSourceSHA256=%s",
			sessionPythonImage, sessionServerSourceSHA256()),
		ClaimLimits:        "benign application-state control only; executes no attack or exploit, exercises zero ATT&CK techniques, and does not establish credential revocation, attack prevention, detection, or security coverage",
		OracleDescription:  "original synthetic session remains usable only when the original Pod UID serves it; loss is credited only after exact original-UID absence, an exact replacement UID explicitly reports the old ID absent, and the same replacement creates and retrieves a new ID",
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
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: sessionDeployment, Namespace: env.Config.Namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": sessionApp}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: map[string]string{"r6th.io/session-source-sha256": sessionServerSourceSHA256()}},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &noToken,
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
	env.Log.Command(fmt.Sprintf("kubectl create deployment %s -n %s  # pinned CPU-only in-memory session fixture", sessionDeployment, env.Config.Namespace))
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
	env.Log.Command(fmt.Sprintf("kubectl run %s -n %s --image=%s  # HTTP producer", sessionProducer, env.Config.Namespace, sessionPythonImage))
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
	if err := ctx.Err(); err != nil {
		return core.AttackResult{}, fmt.Errorf("session producer cancelled: %w", err)
	}
	pod, err := readySessionPod(ctx, env, sessionApp, 40*time.Second)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.originalName, s.originalUID = pod.Name, pod.UID
	if env.Rand == nil {
		return core.AttackResult{}, errors.New("session producer has no deterministic trial RNG")
	}
	sid := fmt.Sprintf("session-%d-%016x", env.Trial, env.Rand.Uint64())
	created, err := performSessionRequest(ctx, env, "POST", sid)
	if err != nil {
		return core.AttackResult{Stages: []string{"create synthetic process-memory session through stable Service"}}, err
	}
	if created.HTTPStatus != 201 || !created.Body.Created || !created.Body.Present || created.Body.PodUID != string(s.originalUID) {
		return core.AttackResult{Stages: []string{"create synthetic process-memory session through stable Service"}}, fmt.Errorf("session create reply did not bind new state to original UID: status=%d created=%v present=%v replyUID=%q originalUID=%q", created.HTTPStatus, created.Body.Created, created.Body.Present, created.Body.PodUID, s.originalUID)
	}
	retained, err := performSessionRequest(ctx, env, "GET", sid)
	if err != nil {
		return core.AttackResult{Stages: []string{"create synthetic process-memory session through stable Service", "retrieve the same synthetic session ID"}}, err
	}
	if retained.HTTPStatus != 200 || !retained.Body.Present || retained.Body.PodUID != string(s.originalUID) {
		return core.AttackResult{Stages: []string{"create synthetic process-memory session through stable Service", "retrieve the same synthetic session ID"}}, fmt.Errorf("session retain reply did not confirm original process state: status=%d present=%v replyUID=%q originalUID=%q", retained.HTTPStatus, retained.Body.Present, retained.Body.PodUID, s.originalUID)
	}
	s.sessionID = sid
	return core.AttackResult{
		Stages: []string{"create synthetic process-memory session through stable Service", "retrieve the same synthetic session ID"},
		Notes: map[string]string{
			"originalPod":        s.originalName,
			"originalPodUID":     string(s.originalUID),
			"sessionID":          sid,
			"transport":          "ordinary HTTP via ClusterIP Service",
			"classification":     "benign functional-effect control",
			"fixtureImage":       sessionPythonImage,
			"serverSourceSHA256": sessionServerSourceSHA256(),
		},
	}, nil
}

func (s *c2EphemeralSessionRotation) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	if s.originalName == "" || s.originalUID == "" || s.sessionID == "" {
		return core.OracleResult{}, errors.New("session stimulus identity or synthetic ID missing")
	}
	pod, originalAbsent, err := c2DwellObservationTarget(ctx, env, sessionApp, s.originalName, s.originalUID)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("session identity observation: %w", err)
	}
	if pod.DeletionTimestamp != nil || !podReady(pod) {
		return core.OracleResult{}, fmt.Errorf("session observation target pod=%s uid=%s is not ready and non-terminating", pod.Name, pod.UID)
	}
	replayed, err := performSessionRequest(ctx, env, "GET", s.sessionID)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("replay original synthetic session: %w", err)
	}
	baseEvidence := map[string]string{
		"originalPodUID":     string(s.originalUID),
		"observedPodUID":     string(pod.UID),
		"serviceReplyPodUID": replayed.Body.PodUID,
		"originalUIDAbsent":  fmt.Sprintf("%v", originalAbsent),
		"oldSessionPresent":  fmt.Sprintf("%v", replayed.Body.Present),
		"oldSessionStatus":   fmt.Sprintf("%d", replayed.HTTPStatus),
		"transport":          "ordinary HTTP via ClusterIP Service",
		"classification":     "benign functional-effect control",
		"fixtureImage":       sessionPythonImage,
		"serverSourceSHA256": sessionServerSourceSHA256(),
	}
	if !originalAbsent {
		if pod.UID != s.originalUID {
			return core.OracleResult{}, fmt.Errorf("identity resolver reported original present but returned uid=%s", pod.UID)
		}
		if replayed.Body.PodUID != string(s.originalUID) {
			return core.OracleResult{}, fmt.Errorf("original UID %s still exists but Service answered from uid=%s; overlap is ambiguous", s.originalUID, replayed.Body.PodUID)
		}
		if replayed.HTTPStatus != 200 || !replayed.Body.Present {
			return core.OracleResult{}, fmt.Errorf("same original UID did not explicitly retain session: status=%d present=%v", replayed.HTTPStatus, replayed.Body.Present)
		}
		return core.OracleResult{Achieved: true, ObservedState: "benign control: same Pod UID served the same synthetic process-memory session ID", Evidence: baseEvidence}, nil
	}
	if replayed.Body.PodUID != string(pod.UID) {
		return core.OracleResult{}, fmt.Errorf("stable Service reply uid=%s does not match confirmed replacement uid=%s", replayed.Body.PodUID, pod.UID)
	}
	if replayed.HTTPStatus == 200 && replayed.Body.Present {
		return core.OracleResult{Achieved: true, ObservedState: "benign control: replacement retained the original synthetic session ID", Evidence: baseEvidence}, nil
	}
	if replayed.HTTPStatus != 404 || replayed.Body.Present {
		return core.OracleResult{}, fmt.Errorf("replacement did not explicitly report old synthetic session absent: status=%d present=%v", replayed.HTTPStatus, replayed.Body.Present)
	}
	newID := s.sessionID + "-new"
	created, err := performSessionRequest(ctx, env, "POST", newID)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("create replacement synthetic session: %w", err)
	}
	if created.HTTPStatus != 201 || !created.Body.Created || !created.Body.Present || created.Body.PodUID != string(pod.UID) {
		return core.OracleResult{}, fmt.Errorf("replacement could not create new process state: status=%d created=%v present=%v replyUID=%q replacementUID=%q", created.HTTPStatus, created.Body.Created, created.Body.Present, created.Body.PodUID, pod.UID)
	}
	verified, err := performSessionRequest(ctx, env, "GET", newID)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("retrieve replacement synthetic session: %w", err)
	}
	if verified.HTTPStatus != 200 || !verified.Body.Present || verified.Body.PodUID != string(pod.UID) {
		return core.OracleResult{}, fmt.Errorf("replacement did not retain newly created process state: status=%d present=%v replyUID=%q replacementUID=%q", verified.HTTPStatus, verified.Body.Present, verified.Body.PodUID, pod.UID)
	}
	baseEvidence["newSessionCreated"] = "true"
	baseEvidence["newSessionRetrieved"] = "true"
	return core.OracleResult{Achieved: false, ObservedState: "benign control: exact original UID was absent; confirmed replacement explicitly lacked the old synthetic ID and retained a new one", Evidence: baseEvidence}, nil
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

type sessionReply struct {
	HTTPStatus int `json:"httpStatus"`
	Body       struct {
		PodUID  string `json:"podUID"`
		ID      string `json:"id"`
		Present bool   `json:"present"`
		Created bool   `json:"created"`
	} `json:"body"`
}

func performSessionRequest(ctx context.Context, env *core.Env, method, id string) (sessionReply, error) {
	if err := ctx.Err(); err != nil {
		return sessionReply{}, fmt.Errorf("HTTP observation cancelled: %w", err)
	}
	url := fmt.Sprintf("http://%s:%d", sessionService, sessionPort)
	res := env.Exec(ctx, sessionProducer, "producer", []string{"python3", "-B", "-c", sessionClientSource, method, url, id})
	if err := ctx.Err(); err != nil {
		return sessionReply{}, fmt.Errorf("HTTP observation cancelled: %w", err)
	}
	if res.Err != nil {
		return sessionReply{}, fmt.Errorf("HTTP transport/exec failed: %w", res.Err)
	}
	if res.ExitCode != 0 {
		return sessionReply{}, fmt.Errorf("HTTP producer exited %d: %s", res.ExitCode, truncateSessionDetail(res.Stderr))
	}
	if len(res.Stdout) > 4096 {
		return sessionReply{}, errors.New("HTTP producer reply exceeded 4096 bytes")
	}
	reply, err := parseSessionReply(res.Stdout, method, id)
	if err != nil {
		return sessionReply{}, err
	}
	if reply.HTTPStatus >= 500 || reply.HTTPStatus < 200 || reply.HTTPStatus == 300 || reply.HTTPStatus == 301 || reply.HTTPStatus == 302 || reply.HTTPStatus == 307 || reply.HTTPStatus == 308 {
		return sessionReply{}, fmt.Errorf("HTTP observation returned unusable status %d", reply.HTTPStatus)
	}
	return reply, nil
}

func parseSessionReply(stdout, method, wantID string) (sessionReply, error) {
	parts := strings.Split(stdout, "\n")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return sessionReply{}, errors.New("malformed HTTP producer envelope")
	}
	for _, r := range parts[0] {
		if r < '0' || r > '9' {
			return sessionReply{}, errors.New("malformed HTTP status in producer envelope")
		}
	}
	status, err := strconv.Atoi(parts[0])
	if err != nil {
		return sessionReply{}, fmt.Errorf("malformed HTTP status in producer envelope: %w", err)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return sessionReply{}, fmt.Errorf("malformed base64 HTTP body: %w", err)
	}
	body, err := parseSessionBody(raw, method)
	if err != nil {
		return sessionReply{}, err
	}
	if body.PodUID == "" || body.ID != wantID {
		return sessionReply{}, fmt.Errorf("HTTP reply identity mismatch: podUID=%q id=%q wantID=%q", body.PodUID, body.ID, wantID)
	}
	return sessionReply{HTTPStatus: status, Body: body}, nil
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
