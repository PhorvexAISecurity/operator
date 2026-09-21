package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
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

func init() { core.RegisterScenario(&c2VoiceWebSocketContinuity{}) }

const (
	voiceWSScenario         = "c2-voice-websocket-continuity"
	voiceWSApp              = "c2-voice-ws"
	voiceWSTargetDeployment = "c2-voice-ws-target"
	voiceWSPeerDeployment   = "c2-voice-ws-peers"
	voiceWSTargetService    = "c2-voice-ws-target"
	voiceWSSharedService    = "c2-voice-ws"
	voiceWSProducer         = "c2-voice-ws-producer"
	voiceWSPort             = 8080
	voiceWSExpectedFrames   = 20

	// This is the observed voice workload image, pinned by immutable digest. The
	// scenario overrides its command with the complete fixture source below and
	// does not import workload configuration, Secrets, or provider clients.
	voiceWSRuntimeImage     = "753556437180.dkr.ecr.us-east-2.amazonaws.com/pipecat-voice@sha256:c9c598c406ed517eebf17f92a36863b39a15d9a7875cfcb2710f7b084dd539b8"
	voiceWSRuntimeDigest    = "sha256:c9c598c406ed517eebf17f92a36863b39a15d9a7875cfcb2710f7b084dd539b8"
	voiceWSRuntimeBotSHA256 = "23b2e6e72912b11a545e06f54af4159789dc3a79f0aaed74cd2ec636cbb371cf"

	voiceWSExecTimeout        = 30 * time.Second
	voiceWSFrameInterval      = 900 * time.Millisecond
	voiceWSAvailabilityPeriod = 200 * time.Millisecond
	voiceWSReplacementTimeout = 25 * time.Second
	voiceWSReceiptLimit       = 32 * 1024
)

// voiceWSServerSource is a deterministic protocol replica. It uses the runtime
// image's FastAPI/Starlette WebSocket stack, but no bot, speech, LLM, CRM,
// transcript, provider, or user-data path. The client sends Twilio-shaped
// connected/start/media/stop frames and the server returns a numbered synthetic
// media response for every input media frame followed by one explicit end mark.
const voiceWSServerSource = `import asyncio, json, os
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, Response
import uvicorn

app = FastAPI()
pod_uid = os.environ["POD_UID"]
allowed_hosts = set(os.environ["ALLOWED_WS_HOSTS"].split(","))

def strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise ValueError("duplicate-json-field")
        out[key] = value
    return out

def exact_object(raw, keys):
    obj = json.loads(raw, object_pairs_hook=strict_object)
    if type(obj) is not dict or set(obj) != set(keys): raise ValueError("invalid-frame-shape")
    return obj

@app.get("/healthz")
async def healthz():
    return JSONResponse({"ok": True, "podUID": pod_uid})

@app.post("/")
async def twiml(request: Request):
    length = request.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) > 4096): return Response(status_code=413)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 4096: return Response(status_code=413)
    host = request.headers.get("host", "")
    if host not in allowed_hosts: return Response(status_code=400)
    xml = '<?xml version="1.0" encoding="UTF-8"?><Response><Connect><Stream url="ws://' + host + '/ws"/></Connect></Response>'
    return Response(content=xml, media_type="application/xml")

@app.websocket("/ws")
async def voice_socket(ws: WebSocket):
    await ws.accept()
    async def receive_text(): return await asyncio.wait_for(ws.receive_text(), timeout=5)
    try:
        connected = exact_object(await receive_text(), ["event", "protocol", "version"])
        if connected != {"event":"connected", "protocol":"Call", "version":"1.0.0"}: raise ValueError("invalid-connected")
        start = exact_object(await receive_text(), ["event", "sequenceNumber", "start", "streamSid"])
        if start["event"] != "start" or start["sequenceNumber"] != "1" or type(start["streamSid"]) is not str: raise ValueError("invalid-start")
        detail = start["start"]
        if type(detail) is not dict or set(detail) != {"accountSid", "callSid", "streamSid"}: raise ValueError("invalid-start-detail")
        if detail["streamSid"] != start["streamSid"]: raise ValueError("stream-mismatch")
        stream = start["streamSid"]
        await ws.send_text(json.dumps({"event":"start", "podUID":pod_uid, "streamSid":stream}, sort_keys=True, separators=(",", ":")))
        expected = 2
        while True:
            frame = json.loads(await receive_text(), object_pairs_hook=strict_object)
            if type(frame) is not dict or frame.get("streamSid") != stream: raise ValueError("invalid-stream")
            if frame.get("event") == "media":
                if set(frame) != {"event", "media", "sequenceNumber", "streamSid"}: raise ValueError("invalid-media-shape")
                if frame["sequenceNumber"] != str(expected): raise ValueError("invalid-media-sequence")
                media = frame["media"]
                if type(media) is not dict or set(media) != {"payload"} or media["payload"] != "AA==": raise ValueError("invalid-media-payload")
                await ws.send_text(json.dumps({"event":"media", "media":{"payload":"AQ=="}, "podUID":pod_uid, "sequenceNumber":str(expected-1), "streamSid":stream}, sort_keys=True, separators=(",", ":")))
                expected += 1
                continue
            if frame.get("event") == "stop":
                if set(frame) != {"event", "sequenceNumber", "stop", "streamSid"} or frame["sequenceNumber"] != str(expected): raise ValueError("invalid-stop")
                if frame["stop"] != {"accountSid":"AC-synthetic", "callSid":"CA-synthetic"}: raise ValueError("invalid-stop-detail")
                await ws.send_text(json.dumps({"event":"mark", "mark":{"name":"end-" + str(expected-2)}, "podUID":pod_uid, "streamSid":stream}, sort_keys=True, separators=(",", ":")))
                await ws.close(code=1000, reason="synthetic-complete")
                return
            raise ValueError("invalid-event")
    except Exception:
        try: await ws.close(code=1002, reason="protocol-error")
        except Exception: pass

uvicorn.run(app, host="0.0.0.0", port=8080, access_log=False, lifespan="off", limit_concurrency=32, timeout_keep_alive=2, ws_max_size=16384, ws_max_queue=4)
`

// voiceWSClientSource runs inside a separately owned producer Pod. It fetches
// and validates the advertised TwiML URL, then performs an actual RFC 6455
// exchange through the target-only ClusterIP Service. Every result is emitted
// as one bounded JSON object; media contents are fixed synthetic bytes.
const voiceWSClientSource = `import asyncio, datetime, hashlib, json, sys, urllib.parse, urllib.request, xml.etree.ElementTree as ET
import websockets

base, session_id, count_text, interval_text = sys.argv[1:]
expected = int(count_text); interval = float(interval_text)
if not 1 <= expected <= 64 or not 0 <= interval <= 2: raise ValueError("invalid-bounds")
if not session_id or len(session_id) > 64: raise ValueError("invalid-session")

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
def strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise ValueError("duplicate-json-field")
        out[key] = value
    return out
base_parsed = urllib.parse.urlsplit(base)
if base_parsed.scheme != "http" or base_parsed.username is not None or base_parsed.password is not None or base_parsed.path or base_parsed.query or base_parsed.fragment or not base_parsed.hostname or base_parsed.port is None: raise ValueError("invalid-base-url")
result = {"version":1,"serviceURL":base,"sessionID":session_id,"startedAtUTC":now(),"endedAtUTC":"","twimlStatus":0,"twimlSHA256":"","webSocketURL":"","targetPodUID":"","outcome":"protocol-error","expectedFrames":expected,"receivedSequences":[],"duplicateSequences":0,"gaps":0,"endMarker":False,"closeCode":0,"failure":""}

async def run():
    data = urllib.parse.urlencode({"CallSid":"CA-synthetic","From":"+15550000000"}).encode()
    req = urllib.request.Request(base + "/", data=data, method="POST", headers={"Content-Type":"application/x-www-form-urlencoded"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, file_pointer, code, message, headers, new_url): return None
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(req, timeout=3) as response:
        raw = response.read(8193)
        result["twimlStatus"] = response.status; result["twimlSHA256"] = hashlib.sha256(raw).hexdigest()
    if result["twimlStatus"] != 200 or len(raw) > 8192: raise ValueError("invalid-twiml-http")
    root = ET.fromstring(raw)
    streams = root.findall("./Connect/Stream")
    if root.tag != "Response" or len(streams) != 1 or set(streams[0].attrib) != {"url"}: raise ValueError("invalid-twiml-shape")
    ws_url = streams[0].attrib["url"]
    parsed = urllib.parse.urlsplit(ws_url)
    if parsed.scheme != "ws" or parsed.username is not None or parsed.password is not None or parsed.path != "/ws" or parsed.query or parsed.fragment or parsed.hostname != base_parsed.hostname or parsed.port != base_parsed.port: raise ValueError("invalid-twiml-stream")
    result["webSocketURL"] = ws_url
    stream = "MZ-" + session_id
    try:
        async with websockets.connect(ws_url, open_timeout=3, close_timeout=1, max_size=16384) as ws:
            await ws.send(json.dumps({"event":"connected","protocol":"Call","version":"1.0.0"}, separators=(",", ":")))
            await ws.send(json.dumps({"event":"start","sequenceNumber":"1","start":{"accountSid":"AC-synthetic","callSid":"CA-synthetic","streamSid":stream},"streamSid":stream}, separators=(",", ":")))
            ack = json.loads(await asyncio.wait_for(ws.recv(), 3), object_pairs_hook=strict_object)
            if type(ack) is not dict or set(ack) != {"event","podUID","streamSid"} or ack["event"] != "start" or ack["streamSid"] != stream or type(ack["podUID"]) is not str or not ack["podUID"]: raise ValueError("invalid-start-ack")
            result["targetPodUID"] = ack["podUID"]
            seen = set()
            for index in range(1, expected + 1):
                await ws.send(json.dumps({"event":"media","media":{"payload":"AA=="},"sequenceNumber":str(index+1),"streamSid":stream}, separators=(",", ":")))
                reply = json.loads(await asyncio.wait_for(ws.recv(), 3), object_pairs_hook=strict_object)
                if type(reply) is not dict or set(reply) != {"event","media","podUID","sequenceNumber","streamSid"} or reply["event"] != "media" or reply["streamSid"] != stream or reply["podUID"] != result["targetPodUID"] or reply["media"] != {"payload":"AQ=="}: raise ValueError("invalid-media-reply")
                sequence_text = reply["sequenceNumber"]
                if type(sequence_text) is not str or not sequence_text or any(char not in "0123456789" for char in sequence_text) or (len(sequence_text) > 1 and sequence_text[0] == "0"): raise ValueError("invalid-media-reply-sequence")
                sequence = int(sequence_text)
                if sequence in seen: result["duplicateSequences"] += 1
                seen.add(sequence); result["receivedSequences"].append(sequence)
                if interval: await asyncio.sleep(interval)
            await ws.send(json.dumps({"event":"stop","sequenceNumber":str(expected+2),"stop":{"accountSid":"AC-synthetic","callSid":"CA-synthetic"},"streamSid":stream}, separators=(",", ":")))
            end = json.loads(await asyncio.wait_for(ws.recv(), 3), object_pairs_hook=strict_object)
            if type(end) is not dict or set(end) != {"event","mark","podUID","streamSid"} or end["event"] != "mark" or end["streamSid"] != stream or end["podUID"] != result["targetPodUID"] or end["mark"] != {"name":"end-" + str(expected)}: raise ValueError("invalid-end-marker")
            result["endMarker"] = True
            try: await ws.recv()
            except websockets.exceptions.ConnectionClosed as closed: result["closeCode"] = closed.code
            want = list(range(1, expected + 1))
            result["gaps"] = len(set(want) - set(result["receivedSequences"]))
            if result["receivedSequences"] != want or result["duplicateSequences"] or result["gaps"] or result["closeCode"] != 1000: raise ValueError("incomplete-sequence")
            result["outcome"] = "completed"
    except websockets.exceptions.ConnectionClosed as closed:
        result["closeCode"] = closed.code
        result["gaps"] = expected - len(set(result["receivedSequences"]))
        result["outcome"] = "early-close"
        result["failure"] = "connection-closed-before-end"

try: asyncio.run(asyncio.wait_for(run(), timeout=27))
except Exception as error:
    result["failure"] = type(error).__name__ + ":" + str(error)
result["endedAtUTC"] = now()
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
`

type c2VoiceWebSocketContinuity struct {
	targetDeploymentUID       types.UID
	peerDeploymentUID         types.UID
	targetServiceUID          types.UID
	sharedServiceUID          types.UID
	producerUID               types.UID
	originalName              string
	originalUID               types.UID
	replacementName           string
	replacementUID            types.UID
	originalAPIAbsent         bool
	originalDeletionTimestamp string
	originalAbsenceObservedAt string
	replacementObservedAt     string
	receipt                   voiceWSReceipt
	recovery                  voiceWSReceipt
	sharedProbe               voiceWSReceipt
	availability              voiceWSAvailability
}

type voiceWSReceipt struct {
	Version            int    `json:"version"`
	ServiceURL         string `json:"serviceURL"`
	SessionID          string `json:"sessionID"`
	StartedAtUTC       string `json:"startedAtUTC"`
	EndedAtUTC         string `json:"endedAtUTC"`
	TwiMLStatus        int    `json:"twimlStatus"`
	TwiMLSHA256        string `json:"twimlSHA256"`
	WebSocketURL       string `json:"webSocketURL"`
	TargetPodUID       string `json:"targetPodUID"`
	Outcome            string `json:"outcome"`
	ExpectedFrames     int    `json:"expectedFrames"`
	ReceivedSequences  []int  `json:"receivedSequences"`
	DuplicateSequences int    `json:"duplicateSequences"`
	Gaps               int    `json:"gaps"`
	EndMarker          bool   `json:"endMarker"`
	CloseCode          int    `json:"closeCode"`
	Failure            string `json:"failure"`
}

type voiceWSAvailability struct {
	Samples            int
	Failures           int
	MinimumReady       int
	OriginalSeen       bool
	OriginalAbsentSeen bool
	ObservedReadyUIDs  []string
}

func (s *c2VoiceWebSocketContinuity) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               voiceWSScenario,
		Category:           core.CategoryR6Claimed,
		Source:             "Post25 voice stack: hash-bound Twilio-shaped WebSocket continuity control",
		R6ResponseTag:      core.R6Partial,
		BenignControl:      true,
		Realism:            core.RealismExecutable,
		Mechanism:          fmt.Sprintf("actual RFC 6455 traffic from a separate producer through target and shared ClusterIP Services; one exact target plus two peer replicas; source-hashed deterministic Twilio-shaped fixture in runtime image %s", voiceWSRuntimeImage),
		ClaimLimits:        "synthetic transport and Kubernetes availability only; no speech, AI semantic quality, provider, transcript, threat, request-drain, or seamless-handoff claim",
		OracleDescription:  "no-action requires every numbered media response and the explicit end marker from one exact Pod UID; rotation requires exact original-UID absence, an incomplete established session, a Ready shared-endpoint floor of two in 200ms samples during the bounded exchange, and a distinct Ready replacement that completes a fresh session",
		CleanupDescription: "UID-preconditioned deletion of both Deployments, both Services and producer Pod; runner-owned cleanup separately verifies absence",
		R6Justification:    "An exact original Pod deletion during a timer-driven Pod-replacement comparison can coincide with established WebSocket interruption while peers preserve new-session availability. Without a target-matched action receipt the raw scenario records the sequence without exclusive causal attribution or application-semantic inference.",
	}
}

func (s *c2VoiceWebSocketContinuity) Setup(ctx context.Context, env *core.Env) error {
	*s = c2VoiceWebSocketContinuity{}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	one, two := int32(1), int32(2)
	target, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Create(ctx, voiceWSDeployment(env, voiceWSTargetDeployment, "target", one, true), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create voice websocket target Deployment: %w", err)
	}
	if target.UID == "" {
		return errors.New("voice websocket target Deployment has empty UID")
	}
	s.targetDeploymentUID = target.UID
	peers, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Create(ctx, voiceWSDeployment(env, voiceWSPeerDeployment, "peer", two, false), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create voice websocket peer Deployment: %w", err)
	}
	if peers.UID == "" {
		return errors.New("voice websocket peer Deployment has empty UID")
	}
	s.peerDeploymentUID = peers.UID
	targetService, err := env.Kube.CoreV1().Services(env.Config.Namespace).Create(ctx, voiceWSService(env, voiceWSTargetService, map[string]string{"app": voiceWSApp, "role": "target"}), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create voice websocket target Service: %w", err)
	}
	if targetService.UID == "" {
		return errors.New("voice websocket target Service has empty UID")
	}
	s.targetServiceUID = targetService.UID
	sharedService, err := env.Kube.CoreV1().Services(env.Config.Namespace).Create(ctx, voiceWSService(env, voiceWSSharedService, map[string]string{"app": voiceWSApp}), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create voice websocket shared Service: %w", err)
	}
	if sharedService.UID == "" {
		return errors.New("voice websocket shared Service has empty UID")
	}
	s.sharedServiceUID = sharedService.UID
	producer, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, voiceWSProducerPod(env), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create voice websocket producer Pod: %w", err)
	}
	if producer.UID == "" {
		return errors.New("voice websocket producer Pod has empty UID")
	}
	s.producerUID = producer.UID
	if err := env.WaitForPodRunning(ctx, voiceWSProducer, 60*time.Second); err != nil {
		return fmt.Errorf("wait voice websocket producer: %w", err)
	}
	if _, err := waitVoiceWSReadyPods(ctx, env, "target", 1, 60*time.Second); err != nil {
		return err
	}
	if _, err := waitVoiceWSReadyPods(ctx, env, "peer", 2, 60*time.Second); err != nil {
		return err
	}
	if err := waitVoiceWSReadyEndpoints(ctx, env, voiceWSSharedService, s.sharedServiceUID, s.targetDeploymentUID, s.peerDeploymentUID, 3, 60*time.Second); err != nil {
		return err
	}
	return nil
}

func voiceWSDeployment(env *core.Env, name, role string, replicas int32, rotate bool) *appsv1.Deployment {
	noToken, nonroot, readOnly, noEsc := false, true, true, false
	uid := int64(65532)
	labels := env.OwnedLabels(map[string]string{"app": voiceWSApp, "role": role})
	podLabels := env.OwnedLabels(map[string]string{"app": voiceWSApp, "role": role})
	if rotate {
		podLabels[defenders.RotationTargetLabel] = "true"
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": voiceWSApp, "role": role}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: map[string]string{"fixture.phorvex.ai/source-sha256": voiceWSServerSourceSHA256(), "fixture.phorvex.ai/runtime-bot-sha256": voiceWSRuntimeBotSHA256}},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &noToken,
					NodeSelector:                 cloneStringMap(env.Config.BenignSessionNodeSelector),
					SecurityContext:              &corev1.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid},
					Containers: []corev1.Container{{
						Name: "fixture", Image: voiceWSRuntimeImage, Command: []string{"python3", "-B", "-c", voiceWSServerSource},
						Env:             []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}, {Name: "ALLOWED_WS_HOSTS", Value: fmt.Sprintf("%s:%d,%s:%d", voiceWSTargetService, voiceWSPort, voiceWSSharedService, voiceWSPort)}},
						Ports:           []corev1.ContainerPort{{Name: "http", ContainerPort: voiceWSPort}},
						ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt(voiceWSPort)}}, InitialDelaySeconds: 1, PeriodSeconds: 1, TimeoutSeconds: 2, FailureThreshold: 15},
						Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("256Mi")}},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEsc, ReadOnlyRootFilesystem: &readOnly, RunAsNonRoot: &nonroot, RunAsUser: &uid, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					}},
				},
			},
		},
	}
}

func voiceWSService(env *core.Env, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(nil)}, Spec: corev1.ServiceSpec{Selector: selector, Ports: []corev1.ServicePort{{Name: "http", Port: voiceWSPort, TargetPort: intstr.FromInt(voiceWSPort)}}}}
}

func voiceWSProducerPod(env *core.Env) *corev1.Pod {
	noToken, nonroot, readOnly, noEsc := false, true, true, false
	uid := int64(65532)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: voiceWSProducer, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(map[string]string{"app": voiceWSProducer}), Annotations: map[string]string{"fixture.phorvex.ai/source-sha256": voiceWSClientSourceSHA256(), "fixture.phorvex.ai/runtime-bot-sha256": voiceWSRuntimeBotSHA256}},
		Spec:       corev1.PodSpec{AutomountServiceAccountToken: &noToken, NodeSelector: cloneStringMap(env.Config.BenignSessionNodeSelector), RestartPolicy: corev1.RestartPolicyNever, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid}, Containers: []corev1.Container{{Name: "producer", Image: voiceWSRuntimeImage, Command: []string{"sh", "-c", "while true; do sleep 3600; done"}, Env: []corev1.EnvVar{{Name: "HTTP_PROXY", Value: ""}, {Name: "HTTPS_PROXY", Value: ""}, {Name: "ALL_PROXY", Value: ""}, {Name: "http_proxy", Value: ""}, {Name: "https_proxy", Value: ""}, {Name: "all_proxy", Value: ""}, {Name: "NO_PROXY", Value: "*"}, {Name: "no_proxy", Value: "*"}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("150m"), corev1.ResourceMemory: resource.MustParse("128Mi")}}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEsc, ReadOnlyRootFilesystem: &readOnly, RunAsNonRoot: &nonroot, RunAsUser: &uid, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}},
	}
}

func (s *c2VoiceWebSocketContinuity) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	targets, err := waitVoiceWSReadyPods(ctx, env, "target", 1, 20*time.Second)
	if err != nil {
		return core.AttackResult{}, err
	}
	original := targets[0]
	if original.UID == "" || original.ResourceVersion == "" || original.DeletionTimestamp != nil {
		return core.AttackResult{}, errors.New("voice websocket original target identity is incomplete")
	}
	if err := validateVoiceWSPodFixture(ctx, env, &original, s.targetDeploymentUID, s.peerDeploymentUID); err != nil {
		return core.AttackResult{}, err
	}
	s.originalName, s.originalUID = original.Name, original.UID
	if env.Rand == nil {
		return core.AttackResult{}, errors.New("voice websocket producer has no deterministic trial RNG")
	}
	stopSamples := make(chan struct{})
	availabilityDone := make(chan voiceWSAvailability, 1)
	go func() {
		availabilityDone <- sampleVoiceWSAvailability(ctx, env, s.sharedServiceUID, s.targetDeploymentUID, s.peerDeploymentUID, s.originalUID, stopSamples)
	}()
	type probeResult struct {
		receipt voiceWSReceipt
		err     error
	}
	sharedDone := make(chan probeResult, 1)
	sharedID := fmt.Sprintf("shared-%d-%016x", env.Trial, env.Rand.Uint64())
	go func() {
		timer := time.NewTimer(15500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			sharedDone <- probeResult{err: ctx.Err()}
			return
		case <-timer.C:
		}
		receipt, err := performVoiceWS(ctx, env, voiceWSSharedService, s.sharedServiceUID, map[string]string{"app": voiceWSApp}, sharedID, 2, 10*time.Millisecond, s.producerUID)
		sharedDone <- probeResult{receipt: receipt, err: err}
	}()
	sessionID := fmt.Sprintf("voice-%d-%016x", env.Trial, env.Rand.Uint64())
	receipt, requestErr := performVoiceWS(ctx, env, voiceWSTargetService, s.targetServiceUID, map[string]string{"app": voiceWSApp, "role": "target"}, sessionID, voiceWSExpectedFrames, voiceWSFrameInterval, s.producerUID)
	shared := <-sharedDone
	close(stopSamples)
	s.availability = <-availabilityDone
	s.receipt, s.sharedProbe = receipt, shared.receipt
	if requestErr != nil {
		return core.AttackResult{Stages: []string{"establish deterministic Twilio-shaped WebSocket through target Service"}}, requestErr
	}
	if shared.err != nil || !voiceWSReceiptCompleted(shared.receipt) {
		return core.AttackResult{}, fmt.Errorf("shared Service availability websocket failed: receipt=%+v err=%v", shared.receipt, shared.err)
	}
	if receipt.TargetPodUID != string(s.originalUID) {
		return core.AttackResult{}, fmt.Errorf("websocket target UID %q differs from authoritative target %q", receipt.TargetPodUID, s.originalUID)
	}
	replacement, replaced, timeline, err := waitVoiceWSTargetOutcome(ctx, env, s.originalName, s.originalUID, s.targetDeploymentUID, voiceWSReplacementTimeout)
	if err != nil {
		return core.AttackResult{}, err
	}
	if replaced {
		if err := validateVoiceWSPodFixture(ctx, env, replacement, s.targetDeploymentUID, s.peerDeploymentUID); err != nil {
			return core.AttackResult{}, fmt.Errorf("replacement voice websocket fixture invalid: %w", err)
		}
		s.replacementName, s.replacementUID, s.originalAPIAbsent = replacement.Name, replacement.UID, true
		s.originalDeletionTimestamp, s.originalAbsenceObservedAt, s.replacementObservedAt = timeline.DeletionTimestamp, timeline.AbsenceObservedAt, timeline.ReplacementObservedAt
		recoveryID := fmt.Sprintf("recovery-%d-%016x", env.Trial, env.Rand.Uint64())
		s.recovery, err = performVoiceWS(ctx, env, voiceWSTargetService, s.targetServiceUID, map[string]string{"app": voiceWSApp, "role": "target"}, recoveryID, 2, 10*time.Millisecond, s.producerUID)
		if err != nil {
			return core.AttackResult{}, fmt.Errorf("replacement websocket recovery: %w", err)
		}
		if s.recovery.TargetPodUID != string(s.replacementUID) || !voiceWSReceiptCompleted(s.recovery) {
			return core.AttackResult{}, errors.New("replacement did not complete exact fresh websocket recovery")
		}
	}
	return core.AttackResult{Stages: []string{"establish one exact UID-bound WebSocket through target Service", "exchange deterministic sequential synthetic media during the defender window", "sample shared Service endpoint availability", "bind original presence or exact controller replacement", "run a concurrent fresh exchange through the shared Service", "run replacement recovery exchange when rotation occurred"}, Notes: map[string]string{"classification": "benign websocket transport continuity control", "originalPodUID": string(s.originalUID), "replacementPodUID": string(s.replacementUID), "fixtureImage": voiceWSRuntimeImage, "runtimeBotSourceSHA256": voiceWSRuntimeBotSHA256, "serverSourceSHA256": voiceWSServerSourceSHA256(), "clientSourceSHA256": voiceWSClientSourceSHA256(), "outcome": receipt.Outcome, "receivedFrames": strconv.Itoa(len(receipt.ReceivedSequences)), "expectedFrames": strconv.Itoa(receipt.ExpectedFrames), "minimumReadyEndpoints": strconv.Itoa(s.availability.MinimumReady), "defenderArm": env.DefenderName, "originalDeletionTimestamp": s.originalDeletionTimestamp, "originalAbsenceObservedAt": s.originalAbsenceObservedAt, "replacementObservedAt": s.replacementObservedAt}}, nil
}

func (s *c2VoiceWebSocketContinuity) SuccessOracle(_ context.Context, _ *core.Env) (core.OracleResult, error) {
	evidence := map[string]string{
		"originalPodUID": string(s.originalUID), "replacementPodUID": string(s.replacementUID), "targetReplyPodUID": s.receipt.TargetPodUID,
		"outcome": s.receipt.Outcome, "endMarker": strconv.FormatBool(s.receipt.EndMarker), "closeCode": strconv.Itoa(s.receipt.CloseCode),
		"receivedFrames": strconv.Itoa(len(s.receipt.ReceivedSequences)), "expectedFrames": strconv.Itoa(s.receipt.ExpectedFrames), "gaps": strconv.Itoa(s.receipt.Gaps), "duplicateSequences": strconv.Itoa(s.receipt.DuplicateSequences),
		"availabilitySamples": strconv.Itoa(s.availability.Samples), "availabilityFailures": strconv.Itoa(s.availability.Failures), "availabilitySamplePeriodMillis": strconv.FormatInt(voiceWSAvailabilityPeriod.Milliseconds(), 10), "availabilityExchangeBoundSeconds": strconv.FormatFloat(voiceWSExecTimeout.Seconds(), 'f', 0, 64), "minimumReadyEndpoints": strconv.Itoa(s.availability.MinimumReady),
		"originalSeen": strconv.FormatBool(s.availability.OriginalSeen), "originalRouteAbsentSeen": strconv.FormatBool(s.availability.OriginalAbsentSeen), "originalAPIAbsent": strconv.FormatBool(s.originalAPIAbsent), "originalDeletionTimestamp": s.originalDeletionTimestamp, "originalAbsenceObservedAt": s.originalAbsenceObservedAt, "replacementObservedAt": s.replacementObservedAt, "readyEndpointUIDs": strings.Join(s.availability.ObservedReadyUIDs, ","),
		"sharedProbeOutcome": s.sharedProbe.Outcome, "sharedProbeTargetPodUID": s.sharedProbe.TargetPodUID,
		"recoveryOutcome": s.recovery.Outcome, "recoveryTargetPodUID": s.recovery.TargetPodUID,
	}
	if s.availability.Samples == 0 || s.availability.Failures != 0 {
		return core.OracleResult{Evidence: evidence}, errors.New("websocket availability sampling incomplete")
	}
	if !s.availability.OriginalSeen {
		return core.OracleResult{Evidence: evidence}, errors.New("exact original Pod UID was not observed as an authorized Ready endpoint")
	}
	if s.availability.MinimumReady < 2 {
		return core.OracleResult{Evidence: evidence}, fmt.Errorf("shared Service Ready endpoint floor fell below two: %d", s.availability.MinimumReady)
	}
	if !voiceWSReceiptCompleted(s.sharedProbe) {
		return core.OracleResult{Evidence: evidence}, errors.New("shared Service did not complete a concurrent fresh websocket")
	}
	if s.replacementUID == "" {
		if !voiceWSReceiptCompleted(s.receipt) {
			return core.OracleResult{Evidence: evidence}, errors.New("no-action websocket did not complete exact sequence and end marker")
		}
		return core.OracleResult{Achieved: true, ObservedState: "no-action control: exact original Pod UID completed every numbered synthetic media response and explicit end marker while shared availability remained at least two", Evidence: evidence}, nil
	}
	if s.replacementUID == s.originalUID || !s.originalAPIAbsent || !s.availability.OriginalAbsentSeen {
		return core.OracleResult{Evidence: evidence}, errors.New("exact original Pod UID route/API absence or distinct replacement is unproven")
	}
	if s.receipt.Outcome != "early-close" || s.receipt.EndMarker || len(s.receipt.ReceivedSequences) >= s.receipt.ExpectedFrames {
		return core.OracleResult{Evidence: evidence}, errors.New("rotation did not yield a discriminating incomplete established-session outcome")
	}
	if s.sharedProbe.TargetPodUID == string(s.originalUID) {
		return core.OracleResult{Evidence: evidence}, errors.New("shared availability probe was still served by deleted original UID")
	}
	if !slices.Contains(s.availability.ObservedReadyUIDs, s.sharedProbe.TargetPodUID) {
		return core.OracleResult{Evidence: evidence}, errors.New("shared availability probe target was not independently observed as an authorized Ready endpoint")
	}
	started, startErr := time.Parse(time.RFC3339Nano, s.receipt.StartedAtUTC)
	absentAt, absentErr := time.Parse(time.RFC3339Nano, s.originalAbsenceObservedAt)
	replacementAt, replacementErr := time.Parse(time.RFC3339Nano, s.replacementObservedAt)
	if startErr != nil || absentErr != nil || replacementErr != nil || absentAt.Before(started) || replacementAt.Before(absentAt) {
		return core.OracleResult{Evidence: evidence}, errors.New("original absence/replacement timeline is invalid")
	}
	if !voiceWSReceiptCompleted(s.recovery) || s.recovery.TargetPodUID != string(s.replacementUID) {
		return core.OracleResult{Evidence: evidence}, errors.New("exact replacement recovery websocket is absent")
	}
	return core.OracleResult{Achieved: false, ObservedState: "timer-driven Pod-replacement comparison: an established WebSocket lost its exact original Pod UID before the end marker; API observations then showed original absence, a Ready replacement, at least two Ready shared endpoints and fresh-session recovery. Without a target-matched actuator receipt this is an observed interruption/replacement sequence, not exclusive causal attribution.", Evidence: evidence}, nil
}

func voiceWSReceiptCompleted(r voiceWSReceipt) bool {
	if r.Version != 1 || r.Outcome != "completed" || !r.EndMarker || r.CloseCode != 1000 || r.ExpectedFrames < 1 || len(r.ReceivedSequences) != r.ExpectedFrames || r.Gaps != 0 || r.DuplicateSequences != 0 || r.Failure != "" || r.TargetPodUID == "" {
		return false
	}
	for i, sequence := range r.ReceivedSequences {
		if sequence != i+1 {
			return false
		}
	}
	return true
}

func performVoiceWS(ctx context.Context, env *core.Env, service string, serviceUID types.UID, selector map[string]string, sessionID string, frames int, interval time.Duration, expectedProducerUID types.UID) (voiceWSReceipt, error) {
	var receipt voiceWSReceipt
	if frames < 1 || frames > 64 || interval < 0 || interval > 2*time.Second {
		return receipt, errors.New("voice websocket producer bounds invalid")
	}
	deadline := voiceWSExecTimeout
	if callerDeadline, ok := ctx.Deadline(); ok && time.Until(callerDeadline) < deadline {
		deadline = time.Until(callerDeadline)
	}
	if deadline <= time.Second {
		return receipt, errors.New("voice websocket caller deadline too short")
	}
	execCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if err := validateVoiceWSService(execCtx, env, service, serviceUID, selector); err != nil {
		return receipt, err
	}
	producer, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(execCtx, voiceWSProducer, metav1.GetOptions{})
	if err != nil || producer.UID != expectedProducerUID || !podReady(producer) || producer.DeletionTimestamp != nil {
		return receipt, fmt.Errorf("voice websocket producer identity/readiness invalid: pod=%v err=%v", producer, err)
	}
	base := fmt.Sprintf("http://%s:%d", service, voiceWSPort)
	result := env.Exec(execCtx, voiceWSProducer, "producer", []string{"python3", "-B", "-c", voiceWSClientSource, base, sessionID, strconv.Itoa(frames), strconv.FormatFloat(interval.Seconds(), 'f', 3, 64)})
	raw := []byte(result.Stdout)
	env.Log.Logf("c2-voice-websocket-continuity receipt service=%s producerUID=%s stdoutBytes=%d stdoutSHA256=%x exit=%d", service, producer.UID, len(raw), sha256.Sum256(raw), result.ExitCode)
	if result.Err != nil || result.ExitCode != 0 {
		return receipt, fmt.Errorf("voice websocket producer failed: exit=%d err=%v stderr=%s", result.ExitCode, result.Err, truncateSessionDetail(result.Stderr))
	}
	if len(raw) > voiceWSReceiptLimit {
		return receipt, fmt.Errorf("voice websocket receipt exceeds %d bytes", voiceWSReceiptLimit)
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return receipt, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("decode voice websocket receipt: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return receipt, err
	}
	if err := validateVoiceWSReceipt(receipt, base, sessionID, frames); err != nil {
		return receipt, err
	}
	if err := validateVoiceWSService(execCtx, env, service, serviceUID, selector); err != nil {
		return receipt, err
	}
	producerAfter, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(execCtx, voiceWSProducer, metav1.GetOptions{})
	if err != nil || producerAfter.UID != expectedProducerUID || !podReady(producerAfter) {
		return receipt, fmt.Errorf("voice websocket producer identity changed after exchange: pod=%v err=%v", producerAfter, err)
	}
	return receipt, nil
}

func validateVoiceWSReceipt(r voiceWSReceipt, base, sessionID string, frames int) error {
	if r.Version != 1 || r.ServiceURL != base || r.SessionID != sessionID || r.ExpectedFrames != frames {
		return errors.New("voice websocket receipt request binding differs")
	}
	if r.TwiMLStatus != 200 || len(r.TwiMLSHA256) != 64 || r.WebSocketURL != strings.Replace(base, "http://", "ws://", 1)+"/ws" {
		return errors.New("voice websocket TwiML binding invalid")
	}
	started, err := time.Parse(time.RFC3339Nano, r.StartedAtUTC)
	if err != nil {
		return errors.New("voice websocket start time invalid")
	}
	ended, err := time.Parse(time.RFC3339Nano, r.EndedAtUTC)
	if err != nil || ended.Before(started) {
		return errors.New("voice websocket end time invalid")
	}
	if r.TargetPodUID == "" || r.Gaps < 0 || r.DuplicateSequences < 0 || len(r.ReceivedSequences) > frames {
		return errors.New("voice websocket receipt counters invalid")
	}
	unique := map[int]bool{}
	for _, sequence := range r.ReceivedSequences {
		if sequence < 1 || sequence > frames {
			return errors.New("voice websocket sequence outside request")
		}
		unique[sequence] = true
	}
	if r.DuplicateSequences != len(r.ReceivedSequences)-len(unique) || r.Gaps != frames-len(unique) {
		return errors.New("voice websocket receipt gap/duplicate summary differs from sequences")
	}
	switch r.Outcome {
	case "completed":
		if !voiceWSReceiptCompleted(r) {
			return errors.New("voice websocket completed outcome is internally inconsistent")
		}
	case "early-close":
		if r.EndMarker || len(r.ReceivedSequences) >= frames || r.Failure == "" {
			return errors.New("voice websocket early-close outcome is internally inconsistent")
		}
	case "protocol-error":
		if r.Failure == "" {
			return errors.New("voice websocket protocol-error omitted failure")
		}
	default:
		return fmt.Errorf("voice websocket outcome %q unknown", r.Outcome)
	}
	return nil
}

func sampleVoiceWSAvailability(ctx context.Context, env *core.Env, serviceUID, targetDeploymentUID, peerDeploymentUID, originalUID types.UID, stop <-chan struct{}) voiceWSAvailability {
	out := voiceWSAvailability{MinimumReady: -1}
	seen := map[string]bool{}
	ticker := time.NewTicker(voiceWSAvailabilityPeriod)
	defer ticker.Stop()
	for {
		uids, err := voiceWSReadyEndpointUIDs(ctx, env, voiceWSSharedService, serviceUID, targetDeploymentUID, peerDeploymentUID)
		if err != nil {
			out.Failures++
		} else {
			out.Samples++
			if out.MinimumReady < 0 || len(uids) < out.MinimumReady {
				out.MinimumReady = len(uids)
			}
			present := false
			for _, uid := range uids {
				text := string(uid)
				seen[text] = true
				if uid == originalUID {
					present = true
					out.OriginalSeen = true
				}
			}
			if !present {
				out.OriginalAbsentSeen = true
			}
		}
		select {
		case <-stop:
			for uid := range seen {
				out.ObservedReadyUIDs = append(out.ObservedReadyUIDs, uid)
			}
			sort.Strings(out.ObservedReadyUIDs)
			return out
		case <-ctx.Done():
			out.Failures++
			for uid := range seen {
				out.ObservedReadyUIDs = append(out.ObservedReadyUIDs, uid)
			}
			sort.Strings(out.ObservedReadyUIDs)
			return out
		case <-ticker.C:
		}
	}
}

func validateVoiceWSService(ctx context.Context, env *core.Env, serviceName string, serviceUID types.UID, selector map[string]string) error {
	svc, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil || serviceUID == "" || svc.UID != serviceUID || svc.DeletionTimestamp != nil || !reflect.DeepEqual(svc.Spec.Selector, selector) {
		return fmt.Errorf("voice websocket Service identity/selector invalid: service=%s uid=%s svc=%v err=%v", serviceName, serviceUID, svc, err)
	}
	return nil
}

func voiceWSReadyEndpointUIDs(ctx context.Context, env *core.Env, serviceName string, serviceUID, targetDeploymentUID, peerDeploymentUID types.UID) ([]types.UID, error) {
	if err := validateVoiceWSService(ctx, env, serviceName, serviceUID, map[string]string{"app": voiceWSApp}); err != nil {
		return nil, err
	}
	list, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + serviceName})
	if err != nil {
		return nil, err
	}
	set := map[types.UID]bool{}
	for i := range list.Items {
		slice := &list.Items[i]
		owned := false
		for _, owner := range slice.OwnerReferences {
			if owner.Kind == "Service" && owner.Name == serviceName && owner.UID == serviceUID && owner.Controller != nil && *owner.Controller {
				owned = true
			}
		}
		if !owned {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != env.Config.Namespace || endpoint.TargetRef.UID == "" {
				continue
			}
			pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, endpoint.TargetRef.Name, metav1.GetOptions{})
			if err != nil || pod.UID != endpoint.TargetRef.UID || !podReady(pod) || pod.DeletionTimestamp != nil {
				continue
			}
			if err := validateVoiceWSPodFixture(ctx, env, pod, targetDeploymentUID, peerDeploymentUID); err != nil {
				continue
			}
			set[pod.UID] = true
		}
	}
	uids := make([]types.UID, 0, len(set))
	for uid := range set {
		uids = append(uids, uid)
	}
	slices.Sort(uids)
	return uids, nil
}

func validateVoiceWSPodFixture(ctx context.Context, env *core.Env, pod *corev1.Pod, targetDeploymentUID, peerDeploymentUID types.UID) error {
	if pod == nil || pod.Labels["app"] != voiceWSApp || pod.Annotations["fixture.phorvex.ai/source-sha256"] != voiceWSServerSourceSHA256() || pod.Annotations["fixture.phorvex.ai/runtime-bot-sha256"] != voiceWSRuntimeBotSHA256 || len(pod.Spec.Containers) != 1 {
		return errors.New("voice websocket Pod fixture declaration differs")
	}
	container := pod.Spec.Containers[0]
	if container.Name != "fixture" || container.Image != voiceWSRuntimeImage || !reflect.DeepEqual(container.Command, []string{"python3", "-B", "-c", voiceWSServerSource}) {
		return errors.New("voice websocket Pod source/image command differs")
	}
	imageReady := false
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "fixture" && status.Ready && strings.HasSuffix(status.ImageID, "@"+voiceWSRuntimeDigest) {
			imageReady = true
		}
	}
	if !imageReady {
		return errors.New("voice websocket Pod runtime image digest/readiness unproven")
	}
	switch pod.Labels["role"] {
	case "target":
		return validateVoiceWSController(ctx, env, pod, voiceWSTargetDeployment, targetDeploymentUID)
	case "peer":
		return validateVoiceWSController(ctx, env, pod, voiceWSPeerDeployment, peerDeploymentUID)
	default:
		return errors.New("voice websocket Pod role unsupported")
	}
}

func waitVoiceWSReadyEndpoints(ctx context.Context, env *core.Env, service string, uid, targetDeploymentUID, peerDeploymentUID types.UID, count int, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		uids, err := voiceWSReadyEndpointUIDs(waitCtx, env, service, uid, targetDeploymentUID, peerDeploymentUID)
		if err == nil && len(uids) == count {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait voice websocket Service %s Ready endpoints=%d: observed=%v lastErr=%v: %w", service, count, uids, err, waitCtx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func waitVoiceWSReadyPods(ctx context.Context, env *core.Env, role string, count int, timeout time.Duration) ([]corev1.Pod, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	selector := fmt.Sprintf("app=%s,role=%s", voiceWSApp, role)
	for {
		list, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(waitCtx, metav1.ListOptions{LabelSelector: selector})
		if err == nil {
			ready := make([]corev1.Pod, 0, len(list.Items))
			for i := range list.Items {
				if podReady(&list.Items[i]) && list.Items[i].DeletionTimestamp == nil {
					ready = append(ready, list.Items[i])
				}
			}
			if len(ready) == count {
				sort.Slice(ready, func(i, j int) bool { return ready[i].Name < ready[j].Name })
				return ready, nil
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("wait voice websocket role=%s Ready pods=%d: lastErr=%v: %w", role, count, err, waitCtx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

type voiceWSTargetTimeline struct{ DeletionTimestamp, AbsenceObservedAt, ReplacementObservedAt string }

func waitVoiceWSTargetOutcome(ctx context.Context, env *core.Env, originalName string, originalUID, deploymentUID types.UID, timeout time.Duration) (*corev1.Pod, bool, voiceWSTargetTimeline, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var timeline voiceWSTargetTimeline
	for {
		original, originalErr := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(waitCtx, originalName, metav1.GetOptions{})
		originalAbsent := apierrors.IsNotFound(originalErr) || originalErr == nil && original.UID != originalUID
		if originalErr != nil && !apierrors.IsNotFound(originalErr) {
			return nil, false, timeline, fmt.Errorf("read original voice websocket Pod: %w", originalErr)
		}
		if originalErr == nil && original.UID == originalUID && original.DeletionTimestamp != nil && timeline.DeletionTimestamp == "" {
			timeline.DeletionTimestamp = original.DeletionTimestamp.UTC().Format(time.RFC3339Nano)
		}
		if originalAbsent && timeline.AbsenceObservedAt == "" {
			timeline.AbsenceObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(waitCtx, metav1.ListOptions{LabelSelector: "app=" + voiceWSApp + ",role=target"})
		if err == nil {
			for i := range pods.Items {
				pod := &pods.Items[i]
				if pod.UID == originalUID || pod.UID == "" || !podReady(pod) || pod.DeletionTimestamp != nil || !originalAbsent {
					continue
				}
				if err := validateVoiceWSController(waitCtx, env, pod, voiceWSTargetDeployment, deploymentUID); err != nil {
					return nil, false, timeline, err
				}
				timeline.ReplacementObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
				return pod, true, timeline, nil
			}
			for i := range pods.Items {
				pod := &pods.Items[i]
				if pod.UID == originalUID && podReady(pod) && pod.DeletionTimestamp == nil {
					return pod, false, timeline, nil
				}
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, false, timeline, fmt.Errorf("wait voice websocket target outcome: %w", waitCtx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func validateVoiceWSController(ctx context.Context, env *core.Env, pod *corev1.Pod, deploymentName string, deploymentUID types.UID) error {
	deployment, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil || deployment.UID != deploymentUID || deployment.UID == "" || deployment.DeletionTimestamp != nil {
		return fmt.Errorf("voice websocket Deployment authority invalid: deployment=%v err=%v", deployment, err)
	}
	var rsRef *metav1.OwnerReference
	for i := range pod.OwnerReferences {
		owner := &pod.OwnerReferences[i]
		if owner.Kind == "ReplicaSet" && owner.Controller != nil && *owner.Controller {
			if rsRef != nil {
				return errors.New("voice websocket Pod has multiple controller owners")
			}
			rsRef = owner
		}
	}
	if rsRef == nil || rsRef.UID == "" {
		return errors.New("voice websocket Pod ReplicaSet owner missing")
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, rsRef.Name, metav1.GetOptions{})
	if err != nil || rs.UID != rsRef.UID {
		return fmt.Errorf("voice websocket ReplicaSet authority invalid: rs=%v err=%v", rs, err)
	}
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" && owner.Name == deploymentName && owner.UID == deploymentUID && owner.Controller != nil && *owner.Controller {
			return nil
		}
	}
	return errors.New("voice websocket ReplicaSet is not owned by exact Deployment")
}

func voiceWSServerSourceSHA256() string {
	sum := sha256.Sum256([]byte(voiceWSServerSource))
	return fmt.Sprintf("%x", sum)
}
func voiceWSClientSourceSHA256() string {
	sum := sha256.Sum256([]byte(voiceWSClientSource))
	return fmt.Sprintf("%x", sum)
}

func (s *c2VoiceWebSocketContinuity) Teardown(ctx context.Context, env *core.Env) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	var errs []error
	deleteDeployment := func(name string, uid types.UID) {
		if uid == "" {
			return
		}
		opts := sessionDeleteOptions(uid)
		if err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Delete(ctx, name, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete Deployment %s uid=%s: %w", name, uid, err))
		}
	}
	deleteService := func(name string, uid types.UID) {
		if uid == "" {
			return
		}
		opts := sessionDeleteOptions(uid)
		if err := env.Kube.CoreV1().Services(env.Config.Namespace).Delete(ctx, name, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete Service %s uid=%s: %w", name, uid, err))
		}
	}
	deleteDeployment(voiceWSTargetDeployment, s.targetDeploymentUID)
	deleteDeployment(voiceWSPeerDeployment, s.peerDeploymentUID)
	deleteService(voiceWSTargetService, s.targetServiceUID)
	deleteService(voiceWSSharedService, s.sharedServiceUID)
	if s.producerUID != "" {
		opts := sessionDeleteOptions(s.producerUID)
		if err := env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, voiceWSProducer, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete producer uid=%s: %w", s.producerUID, err))
		}
	}
	return errors.Join(errs...)
}
