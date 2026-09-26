package console

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

type outputSnapshot struct {
	ClusterUID               string `json:"clusterUID"`
	TargetPodUID             string `json:"targetPodUID"`
	TargetProxyImageID       string `json:"targetProxyImageID"`
	TargetSupportImageID     string `json:"targetSupportImageID"`
	ServiceUID               string `json:"serviceUID"`
	SourceUID                string `json:"sourceUID"`
	ModelPodUID              string `json:"modelPodUID"`
	ModelImageID             string `json:"modelImageID"`
	ModelServiceUID          string `json:"modelServiceUID"`
	ManagerPodUID            string `json:"managerPodUID"`
	ManagerImageID           string `json:"managerImageID"`
	ConsolePodUID            string `json:"consolePodUID"`
	ConsoleImageID           string `json:"consoleImageID"`
	ConsoleDeploymentUID     string `json:"consoleDeploymentUID"`
	PolicyUID                string `json:"policyUID"`
	PolicyGeneration         int64  `json:"policyGeneration"`
	PolicySpecSHA256         string `json:"policySpecSHA256"`
	ConfigMapUID             string `json:"configMapUID"`
	ConfigMapResourceVersion string `json:"configMapResourceVersion"`
	RuleSHA256               string `json:"ruleSHA256"`
	Active                   bool   `json:"active"`
	Revision                 int64  `json:"revision"`
	OperationID              string `json:"operationId"`
	ProxyReady               bool   `json:"proxyReady"`
	CompletedModelCalls      int64  `json:"completedModelCalls"`
}

type outputWorker struct {
	*availabilityWorker
	cancel       context.CancelFunc
	profile      guardrailOutputProfile
	marker       string
	request      []byte
	before       outputSnapshot
	beforeStatus int
	beforeBody   []byte
	afterStatus  int
	afterBody    []byte
}

func newOutputWorker(cfg Config, p guardrailOutputProfile, id, out string) *outputWorker {
	var carrier guardrailAvailabilityProfile
	carrier.Context = p.Context
	carrier.Fixture.PodName = p.Fixture.PodName
	carrier.Fixture.PodUID = p.Fixture.PodUID
	carrier.Fixture.ClusterUID = p.Fixture.ClusterUID
	carrier.Fixture.EventCreator = p.Fixture.EventCreator
	carrier.Fixture.PolicyUID = p.Fixture.PolicyUID
	carrier.Fixture.ConsoleURL = p.Fixture.ConsoleURL
	carrier.Fixture.AuditURL = p.Fixture.AuditURL
	carrier.Fixture.AuditServerName = p.Fixture.AuditServerName
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	return &outputWorker{availabilityWorker: &availabilityWorker{
		rm: &RunManager{cfg: cfg}, ctx: ctx, out: out, p: carrier,
		deadline: time.Now().Add(900 * time.Second), selfName: os.Getenv("PHORVEX_CONSOLE_POD_NAME"),
		selfUID: os.Getenv("PHORVEX_CONSOLE_POD_UID"),
		t: availabilityTerminal{Schema: "guardrail-output-terminal-v2", RunID: id, ProfileSHA256: cfg.GuardrailOutputProfileSHA256,
			Status: "UNKNOWN", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ConsolePOSTsAttempted: 1},
	}, cancel: cancel, profile: p, request: []byte(guardrailOutputBody)}
}

// Only the two fixed containers and scripts are executable in this case.
// The marker never appears in argv, public API responses, or event metadata.
const outputMarkerReadCode = "import os,sys\np=os.environ.get('SUPPORT_FIXTURE_MARKER_FILE','/etc/phorvex-support/marker')\nb=open(p,'rb').read(257)\nif not 32<=len(b.strip())<=128:raise RuntimeError('marker bound')\nsys.stdout.buffer.write(b.strip())\n"
const outputHTTPRequestCode = "import base64,http.client,json,signal,sys\nsignal.alarm(35)\nv=json.loads(sys.stdin.buffer.read(4097))\nif v['method'] not in ('GET','POST') or v['path'] not in ('/v1/support/case','/v1/support/state','/v1/output-policy/state'):raise RuntimeError('route')\nb=base64.b64decode(v['body'])\nif len(b)>4096:raise RuntimeError('request bound')\nc=http.client.HTTPConnection('127.0.0.1',v['port'],timeout=30)\ntry:\n c.request(v['method'],v['path'],body=b,headers={'Content-Type':'application/json'})\n r=c.getresponse();x=r.read(65537)\n if len(x)>65536:raise RuntimeError('reply bound')\n print(json.dumps({'status':r.status,'bodyBase64':base64.b64encode(x).decode()}))\nfinally:c.close()\n"
const outputGuardedModelCode = "import base64,http.client,json,os,signal,sys,urllib.parse\nsignal.alarm(35)\nv=json.loads(sys.stdin.buffer.read(4097))\nu=urllib.parse.urlparse(os.environ['SUPPORT_FIXTURE_MODEL_URL'])\nif u.scheme!='http' or u.hostname!=v['host'] or u.port!=8000 or u.path not in ('','/') or u.query or u.fragment:raise RuntimeError('model route')\nb=base64.b64decode(v['body'])\nif len(b)>4096:raise RuntimeError('request bound')\nh={'Content-Type':'application/json'}\nk=os.environ.get('VLLM_API_KEY','')\nif k:h['Authorization']='Bearer '+k\nc=http.client.HTTPConnection(u.hostname,8000,timeout=30)\ntry:\n c.request('POST','/v1/chat/completions',body=b,headers=h)\n r=c.getresponse();x=r.read(8193)\n if len(x)>8192:raise RuntimeError('reply bound')\n print(json.dumps({'status':r.status,'bodyBase64':base64.b64encode(x).decode()}))\nfinally:c.close()\n"

func (w *outputWorker) execContainer(label, container, code string, stdin []byte, bound int) ([]byte, error) {
	if container != "guardrail-proxy" && container != "support-app" {
		return nil, errors.New("unreviewed fixture container")
	}
	left, err := w.remaining(time.Second)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithTimeout(w.ctx, min(left, 40*time.Second))
	defer stop()
	cmd := exec.CommandContext(ctx, "kubectl", "--context="+w.profile.Context, "-n", "vllm", "exec", "-i", w.profile.Fixture.PodName, "-c", container, "--", "python3", "-B", "-c", code)
	cmd.Stdin = bytes.NewReader(stdin)
	stdout, stderr := availabilityCappedWriter{max: bound}, availabilityCappedWriter{max: 4096}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if len(stdout.Bytes()) > 0 {
		if saveErr := w.save(label+"-stdout.bin", stdout.Bytes()); saveErr != nil {
			return nil, saveErr
		}
	}
	if err != nil || stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("fixed fixture exec unresolved: %s", label)
	}
	return stdout.Bytes(), nil
}

func (w *outputWorker) httpCall(label, container string, port int, method, path string, request []byte) (int, []byte, error) {
	if (container == "guardrail-proxy" && port != 8000) || (container == "support-app" && port != 8002) ||
		(method != "POST" && method != "GET") {
		return 0, nil, errors.New("fixture transport outside fixed route")
	}
	if method == "POST" && path == guardrailOutputPath && !bytes.Equal(request, w.request) &&
		!bytes.Equal(request, []byte(guardrailOutputUnrelatedBody)) {
		return 0, nil, errors.New("support case request differs from frozen bytes")
	}
	input, _ := json.Marshal(map[string]any{"port": port, "method": method, "path": path, "body": base64.StdEncoding.EncodeToString(request)})
	if err := w.saveJSON(label+"-intent.json", map[string]any{"method": method, "path": path, "requestSHA256": availabilityHash(request), "port": port, "oneDispatchNoRetry": true}); err != nil {
		return 0, nil, err
	}
	stdout, err := w.execContainer(label, container, outputHTTPRequestCode, input, 90<<10)
	if err != nil {
		return 0, nil, err
	}
	var response availabilityHTTP
	if err = availabilityDecode(stdout, &response); err != nil || response.Status < 100 || response.Status > 599 {
		return 0, nil, errors.New("original fixture HTTP envelope malformed")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(response.BodyBase64)
	if err != nil || len(body) > 65536 {
		return 0, nil, errors.New("original fixture HTTP body malformed")
	}
	if err = w.save(label+"-body.bin", body); err != nil {
		return 0, nil, err
	}
	return response.Status, body, nil
}

func (w *outputWorker) privateMarker() (string, error) {
	raw, err := w.execContainer("owned-marker", "support-app", outputMarkerReadCode, nil, 256)
	if err != nil {
		return "", err
	}
	marker := strings.TrimSpace(string(raw))
	if !outputMarkerPattern.MatchString(marker) || !bytes.Equal(raw, []byte(marker)) {
		return "", errors.New("run-owned private marker malformed")
	}
	return marker, nil
}

func (w *outputWorker) control(phase, which string) (string, error) {
	if which != "say_ok" && which != "arithmetic" {
		return "UNKNOWN", errors.New("unknown ordinary control")
	}
	request := availabilityRequest(w.profile.Fixture.ModelID, "CNR_00000000", which)
	label := phase + "-" + which
	host := w.profile.Fixture.ModelServiceName + ".vllm.svc"
	if err := w.saveJSON(label+"-intent.json", map[string]any{"method": "POST", "path": "/v1/chat/completions",
		"host": host, "port": 8000, "requestSHA256": availabilityHash(request), "oneDispatchNoRetry": true}); err != nil {
		return "UNKNOWN", err
	}
	input, _ := json.Marshal(map[string]string{"host": host, "body": base64.StdEncoding.EncodeToString(request)})
	stdout, err := w.execContainer(label, "support-app", outputGuardedModelCode, input, 12000)
	if err != nil {
		return "UNKNOWN", err
	}
	var response availabilityHTTP
	if availabilityDecode(stdout, &response) != nil {
		return "UNKNOWN", errors.New("guarded model control envelope malformed")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(response.BodyBase64)
	if err != nil || len(body) == 0 || len(body) > 8192 {
		return "UNKNOWN", errors.New("guarded model control response malformed")
	}
	if err = w.save(label+"-body.bin", body); err != nil {
		return "UNKNOWN", err
	}
	status := response.Status
	return availabilityClass(which, status, body, "CNR_00000000"), nil
}

func (s *Server) startGuardrailOutput(p guardrailOutputProfile, raw []byte) string {
	started := s.cfg.now()
	id := "atk-" + strconv.FormatInt(started.UnixNano(), 36) + strconv.FormatUint(vllmEventSequence.Add(1), 36)
	r := &attackRecord{ID: id, FiredAt: started.UTC().Format(time.RFC3339Nano), Service: "vllm", Namespace: "vllm",
		Pod: p.Fixture.PodName, Attack: "Synthetic support application output exposure", AttackID: "guardrail-output-v2",
		MITRE: "application-output-field-egress", Expected: "sensitive-output-policy-activate", EvidenceKind: "vllm-in-place-effect",
		TargetUID: p.Fixture.PodUID, OutcomeClass: "guardrail-output-pending", Status: "running",
		ObservationStart: started.UTC().Format(time.RFC3339Nano), ObservationEnd: started.Add(900 * time.Second).UTC().Format(time.RFC3339Nano),
		GuardrailOutputProbe: newGuardrailOutputProbeResult(s.cfg.GuardrailOutputProfileSHA256), started: started, accepted: started}
	publishAttack(r)
	go s.runGuardrailOutput(r, p, raw)
	return id
}

func (s *Server) runGuardrailOutput(r *attackRecord, p guardrailOutputProfile, raw []byte) {
	out := s.cfg.statePath(filepath.Join("guardrail-output", r.ID))
	w := newOutputWorker(s.cfg, p, r.ID, out)
	defer w.cancel()
	var err error
	if out == "" || w.selfName == "" || len(validation.IsDNS1123Subdomain(w.selfName)) != 0 || !staticUID.MatchString(w.selfUID) {
		err = errors.New("guardrail output private storage or console Pod identity unavailable")
	} else if err = os.MkdirAll(out, 0700); err == nil {
		if err = w.save("profile-original.yaml", raw); err == nil {
			err = w.saveJSON("self-identity.json", map[string]string{"name": w.selfName, "uid": w.selfUID})
		}
		if err == nil {
			err = s.executeGuardrailOutput(w, r)
		}
	}
	if err != nil {
		w.t.Issue = guardrailEffectSafeIssue(err)
	}
	w.t.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if out != "" {
		_ = w.saveJSON("guardrail-output-terminal.json", w.t)
	}
	result, readErr := readGuardrailOutputProbeResult(out, r.ID, s.cfg.GuardrailOutputProfileSHA256)
	if readErr != nil || result == nil {
		result = newGuardrailOutputProbeResult(s.cfg.GuardrailOutputProfileSHA256)
		result.Issues = append(result.Issues, "independent original-receipt projection unavailable")
	}
	if err != nil {
		result.Accepted = false
		result.Status = "UNKNOWN"
		result.Issues = append(result.Issues, guardrailEffectSafeIssue(err))
	}
	r.GuardrailOutputProbe = result
	r.OutcomeClass = "guardrail-output-" + result.Status
	r.Outcome, r.Containment, r.DefendedPod = "", "", ""
	r.Actuated, r.DwellOngoing, r.TimeToDefendSec, r.DwellSec = false, false, 0, 0
	r.Status = "done"
	if !result.Accepted {
		r.Status = "partial"
	}
	publishAttack(r)
	if e := s.persistAttack(r); e != nil {
		r.Status = "partial"
		r.PersistenceError = "guardrail output evidence persistence unavailable; unsafe to retry"
		s.recordStateError(fmt.Errorf("persist measured guardrail output: %w", e))
		publishAttack(r)
	}
}
