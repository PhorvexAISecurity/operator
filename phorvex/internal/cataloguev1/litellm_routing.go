package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	liteRoutingPath         = "/v1/chat/completions"
	liteUnknownAlias        = "phorvex-catalogue-nonexistent-model-v1"
	liteRoutingMaxBody      = 16 << 10
	liteRoutingCallTime     = 30 * time.Second
	liteRoutingTotalTime    = 180 * time.Second
	liteRoutingAfterReserve = 15 * time.Second
)

var liteModelAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// ValidateLiteLLMInferenceRuntime adds a separate, default-off authority to
// the existing GET controls. The alias must also occur exactly once in the
// independently SHA-pinned mounted configuration before any POST.
func ValidateLiteLLMInferenceRuntime(c LiteLLMRuntime) error {
	if err := ValidateLiteLLMRuntime(c); err != nil {
		return err
	}
	if !c.InferenceEnabled || !liteModelAliasPattern.MatchString(c.ModelAlias) || c.ModelAlias == liteUnknownAlias {
		return errors.New("LiteLLM inference is disabled or its reviewed model alias is invalid")
	}
	return nil
}

type liteRoutingResponse struct {
	Status                int    `json:"status"`
	ContentType           string `json:"contentType"`
	BodySHA256            string `json:"bodySHA256"`
	BodyBytes             int    `json:"bodyBytes"`
	BoundExceeded         bool   `json:"boundExceeded"`
	CompletionValid       bool   `json:"completionValid"`
	ReturnedModel         string `json:"returnedModel"`
	UsagePromptTokens     int    `json:"usagePromptTokens"`
	UsageCompletionTokens int    `json:"usageCompletionTokens"`
	Reason                string `json:"reason"`
	ErrorCode             string `json:"errorCode"`
}

type liteRoutingTransport interface {
	snapshot(context.Context, LiteLLMRuntime) (liteAuthority, error)
	sourcePin(context.Context, LiteLLMRuntime, litePod) error
	inferenceConfig(context.Context, LiteLLMRuntime, liteAuthority) error
	post(context.Context, LiteLLMRuntime, litePod, string) (liteRoutingResponse, error)
}

type liteRoutingHandler struct{ transport liteRoutingTransport }

func NewLiteLLMRoutingHandler() Handler           { return liteRoutingHandler{} }
func (liteRoutingHandler) Definition() Definition { d, _ := DefinitionFor(LiteLLMRouting); return d }
func (liteRoutingHandler) Reconcile(_ context.Context, _ JobContext, _ Journal) Cleanup {
	return Cleanup{Verified: true, Status: "no-mutation"}
}
func (liteRoutingHandler) Validate(r Runtime) error {
	if err := ValidateLiteLLMInferenceRuntime(r.LiteLLM); err != nil {
		return err
	}
	if r.Kube == nil || r.RESTConfig == nil {
		return errors.New("LiteLLM inference Kubernetes transport unavailable")
	}
	return nil
}

type liteRoutingConfig struct {
	GeneralSettings struct {
		MasterKey string `yaml:"master_key"`
	} `yaml:"general_settings"`
	ModelList []struct {
		ModelName string `yaml:"model_name"`
	} `yaml:"model_list"`
}

func (t liteKubeTransport) inferenceConfig(ctx context.Context, c LiteLLMRuntime, authority liteAuthority) error {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cm, err := t.runtime.Kube.CoreV1().ConfigMaps(c.Namespace).Get(bounded, c.ConfigMap, metav1.GetOptions{})
	if err != nil || string(cm.UID) != authority.ConfigUID || cm.ResourceVersion != authority.ConfigRV || cm.DeletionTimestamp != nil || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return errors.New("LiteLLM inference configuration authority unavailable")
	}
	bytes, ok := cm.Data[c.ConfigKey]
	sum := sha256.Sum256([]byte(bytes))
	if !ok || hex.EncodeToString(sum[:]) != authority.ConfigSHA || authority.ConfigSHA != c.ExpectedConfigSHA256 {
		return errors.New("LiteLLM inference mounted configuration differs")
	}
	var parsed liteRoutingConfig
	if yaml.Unmarshal([]byte(bytes), &parsed) != nil || parsed.GeneralSettings.MasterKey != "os.environ/LITELLM_MASTER_KEY" || len(parsed.ModelList) != 2 {
		return errors.New("LiteLLM inference master-key reference or model list differs")
	}
	seen := map[string]bool{}
	for _, item := range parsed.ModelList {
		if !liteModelAliasPattern.MatchString(item.ModelName) || seen[item.ModelName] || item.ModelName == liteUnknownAlias {
			return errors.New("LiteLLM inference model aliases invalid or ambiguous")
		}
		seen[item.ModelName] = true
	}
	if !seen[c.ModelAlias] || len(authority.Pods) != 2 {
		return errors.New("LiteLLM reviewed inference alias or serving Pods unavailable")
	}
	for _, pod := range authority.Pods {
		if !pod.MasterKeyDeclared {
			return errors.New("LiteLLM exact Pod master-key env declaration unavailable")
		}
	}
	return nil
}

// The only application POST is made inside the exact Pod. The declared master
// key is read solely by that process and never appears in argv, stdout, stderr,
// response artifacts or the console's application HTTP transport.
const liteRoutingProbeScript = `import hashlib,http.client,json,os,signal,sys
alias,port=sys.argv[1:]
key=os.environ.get('LITELLM_MASTER_KEY','')
if not key: raise RuntimeError('declared master credential unavailable')
payload=json.dumps({'model':alias,'messages':[{'role':'user','content':'Reply with OK.'}],'max_tokens':16,'temperature':0,'stream':False},separators=(',',':'))
conn=http.client.HTTPConnection('127.0.0.1',int(port),timeout=25)
absolute_seconds=25
def timeout_handler(_signum,_frame):raise TimeoutError('bounded inference request elapsed')
old_handler=signal.signal(signal.SIGALRM,timeout_handler)
signal.setitimer(signal.ITIMER_REAL,absolute_seconds)
try:
 conn.request('POST','/v1/chat/completions',body=payload,headers={'Authorization':'Bearer '+key,'Accept':'application/json','Content-Type':'application/json'})
 response=conn.getresponse()
 body=response.read(16385)
 ct=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
 out={'status':response.status,'contentType':ct,'bodySHA256':hashlib.sha256(body).hexdigest(),'bodyBytes':len(body),'boundExceeded':len(body)>16384,'completionValid':False,'returnedModel':'','usagePromptTokens':0,'usageCompletionTokens':0,'reason':'OTHER_REDACTED','errorCode':''}
 if not out['boundExceeded'] and ct=='application/json':
  try:
   value=json.loads(body)
   if response.status==200 and isinstance(value,dict) and 'error' not in value and value.get('object')=='chat.completion':
    choices=value.get('choices'); usage=value.get('usage'); model=value.get('model')
    if isinstance(choices,list) and len(choices)==1 and isinstance(choices[0],dict):
     choice=choices[0]; message=choice.get('message')
     model_safe=isinstance(model,str) and model==alias
     if isinstance(message,dict) and message.get('role')=='assistant' and isinstance(message.get('content'),str) and message['content'].strip() and choice.get('finish_reason')=='stop' and model_safe and isinstance(usage,dict):
      p=usage.get('prompt_tokens'); c=usage.get('completion_tokens'); total=usage.get('total_tokens')
      if type(p)==int and type(c)==int and type(total)==int and p>=0 and c>0 and total==p+c:
       out.update(completionValid=True,returnedModel=model,usagePromptTokens=p,usageCompletionTokens=c,reason='VALID_ASSISTANT_COMPLETION')
   elif isinstance(value,dict) and isinstance(value.get('error'),dict):
    err=value['error']; code=err.get('code'); typ=err.get('type'); msg=err.get('message')
    if response.status==400 and isinstance(msg,str) and 'no connected db' in msg.lower():out['reason']='NO_CONNECTED_DB'
    elif response.status in (400,404) and (code in ('model_not_found','model_not_found_error','ModelNotFoundError') or typ in ('model_not_found','model_not_found_error','ModelNotFoundError')):
     out.update(reason='MODEL_NOT_FOUND',errorCode='MODEL_NOT_FOUND')
    elif response.status in (401,403):out['reason']='AUTH_DENIED'
    elif response.status==429:out['reason']='RATE_LIMITED'
    elif response.status>=500:out['reason']='PROVIDER_OR_GATEWAY_ERROR'
    elif response.status in (400,404):out['reason']='CONFIGURATION_ERROR'
  except (ValueError,UnicodeDecodeError):out['reason']='MALFORMED_RESPONSE'
 if response.status==200 and not out['completionValid']:out['reason']='MALFORMED_RESPONSE'
 if ct!='application/json':out['reason']='MALFORMED_RESPONSE'
 print(json.dumps(out,sort_keys=True))
finally:
 signal.setitimer(signal.ITIMER_REAL,0)
 signal.signal(signal.SIGALRM,old_handler)
 conn.close()`

func (t liteKubeTransport) post(ctx context.Context, c LiteLLMRuntime, p litePod, alias string) (liteRoutingResponse, error) {
	if alias != c.ModelAlias && alias != liteUnknownAlias {
		return liteRoutingResponse{}, errors.New("LiteLLM inference alias not in fixed request plan")
	}
	bounded, cancel := context.WithTimeout(ctx, liteRoutingCallTime)
	defer cancel()
	command := []string{"python", "-c", liteRoutingProbeScript, alias, strconv.Itoa(int(c.Port))}
	req := t.runtime.Kube.CoreV1().RESTClient().Post().Resource("pods").Name(p.Name).Namespace(c.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: c.Container, Command: command, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(t.runtime.RESTConfig, http.MethodPost, req.URL())
	if err != nil {
		return liteRoutingResponse{}, errors.New("LiteLLM inference exact-Pod exec unavailable")
	}
	var stdout, stderr liteLimitedBuffer
	stdout.limit, stderr.limit = 2048, 128
	if executor.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}) != nil || stdout.overflow || stderr.overflow {
		return liteRoutingResponse{}, errors.New("LiteLLM inference POST outcome ambiguous")
	}
	var response liteRoutingResponse
	decoder := json.NewDecoder(strings.NewReader(stdout.String()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || validateLiteRoutingResponse(response) != nil {
		return liteRoutingResponse{}, errors.New("LiteLLM inference sanitized receipt invalid")
	}
	return response, nil
}

func validateLiteRoutingResponse(r liteRoutingResponse) error {
	if r.Status < 100 || r.Status > 599 || r.BodyBytes < 0 || r.BodyBytes > liteRoutingMaxBody || r.BoundExceeded || len(r.BodySHA256) != 64 {
		return errors.New("LiteLLM inference response bound invalid")
	}
	if _, err := hex.DecodeString(r.BodySHA256); err != nil || len(r.ContentType) > 64 || strings.ContainsAny(r.ContentType, "\r\n\x00") {
		return errors.New("LiteLLM inference receipt encoding invalid")
	}
	switch r.Reason {
	case "VALID_ASSISTANT_COMPLETION":
		if r.Status != 200 || r.ContentType != "application/json" || !r.CompletionValid || !liteModelAliasPattern.MatchString(r.ReturnedModel) || r.UsagePromptTokens < 0 || r.UsageCompletionTokens <= 0 || r.ErrorCode != "" {
			return errors.New("LiteLLM completion receipt contradictory")
		}
	case "MODEL_NOT_FOUND":
		if (r.Status != 400 && r.Status != 404) || r.ContentType != "application/json" || r.ErrorCode != "MODEL_NOT_FOUND" || r.CompletionValid || r.ReturnedModel != "" || r.UsagePromptTokens != 0 || r.UsageCompletionTokens != 0 {
			return errors.New("LiteLLM unknown-model receipt contradictory")
		}
	case "NO_CONNECTED_DB", "AUTH_DENIED", "RATE_LIMITED", "PROVIDER_OR_GATEWAY_ERROR", "CONFIGURATION_ERROR", "MALFORMED_RESPONSE", "OTHER_REDACTED":
		if r.CompletionValid || r.ReturnedModel != "" || r.ErrorCode != "" || r.UsagePromptTokens != 0 || r.UsageCompletionTokens != 0 {
			return errors.New("LiteLLM error receipt contains completion")
		}
	default:
		return errors.New("LiteLLM inference reason is unrecognized")
	}
	return nil
}

func (h liteRoutingHandler) Run(ctx context.Context, jc JobContext) (out Result) {
	out = Result{Outcome: OutcomeInconclusive, Summary: "LiteLLM authenticated routing incomplete", StartedAt: time.Now().UTC(), Evidence: map[string]string{
		"securityOutcome": "NOT_EVALUATED", "installedDefense": "NOT_EVALUATED", "brain": "NOT_EVALUATED", "actuator": "NOT_EVALUATED", "securityEvent": "NOT_REQUIRED", "eventMode": "none", "sourceType": "direct-exact-pod-loopback", "requestCount": "0", "knownModelState": "UNVERIFIED", "unknownModelState": "UNVERIFIED"},
		Limits: []string{h.Definition().ClaimLimits}, Cleanup: Cleanup{Verified: true, Status: "no-mutation"}}
	defer func() { out.FinishedAt = time.Now().UTC() }()
	if h.Validate(jc.Runtime) != nil || jc.Recorder == nil {
		out.Summary = "LiteLLM inference runtime or recorder unavailable"
		return
	}
	ctx, cancel := context.WithTimeout(ctx, liteRoutingTotalTime)
	defer cancel()
	t := h.transport
	if t == nil {
		t = liteKubeTransport{runtime: jc.Runtime}
	}
	c := jc.Runtime.LiteLLM
	initial, err := t.snapshot(ctx, c)
	if err != nil || len(initial.Pods) != 2 {
		out.Summary = "LiteLLM inference target preflight unavailable or too many Pods"
		return
	}
	initialHash := initial.fingerprint()
	out.Evidence["authorityBeforeSHA256"] = initialHash
	out.Evidence["configSHA256"] = initial.ConfigSHA
	out.Evidence["modelAlias"] = c.ModelAlias
	out.Evidence["targetPodCount"] = strconv.Itoa(len(initial.Pods))
	if t.inferenceConfig(ctx, c, initial) != nil {
		out.Summary = "LiteLLM inference alias or master-key configuration unavailable"
		return
	}
	requests, knownOK, unknownOK, unexpectedSuccess := 0, true, true, false
	for i, pod := range initial.Pods {
		prefix := "pod" + strconv.Itoa(i+1) + "."
		out.Evidence[prefix+"name"] = pod.Name
		out.Evidence[prefix+"uid"] = pod.UID
		out.Evidence[prefix+"imageID"] = pod.ImageID
		out.Evidence[prefix+"version"] = liteSourceFor(pod.ImageID).version
		for _, step := range []struct{ name, alias string }{{"known", c.ModelAlias}, {"unknown", liteUnknownAlias}} {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < liteRoutingCallTime+liteRoutingAfterReserve {
				out.Summary = "LiteLLM inference insufficient remaining budget before POST"
				return
			}
			before, e := t.snapshot(ctx, c)
			if e != nil || before.fingerprint() != initialHash || t.inferenceConfig(ctx, c, before) != nil || t.sourcePin(ctx, c, pod) != nil {
				out.Summary = "LiteLLM inference authority or source changed before POST"
				return
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < liteRoutingCallTime+liteRoutingAfterReserve {
				out.Summary = "LiteLLM inference insufficient remaining budget before POST"
				out.Evidence["admissionState"] = "INSUFFICIENT_BUDGET"
				return
			}
			identity := map[string]string{"podUID": pod.UID, "podName": pod.Name, "route": liteRoutingPath, "requestKind": step.name, "modelAlias": step.alias}
			if jc.Recorder.Intent(Intent{Step: "litellm.routing." + step.name, At: time.Now().UTC(), Identity: identity}) != nil {
				out.Summary = "LiteLLM inference POST intent unavailable"
				return
			}
			response, callErr := t.post(ctx, c, pod, step.alias)
			requests++
			out.Evidence["requestCount"] = strconv.Itoa(requests)
			if callErr != nil || validateLiteRoutingResponse(response) != nil || (step.name == "known" && response.Reason == "VALID_ASSISTANT_COMPLETION" && response.ReturnedModel != c.ModelAlias) {
				out.Evidence[prefix+step.name+".state"] = "UNVERIFIED"
				out.Evidence[prefix+step.name+".reason"] = "REQUEST_UNAVAILABLE"
				out.Summary = "LiteLLM inference POST receipt unavailable or ambiguous"
				return
			}
			out.Evidence[prefix+step.name+".status"] = strconv.Itoa(response.Status)
			out.Evidence[prefix+step.name+".bodySHA256"] = response.BodySHA256
			out.Evidence[prefix+step.name+".bodyBytes"] = strconv.Itoa(response.BodyBytes)
			out.Evidence[prefix+step.name+".reason"] = response.Reason
			state := "UNVERIFIED"
			if step.name == "known" {
				if response.Reason == "VALID_ASSISTANT_COMPLETION" {
					state = "COMPLETION_SERVED"
					out.Evidence[prefix+"known.returnedModel"] = response.ReturnedModel
					out.Evidence[prefix+"known.usagePromptCount"] = strconv.Itoa(response.UsagePromptTokens)
					out.Evidence[prefix+"known.usageCompletionCount"] = strconv.Itoa(response.UsageCompletionTokens)
				} else {
					knownOK = false
				}
			} else {
				if response.Reason == "MODEL_NOT_FOUND" {
					state = "MODEL_REJECTED"
				} else {
					unknownOK = false
					if response.Reason == "VALID_ASSISTANT_COMPLETION" {
						unexpectedSuccess = true
					}
				}
			}
			out.Evidence[prefix+step.name+".state"] = state
			if jc.Recorder.Event(Event{Step: "litellm.routing." + step.name, Status: "observed", At: time.Now().UTC(), Identity: liteRoutingEventIdentity(pod, response, state)}) != nil {
				out.Summary = "LiteLLM inference receipt persistence unavailable"
				return
			}
			after, e := t.snapshot(ctx, c)
			if e != nil || after.fingerprint() != initialHash || t.inferenceConfig(ctx, c, after) != nil || t.sourcePin(ctx, c, pod) != nil {
				out.Summary = "LiteLLM inference authority or source changed after POST"
				return
			}
		}
	}
	final, err := t.snapshot(ctx, c)
	if err != nil || final.fingerprint() != initialHash {
		out.Summary = "LiteLLM inference final authority changed"
		return
	}
	out.Evidence["authorityAfterSHA256"] = final.fingerprint()
	if knownOK {
		out.Evidence["knownModelState"] = "COMPLETION_SERVED"
	}
	if unknownOK {
		out.Evidence["unknownModelState"] = "MODEL_REJECTED"
	}
	if unexpectedSuccess {
		out.Outcome = OutcomeFunctionalFail
		out.Summary = "nonexistent model unexpectedly returned a valid completion on an exact Pod"
		return
	}
	if !knownOK || !unknownOK {
		out.Summary = "LiteLLM inference serving or typed model rejection unverified on one or more Pods"
		return
	}
	out.Outcome = OutcomeFunctionalPass
	out.Summary = "each exact LiteLLM Pod served a bounded assistant completion and explicitly rejected the unknown model"
	return
}

func liteRoutingEventIdentity(pod litePod, response liteRoutingResponse, state string) map[string]string {
	return map[string]string{
		"podUID": pod.UID, "podName": pod.Name, "httpStatus": strconv.Itoa(response.Status),
		"contentType": response.ContentType, "bodySHA256": response.BodySHA256, "bodyBytes": strconv.Itoa(response.BodyBytes),
		"completionValid": strconv.FormatBool(response.CompletionValid), "returnedModel": response.ReturnedModel,
		"usagePromptCount": strconv.Itoa(response.UsagePromptTokens), "usageCompletionCount": strconv.Itoa(response.UsageCompletionTokens),
		"reason": response.Reason, "errorCode": response.ErrorCode, "state": state,
	}
}
