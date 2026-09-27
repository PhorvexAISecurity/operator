package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

const endpointLeaseAdminProbe = `import http.client,json,os,signal,socket,ssl,sys
signal.alarm(12)
v=json.load(sys.stdin)
if set(v)!={'revokedClientHMAC','retainedClientHMAC'} or any(len(x)!=64 or any(c not in '0123456789abcdef' for c in x) for x in v.values()):raise RuntimeError('query')
token=os.environ.get('PHORVEX_GUARDRAIL_ADMIN_KEY','')
cert=os.environ.get('PHORVEX_ADMIN_TLS_CERT_FILE','')
if not 32<=len(token)<=256 or not cert:raise RuntimeError('admin authority')
ctx=ssl.create_default_context(cafile=cert)
raw=socket.create_connection(('127.0.0.1',8443),timeout=8)
sock=ctx.wrap_socket(raw,server_hostname='vllm-admin.vllm.svc')
try:
 path='/v1/endpoint-lease/state?revokedClientHMAC='+v['revokedClientHMAC']+'&retainedClientHMAC='+v['retainedClientHMAC']
 req=('GET '+path+' HTTP/1.1\r\nHost: vllm-admin.vllm.svc\r\nAuthorization: Bearer '+token+'\r\nConnection: close\r\n\r\n').encode()
 sock.sendall(req)
 response=http.client.HTTPResponse(sock);response.begin();body=response.read(8193)
 if response.status!=200 or len(body)>8192 or response.getheader('Content-Type','').split(';')[0]!='application/json':raise RuntimeError('status')
 value=json.loads(body)
 print(json.dumps(value,sort_keys=True,separators=(',',':')))
finally:sock.close()
`

type endpointLeaseStatus struct {
	Version               int    `json:"version"`
	PodUID                string `json:"podUID"`
	ServiceUID            string `json:"serviceUID"`
	PolicyConfigMapUID    string `json:"policyConfigMapUID"`
	SecretUID             string `json:"secretUID"`
	ProxySourceSHA256     string `json:"proxySourceSHA256"`
	SeedSHA256            string `json:"seedSHA256"`
	StateSHA256           string `json:"stateSHA256"`
	Revision              uint64 `json:"revision"`
	LastOperationID       string `json:"lastOperationID"`
	RevokedClientHMAC     string `json:"revokedClientHMAC"`
	RetainedClientHMAC    string `json:"retainedClientHMAC"`
	RevokedClientAllowed  bool   `json:"revokedClientAllowed"`
	RetainedClientAllowed bool   `json:"retainedClientAllowed"`
	OldRevisionInFlight   uint64 `json:"oldRevisionInFlight"`
	Ready                 bool   `json:"ready"`
}

func endpointLeaseStatusMatches(status endpointLeaseStatus, p endpointLeaseProfile, snap endpointLeaseSnapshot,
	pod corev1.Pod, revoked bool) bool {
	return status.Version == 1 && status.Ready && status.PodUID == string(pod.UID) &&
		status.ServiceUID == p.ServiceUID && status.PolicyConfigMapUID == p.PolicyConfigMapUID &&
		status.SecretUID == p.TenantSecretUID && status.ProxySourceSHA256 == p.ProxySourceSHA256 &&
		status.SeedSHA256 == p.SeedSHA256 && status.StateSHA256 == snap.StateSHA256 &&
		status.Revision == snap.State.Revision && status.LastOperationID == snap.State.LastOperationID &&
		status.RevokedClientHMAC == p.ClientAHMAC && status.RetainedClientHMAC == p.ClientBHMAC &&
		status.RevokedClientAllowed == !revoked && status.RetainedClientAllowed &&
		(!revoked || status.OldRevisionInFlight == 0)
}

func endpointLeaseAdminState(ctx context.Context, config *rest.Config, kube kubernetes.Interface,
	pod corev1.Pod, p endpointLeaseProfile) (endpointLeaseStatus, error) {
	var status endpointLeaseStatus
	if pod.Namespace != "vllm" || pod.Name == "" || pod.UID == "" {
		return status, errors.New("endpoint lease proxy identity unavailable")
	}
	input, _ := json.Marshal(map[string]string{"revokedClientHMAC": p.ClientAHMAC, "retainedClientHMAC": p.ClientBHMAC})
	request := kube.CoreV1().RESTClient().Post().Resource("pods").Name(pod.Name).Namespace("vllm").SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: "guardrail", Command: []string{"python3", "-B", "-c", endpointLeaseAdminProbe},
			Stdin: true, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, request.URL())
	if err != nil {
		return status, errors.New("endpoint lease authenticated Pod readback unavailable")
	}
	stdout, stderr := &voiceAgencyLimitedWriter{limit: 8192}, &voiceAgencyLimitedWriter{limit: 1024}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = executor.StreamWithContext(callCtx, remotecommand.StreamOptions{Stdin: bytes.NewReader(input), Stdout: stdout, Stderr: stderr})
	if err != nil || stdout.over || stderr.over || stderr.Len() != 0 || endpointLeaseStrictJSON(stdout.Bytes(), &status, 8192) != nil {
		return endpointLeaseStatus{}, errors.New("endpoint lease authenticated Pod readback invalid")
	}
	current, err := kube.CoreV1().Pods("vllm").Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || current.UID != pod.UID || current.ResourceVersion == "" || current.DeletionTimestamp != nil ||
		endpointLeaseProxyContainerID(pod) == "" || endpointLeaseProxyContainerID(*current) != endpointLeaseProxyContainerID(pod) {
		return endpointLeaseStatus{}, errors.New("endpoint lease proxy incarnation changed during readback")
	}
	return status, nil
}

func endpointLeaseRequestBody() []byte {
	b, _ := json.Marshal(map[string]any{"model": endpointLeaseModel, "messages": []map[string]string{{"role": "user", "content": "Reply with exactly OK."}},
		"temperature": 0, "max_tokens": 16, "stream": false})
	return b
}

type endpointLeaseHTTPReceipt struct {
	Status          int    `json:"status"`
	ResponseSHA256  string `json:"responseSHA256"`
	CompletionID    string `json:"completionId,omitempty"`
	Model           string `json:"model,omitempty"`
	ValidCompletion bool   `json:"validCompletion"`
	ExactDenial     bool   `json:"exactDenial"`
	Raw             []byte `json:"-"`
}

func endpointLeasePublicCall(ctx context.Context, bearer []byte) (endpointLeaseHTTPReceipt, error) {
	var result endpointLeaseHTTPReceipt
	if !endpointLeaseTokenValid(bearer) {
		return result, errors.New("endpoint lease owned caller unavailable")
	}
	body := endpointLeaseRequestBody()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	callCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost,
		"http://vllm.vllm.svc.cluster.local:8000/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return result, errors.New("endpoint lease public request unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+string(bearer))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return result, errors.New("endpoint lease public Service response unavailable")
	}
	defer response.Body.Close()
	return endpointLeaseParsePublicResponse(response)
}

func endpointLeaseParsePublicResponse(response *http.Response) (endpointLeaseHTTPReceipt, error) {
	var result endpointLeaseHTTPReceipt
	if response.Header.Get("Location") != "" || strings.Split(response.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return result, errors.New("endpoint lease public response route or media type differs")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(raw) == 0 || len(raw) > 8192 {
		return result, errors.New("endpoint lease public response exceeds bound")
	}
	result.Status, result.ResponseSHA256, result.Raw = response.StatusCode, endpointLeaseSHA(raw), raw
	if response.StatusCode == http.StatusUnauthorized {
		result.ExactDenial = bytes.Equal(raw, []byte(`{"error":"unauthorized"}`))
		return result, nil
	}
	if response.StatusCode != http.StatusOK || rejectNATSNestedDuplicates(raw) != nil {
		return result, nil
	}
	var completion struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &completion) != nil || completion.ID == "" || completion.Model != endpointLeaseModel ||
		len(completion.Choices) != 1 || strings.TrimSpace(completion.Choices[0].Message.Content) != "OK" ||
		completion.Choices[0].FinishReason != "stop" {
		return result, nil
	}
	result.CompletionID, result.Model, result.ValidCompletion = completion.ID, completion.Model, true
	return result, nil
}
