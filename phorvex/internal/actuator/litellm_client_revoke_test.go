package actuator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/litellmclient"
	corev1 "k8s.io/api/core/v1"
)

type litellmRoundTrip func(*http.Request) (*http.Response, error)

func (f litellmRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLiteLLMClientJournalAndBothExactGatewayReadbacks(t *testing.T) {
	clientSHA := strings.Repeat("a", 64)
	live := litellmclient.Live{SourceSHA256: litellmclient.ApprovedSourceSHA256, PolicyUID: "cm-uid", ClientSHA256: clientSHA,
		Pods: []litellmclient.Pod{{UID: "uid-a", IP: "10.1.0.1"}, {UID: "uid-b", IP: "10.1.0.2"}}}
	r := litellmRevokeReceipt{Version: 1, Phase: "prepared", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1,
		TargetUID: "uid-a", PeerUID: "uid-b", EventName: "event", EventUID: "event-uid", ClientSHA256: clientSHA,
		ConfigMapUID: "cm-uid", ServiceUID: "svc-uid", SourceSHA256: live.SourceSHA256,
		OperationID: "decision-1", SelectionDecisionID: "decision-1", TickID: "tick-1"}
	cm := &corev1.ConfigMap{Data: map[string]string{"receipt": litellmReceiptRaw(r)}}
	if got, e := litellmReadReceipt(cm); e != nil || got != r {
		t.Fatalf("prepared journal: %+v %v", got, e)
	}
	cm.Data["receipt"] = strings.Replace(cm.Data["receipt"], `"phase":"prepared"`, `"phase":"terminal-full"`, 1)
	if _, e := litellmReadReceipt(cm); e != nil {
		t.Fatalf("terminal journal: %v", e)
	}
	for _, bad := range []string{
		strings.Replace(cm.Data["receipt"], `"eventUID":"event-uid"`, `"eventUID":"event-uid","eventUID":"other"`, 1),
		strings.Replace(cm.Data["receipt"], `"selectionDecisionId":"decision-1"`, `"selectionDecisionId":"other"`, 1),
		cm.Data["receipt"] + "\n",
	} {
		cm.Data["receipt"] = bad
		if _, e := litellmReadReceipt(cm); e == nil {
			t.Fatal("invalid journal accepted")
		}
	}
	if litellmJournalName("policy-uid", clientSHA) == litellmJournalName("other-policy", clientSHA) {
		t.Fatal("journal name lacks policy UID ownership")
	}
	base := map[string]any{"version": 1, "sourceSHA256": live.SourceSHA256, "configMapUID": "cm-uid",
		"clientSHA256": clientSHA, "active": true, "revision": 1, "operationId": "decision-1", "ready": true,
		"counters": map[string]any{"attacker": map[string]int{"deniedRequests": 1}, "control": map[string]int{"forwardedRequests": 1}}}
	preflight := EnactCtx{LiteLLMStatusToken: "private-test-token-1234567890123456", LiteLLMStatusTransport: litellmRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer private-test-token-1234567890123456" {
			t.Fatal("status credential not used")
		}
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body["podUID"] = "uid-a"
		if req.URL.Hostname() == "10.1.0.2" {
			body["podUID"] = "uid-b"
		}
		body["active"], body["revision"], body["operationId"] = false, 0, ""
		raw, _ := json.Marshal(body)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}
	if e := litellmCheckGatewayState(context.Background(), preflight, live, "", false); e != nil {
		t.Fatalf("inactive exact both-gateway preflight: %v", e)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"positive", func(map[string]any) {}},
		{"wrong-operation", func(x map[string]any) { x["operationId"] = "other" }},
		{"not-ready", func(x map[string]any) { x["ready"] = false }},
		{"wrong-source", func(x map[string]any) { x["sourceSHA256"] = strings.Repeat("b", 64) }},
		{"wrong-pod", func(x map[string]any) { x["podUID"] = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[string]bool{}
			ec := EnactCtx{LiteLLMStatusToken: "private-test-token-123456", LiteLLMStatusTransport: litellmRoundTrip(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "Bearer private-test-token-123456" || req.URL.Path != "/v1/admission/state" || req.URL.Port() != "4002" {
					t.Fatal("readback request differs")
				}
				uid := "uid-a"
				if req.URL.Hostname() == "10.1.0.2" {
					uid = "uid-b"
				}
				seen[uid] = true
				body := map[string]any{}
				for k, v := range base {
					body[k] = v
				}
				body["podUID"] = uid
				tc.change(body)
				raw, _ := json.Marshal(body)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: http.Header{}}, nil
			})}
			err := litellmReadback(context.Background(), ec, live, "decision-1")
			if tc.name == "positive" && (err != nil || len(seen) != 2) {
				t.Fatalf("both readbacks: seen=%v err=%v", seen, err)
			}
			if tc.name != "positive" && err == nil {
				t.Fatal("wrong effective gateway state accepted")
			}
		})
	}
}
