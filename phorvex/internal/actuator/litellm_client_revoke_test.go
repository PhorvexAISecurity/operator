package actuator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/litellmclient"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type litellmRoundTrip func(*http.Request) (*http.Response, error)

func (f litellmRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLiteLLMEventSecondPrecisionObservationBoundary(t *testing.T) {
	created := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	now := created.Add(5 * time.Second)
	if !litellmEventTimeMatches(created, created.Add(950*time.Millisecond), now) {
		t.Fatal("same-second observed request rejected after Kubernetes timestamp truncation")
	}
	for _, observed := range []time.Time{
		created.Add(time.Second + time.Nanosecond),
		created.Add(6 * time.Second),
		created.Add(-61 * time.Second),
	} {
		if litellmEventTimeMatches(created, observed, now) {
			t.Fatalf("unrelated observation time accepted: %s", observed)
		}
	}
}

func liteReceiptForTest(clientSHA, opID string) litellmRevokeReceipt {
	return litellmRevokeReceipt{Version: 2, Phase: "prepared", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1,
		TargetUID: "uid-a", PeerUID: "uid-b", EventName: "event-" + opID, EventUID: "event-uid-" + opID,
		ClientSHA256: clientSHA, ConfigMapUID: "cm-uid", ClientsConfigMapUID: "clients-uid",
		SeedSHA256: strings.Repeat("c", 64), ServiceUID: "svc-uid", SourceSHA256: litellmclient.ApprovedSourceSHA256,
		OperationID: opID, SelectionDecisionID: opID, TickID: "tick-" + opID}
}

func TestLiteLLMFixedJournalPreservesDistinctRuns(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	first := liteReceiptForTest(b, "decision-1")
	doc := litellmRevokeJournal{Version: 2, Receipts: []litellmRevokeReceipt{first}}
	second, e := doc.append(liteReceiptForTest(a, "decision-2"))
	if e != nil || len(second.Receipts) != 2 || second.Receipts[0].ClientSHA256 != a || second.Receipts[1] != first {
		t.Fatalf("prior prepared receipt not retained: %+v %v", second, e)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: litellmclient.JournalName,
		Labels: map[string]string{litellmclient.JournalLabel: "v2"}},
		Data: map[string]string{litellmclient.JournalKey: litellmJournalRaw(second)}}
	parsed, e := litellmReadJournal(cm)
	if e != nil || parsed.Receipts[1] != first {
		t.Fatalf("fixed protected journal replay: %+v %v", parsed, e)
	}
	if _, e := second.append(liteReceiptForTest(a, "decision-3")); e == nil {
		t.Fatal("same client hash accepted as a second trial")
	}
	if _, e := second.append(liteReceiptForTest(strings.Repeat("d", 64), "decision-1")); e == nil {
		t.Fatal("same selected operation accepted for another client")
	}
	for _, raw := range []string{
		cm.Data[litellmclient.JournalKey] + "\n",
		strings.Replace(cm.Data[litellmclient.JournalKey], `"clientSHA256":`, `"ClientSHA256":"x","clientSHA256":`, 1),
		strings.Replace(cm.Data[litellmclient.JournalKey], `"phase":"prepared"`, `"phase":"terminal-full","phase":"prepared"`, 1),
	} {
		cm.Data[litellmclient.JournalKey] = raw
		if _, e := litellmReadJournal(cm); e == nil {
			t.Fatal("malformed or aliased journal accepted")
		}
	}
}

func TestLiteLLMBothExactGatewayStatusBeforeAndAfterCAS(t *testing.T) {
	clientSHA := strings.Repeat("a", 64)
	live := litellmclient.Live{SourceSHA256: litellmclient.ApprovedSourceSHA256, PolicyUID: "cm-uid",
		SeedSHA256: strings.Repeat("c", 64), State: litellmclient.State{Version: 2, Revision: 1,
			Entries: []litellmclient.Entry{{Active: true, ClientSHA256: clientSHA, OperationID: "decision-1"}}},
		Pods: []litellmclient.Pod{{UID: "uid-a", IP: "10.1.0.1"}, {UID: "uid-b", IP: "10.1.0.2"}}}
	base := map[string]any{"version": 2, "sourceSHA256": live.SourceSHA256, "seedSHA256": live.SeedSHA256,
		"configMapUID": "cm-uid", "clientSHA256": clientSHA, "active": true, "revision": 1,
		"operationId": "decision-1", "role": "attacker", "ready": true,
		"counters": map[string]any{"forwardedRequests": 1, "upstreamCompletions": 1,
			"deniedRequests": 0, "usageTokens": 2}}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"positive", func(map[string]any) {}},
		{"wrong-operation", func(x map[string]any) { x["operationId"] = "other" }},
		{"not-ready", func(x map[string]any) { x["ready"] = false }},
		{"wrong-source", func(x map[string]any) { x["sourceSHA256"] = strings.Repeat("b", 64) }},
		{"wrong-pod", func(x map[string]any) { x["podUID"] = "other" }},
		{"case-alias", func(x map[string]any) { x["PodUID"] = x["podUID"]; delete(x, "podUID") }},
		{"unrecognized-client", func(x map[string]any) { x["role"] = "" }},
		{"no-original-completion", func(x map[string]any) {
			x["counters"] = map[string]any{"forwardedRequests": 1, "upstreamCompletions": 0,
				"deniedRequests": 0, "usageTokens": 0}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[string]bool{}
			ec := EnactCtx{LiteLLMStatusToken: "private-test-token-1234567890123456", LiteLLMStatusTransport: litellmRoundTrip(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "Bearer private-test-token-1234567890123456" ||
					req.URL.Path != "/v1/admission/state" || req.URL.Port() != "4002" ||
					req.URL.Query().Get("clientSHA256") != clientSHA {
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
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}
			err := litellmReadback(context.Background(), ec, live, clientSHA, "decision-1")
			if tc.name == "positive" && (err != nil || len(seen) != 2) {
				t.Fatalf("both readbacks: seen=%v err=%v", seen, err)
			}
			if tc.name != "positive" && err == nil {
				t.Fatal("wrong effective gateway state accepted")
			}
		})
	}
}
