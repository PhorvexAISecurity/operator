package console

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRetainedCallerBRemainsUsableAfterDurableARevocation(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	p := endpointLeaseProfile{PolicyUID: "policy", PolicyConfigMapUID: "policy-cm", TenantSecretUID: "tenant",
		ServiceUID: "service", ProxySourceSHA256: strings.Repeat("c", 64), ClientAHMAC: a, ClientBHMAC: b}
	before := endpointLeaseState{Revision: 0, AllowedClientHMACs: []string{a, b}}
	if !retainedCallerAllowed(before, endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseJournalReceipt{}}, p) {
		t.Fatal("authorized B refused before cutover")
	}
	if retainedCallerAllowed(endpointLeaseState{AllowedClientHMACs: []string{b}}, endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseJournalReceipt{}}, p) {
		t.Fatal("unexplained B-only revision zero admitted")
	}
	after := endpointLeaseState{Revision: 1, AllowedClientHMACs: []string{b}, RevokedClientHMACs: []string{a},
		LastOperationID: strings.Repeat("d", 32)}
	terminal := endpointLeaseJournalReceipt{Phase: "terminal-full", NewRevision: 1,
		NewStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(after)), OperationID: after.LastOperationID,
		PolicyUID: p.PolicyUID, PolicyConfigMapUID: p.PolicyConfigMapUID, SecretUID: p.TenantSecretUID,
		ServiceUID: p.ServiceUID, ProxySourceSHA256: p.ProxySourceSHA256, RetainedClientHMAC: b}
	journal := endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseJournalReceipt{terminal}}
	if !retainedCallerAllowed(after, journal, p) {
		t.Fatal("retained B refused after exact terminal A revocation")
	}
	for name, mutate := range map[string]func(*endpointLeaseState, *endpointLeaseJournal){
		"pending": func(_ *endpointLeaseState, j *endpointLeaseJournal) {
			j.Receipts = append(j.Receipts, endpointLeaseJournalReceipt{Phase: "prepared"})
		},
		"B revoked":        func(s *endpointLeaseState, _ *endpointLeaseJournal) { s.RevokedClientHMACs = []string{a, b} },
		"missing terminal": func(_ *endpointLeaseState, j *endpointLeaseJournal) { j.Receipts = nil },
		"different state":  func(s *endpointLeaseState, _ *endpointLeaseJournal) { s.LastOperationID = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			s, j := after, journal
			s.AllowedClientHMACs = append([]string(nil), after.AllowedClientHMACs...)
			s.RevokedClientHMACs = append([]string(nil), after.RevokedClientHMACs...)
			j.Receipts = append([]endpointLeaseJournalReceipt(nil), journal.Receipts...)
			mutate(&s, &j)
			if retainedCallerAllowed(s, j, p) {
				t.Fatal("unresolved or different B authority admitted")
			}
		})
	}
}

func TestRetainedGuardrailChatUsesBWithoutCrediting401AsDefense(t *testing.T) {
	const bearer = "synthetic-retained-b-credential-1234567890"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"type":"unauthorized"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	code := strings.ReplaceAll(availabilityRetainedChatCode, ",8000,", ","+u.Port()+",")
	for _, tc := range []struct {
		key   string
		want  int
		class string
	}{
		{bearer, 200, "OK"},
		{"synthetic-wrong-retained-b-credential-123456", 401, "UNKNOWN_HTTP_OR_ERROR"},
	} {
		input, _ := json.Marshal(map[string]string{"body": base64.StdEncoding.EncodeToString([]byte(`{}`)),
			"bearer": base64.StdEncoding.EncodeToString([]byte(tc.key))})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "python3", "-B", "-c", code)
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.Output()
		cancel()
		if err != nil || bytes.Contains(out, []byte(bearer)) {
			t.Fatalf("bounded retained chat failed or leaked credential: %v", err)
		}
		var reply availabilityHTTP
		if err := json.Unmarshal(out, &reply); err != nil || reply.Status != tc.want {
			t.Fatalf("HTTP projection = %+v, %v", reply, err)
		}
		body, _ := base64.StdEncoding.DecodeString(reply.BodyBase64)
		if got := availabilityClass("say_ok", reply.Status, body, "CNR_1234abcd"); got != tc.class {
			t.Fatal(fmt.Sprintf("status %d classified as %s", reply.Status, got))
		}
	}
}

func TestDrainRetainedModelAndBenignCallsRejectUnauthenticated401(t *testing.T) {
	const bearer = "synthetic-retained-b-credential-1234567890"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"type":"unauthorized"}}`))
			return
		}
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"data":[{"id":"Qwen/Qwen2.5-7B-Instruct-AWQ"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","text":"Clouds form from water vapor."}]}`))
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	modelCode := strings.Replace(drainRetainedModelPython, `"vllm.vllm.svc.cluster.local",8000`, `"127.0.0.1",`+u.Port(), 1)
	benignCode := strings.Replace(drainBenignPython, `"vllm.vllm.svc.cluster.local",8000`, `"127.0.0.1",`+u.Port(), 1)
	for _, tc := range []struct {
		name, key string
		accepted  bool
	}{
		{"B accepted", bearer, true}, {"wrong caller refused", "synthetic-wrong-retained-b-credential-123456", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			model := exec.CommandContext(ctx, "python3", "-B", "-c", modelCode)
			model.Stdin = strings.NewReader(tc.key)
			modelOut, modelErr := model.Output()
			if bytes.Contains(modelOut, []byte(bearer)) || (modelErr == nil) != tc.accepted {
				t.Fatalf("model auth outcome mismatch or bearer reflected: %v", modelErr)
			}
			input, _ := json.Marshal(map[string]string{"body": base64.StdEncoding.EncodeToString(drainRequestBody(endpointLeaseModel, 8, false)),
				"bearer": base64.StdEncoding.EncodeToString([]byte(tc.key))})
			benign := exec.CommandContext(ctx, "python3", "-B", "-c", benignCode)
			benign.Stdin = bytes.NewReader(input)
			benignOut, benignErr := benign.Output()
			if benignErr != nil || bytes.Contains(benignOut, []byte(bearer)) {
				t.Fatalf("benign auth projection failed or leaked credential: %v", benignErr)
			}
			var row struct {
				Status int  `json:"status"`
				Valid  bool `json:"valid"`
			}
			if json.Unmarshal(benignOut, &row) != nil || (row.Status == 200 && row.Valid) != tc.accepted {
				t.Fatalf("benign auth result = %+v", row)
			}
		})
	}
}

func TestRetainedSourceModeRequiresMatchingProfile(t *testing.T) {
	source := map[string]any{"data": map[string]any{"endpoint_lease.py": "reviewed source"}}
	w := &availabilityWorker{}
	if err := w.retainedSourceMode(source); err == nil {
		t.Fatal("five-file source admitted without retained B")
	}
	if err := w.retainedSourceMode(map[string]any{"data": map[string]any{"guardrail_proxy.py": "legacy"}}); err != nil {
		t.Fatal(err)
	}
	w.retainedCaller = &retainedCallerAuthority{}
	if err := w.retainedSourceMode(source); err != nil {
		t.Fatal(err)
	}
	if err := w.retainedSourceMode(map[string]any{"data": map[string]any{"guardrail_proxy.py": "legacy"}}); err == nil {
		t.Fatal("legacy source admitted under five-file credential profile")
	}
}
