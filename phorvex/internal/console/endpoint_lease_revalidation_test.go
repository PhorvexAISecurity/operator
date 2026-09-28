package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func revalidationFixture(t *testing.T) (endpointLeaseProfile, endpointLeaseSnapshot, *corev1.ConfigMap) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/endpoint-lease-source-upgrade/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p, err := parseEndpointLeaseProfile(read("prior-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, journal := read("prior-state.json"), read("prior-journal.json")
	prior, err := parseEndpointLeaseState(raw, p)
	if err != nil {
		t.Fatal(err)
	}
	oldUID := p.SourceConfigMapUID
	p.SourceConfigMapUID, p.ProxySourceSHA256 = "88888888-8888-4888-8888-888888888888", "322595a608b2384f2ed6994886416838fc4e1d1c45c9dadbf1c00f04a5f52691"
	state := prior
	state.Revision++
	state.ProxySourceSHA256 = p.ProxySourceSHA256
	p.SourceUpgrade = &endpointLeaseSourceUpgrade{Version: 1, PriorStateJSON: string(raw), PriorStateSHA256: endpointLeaseSHA(raw),
		PriorJournalSHA256: endpointLeaseSHA(journal), CurrentStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(state)), PriorSourceConfigMapUID: oldUID}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointLeaseJournalCM, Namespace: "phorvex-system", UID: types.UID(p.JournalUID), ResourceVersion: "7"}, Data: map[string]string{"receipts.json": string(journal)}}
	pods := []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "vllm-one", Namespace: "vllm", UID: "99999999-9999-4999-8999-999999999999"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "guardrail", ContainerID: "proxy-one"}, {Name: "vllm", ContainerID: "engine-one"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "vllm-two", Namespace: "vllm", UID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "guardrail", ContainerID: "proxy-two"}, {Name: "vllm", ContainerID: "engine-two"}}}}}
	snap := endpointLeaseSnapshot{State: state, StateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(state)), ServiceUID: p.ServiceUID, PolicyUID: p.PolicyUID, PolicyGeneration: p.PolicyGeneration,
		ConfigMapUID: p.PolicyConfigMapUID, ConfigMapRV: "8", SecretUID: p.TenantSecretUID, SourceConfigMapUID: p.SourceConfigMapUID, JournalUID: p.JournalUID, Pods: pods}
	return p, snap, cm
}

func TestEndpointLeaseRevalidationUsesActualHTTPAndPreservesAccounting(t *testing.T) {
	p, snap, journal := revalidationFixture(t)
	for _, mode := range []string{"verified", "A lands", "wrong denial", "B error", "second proxy differs", "state drift", "source drift", "Secret drift", "policy drift", "container drift", "policy RV drift", "journal drift", "journal UID drift", "journal RV drift", "archive fails", "persistence fails"} {
		t.Run(mode, func(t *testing.T) {
			tokens := endpointLeaseTokens{A: []byte(strings.Repeat("a", 32)), B: []byte(strings.Repeat("b", 32))}
			publicCalls, statuses := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				publicCalls++
				if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" {
					t.Error("wrong producer route")
				}
				w.Header().Set("Content-Type", "application/json")
				isA := r.Header.Get("Authorization") == "Bearer "+string(tokens.A)
				if isA && mode != "A lands" {
					w.WriteHeader(401)
					if mode == "wrong denial" {
						_, _ = w.Write([]byte(`{"error":"different"}`))
					} else {
						_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
					}
					return
				}
				if !isA && mode == "B error" {
					w.WriteHeader(503)
					_, _ = w.Write([]byte(`{"error":"unavailable"}`))
					return
				}
				_, _ = w.Write([]byte(`{"id":"real-http-fixture-completion","model":"Qwen/Qwen2.5-7B-Instruct-AWQ","choices":[{"message":{"content":"OK"},"finish_reason":"stop"}]}`))
			}))
			defer server.Close()
			record := &attackRecord{ID: "endpoint-revalidation-" + strings.ReplaceAll(mode, " ", "-"), EvidenceKind: "vllm-endpoint-lease-live", Namespace: "vllm", Service: "vllm", EndpointLeaseProbe: &endpointLeaseProbeResult{Schema: "vllm-endpoint-lease-live-v1", ScenarioID: endpointLeaseScenario, Status: "UNKNOWN", Cleanup: "NOT_NEEDED"}}
			reads := endpointLeaseRevalidationReads{
				public: func(ctx context.Context, bearer []byte) (endpointLeaseHTTPReceipt, error) {
					return endpointLeasePublicCallURL(ctx, bearer, server.URL+"/v1/chat/completions")
				},
				status: func(_ context.Context, pod corev1.Pod) (endpointLeaseStatus, error) {
					statuses++
					state := endpointLeaseStatus{Version: 1, Ready: true, PodUID: string(pod.UID), ServiceUID: p.ServiceUID, PolicyConfigMapUID: p.PolicyConfigMapUID, SecretUID: p.TenantSecretUID, ProxySourceSHA256: p.ProxySourceSHA256, SeedSHA256: p.SeedSHA256, StateSHA256: snap.StateSHA256, Revision: snap.State.Revision, LastOperationID: snap.State.LastOperationID, RevokedClientHMAC: p.ClientAHMAC, RetainedClientHMAC: p.ClientBHMAC, RetainedClientAllowed: true}
					if mode == "second proxy differs" && pod.Name == "vllm-two" {
						state.RevokedClientAllowed = true
					}
					return state, nil
				},
				snapshot: func(context.Context) (endpointLeaseSnapshot, error) {
					next := snap
					if mode == "state drift" {
						next.StateSHA256 = leaseHex('0')
					}
					switch mode {
					case "source drift":
						next.SourceConfigMapUID = "different"
					case "Secret drift":
						next.SecretUID = "different"
					case "policy drift":
						next.PolicyGeneration++
					case "policy RV drift":
						next.ConfigMapRV = "different"
					case "container drift":
						next.Pods = make([]corev1.Pod, len(snap.Pods))
						for i := range snap.Pods {
							next.Pods[i] = *snap.Pods[i].DeepCopy()
						}
						next.Pods[0].Status.ContainerStatuses[0].ContainerID = "different"
					}
					return next, nil
				},
				journal: func(context.Context) (*corev1.ConfigMap, error) {
					next := journal.DeepCopy()
					if mode == "journal drift" {
						next.Data["receipts.json"] += "\n"
					}
					if mode == "journal UID drift" {
						next.UID = "different"
					}
					if mode == "journal RV drift" {
						next.ResourceVersion = "different"
					}
					return next, nil
				},
				archive: func(name string, raw []byte) error {
					if mode == "archive fails" && name == "revalidation-B-original.json" {
						return errors.New("archive failed")
					}
					if len(raw) == 0 {
						t.Error("empty evidence")
					}
					return nil
				},
			}
			runEndpointLeaseRevalidation(context.Background(), record, p, snap, journal, tokens, reads)
			probe := record.EndpointLeaseProbe
			if mode == "verified" || mode == "persistence fails" {
				if probe.Status != "PROTECTION_REVALIDATED" || record.Outcome != "PROTECTION_REVALIDATED" || !probe.ProtectionRevalidated || publicCalls != 2 || statuses != 4 || !probe.PostAExactDenial || !probe.PostBValidCompletion {
					t.Fatalf("actual current protection not verified: %+v calls=%d states=%d", probe, publicCalls, statuses)
				}
				server := &Server{cfg: Config{Root: t.TempDir()}}
				if mode == "persistence fails" {
					server.cfg.StateAppend = func(string, []byte) error { return errors.New("durable storage unavailable") }
				}
				server.finishEndpointLease(record)
				if mode == "persistence fails" {
					if record.Status != "partial" || record.Outcome != "" || probe.Status != "UNKNOWN" || record.Actuated || record.PersistenceError == "" {
						t.Fatal("persistence failure retained verified outcome")
					}
					return
				}
				if record.Status != "done" || record.Outcome != "PROTECTION_REVALIDATED" || record.Actuated || record.Action != "" || record.TimeToDefendSec != 0 || probe.FirstAccepted || probe.EventUID != "" || probe.SelectedDecisionID != "" || probe.SelectedTickID != "" {
					t.Fatal("revalidation received new response/selection credit")
				}
				// Exercise the actual GET clone/serialization boundary as well as
				// the producer: an empty issues slice must survive as [] rather than null.
				raw, err := json.Marshal(cloneAttackRecord(record))
				if err != nil {
					t.Fatal(err)
				}
				var serialized struct {
					Probe struct {
						Issues json.RawMessage `json:"issues"`
						Status string          `json:"status"`
					} `json:"endpointLeaseProbe"`
				}
				if json.Unmarshal(raw, &serialized) != nil || string(serialized.Probe.Issues) != "[]" || serialized.Probe.Status != "PROTECTION_REVALIDATED" {
					t.Fatalf("successful producer GET lost empty array: %s", raw)
				}
			} else if mode == "A lands" {
				if record.Outcome != "LANDED" || probe.Status != "LANDED" || probe.ProtectionRevalidated {
					t.Fatal("real A completion masked")
				}
			} else if record.Outcome != "" || probe.ProtectionRevalidated || probe.Status != "UNKNOWN" {
				t.Fatalf("incomplete evidence credited: %+v", probe)
			}
		})
	}
}

func TestEndpointLeaseRevalidationRefusesChangedProvenanceBeforePublicCall(t *testing.T) {
	for _, mode := range []string{"prepared", "changed witness", "A rearmed", "historical event missing", "journal UID"} {
		t.Run(mode, func(t *testing.T) {
			p, snap, cm := revalidationFixture(t)
			switch mode {
			case "prepared":
				j, _ := parseEndpointLeaseJournal([]byte(cm.Data["receipts.json"]))
				j.Receipts = append(j.Receipts, endpointLeaseJournalReceipt{Phase: "prepared"})
				cm.Data["receipts.json"] = string(endpointLeaseJournalBytes(j))
			case "changed witness":
				copy := *p.SourceUpgrade
				copy.CurrentStateSHA256 = leaseHex('0')
				p.SourceUpgrade = &copy
			case "A rearmed":
				snap.State.AllowedClientHMACs = []string{p.ClientAHMAC, p.ClientBHMAC}
				snap.State.RevokedClientHMACs = []string{}
			case "historical event missing":
				j, _ := parseEndpointLeaseJournal([]byte(cm.Data["receipts.json"]))
				j.Receipts[0].EventUID = ""
				cm.Data["receipts.json"] = string(endpointLeaseJournalBytes(j))
				copy := *p.SourceUpgrade
				copy.PriorJournalSHA256 = endpointLeaseSHA([]byte(cm.Data["receipts.json"]))
				p.SourceUpgrade = &copy
			case "journal UID":
				cm.UID = "unknown"
			}
			if _, err := endpointLeaseProtectionOrigin(snap, cm, p); err == nil {
				t.Fatal("changed history/protection accepted")
			}
		})
	}
}
