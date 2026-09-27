package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOtherLiveResultVisibilityAndSnapshotIsolation(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		kind      string
		probe     func(*attackRecord)
		mutate    func(*attackRecord)
		fields    func(*attackRecord) (status, issue, reserved string)
	}{
		{
			name: "request drain", namespace: "vllm", kind: "vllm-drain-owned-observation",
			probe:  func(r *attackRecord) { r.DrainLiveProbe = &drainLiveProbeResult{Status: "UNKNOWN", Issue: "initial"} },
			mutate: func(r *attackRecord) { r.DrainLiveProbe.Status, r.DrainLiveProbe.Issue = "DEFENDED", "changed" },
			fields: func(r *attackRecord) (string, string, string) {
				if r.DrainLiveProbe == nil {
					return "missing", "", ""
				}
				return r.DrainLiveProbe.Status, r.DrainLiveProbe.Issue, ""
			},
		},
		{
			name: "voice output", namespace: "voice", kind: "voice-output-live",
			probe: func(r *attackRecord) {
				r.VoiceOutputProbe = &voiceOutputProbeResult{Status: "UNKNOWN", Issues: []string{"initial"}}
			},
			mutate: func(r *attackRecord) { r.VoiceOutputProbe.Status, r.VoiceOutputProbe.Issues[0] = "DEFENDED", "changed" },
			fields: func(r *attackRecord) (string, string, string) {
				if r.VoiceOutputProbe == nil || len(r.VoiceOutputProbe.Issues) != 1 {
					return "missing", "", ""
				}
				return r.VoiceOutputProbe.Status, r.VoiceOutputProbe.Issues[0], ""
			},
		},
		{
			name: "litellm client policy", namespace: "litellm", kind: "litellm-live-client-policy",
			probe: func(r *attackRecord) {
				r.LiteLLMLiveProbe = &liteLLMLiveProbeResult{Status: "UNKNOWN", Issues: []string{"initial"}}
			},
			mutate: func(r *attackRecord) { r.LiteLLMLiveProbe.Status, r.LiteLLMLiveProbe.Issues[0] = "DEFENDED", "changed" },
			fields: func(r *attackRecord) (string, string, string) {
				if r.LiteLLMLiveProbe == nil || len(r.LiteLLMLiveProbe.Issues) != 1 {
					return "missing", "", ""
				}
				return r.LiteLLMLiveProbe.Status, r.LiteLLMLiveProbe.Issues[0], ""
			},
		},
		{
			name: "litellm provider output", namespace: "litellm", kind: "litellm-real-provider-output",
			probe: func(r *attackRecord) {
				r.LiteLLMOutputProbe = &liteLLMOutputProbeResult{Status: "UNKNOWN", Issues: []string{"initial"}, ReservedRuleSlots: []string{"initial"}}
			},
			mutate: func(r *attackRecord) {
				r.LiteLLMOutputProbe.Status = "DEFENDED"
				r.LiteLLMOutputProbe.Issues[0] = "changed"
				r.LiteLLMOutputProbe.ReservedRuleSlots[0] = "changed"
			},
			fields: func(r *attackRecord) (string, string, string) {
				if r.LiteLLMOutputProbe == nil || len(r.LiteLLMOutputProbe.Issues) != 1 || len(r.LiteLLMOutputProbe.ReservedRuleSlots) != 1 {
					return "missing", "", ""
				}
				return r.LiteLLMOutputProbe.Status, r.LiteLLMOutputProbe.Issues[0], r.LiteLLMOutputProbe.ReservedRuleSlots[0]
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attackMu.Lock()
			savedList, savedLoaded := attackList, attackLoaded
			attackList, attackLoaded = nil, true
			attackMu.Unlock()
			t.Cleanup(func() {
				attackMu.Lock()
				attackList, attackLoaded = savedList, savedLoaded
				attackMu.Unlock()
			})

			s := &Server{cfg: Config{Root: t.TempDir()}}
			record := &attackRecord{ID: "live-result", Namespace: tc.namespace, EvidenceKind: tc.kind, Status: "running"}
			tc.probe(record)
			publishAttack(record)
			tc.mutate(record)

			get := func(id, scope string, observations bool) []attackRecord {
				t.Helper()
				url := "/api/attack-results?limit=10&id=" + id
				if observations {
					url += "&includeObservations=true"
				}
				req := withTestPrincipal(httptest.NewRequest(http.MethodGet, url, nil), testOperatorPrincipal(scope))
				out := httptest.NewRecorder()
				s.attackResults(out, req)
				if out.Code != http.StatusOK {
					t.Fatalf("GET %s scope=%s: status=%d body=%s", url, scope, out.Code, out.Body.String())
				}
				var body struct {
					Attacks []attackRecord `json:"attacks"`
				}
				if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
					t.Fatalf("GET %s: decode: %v", url, err)
				}
				return body.Attacks
			}

			if rows := get(record.ID, tc.namespace, false); len(rows) != 0 {
				t.Fatalf("default report exposed %s: %+v", tc.kind, rows)
			}
			rows := get(record.ID, tc.namespace, true)
			if len(rows) != 1 || rows[0].Status != "running" {
				t.Fatalf("running result absent: %+v", rows)
			}
			status, issue, reserved := tc.fields(&rows[0])
			if status != "UNKNOWN" || issue != "initial" || (tc.kind == "litellm-real-provider-output" && reserved != "initial") {
				t.Fatalf("published running probe mutated: %+v", rows)
			}
			if rows := get(record.ID, "other-tenant", true); len(rows) != 0 {
				t.Fatalf("tenant leak: %+v", rows)
			}
			if rows := get("unrelated-id", tc.namespace, true); len(rows) != 0 {
				t.Fatalf("exact ID leak: %+v", rows)
			}

			record.Status = "done"
			publishAttack(record)
			rows = get(record.ID, tc.namespace, true)
			if len(rows) != 1 || rows[0].Status != "done" {
				t.Fatalf("terminal result absent: %+v", rows)
			}
			status, issue, reserved = tc.fields(&rows[0])
			if status != "DEFENDED" || issue != "changed" || (tc.kind == "litellm-real-provider-output" && reserved != "changed") {
				t.Fatalf("terminal probe stale: %+v", rows)
			}
			if rows := get(record.ID, tc.namespace, false); len(rows) != 0 {
				t.Fatalf("terminal result in default report: %+v", rows)
			}
			if rows := get(record.ID, "other-tenant", true); len(rows) != 0 {
				t.Fatalf("terminal tenant leak: %+v", rows)
			}

			publishAttack(&attackRecord{ID: "unknown-kind", Namespace: tc.namespace, EvidenceKind: "unreviewed-kind"})
			if rows := get("unknown-kind", tc.namespace, true); len(rows) != 0 {
				t.Fatalf("unknown category exposed: %+v", rows)
			}
			publishAttack(&attackRecord{ID: "ordinary", Namespace: tc.namespace})
			if rows := get("ordinary", tc.namespace, false); len(rows) != 1 || rows[0].ID != "ordinary" {
				t.Fatalf("ordinary result changed: %+v", rows)
			}
		})
	}
}

func TestVoiceMCPPublishedProbeIsolation(t *testing.T) {
	probe := &voiceMCPLiveProbeResult{Status: "UNKNOWN", Issues: []string{"initial"}}
	snapshot := cloneAttackRecord(&attackRecord{VoiceMCPProbe: probe})
	probe.Status = "DEFENDED"
	probe.Issues[0] = "changed"
	if snapshot.VoiceMCPProbe == nil || snapshot.VoiceMCPProbe.Status != "UNKNOWN" ||
		len(snapshot.VoiceMCPProbe.Issues) != 1 || snapshot.VoiceMCPProbe.Issues[0] != "initial" {
		t.Fatalf("published Voice MCP snapshot changed with worker probe: %+v", snapshot.VoiceMCPProbe)
	}
}
