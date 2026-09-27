package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLiteLiveReviewedProfileRejectsMutableSourceAndRuntimeUIDs(t *testing.T) {
	hash := strings.Repeat("a", 64)
	image := "example.invalid/litellm@sha256:" + hash
	profile := liteLLMLiveProfile{
		Version: 2, SourceSHA256: hash, GatewayImage: image, ClientsSHA256: hash,
		SeedSHA256: strings.Repeat("b", 64), PolicyName: "litellm-defense",
		ModelAlias:          "gpt-4o-mini",
		EventCreator:        "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
		AuditSourceIdentity: "reviewed-audit", MaxRunSeconds: 900,
	}
	encode := func(value liteLLMLiveProfile) []byte {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := parseLiteLiveProfile(encode(profile)); err != nil {
		t.Fatalf("valid stable profile rejected: %v", err)
	}
	invalid := profile
	invalid.GatewayImage = "example.invalid/litellm:latest"
	if _, err := parseLiteLiveProfile(encode(invalid)); err == nil {
		t.Fatal("mutable gateway image accepted")
	}
	if _, err := parseLiteLiveProfile(append(encode(profile), []byte(`{"pods":[{"uid":"stale"}]}`)...)); err == nil {
		t.Fatal("runtime UID accepted in stable profile")
	}
	if _, err := parseLiteLiveProfile(append(encode(profile), []byte(`{"extra":true}`)...)); err == nil {
		t.Fatal("additional top-level JSON accepted")
	}
}

func TestLiteLiveTokenTransportRejectsRedirectsAndProxies(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-test-token" {
			t.Error("first exact target lost bearer")
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	client := liteHTTPClient(0)
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("LiteLLM credential transport accepted ambient proxy")
	}
	req, _ := http.NewRequest(http.MethodGet, redirect.URL, nil)
	req.Header.Set("Authorization", "Bearer private-test-token")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || targetCalls != 0 {
		t.Fatal("LiteLLM credential transport followed redirect")
	}
}

func TestLiteLiveJournalNameIsScopedFixedRead(t *testing.T) {
	if liteJournalName() != "phorvex-litellm-revoke-journal" {
		t.Fatal("protected journal escaped scoped RBAC name")
	}
}

func TestLiteLiveDefendedVerdictRequiresDurableTerminalAndRecord(t *testing.T) {
	{
		probe := &liteLLMLiveProbeResult{Status: "STOPPED_WITH_BENIGN_CONTINUITY"}
		record := &attackRecord{LiteLLMLiveProbe: probe}
		var evidence []byte
		liteFinalizeProbe(record, probe, liteLiveSnapshot{}, nil,
			func(raw []byte) error { evidence = append([]byte(nil), raw...); return nil },
			func(r *attackRecord) error {
				if r.Outcome != "DEFENDED" || !r.Actuated {
					t.Fatal("proved defense was not persisted")
				}
				return nil
			}, func(*attackRecord) {})
		var saved struct {
			Probe liteLLMLiveProbeResult `json:"probe"`
		}
		if err := json.Unmarshal(evidence, &saved); err != nil || saved.Probe.Accepted ||
			!record.LiteLLMLiveProbe.Accepted || record.Outcome != "DEFENDED" {
			t.Fatal("evidence-only receipt or final durable result differs")
		}
	}
	for _, tc := range []struct {
		name         string
		terminalFail bool
		recordFail   bool
	}{
		{name: "terminal write fails", terminalFail: true},
		{name: "record write fails", recordFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &liteLLMLiveProbeResult{Status: "STOPPED_WITH_BENIGN_CONTINUITY"}
			record := &attackRecord{LiteLLMLiveProbe: probe}
			var terminal []byte
			published, persisted, terminalWrites := 0, 0, 0
			liteFinalizeProbe(record, probe, liteLiveSnapshot{Pods: []liteLivePod{{Name: "a"}, {Name: "b"}}}, nil,
				func(raw []byte) error {
					terminalWrites++
					if tc.terminalFail || terminalWrites > 1 {
						return errors.New("injected terminal failure")
					}
					terminal = append([]byte(nil), raw...)
					return nil
				},
				func(r *attackRecord) error {
					persisted++
					if tc.recordFail {
						return errors.New("injected record failure")
					}
					if r.Outcome == "DEFENDED" || r.Actuated {
						t.Fatal("defense persisted without terminal receipt")
					}
					return nil
				},
				func(r *attackRecord) {
					published++
					if r.Outcome == "DEFENDED" || r.Actuated || r.LiteLLMLiveProbe.Accepted {
						t.Fatal("unproven defense published")
					}
				})
			if published != 1 || persisted != 1 || terminalWrites != 1 || record.Status != "partial" {
				t.Fatal("failed finalization not published as partial")
			}
			if tc.recordFail {
				var saved struct {
					Kind                        string                 `json:"kind"`
					Probe                       liteLLMLiveProbeResult `json:"probe"`
					VerdictRequiresAttackRecord bool                   `json:"verdictRequiresAttackRecord"`
				}
				if err := json.Unmarshal(terminal, &saved); err != nil || saved.Probe.Accepted ||
					saved.Kind != "litellm-live-evidence-v1" || !saved.VerdictRequiresAttackRecord {
					t.Fatal("private terminal retained false success after record failure")
				}
			}
		})
	}
}

func TestLiteLiveSecondFirePreservesFirstRevocation(t *testing.T) {
	first := liteLiveEntry{Active: true, ClientSHA256: strings.Repeat("a", 64), OperationID: "first-decision"}
	second := liteLiveEntry{Active: true, ClientSHA256: strings.Repeat("b", 64), OperationID: "second-decision"}
	before := liteLiveSnapshot{Entries: []liteLiveEntry{first}}
	after := liteLiveSnapshot{Entries: []liteLiveEntry{first, second}}
	if !litePriorEntriesPreserved(before, after) {
		t.Fatal("append-only second Fire rejected")
	}
	after.Entries[0].OperationID = "rewritten-decision"
	if litePriorEntriesPreserved(before, after) {
		t.Fatal("second Fire silently rewrote first revocation")
	}
}

func TestLiteLiveReadyEndpointsAcrossSlices(t *testing.T) {
	pods := []liteLivePod{{Name: "first", UID: "uid-a"}, {Name: "second", UID: "uid-b"}}
	ips := map[string]string{"uid-a": "10.0.0.1", "uid-b": "10.0.0.2"}
	endpoint := func(uid, name, ip string) map[string]any {
		return map[string]any{"targetRef": map[string]any{"kind": "Pod", "name": name, "uid": uid},
			"conditions": map[string]any{"ready": true}, "addresses": []any{ip}}
	}
	slice := func(ep map[string]any) map[string]any {
		return map[string]any{"ports": []any{map[string]any{"port": float64(4001), "protocol": "TCP"}},
			"endpoints": []any{ep}}
	}
	items := []any{slice(endpoint("uid-a", "first", "10.0.0.1")), slice(endpoint("uid-b", "second", "10.0.0.2"))}
	if err := liteReadyEndpointBindings(items, pods, ips); err != nil {
		t.Fatalf("valid two-slice target inventory rejected: %v", err)
	}
	items = append(items, slice(endpoint("foreign", "other", "10.0.0.3")))
	if err := liteReadyEndpointBindings(items, pods, ips); err == nil {
		t.Fatal("foreign Ready endpoint accepted")
	}
	items = []any{slice(endpoint("uid-a", "first", "10.0.0.1")), slice(endpoint("uid-a", "first", "10.0.0.1"))}
	if err := liteReadyEndpointBindings(items, pods, ips); err == nil {
		t.Fatal("duplicate Ready target accepted")
	}
}

func TestLiteLiveBackendBypassClassification(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   bool
	}{
		{http.StatusBadRequest, `{"error":{"message":"No connected db."}}`, true},
		{http.StatusUnauthorized, `{"error":"invalid key"}`, true},
		{http.StatusBadRequest, `{"error":"model unavailable"}`, false},
		{http.StatusOK, `{"data":[{"id":"gpt-4o-mini"}]}`, false},
	} {
		if got := liteBackendAuthRejected(tc.status, []byte(tc.body)); got != tc.want {
			t.Fatalf("backend auth classification status %d = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestLiteLivePriorJournalMatchesActiveEntriesAndAborts(t *testing.T) {
	active := strings.Repeat("a", 64)
	aborted := strings.Repeat("b", 64)
	snapshot := liteLiveSnapshot{Revision: 1, Entries: []liteLiveEntry{
		{Active: true, ClientSHA256: active, OperationID: "selected-op"}}}
	terminal := map[string]any{"phase": "terminal-full", "clientSHA256": active,
		"operationId": "selected-op", "abortReason": ""}
	noWrite := map[string]any{"phase": "aborted", "clientSHA256": aborted,
		"operationId": "other-op", "abortReason": "definitive-policy-conflict"}
	if prior, err := litePriorJournal(snapshot, []map[string]any{terminal, noWrite}); err != nil || len(prior) != 2 {
		t.Fatalf("retained proved-no-write attempt rejected: %v", err)
	}
	bad := liteLiveSnapshot{Revision: 2, Entries: []liteLiveEntry{snapshot.Entries[0],
		{Active: true, ClientSHA256: aborted, OperationID: "other-op"}}}
	if _, err := litePriorJournal(bad, []map[string]any{terminal, noWrite}); err == nil {
		t.Fatal("aborted hash became active")
	}
	if _, err := litePriorJournal(snapshot, []map[string]any{terminal,
		{"phase": "prepared", "clientSHA256": aborted, "operationId": "other-op", "abortReason": ""}}); err == nil {
		t.Fatal("unresolved prepared attempt accepted as prior history")
	}
}
