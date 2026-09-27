package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEndpointLeaseResultVisibilityAndSnapshotIsolation(t *testing.T) {
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
	probe := &endpointLeaseProbeResult{
		Schema: "vllm-endpoint-lease-live-v1", Status: "UNKNOWN", Issues: []string{"initial issue"},
	}
	record := &attackRecord{
		ID: "endpoint-lease-test", Namespace: "vllm", Service: "vllm", Status: "running",
		EvidenceKind: "vllm-endpoint-lease-live", OutcomeClass: "endpoint-lease-UNKNOWN",
		EndpointLeaseProbe: probe,
	}
	publishAttack(record)
	// The worker continues changing its private probe after publishing. The running
	// ledger snapshot must retain both the original pointer fields and issue slice.
	probe.Status = "DEFENDED"
	probe.Issues[0] = "changed issue"
	probe.Issues = append(probe.Issues, "later issue")

	get := func(id, scope, observations string) []attackRecord {
		t.Helper()
		url := "/api/attack-results?limit=10&id=" + id
		if observations != "" {
			url += "&includeObservations=" + observations
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
			t.Fatalf("GET %s scope=%s: decode %s: %v", url, scope, out.Body.String(), err)
		}
		return body.Attacks
	}

	if rows := get(record.ID, "vllm", ""); len(rows) != 0 {
		t.Fatalf("default report exposed endpoint observation: %+v", rows)
	}
	rows := get(record.ID, "vllm", "true")
	if len(rows) != 1 || rows[0].Status != "running" || rows[0].EndpointLeaseProbe == nil ||
		rows[0].EndpointLeaseProbe.Status != "UNKNOWN" || len(rows[0].EndpointLeaseProbe.Issues) != 1 ||
		rows[0].EndpointLeaseProbe.Issues[0] != "initial issue" {
		t.Fatalf("running snapshot changed after worker mutation: %+v", rows)
	}
	if rows := get(record.ID, "other-tenant", "true"); len(rows) != 0 {
		t.Fatalf("other tenant observed endpoint result: %+v", rows)
	}
	if rows := get("unrelated-id", "vllm", "true"); len(rows) != 0 {
		t.Fatalf("exact ID returned unrelated result: %+v", rows)
	}

	record.Status = "done"
	record.OutcomeClass = "endpoint-lease-DEFENDED"
	publishAttack(record)
	rows = get(record.ID, "vllm", "true")
	if len(rows) != 1 || rows[0].Status != "done" || rows[0].OutcomeClass != "endpoint-lease-DEFENDED" ||
		rows[0].EndpointLeaseProbe == nil || rows[0].EndpointLeaseProbe.Status != "DEFENDED" ||
		len(rows[0].EndpointLeaseProbe.Issues) != 2 {
		t.Fatalf("terminal endpoint result absent or stale: %+v", rows)
	}
	if rows := get(record.ID, "vllm", "false"); len(rows) != 0 {
		t.Fatalf("default report exposed terminal endpoint observation: %+v", rows)
	}
	if rows := get(record.ID, "other-tenant", "true"); len(rows) != 0 {
		t.Fatalf("other tenant observed terminal endpoint result: %+v", rows)
	}

	publishAttack(&attackRecord{ID: "unknown-kind", Namespace: "vllm", EvidenceKind: "unreviewed-kind"})
	if rows := get("unknown-kind", "vllm", "true"); len(rows) != 0 {
		t.Fatalf("unreviewed category became visible: %+v", rows)
	}
	publishAttack(&attackRecord{ID: "ordinary", Namespace: "vllm"})
	if rows := get("ordinary", "vllm", ""); len(rows) != 1 || rows[0].ID != "ordinary" {
		t.Fatalf("ordinary attack visibility changed: %+v", rows)
	}
}
