package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

// Private source overlay: actual persisted status, constructor, signed route and launcher.
// Expected RED at the current source: the scoped admission route is absent.
func TestCatalogueAdmissionVisibilityPrivateBaseline(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	f := newAuthFixture(t, cfg, operatorGrant("admitted-operator", []string{"vllm"}, []string{wildcardScope}))
	prior := &RunStatus{ID: "v1run-5", Config: string(cataloguev1.VoiceRecovery), State: "partial",
		ExecutionKind: "fixed-suite", ScopeTarget: "default", ScopeTenant: "voice",
		Outcome: outcomeTestFailed, CleanupStatus: "FAIL", UnsafeToRetry: true}
	if err := f.srv.runs.persistStatus(prior, prior.ID); err != nil { t.Fatal(err) }
	f.srv.runs = NewRunManager(cfg)
	if f.srv.runs.loadErr != nil || f.srv.runs.runs[prior.ID] == nil { t.Fatal("retained unsafe run did not load") }

	get := f.do(f.albReqAs(t, http.MethodGet, "/api/catalog", "", "admitted-operator"))
	if get.Code != http.StatusOK { t.Fatalf("catalog GET=%d", get.Code) }
	var catalog struct { Items []CatalogItem `json:"items"` }
	if err := json.Unmarshal(get.Body.Bytes(), &catalog); err != nil { t.Fatal(err) }
	configured := false
	for _, item := range catalog.Items {
		if item.Profile == string(cataloguev1.AuthUnauth) { configured = item.Available }
	}
	if !configured { t.Fatal("positive control: auth profile is not configured") }
	post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional",
		`{"profile":"limited-v1-console-unauthenticated"}`, "admitted-operator"))
	if post.Code != http.StatusBadRequest || !strings.Contains(post.Body.String(), "requires reconciliation") {
		t.Fatalf("actual fixed-suite launch did not refuse retained unsafe run: code=%d body=%s", post.Code, post.Body.String())
	}
	if f.srv.runs.seq != 5 || len(f.srv.runs.runs) != 1 { t.Fatal("refused launch changed run history") }
	t.Log("observed: authenticated catalogue says configured available=true; authenticated functional POST refuses prior unsafe run")

	admission := f.do(f.albReqAs(t, http.MethodGet,
		"/api/runs/functional/admission?profile=limited-v1-console-unauthenticated", "", "admitted-operator"))
	if admission.Code != http.StatusOK {
		t.Fatalf("expected scoped admission projection, got HTTP %d (baseline RED)", admission.Code)
	}
}
