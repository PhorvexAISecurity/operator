package console

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/audittransport"
)

// Exercise the real auth router and history/evidence handlers. The existing
// completed run is local and has no terminal artifact, so its typed projection
// must be UNKNOWN; no worker or cluster transport is started by this test.
func TestGuardrailAvailabilityRouteScopeAndUnknownEvidence(t *testing.T) {
	dir := t.TempDir()
	raw := guardrailAvailabilityPinnedProfile(t)
	sha := fmt.Sprintf("%x", sha256.Sum256(raw))
	if err := os.WriteFile(filepath.Join(dir, allowedConfigs[guardrailAvailabilityConfig].File), raw, 0600); err != nil {
		t.Fatal(err)
	}
	f := newAuthFixture(t, Config{Root: dir, HarnessDir: dir, GuardrailAvailabilityEnabled: true, GuardrailAvailabilityProfileSHA256: sha, AuditSource: &audittransport.Client{}, AuditSourceIdentity: "https://audit.phorvex-system.svc:8445|audit.phorvex-system.svc"},
		operatorGrant("full", []string{"vllm", "phorvex-system"}, []string{hostTargetID, "reviewed-cluster"}),
		operatorGrant("no-host", []string{"vllm", "phorvex-system"}, []string{"reviewed-cluster"}),
		operatorGrant("no-cluster", []string{"vllm", "phorvex-system"}, []string{hostTargetID}),
		operatorGrant("no-vllm", []string{"phorvex-system"}, []string{hostTargetID, "reviewed-cluster"}),
		operatorGrant("no-fixture", []string{"vllm"}, []string{hostTargetID, "reviewed-cluster"}),
	)
	id := "run-99"
	f.srv.runs.mu.Lock()
	f.srv.runs.runs[id] = &RunStatus{ID: id, Config: guardrailAvailabilityConfig, State: "done", ScopeTarget: "reviewed-cluster", ScopeTenant: "vllm", FixtureTenant: "phorvex-system", ProfileSHA256: sha}
	f.srv.runs.runOut[id] = id
	f.srv.runs.mu.Unlock()
	for _, route := range []string{"/api/runs/status?id=" + id, "/api/runs/evidence?id=" + id, "/api/runs/list"} {
		w := f.do(f.albReqAs(t, http.MethodGet, route, "", "full"))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), id) {
			t.Fatalf("fully granted run hidden at %s: %d %s", route, w.Code, w.Body.String())
		}
		if strings.Contains(route, "evidence") {
			var body struct {
				Result GuardrailAvailabilityResult `json:"guardrailAvailabilityResult"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Result.Accepted || body.Result.Status != "UNKNOWN" || body.Result.Route != "Pod-loopback-8000" || body.Result.NaturalDetector != "NOT_EVALUATED" {
				t.Fatalf("completed run lacks typed UNKNOWN projection: %+v %v", body.Result, err)
			}
		}
	}
	for _, name := range []string{"no-host", "no-cluster", "no-vllm", "no-fixture"} {
		for _, route := range []string{"/api/runs/status?id=" + id, "/api/runs/evidence?id=" + id} {
			w := f.do(f.albReqAs(t, http.MethodGet, route, "", name))
			if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), id) {
				t.Fatalf("%s read %s: %d %s", name, route, w.Code, w.Body.String())
			}
		}
		w := f.do(f.albReqAs(t, http.MethodGet, "/api/runs/list", "", name))
		if strings.Contains(w.Body.String(), id) {
			t.Fatalf("%s listed revoked run: %s", name, w.Body.String())
		}
		w = f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"guardrail-availability-recovery"}`, name))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "credential or mTLS mount unavailable") {
			t.Fatalf("%s passed exact local mount admission: %d %s", name, w.Code, w.Body.String())
		}
	}
	if len(f.srv.runs.runs) != 1 {
		t.Fatal("refused POST allocated a run")
	}
}
