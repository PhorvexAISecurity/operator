package console

import (
	"net/http"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func modelAdmissionConfig(t *testing.T) Config {
	t.Helper()
	cfg := disjointFixtureConfig(t)
	m := configuredMCP()
	cfg.CatalogueV1.MCPEnabled = m.MCPEnabled
	cfg.CatalogueV1.MCPNamespace = m.MCPNamespace
	cfg.CatalogueV1.MCPDeployment = m.MCPDeployment
	cfg.CatalogueV1.MCPService = m.MCPService
	cfg.CatalogueV1.MCPContainer = m.MCPContainer
	cfg.CatalogueV1.MCPPort = m.MCPPort
	cfg.CatalogueV1.MCPSourceConfigMap = m.MCPSourceConfigMap
	cfg.CatalogueV1.MCPSourceKey = m.MCPSourceKey
	cfg.CatalogueV1.MCPImageID = m.MCPImageID
	cfg.CatalogueV1.MCPSourceSHA256 = m.MCPSourceSHA256
	cfg.CatalogueV1.LiteLLMInferenceEnabled = true
	cfg.CatalogueV1.LiteLLMModelAlias = "gpt-4o-mini"
	cfg.CatalogueV1.MCPVoiceModelEnabled = true
	cfg.CatalogueV1.MCPVoiceSourceSHA256 = "23b2e6e72912b11a545e06f54af4159789dc3a79f0aaed74cd2ec636cbb371cf"
	return cfg
}
func TestMCPVoiceModelCrossTenantGrantAndUnsafeVoiceAdmission(t *testing.T) {
	cfg := modelAdmissionConfig(t)
	profile := string(cataloguev1.MCPVoiceModel)
	if ready, reason := cfg.functionalProfileAvailable(cataloguev1.MCPVoiceModel); !ready {
		t.Fatalf("configured source row unavailable: %s", reason)
	}
	f := newAuthFixture(t, cfg,
		operatorGrant("op", []string{"voice", "mcp", "litellm"}, []string{defaultTargetID}),
		operatorGrant("no-voice", []string{"mcp", "litellm"}, []string{defaultTargetID}),
		operatorGrant("no-mcp", []string{"voice", "litellm"}, []string{defaultTargetID}),
		operatorGrant("no-lite", []string{"voice", "mcp"}, []string{defaultTargetID}))
	d, err := f.srv.runs.FunctionalDestination(cataloguev1.MCPVoiceModel)
	if err != nil || d.ScopeTenant != "voice" || strings.Join(d.Tenants, ",") != "voice,mcp,litellm" {
		t.Fatalf("effective destination: %+v, %v", d, err)
	}
	path := "/api/runs/functional/admission?profile=" + profile
	body := `{"profile":"` + profile + `"}`
	for _, subject := range []string{"no-voice", "no-mcp", "no-lite"} {
		for _, request := range []*http.Request{f.albReqAs(t, http.MethodGet, path, "", subject), f.albReqAs(t, http.MethodPost, "/api/runs/functional", body, subject)} {
			response := f.do(request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("%s %s code=%d body=%s", subject, request.Method, response.Code, response.Body.String())
			}
		}
	}
	if f.srv.runs.seq != 0 {
		t.Fatal("unauthorized request allocated a run")
	}
	code, ready, _ := readAdmission(t, f, path)
	if code != http.StatusOK || !ready.Launchable || ready.ReasonCode != string(functionalReady) {
		t.Fatalf("full grant positive admission: %+v code=%d", ready, code)
	}
	// Existing unsafe Voice history shares the very Pod/source used by this case.
	writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
	f = newAuthFixture(t, cfg, operatorGrant("op", []string{"voice", "mcp", "litellm"}, []string{defaultTargetID}))
	code, blocked, _ := readAdmission(t, f, path)
	if code != http.StatusOK || blocked.Launchable || blocked.ReasonCode != string(functionalPriorUnsafe) {
		t.Fatalf("unsafe Voice admission: %+v code=%d", blocked, code)
	}
	post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", body, "op"))
	if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
		t.Fatalf("unsafe Voice POST accepted: code=%d seq=%d", post.Code, f.srv.runs.seq)
	}
}
