package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func TestStackCasesClosedCatalogueAndRuntimeAuthority(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	rows := cfg.limitedV1Catalogue()
	for _, id := range []cataloguev1.ProfileID{cataloguev1.ChromaOwnedVector, cataloguev1.LiteLLMHealth, cataloguev1.LiteLLMCredential, cataloguev1.LiteLLMRouting} {
		var found *CatalogItem
		for i := range rows {
			if rows[i].Profile == string(id) {
				found = &rows[i]
			}
		}
		if found == nil || found.Available || found.LaunchKind != "fixed-suite" || found.EventMode != "none; direct protocol control" ||
			len(found.ExpectedActuators) != 0 || !strings.Contains(found.ResponseGuidance, "NOT_EVALUATED") {
			t.Fatalf("profile %s catalogue authority=%+v", id, found)
		}
	}
	runtime := cfg.catalogueV1RuntimeConfig()
	raw, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"chroma"`) || strings.Contains(string(raw), `"liteLLM"`) {
		t.Fatalf("disabled stack runtime changed historical serialization: %s", raw)
	}
	cfg.CatalogueV1.ChromaEnabled = true
	cfg.CatalogueV1.ChromaNamespace = "document-store"
	cfg.CatalogueV1.LiteLLMEnabled = true
	cfg.CatalogueV1.LiteLLMNamespace = "litellm"
	for id, want := range map[cataloguev1.ProfileID]string{
		cataloguev1.ChromaOwnedVector: "document-store", cataloguev1.LiteLLMHealth: "litellm", cataloguev1.LiteLLMCredential: "litellm", cataloguev1.LiteLLMRouting: "litellm",
	} {
		rm := NewRunManager(cfg)
		d, err := rm.FunctionalDestination(id)
		if err != nil || d.ScopeTenant != want || d.ScopeTarget != "default" {
			t.Fatalf("profile %s destination=%+v err=%v", id, d, err)
		}
	}
}

func TestStackCasesRealRouteChecksResolvedTenantAndTargetBeforeAdmission(t *testing.T) {
	for _, tc := range []struct {
		profile cataloguev1.ProfileID
		tenant  string
	}{
		{cataloguev1.ChromaOwnedVector, "document-store"},
		{cataloguev1.LiteLLMHealth, "litellm"},
		{cataloguev1.LiteLLMCredential, "litellm"},
		{cataloguev1.LiteLLMRouting, "litellm"},
	} {
		t.Run(string(tc.profile), func(t *testing.T) {
			cfg := functionalLedgerTestConfig(t)
			cfg.CatalogueV1.ChromaNamespace = "document-store"
			cfg.CatalogueV1.LiteLLMNamespace = "litellm"
			f := newAuthFixture(t, cfg,
				operatorGrant("allowed", []string{tc.tenant}, []string{wildcardScope}),
				operatorGrant("wrong-tenant", []string{"foreign"}, []string{wildcardScope}),
				operatorGrant("wrong-target", []string{tc.tenant}, []string{"foreign-target"}))
			path := "/api/runs/functional/admission?profile=" + string(tc.profile)
			body := `{"profile":"` + string(tc.profile) + `"}`
			for _, subject := range []string{"wrong-tenant", "wrong-target"} {
				for _, request := range []*http.Request{
					f.albReqAs(t, http.MethodGet, path, "", subject),
					f.albReqAs(t, http.MethodPost, "/api/runs/functional", body, subject),
				} {
					response := f.do(request)
					if response.Code != http.StatusForbidden {
						t.Fatalf("%s %s code=%d body=%s", subject, request.Method, response.Code, response.Body.String())
					}
				}
			}
			response := f.do(f.albReqAs(t, http.MethodGet, path, "", "allowed"))
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), string(functionalConfigUnavailable)) {
				t.Fatalf("allowed admission code=%d body=%s", response.Code, response.Body.String())
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", body, "allowed"))
			if post.Code != http.StatusBadRequest || strings.Contains(post.Body.String(), "forbidden") || f.srv.runs.seq != 0 {
				t.Fatalf("allowed disabled POST code=%d body=%s seq=%d", post.Code, post.Body.String(), f.srv.runs.seq)
			}
		})
	}
}
