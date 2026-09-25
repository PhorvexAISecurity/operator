package console

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func extraDisjointConfig(t *testing.T, profile cataloguev1.ProfileID) Config {
	t.Helper()
	cfg := disjointFixtureConfig(t)
	switch profile {
	case cataloguev1.GuardrailCalibration:
		cfg.CatalogueV1.GuardrailCalibrationEnabled = true
		cfg.CatalogueV1.GuardrailNamespace = "vllm"
		cfg.CatalogueV1.GuardrailService = "vllm"
		cfg.CatalogueV1.GuardrailPort = 8000
		cfg.CatalogueV1.GuardrailContainer = "guardrail"
		cfg.CatalogueV1.GuardrailSourceConfigMap = "guardrail-proxy"
		cfg.CatalogueV1.GuardrailSourceKey = "guardrail_proxy.py"
		cfg.CatalogueV1.GuardrailSourceSHA256 = strings.Repeat("a", 64)
	case cataloguev1.MCPSessionBaseline:
		mcp := configuredMCP()
		cfg.CatalogueV1.MCPEnabled = mcp.MCPEnabled
		cfg.CatalogueV1.MCPNamespace = mcp.MCPNamespace
		cfg.CatalogueV1.MCPDeployment = mcp.MCPDeployment
		cfg.CatalogueV1.MCPService = mcp.MCPService
		cfg.CatalogueV1.MCPContainer = mcp.MCPContainer
		cfg.CatalogueV1.MCPPort = mcp.MCPPort
		cfg.CatalogueV1.MCPSourceConfigMap = mcp.MCPSourceConfigMap
		cfg.CatalogueV1.MCPSourceKey = mcp.MCPSourceKey
		cfg.CatalogueV1.MCPImageID = mcp.MCPImageID
		cfg.CatalogueV1.MCPSourceSHA256 = mcp.MCPSourceSHA256
	default:
		t.Fatalf("unsupported test profile %s", profile)
	}
	return cfg
}

func TestDisjointAdmissionCalibrationAndMCPSessionRealRouter(t *testing.T) {
	for _, profile := range []cataloguev1.ProfileID{cataloguev1.GuardrailCalibration, cataloguev1.MCPSessionBaseline} {
		t.Run(string(profile), func(t *testing.T) {
			cfg := extraDisjointConfig(t, profile)
			prior, hashes := writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{"vllm", "mcp"}, []string{hostTargetID, defaultTargetID}))
			path := "/api/runs/functional/admission?profile=" + string(profile)
			code, got, _ := readAdmission(t, f, path)
			if code != http.StatusOK || !got.Launchable || got.ReasonCode != string(functionalReady) {
				t.Fatalf("validated Voice did not permit exact fixed GET: %d %+v", code, got)
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"`+string(profile)+`"}`, "op"))
			if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "v1run-6") {
				t.Fatalf("exact fixed POST: %d %s", post.Code, post.Body.String())
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				status, ok := f.srv.runs.Status("v1run-6")
				if ok && status.State != "running" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("fixed worker did not terminate in test fixture")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if old, ok := f.srv.runs.Status(prior.ID); !ok || !reflect.DeepEqual(*old, *prior) {
				t.Fatalf("old Voice status changed: %+v", old)
			}
			for name, want := range hashes {
				raw, err := os.ReadFile(filepath.Join(cfg.runOutputPath(prior.ID), name))
				if err != nil || mongoHash(raw) != want {
					t.Fatalf("old Voice %s changed: %v", name, err)
				}
			}
			if loaded, ok := NewRunManager(cfg).Status(prior.ID); !ok || !reflect.DeepEqual(*loaded, *prior) {
				t.Fatalf("reloaded old Voice status changed: %+v", loaded)
			}
		})
	}
}

func TestDisjointAdmissionExtraProfilesRefuseChangedAuthorityAndOriginals(t *testing.T) {
	for _, profile := range []cataloguev1.ProfileID{cataloguev1.GuardrailCalibration, cataloguev1.MCPSessionBaseline} {
		for _, mode := range []string{"wrong-namespace", "wrong-source", "missing-original", "active", "second-unsafe"} {
			t.Run(string(profile)+"/"+mode, func(t *testing.T) {
				cfg := extraDisjointConfig(t, profile)
				writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
				if mode == "wrong-namespace" {
					if profile == cataloguev1.GuardrailCalibration {
						cfg.CatalogueV1.GuardrailNamespace = "voice"
					} else {
						cfg.CatalogueV1.MCPNamespace = "voice"
					}
				}
				if mode == "wrong-source" {
					if profile == cataloguev1.GuardrailCalibration {
						cfg.CatalogueV1.GuardrailSourceSHA256 = "invalid"
					} else {
						cfg.CatalogueV1.MCPSourceSHA256 = "invalid"
					}
				}
				f := newAuthFixture(t, cfg, operatorGrant("op", []string{"vllm", "mcp", "voice"}, []string{hostTargetID, defaultTargetID}))
				switch mode {
				case "missing-original":
					if err := os.Remove(filepath.Join(cfg.runOutputPath("v1run-5"), "journal.jsonl")); err != nil {
						t.Fatal(err)
					}
				case "active":
					f.srv.runs.stopping["v1run-5"] = true
				case "second-unsafe":
					f.srv.runs.runs["other"] = &RunStatus{ID: "other", UnsafeToRetry: true}
				}
				code, got, _ := readAdmission(t, f, "/api/runs/functional/admission?profile="+string(profile))
				if code != http.StatusOK || got.Launchable {
					t.Fatalf("changed authority GET: %d %+v", code, got)
				}
				post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"`+string(profile)+`"}`, "op"))
				if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
					t.Fatalf("changed authority allocated run: %d seq=%d body=%s", post.Code, f.srv.runs.seq, post.Body.String())
				}
			})
		}
	}
}

func TestDisjointAdmissionExtraProfilesDoNotOpenGenericRoute(t *testing.T) {
	cfg := extraDisjointConfig(t, cataloguev1.MCPSessionBaseline)
	rm := NewRunManager(cfg)
	f := newAuthFixture(t, cfg, operatorGrant("op", []string{"vllm", "mcp", scenarioSandboxNamespace}, []string{hostTargetID, defaultTargetID, scenarioFallbackContext}))
	for _, profile := range []cataloguev1.ProfileID{cataloguev1.GuardrailCalibration, cataloguev1.MCPSessionBaseline} {
		if _, err := rm.StartScenario([]string{string(profile)}, false, false, "", "", "", "op"); err == nil || rm.seq != 0 {
			t.Fatalf("generic scenario admitted fixed profile %s: %v", profile, err)
		}
		post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/scenario", `{"scenario":"`+string(profile)+`"}`, "op"))
		if post.Code == http.StatusOK || f.srv.runs.seq != 0 {
			t.Fatalf("generic HTTP route admitted fixed profile %s: %d %s", profile, post.Code, post.Body.String())
		}
	}
}
