package console

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/cataloguev1"
)

const mongoNodeFQDN = "ip-172-27-12-10.us-east-2.compute.internal"

func mongoAdmissionProfile(target, node string) []byte {
	return []byte(fmt.Sprintf(`context: %q
namespace: document-store
ownedAck: true
trialsPerArm: 1
scenarioFilter: [c2-mongo-uncredentialed-service-exposure]
defenderFilter: []
mongoExposureFixture:
  transport: in-cluster
  clusterUID: 11111111-1111-4111-8111-111111111111
  mongoDeployment: mongo
  mongoService: mongo
  mongoImageID: registry.test/mongo@sha256:%s
  policyName: mongo-defense
  managerNamespace: phorvex-system
  managerDeployment: phorvex-phorvex
  managerImageID: registry.test/manager@sha256:%s
  allowedNodeNames: [%s]
  maxRunSeconds: 600
`, target, strings.Repeat("a", 64), strings.Repeat("b", 64), node))
}

func mongoAdmissionConfig(t *testing.T) Config {
	t.Helper()
	cfg := disjointFixtureConfig(t)
	cfg.MongoExposureEnabled = true
	cfg.AuditSource = &audittransport.Client{}
	cfg.AuditSourceIdentity = "authenticated-test-source"
	raw := mongoAdmissionProfile("reviewed-cluster", `"`+mongoNodeFQDN+`"`)
	mongoTestWrite(t, filepath.Join(cfg.HarnessDir, allowedConfigs[mongoExposureConfig].File), raw)
	return cfg
}

func TestMongoNamedProfileAcceptsKubernetesNodeSubdomainOnly(t *testing.T) {
	for _, tc := range []struct {
		name, nodes string
		valid       bool
	}{
		{"eks-fqdn", `"` + mongoNodeFQDN + `"`, true},
		{"short-label", `"cpu-node"`, true},
		{"uppercase", `"IP-172-27-12-10.us-east-2.compute.internal"`, false},
		{"whitespace", `"cpu node"`, false},
		{"slash", `"cpu/node"`, false},
		{"empty", `""`, false},
		{"overlong-name", `"` + strings.Repeat("a.", 127) + `a"`, false},
		{"duplicate", `"` + mongoNodeFQDN + `", "` + mongoNodeFQDN + `"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mongoAdmissionConfig(t)
			raw := mongoAdmissionProfile("reviewed-cluster", tc.nodes)
			mongoTestWrite(t, filepath.Join(cfg.HarnessDir, allowedConfigs[mongoExposureConfig].File), raw)
			h := sha256.Sum256(raw)
			dest, err := (&RunManager{cfg: cfg}).SuiteDestination(mongoExposureConfig)
			if (err == nil) != tc.valid {
				t.Fatalf("node %q: destination=%+v error=%v", tc.nodes, dest, err)
			}
			if tc.valid && (dest.ScopeTenant != mongoExposureNamespace || dest.ScopeTarget != "reviewed-cluster" || dest.SuiteSHA256 != hex.EncodeToString(h[:])) {
				t.Fatalf("valid node changed named profile scope: %+v", dest)
			}
		})
	}
}

func mongoAuditFixture(t *testing.T, cfg *Config) {
	t.Helper()
	dir := t.TempDir()
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	auditPath := filepath.Join(dir, "audit.jsonl")
	mongoTestWrite(t, auditPath, []byte("{\"kind\":\"heartbeat\"}\n"))
	ts := httptest.NewUnstartedServer((audittransport.ServerConfig{AuditPath: auditPath, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 2}).Handler())
	ts.TLS = (audittransport.ServerConfig{AuditPath: auditPath, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 2}).TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuditSource, cfg.AuditSourceIdentity = client, ts.URL+"#audit-source.test"
}

func TestMongoNamedRouterAdmitsOnlyValidatedVoicePredecessor(t *testing.T) {
	for _, profile := range []cataloguev1.ProfileID{cataloguev1.VoiceMedia, cataloguev1.VoiceRecovery} {
		t.Run(string(profile), func(t *testing.T) {
			cfg := mongoAdmissionConfig(t)
			mongoAuditFixture(t, &cfg)
			prior, hashes := writeVoiceFailureRun(t, cfg, profile)
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{mongoExposureNamespace}, []string{hostTargetID, "reviewed-cluster"}))
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"mongo-exposure-baseline"}`, "op"))
			if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), `"id":"run-6"`) {
				t.Fatalf("validated Voice did not reach authenticated Mongo launch: %d %s", post.Code, post.Body.String())
			}
			old, ok := f.srv.runs.Status(prior.ID)
			if !ok || !reflect.DeepEqual(*old, *prior) {
				t.Fatalf("prior Voice status changed: %+v", old)
			}
			for name, want := range hashes {
				raw, err := os.ReadFile(filepath.Join(cfg.runOutputPath(prior.ID), name))
				h := sha256.Sum256(raw)
				if err != nil || hex.EncodeToString(h[:]) != want {
					t.Fatalf("prior Voice %s changed: %v", name, err)
				}
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				status, ok := f.srv.runs.Status("run-6")
				if ok && status.State != "running" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("test harness worker did not terminate")
				}
				time.Sleep(10 * time.Millisecond)
			}
			loaded := NewRunManager(cfg)
			if got, ok := loaded.Status(prior.ID); !ok || !reflect.DeepEqual(*got, *prior) {
				t.Fatalf("reloaded Voice debt changed: %+v", got)
			}
		})
	}
}

func TestMongoNamedRouterPreservesEmptyHistoryAndCurrentGrants(t *testing.T) {
	cfg := mongoAdmissionConfig(t)
	mongoAuditFixture(t, &cfg)
	for _, tc := range []struct {
		name  string
		grant SubjectGrant
		want  int
	}{
		{"missing-tenant", operatorGrant("op", []string{"voice"}, []string{hostTargetID, "reviewed-cluster"}), http.StatusForbidden},
		{"missing-cluster-target", operatorGrant("op", []string{mongoExposureNamespace}, []string{hostTargetID}), http.StatusForbidden},
		{"complete-grants", operatorGrant("op", []string{mongoExposureNamespace}, []string{hostTargetID, "reviewed-cluster"}), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyCfg := cfg
			copyCfg.StateDir = filepath.Join(t.TempDir(), "state")
			f := newAuthFixture(t, copyCfg, tc.grant)
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"mongo-exposure-baseline"}`, "op"))
			if post.Code != tc.want {
				t.Fatalf("empty-history launch with grant %s: %d %s", tc.name, post.Code, post.Body.String())
			}
			if tc.want != http.StatusOK && f.srv.runs.seq != 0 {
				t.Fatalf("wrong grant allocated run: seq=%d", f.srv.runs.seq)
			}
			if tc.want == http.StatusOK {
				deadline := time.Now().Add(3 * time.Second)
				for {
					status, ok := f.srv.runs.Status("run-1")
					if ok && status.State != "running" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("empty-history worker did not terminate")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}

func TestMongoNamedRouterPreservesSharedRateAndConcurrencyGates(t *testing.T) {
	for _, mode := range []string{"rate", "concurrency", "new-mongo-unsafe"} {
		t.Run(mode, func(t *testing.T) {
			cfg := mongoAdmissionConfig(t)
			writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{mongoExposureNamespace}, []string{hostTargetID, "reviewed-cluster"}))
			switch mode {
			case "rate":
				f.srv.runs.lastStart = time.Now()
			case "concurrency":
				f.srv.runs.active = maxConcurrentRuns
			case "new-mongo-unsafe":
				f.srv.runs.runs["run-7"] = &RunStatus{ID: "run-7", Config: mongoExposureConfig, UnsafeToRetry: true}
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"mongo-exposure-baseline"}`, "op"))
			if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
				t.Fatalf("shared %s guard allocated run: %d seq=%d body=%s", mode, post.Code, f.srv.runs.seq, post.Body.String())
			}
		})
	}
}

func TestMongoNamedRouterRejectsUnclassifiedVoiceBeforeAllocation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, Config, *RunManager)
	}{
		{"missing-job", func(t *testing.T, cfg Config, _ *RunManager) {
			if err := os.Remove(filepath.Join(cfg.runOutputPath("v1run-5"), "job.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-runtime", func(t *testing.T, cfg Config, _ *RunManager) {
			if err := os.Remove(filepath.Join(cfg.runOutputPath("v1run-5"), "runtime.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-result", func(t *testing.T, cfg Config, _ *RunManager) {
			if err := os.Remove(filepath.Join(cfg.runOutputPath("v1run-5"), "result.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-metrics", func(t *testing.T, cfg Config, _ *RunManager) {
			if err := os.Remove(filepath.Join(cfg.runOutputPath("v1run-5"), "metrics.jsonl")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-journal", func(t *testing.T, cfg Config, _ *RunManager) {
			if err := os.Remove(filepath.Join(cfg.runOutputPath("v1run-5"), "journal.jsonl")); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt-job", func(t *testing.T, cfg Config, _ *RunManager) {
			mongoTestWrite(t, filepath.Join(cfg.runOutputPath("v1run-5"), "job.json"), []byte("corrupt"))
		}},
		{"corrupt-runtime", func(t *testing.T, cfg Config, _ *RunManager) {
			mongoTestWrite(t, filepath.Join(cfg.runOutputPath("v1run-5"), "runtime.json"), []byte("corrupt"))
		}},
		{"corrupt-result", func(t *testing.T, cfg Config, _ *RunManager) {
			mongoTestWrite(t, filepath.Join(cfg.runOutputPath("v1run-5"), "result.json"), []byte("corrupt"))
		}},
		{"corrupt-metrics", func(t *testing.T, cfg Config, _ *RunManager) {
			mongoTestWrite(t, filepath.Join(cfg.runOutputPath("v1run-5"), "metrics.jsonl"), []byte("corrupt"))
		}},
		{"foreign-journal", func(t *testing.T, cfg Config, _ *RunManager) {
			path := filepath.Join(cfg.runOutputPath("v1run-5"), "journal.jsonl")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(raw), "voice.availability", "voice.foreign", 1)
			if changed == string(raw) {
				t.Fatal("producer journal lacks expected step")
			}
			mongoTestWrite(t, path, []byte(changed))
		}},
		{"source-identity", func(t *testing.T, cfg Config, _ *RunManager) {
			path := filepath.Join(cfg.runOutputPath("v1run-5"), "result.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(raw), voiceSourceSHA, strings.Repeat("0", 64), 1)
			if changed == string(raw) {
				t.Fatal("producer source pin absent")
			}
			mongoTestWrite(t, path, []byte(changed))
		}},
		{"second-unsafe", func(_ *testing.T, _ Config, rm *RunManager) {
			rm.runs["other"] = &RunStatus{ID: "other", UnsafeToRetry: true}
		}},
		{"nonvoice-unsafe", func(_ *testing.T, _ Config, rm *RunManager) {
			rm.runs["v1run-5"].Config = string(cataloguev1.ChromaOwnedVector)
		}},
		{"nonterminal", func(_ *testing.T, _ Config, rm *RunManager) { rm.runs["v1run-5"].State = "running" }},
		{"wrong-target", func(_ *testing.T, _ Config, rm *RunManager) { rm.runs["v1run-5"].ScopeTarget = "other" }},
		{"wrong-tenant", func(_ *testing.T, _ Config, rm *RunManager) { rm.runs["v1run-5"].ScopeTenant = "other" }},
		{"wrong-owner", func(_ *testing.T, _ Config, rm *RunManager) { rm.runs["v1run-5"].Owner = "other" }},
		{"wrong-current-voice", func(_ *testing.T, _ Config, rm *RunManager) { rm.cfg.CatalogueV1.VoiceNamespace = "other" }},
		{"active-process", func(_ *testing.T, _ Config, rm *RunManager) { rm.procs["v1run-5"] = &exec.Cmd{} }},
		{"active-predecessor", func(_ *testing.T, _ Config, rm *RunManager) { rm.stopping["v1run-5"] = true }},
		{"execution-locked", func(t *testing.T, cfg Config, _ *RunManager) {
			release, err := cataloguev1.AcquireExecutionLock(cfg.runOutputPath("v1run-5"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = release() })
		}},
		{"pending-reconciliation", func(_ *testing.T, _ Config, rm *RunManager) { rm.runs["v1run-5"].Error = "reconciliation pending" }},
		{"unavailable-ledger", func(_ *testing.T, _ Config, rm *RunManager) { rm.loadErr = fmt.Errorf("damaged ledger") }},
		{"nil-status", func(_ *testing.T, _ Config, rm *RunManager) { rm.runs["other"] = nil }},
		{"rate-limit", func(_ *testing.T, _ Config, rm *RunManager) { rm.lastStart = time.Now() }},
		{"concurrency-limit", func(_ *testing.T, _ Config, rm *RunManager) { rm.active = maxConcurrentRuns }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mongoAdmissionConfig(t)
			writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{mongoExposureNamespace}, []string{hostTargetID, "reviewed-cluster"}))
			tc.edit(t, cfg, f.srv.runs)
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"mongo-exposure-baseline"}`, "op"))
			if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
				t.Fatalf("unclassified prior allocated run: code=%d seq=%d body=%s", post.Code, f.srv.runs.seq, post.Body.String())
			}
		})
	}
}
