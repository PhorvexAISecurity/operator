package console

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func crmAdmissionConfig(t *testing.T) (Config, string, *httptest.Server) {
	t.Helper()
	cfg := functionalLedgerTestConfig(t)
	cfg.HarnessDir = cfg.StateDir
	cfg.HarnessBin = filepath.Join(cfg.StateDir, "inert-worker")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			fmt.Fprint(w, `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","status":{"userInfo":{"username":"system:serviceaccount:crm-fixture:fixture-sa"}}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/crm-fixture":
			fmt.Fprint(w, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"crm-fixture","uid":"11111111-1111-4111-8111-111111111111","labels":{"phorvex.ai/crm-capability-fixture":"true"}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	manifest := map[string]any{"schema": "phorvex.crm-fixture.v1", "crmImage": "example.invalid/crm@sha256:" + strings.Repeat("a", 64), "mongoImage": "example.invalid/mongo@sha256:" + strings.Repeat("b", 64), "baseImageDigest": "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff", "sourceSHA256": "328f37a8d6d3692fb3bd6d4db2637e72d54becf8e9e4396d5e47f4ab5f909350", "dependencyLockSHA256": "50143dfea339319c70edcc4e37c5d852031446f5e609ef4f538c68a0436f956a", "wheelhouseManifestSHA256": strings.Repeat("c", 64), "dependencies": map[string]string{"fastapi": "0.115.14", "pydantic": "2.13.4", "pymongo": "4.17.0", "uvicorn": "0.30.6"}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(cfg.StateDir, "crm-manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	kube := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n  cluster:\n    server: %s\ncontexts:\n- name: fixture\n  context:\n    cluster: fixture\n    user: fixture\ncurrent-context: fixture\nusers:\n- name: fixture\n  user:\n    token: fixture-token\n", server.URL)
	kubePath := filepath.Join(cfg.StateDir, "crm-kubeconfig")
	if err := os.WriteFile(kubePath, []byte(kube), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(cfg.HarnessBin)
	if err != nil {
		t.Fatal(err)
	}
	h := func(v []byte) string { sum := sha256.Sum256(v); return fmt.Sprintf("%x", sum) }
	cfg.CatalogueV1.CRMEnabled = true
	cfg.CatalogueV1.CRMNamespace = "crm-fixture"
	cfg.CatalogueV1.CRMNamespaceUID = "11111111-1111-4111-8111-111111111111"
	cfg.CatalogueV1.CRMServiceAccountName = "fixture-sa"
	cfg.CatalogueV1.CRMManifestFile = manifestPath
	cfg.CatalogueV1.CRMManifestSHA256 = h(raw)
	cfg.CatalogueV1.CRMHarnessSHA256 = h(binary)
	cfg.CatalogueV1.CRMKubeconfigPath = kubePath
	cfg.CatalogueV1.CRMKubeconfigSHA256 = h([]byte(kube))
	cfg.CatalogueV1.CRMKubeContext = "fixture"
	return cfg, manifestPath, server
}

func TestCRMAdmissionGETAndPOSTShareCurrentAuthorityAndUnsafeBlock(t *testing.T) {
	cfg, manifest, _ := crmAdmissionConfig(t)
	f := newAuthFixture(t, cfg, operatorGrant("op", []string{"crm-fixture"}, []string{wildcardScope}))
	path := "/api/runs/functional/admission?profile=" + string(cataloguev1.CRMRefund)
	code, ready, _ := readAdmission(t, f, path)
	if code != http.StatusOK || !ready.Launchable || ready.ReasonCode != string(functionalReady) || f.srv.runs.seq != 0 {
		t.Fatalf("CRM GET admission=%d %+v seq=%d", code, ready, f.srv.runs.seq)
	}
	original, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, append(append([]byte{}, original...), ' '), 0600); err != nil {
		t.Fatal(err)
	}
	code, blocked, _ := readAdmission(t, f, path)
	if code != http.StatusOK || blocked.Launchable || f.srv.runs.seq != 0 {
		t.Fatalf("changed manifest admitted: %d %+v", code, blocked)
	}
	post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"c2-crm-refund-capability"}`, "op"))
	if post.Code != http.StatusBadRequest || f.srv.runs.seq != 0 {
		t.Fatalf("changed manifest POST allocated run: %d %s", post.Code, post.Body.String())
	}
	if err := os.WriteFile(manifest, original, 0600); err != nil {
		t.Fatal(err)
	}
	post = f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"c2-crm-refund-capability","target":"crm"}`, "op"))
	if post.Code == http.StatusOK || f.srv.runs.seq != 0 {
		t.Fatalf("caller target override admitted: %d %s", post.Code, post.Body.String())
	}
	post = f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"c2-crm-refund-capability"}`, "op"))
	if post.Code != http.StatusOK || f.srv.runs.seq != 1 {
		t.Fatalf("ready CRM POST refused: %d %s", post.Code, post.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		st, ok := f.srv.runs.Status("v1run-1")
		if ok && st.State != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inert CRM worker did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	unsafeCfg, _, _ := crmAdmissionConfig(t)
	seed := NewRunManager(unsafeCfg)
	prior := &RunStatus{ID: "v1run-5", Config: string(cataloguev1.VoiceRecovery), State: "partial", ExecutionKind: "fixed-suite", ScopeTarget: "default", ScopeTenant: "voice", CleanupStatus: "FAIL", UnsafeToRetry: true}
	if err := seed.persistStatus(prior, prior.ID); err != nil {
		t.Fatal(err)
	}
	unsafeFixture := newAuthFixture(t, unsafeCfg, operatorGrant("op", []string{"crm-fixture"}, []string{wildcardScope}))
	code, blocked, _ = readAdmission(t, unsafeFixture, path)
	if code != http.StatusOK || blocked.Launchable || blocked.ReasonCode != string(functionalPriorUnsafe) {
		t.Fatalf("unsafe predecessor admitted: %d %+v", code, blocked)
	}
	post = unsafeFixture.do(unsafeFixture.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"c2-crm-refund-capability"}`, "op"))
	if post.Code != http.StatusBadRequest || unsafeFixture.srv.runs.seq != 5 {
		t.Fatalf("unsafe predecessor POST admitted: %d %s", post.Code, post.Body.String())
	}
	for _, tc := range []struct {
		name             string
		tenants, targets []string
	}{{"foreign-tenant", []string{"other"}, []string{wildcardScope}}, {"foreign-target", []string{"crm-fixture"}, []string{"other-target"}}} {
		t.Run(tc.name, func(t *testing.T) {
			deniedCfg, _, _ := crmAdmissionConfig(t)
			denied := newAuthFixture(t, deniedCfg, operatorGrant("op", tc.tenants, tc.targets))
			code, admission, _ := readAdmission(t, denied, path)
			if code == http.StatusOK && admission.Launchable {
				t.Fatalf("foreign grant admitted GET: %+v", admission)
			}
			post := denied.do(denied.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"c2-crm-refund-capability"}`, "op"))
			if post.Code == http.StatusOK || denied.srv.runs.seq != 0 {
				t.Fatalf("foreign grant admitted POST: %d %s", post.Code, post.Body.String())
			}
		})
	}
	wrongUIDCfg, _, _ := crmAdmissionConfig(t)
	wrongUIDCfg.CatalogueV1.CRMNamespaceUID = "22222222-2222-4222-8222-222222222222"
	wrongUID := newAuthFixture(t, wrongUIDCfg, operatorGrant("op", []string{"crm-fixture"}, []string{wildcardScope}))
	code, blocked, _ = readAdmission(t, wrongUID, path)
	if code != http.StatusOK || blocked.Launchable || wrongUID.srv.runs.seq != 0 {
		t.Fatalf("wrong namespace UID admitted: %d %+v", code, blocked)
	}
	post = wrongUID.do(wrongUID.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"c2-crm-refund-capability"}`, "op"))
	if post.Code != http.StatusBadRequest || wrongUID.srv.runs.seq != 0 {
		t.Fatalf("wrong namespace UID POST allocated run: %d %s", post.Code, post.Body.String())
	}
}
