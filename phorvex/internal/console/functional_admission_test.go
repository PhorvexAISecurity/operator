package console

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

const admissionAuthProfile = "/api/runs/functional/admission?profile=limited-v1-console-unauthenticated"

func admissionFixture(t *testing.T, cfg Config) *authFixture {
	t.Helper()
	return newAuthFixture(t, cfg, operatorGrant("op", []string{"vllm"}, []string{wildcardScope}))
}

func readAdmission(t *testing.T, f *authFixture, path string) (int, FunctionalAdmission, string) {
	t.Helper()
	w := f.do(f.albReqAs(t, http.MethodGet, path, "", "op"))
	var admission FunctionalAdmission
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &admission); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, admission, w.Body.String()
}

func TestFunctionalAdmissionRealRouterAndRetainedUnsafeHistory(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	f := admissionFixture(t, cfg)
	code, ready, _ := readAdmission(t, f, admissionAuthProfile)
	if code != http.StatusOK || !ready.Launchable || ready.ReasonCode != string(functionalReady) || ready.Profile != string(cataloguev1.AuthUnauth) || ready.ObservedAt == "" {
		t.Fatalf("healthy scoped admission: code=%d result=%+v", code, ready)
	}
	if _, err := time.Parse(time.RFC3339Nano, ready.ObservedAt); err != nil {
		t.Fatalf("admission timestamp invalid: %v", err)
	}
	if f.srv.runs.seq != 0 || len(f.srv.runs.runs) != 0 {
		t.Fatal("read-only admission allocated a run")
	}
	control := admissionFixture(t, functionalLedgerTestConfig(t))
	if gotCode, got, _ := readAdmission(t, control, admissionAuthProfile); gotCode != http.StatusOK || !got.Launchable {
		t.Fatalf("healthy positive control not ready: code=%d result=%+v", gotCode, got)
	}
	allowed := control.do(control.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"limited-v1-console-unauthenticated"}`, "op"))
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), "v1run-1") {
		t.Fatalf("healthy scoped POST did not admit inert worker: code=%d body=%s", allowed.Code, allowed.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, ok := control.srv.runs.Status("v1run-1")
		if ok && status.State != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inert worker did not reach terminal status before fixture cleanup")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// State changes after a READY snapshot: the POST remains the authority.
	prior := &RunStatus{ID: "v1run-5", Config: string(cataloguev1.VoiceRecovery), State: "partial",
		ExecutionKind: "fixed-suite", ScopeTarget: "default", ScopeTenant: "voice", Owner: "foreign-owner-private",
		CleanupStatus: "FAIL", UnsafeToRetry: true}
	if err := f.srv.runs.persistStatus(prior, prior.ID); err != nil {
		t.Fatal(err)
	}
	f.srv.runs = NewRunManager(cfg)
	if f.srv.runs.loadErr != nil {
		t.Fatal(f.srv.runs.loadErr)
	}
	post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"limited-v1-console-unauthenticated"}`, "op"))
	if post.Code != http.StatusBadRequest || !strings.Contains(post.Body.String(), "requires reconciliation") || f.srv.runs.seq != 5 {
		t.Fatalf("POST promoted stale READY or changed sequence: code=%d seq=%d", post.Code, f.srv.runs.seq)
	}
	code, blocked, body := readAdmission(t, f, admissionAuthProfile)
	if code != http.StatusOK || blocked.Launchable || blocked.ReasonCode != string(functionalPriorUnsafe) {
		t.Fatalf("unsafe status hidden: code=%d result=%+v", code, blocked)
	}
	for _, private := range []string{prior.ID, prior.Owner, prior.ScopeTenant} {
		if strings.Contains(body, private) {
			t.Fatalf("admission leaked foreign-run identity %q", private)
		}
	}
	if f.srv.runs.seq != 5 || len(f.srv.runs.runs) != 1 {
		t.Fatal("admission GET or refused POST changed retained run history")
	}
}

func TestFunctionalAdmissionConsoleReadsBesideExactUnsafeVoice(t *testing.T) {
	for _, tc := range []struct{ profile, prior cataloguev1.ProfileID }{
		{cataloguev1.AuthUnauth, cataloguev1.VoiceMedia},
		{cataloguev1.AuthScope, cataloguev1.VoiceRecovery},
	} {
		t.Run(string(tc.profile), func(t *testing.T) {
			cfg := functionalLedgerTestConfig(t)
			cfg.CatalogueV1.VoiceNamespace = "voice"
			seed := NewRunManager(cfg)
			prior := &RunStatus{ID: "v1run-5", Config: string(tc.prior), State: "partial",
				ExecutionKind: "fixed-suite", ScopeTarget: defaultTargetID, ScopeTenant: "voice",
				Outcome: "test-failed", CleanupStatus: "FAIL", UnsafeToRetry: true, Finished: tsNow()}
			if err := seed.persistStatus(prior, prior.ID); err != nil {
				t.Fatal(err)
			}
			ledger := filepath.Join(cfg.StateDir, "run-events.jsonl")
			original, err := os.ReadFile(ledger)
			if err != nil {
				t.Fatal(err)
			}
			f := admissionFixture(t, cfg)
			path := "/api/runs/functional/admission?profile=" + string(tc.profile)
			code, admission, body := readAdmission(t, f, path)
			if code != http.StatusOK || !admission.Launchable || admission.ReasonCode != string(functionalReady) ||
				strings.Contains(body, prior.ID) || strings.Contains(body, prior.ScopeTenant) {
				t.Fatalf("disjoint console GET admission: code=%d admission=%+v", code, admission)
			}
			if f.srv.runs.seq != 5 || len(f.srv.runs.runs) != 1 {
				t.Fatal("admission GET changed retained history")
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"`+string(tc.profile)+`"}`, "op"))
			if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "v1run-6") {
				t.Fatalf("disjoint console POST refused: code=%d body=%s", post.Code, post.Body.String())
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				status, ok := f.srv.runs.Status("v1run-6")
				if ok && status.State != "running" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("inert worker did not finish")
				}
				time.Sleep(10 * time.Millisecond)
			}
			current, ok := f.srv.runs.Status(prior.ID)
			if !ok || !reflect.DeepEqual(*current, *prior) {
				t.Fatalf("unsafe Voice history changed: %+v", current)
			}
			appended, err := os.ReadFile(ledger)
			if err != nil || !strings.HasPrefix(string(appended), string(original)) {
				t.Fatalf("original retained ledger bytes changed: %v", err)
			}
			reloaded := NewRunManager(cfg)
			if reloaded.loadErr != nil {
				t.Fatal(reloaded.loadErr)
			}
			current, ok = reloaded.Status(prior.ID)
			if !ok || !reflect.DeepEqual(*current, *prior) {
				t.Fatalf("unsafe Voice status changed after restart: %+v", current)
			}
		})
	}
}

func TestFunctionalAdmissionConsoleExceptionFailsClosed(t *testing.T) {
	base := func() *RunStatus {
		return &RunStatus{ID: "v1run-5", Config: string(cataloguev1.VoiceRecovery), State: "partial",
			ExecutionKind: "fixed-suite", ScopeTarget: defaultTargetID, ScopeTenant: "voice",
			Outcome: "test-failed", CleanupStatus: "FAIL", UnsafeToRetry: true, Finished: tsNow()}
	}
	for _, tc := range []struct {
		name string
		edit func(*RunStatus, *Config)
	}{
		{"unknown-profile", func(p *RunStatus, _ *Config) { p.Config = "unknown" }},
		{"unsafe-auth", func(p *RunStatus, _ *Config) { p.Config = string(cataloguev1.AuthScope) }},
		{"unknown-outcome", func(p *RunStatus, _ *Config) { p.Outcome = "" }},
		{"unknown-cleanup", func(p *RunStatus, _ *Config) { p.CleanupStatus = "UNVERIFIED" }},
		{"missing-finish", func(p *RunStatus, _ *Config) { p.Finished = "" }},
		{"wrong-tenant", func(p *RunStatus, _ *Config) { p.ScopeTenant = "other" }},
		{"same-tenant", func(_ *RunStatus, c *Config) { c.CatalogueV1.AllowedTenant = "voice" }},
		{"missing-voice-tenant", func(_ *RunStatus, c *Config) { c.CatalogueV1.VoiceNamespace = "" }},
		{"wrong-target", func(p *RunStatus, _ *Config) { p.ScopeTarget = "other-target" }},
		{"nonterminal", func(p *RunStatus, _ *Config) { p.State = "queued" }},
		{"reconciling", func(p *RunStatus, _ *Config) { p.Error = "reconciliation pending" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := functionalLedgerTestConfig(t)
			cfg.CatalogueV1.VoiceNamespace = "voice"
			prior := base()
			tc.edit(prior, &cfg)
			seed := NewRunManager(cfg)
			if err := seed.persistStatus(prior, prior.ID); err != nil {
				t.Fatal(err)
			}
			rm := NewRunManager(cfg)
			admission := rm.CurrentFunctionalAdmission(cataloguev1.AuthUnauth)
			if admission.Launchable || admission.ReasonCode != string(functionalPriorUnsafe) {
				t.Fatalf("unknown predecessor admitted: %+v", admission)
			}
			id, err := rm.StartFunctional(cataloguev1.AuthUnauth, tsNow(), "op")
			if err == nil || id != "" || rm.seq != 5 {
				t.Fatalf("unsafe POST admitted: id=%q err=%v seq=%d", id, err, rm.seq)
			}
		})
	}
	for _, tc := range []struct {
		name string
		mark func(*RunManager)
	}{
		{"live-process", func(rm *RunManager) { rm.procs["v1run-5"] = &exec.Cmd{} }},
		{"stopping", func(rm *RunManager) { rm.stopping["v1run-5"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := functionalLedgerTestConfig(t)
			cfg.CatalogueV1.VoiceNamespace = "voice"
			rm := NewRunManager(cfg)
			rm.runs["v1run-5"] = base()
			tc.mark(rm)
			if got := rm.CurrentFunctionalAdmission(cataloguev1.AuthUnauth); got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
				t.Fatalf("active predecessor admitted: %+v", got)
			}
		})
	}
}

func TestFunctionalAdmissionConsoleExceptionDoesNotGeneralize(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	cfg.CatalogueV1.VoiceNamespace = "voice"
	rm := NewRunManager(cfg)
	rm.runs["v1run-5"] = &RunStatus{ID: "v1run-5", Config: string(cataloguev1.VoiceRecovery), State: "partial",
		ExecutionKind: "fixed-suite", ScopeTarget: defaultTargetID, ScopeTenant: "voice",
		Outcome: "test-failed", CleanupStatus: "FAIL", UnsafeToRetry: true, Finished: tsNow()}
	destination := runDestination{ScopeTarget: defaultTargetID, ScopeTenant: "vllm"}
	for _, profile := range []cataloguev1.ProfileID{cataloguev1.VoiceMedia, cataloguev1.VoiceRecovery,
		cataloguev1.GPUDrain, cataloguev1.GuardrailCalibration, cataloguev1.MCPSessionBaseline} {
		rm.mu.Lock()
		reason, err := rm.fixedSuiteAdmissionLocked(profile, destination, time.Now())
		rm.mu.Unlock()
		if reason != functionalPriorUnsafe || err == nil {
			t.Fatalf("workload profile %q bypassed unsafe Voice: reason=%q err=%v", profile, reason, err)
		}
	}
	rm.mu.Lock()
	rm.runs["v1run-6"] = &RunStatus{ID: "v1run-6", Config: string(cataloguev1.AuthScope), ExecutionKind: "fixed-suite", UnsafeToRetry: true}
	rm.mu.Unlock()
	if got := rm.CurrentFunctionalAdmission(cataloguev1.AuthUnauth); got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
		t.Fatalf("second unsafe predecessor ignored: %+v", got)
	}
}

func TestFunctionalAdmissionConsoleExceptionKeepsSharedLimits(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	cfg.CatalogueV1.VoiceNamespace = "voice"
	rm := NewRunManager(cfg)
	rm.runs["v1run-5"] = &RunStatus{ID: "v1run-5", Config: string(cataloguev1.VoiceRecovery), State: "partial",
		ExecutionKind: "fixed-suite", ScopeTarget: defaultTargetID, ScopeTenant: "voice",
		Outcome: "test-failed", CleanupStatus: "FAIL", UnsafeToRetry: true, Finished: tsNow()}
	rm.mu.Lock()
	rm.active = maxConcurrentRuns
	rm.mu.Unlock()
	if got := rm.CurrentFunctionalAdmission(cataloguev1.AuthScope); got.Launchable || got.ReasonCode != string(functionalConcurrent) {
		t.Fatalf("shared concurrency cap bypassed: %+v", got)
	}
	rm.mu.Lock()
	rm.active = 0
	rm.lastStart = time.Now()
	rm.mu.Unlock()
	if got := rm.CurrentFunctionalAdmission(cataloguev1.AuthScope); got.Launchable || got.ReasonCode != string(functionalRateLimited) {
		t.Fatalf("shared rate limit bypassed: %+v", got)
	}
}

func TestFunctionalAdmissionUnsafeVoiceStillBlocksConfiguredVoiceRoute(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	cfg.CatalogueV1.VoiceEnabled = true
	cfg.CatalogueV1.VoiceNamespace = "voice"
	cfg.CatalogueV1.VoiceDeployment = "voice-bot"
	cfg.CatalogueV1.VoiceService = "voice-bot"
	cfg.CatalogueV1.VoiceContainer = "voice"
	cfg.CatalogueV1.VoiceServicePort = 8080
	cfg.CatalogueV1.VoicePDB = "voice-bot"
	cfg.CatalogueV1.TranscriptSelector = "app=voice-bot"
	cfg.CatalogueV1.TranscriptContainer = "mongo"
	seed := NewRunManager(cfg)
	prior := &RunStatus{ID: "v1run-5", Config: string(cataloguev1.VoiceRecovery), State: "partial",
		ExecutionKind: "fixed-suite", ScopeTarget: defaultTargetID, ScopeTenant: "voice",
		Outcome: "test-failed", CleanupStatus: "FAIL", UnsafeToRetry: true, Finished: tsNow()}
	if err := seed.persistStatus(prior, prior.ID); err != nil {
		t.Fatal(err)
	}
	f := newAuthFixture(t, cfg, operatorGrant("op", []string{"voice", "vllm"}, []string{defaultTargetID}))
	path := "/api/runs/functional/admission?profile=" + string(cataloguev1.VoiceMedia)
	code, admission, _ := readAdmission(t, f, path)
	if code != http.StatusOK || admission.Launchable || admission.ReasonCode != string(functionalPriorUnsafe) {
		t.Fatalf("configured Voice GET admission bypassed unsafe history: code=%d result=%+v", code, admission)
	}
	post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"limited-v1-voice-media"}`, "op"))
	if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
		t.Fatalf("configured Voice POST bypassed unsafe history: code=%d seq=%d", post.Code, f.srv.runs.seq)
	}
}

func TestFunctionalAdmissionRetainedStateRuntimeAndTransientLimits(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "run-events.jsonl"), []byte("{broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := admissionFixture(t, cfg)
	code, projection, body := readAdmission(t, f, admissionAuthProfile)
	if code != http.StatusOK || projection.Launchable || projection.ReasonCode != string(functionalRetainedUnavailable) || strings.Contains(body, "broken") {
		t.Fatalf("unreadable history disclosed or admitted: code=%d result=%+v", code, projection)
	}
	if f.srv.runs.seq != 0 {
		t.Fatal("unreadable history admission allocated a run")
	}

	invalid := functionalLedgerTestConfig(t)
	invalid.CatalogueV1.KubeconfigPath = "relative"
	invalid.CatalogueV1.KubeContext = "dev"
	brokenRuntime := admissionFixture(t, invalid)
	code, projection, body = readAdmission(t, brokenRuntime, admissionAuthProfile)
	if code != http.StatusOK || projection.Launchable || projection.ReasonCode != string(functionalRuntimeUnavailable) || strings.Contains(body, "relative") {
		t.Fatalf("invalid runtime falsely ready or leaked path: code=%d result=%+v", code, projection)
	}
	post := brokenRuntime.do(brokenRuntime.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"limited-v1-console-unauthenticated"}`, "op"))
	if post.Code != http.StatusBadRequest {
		t.Fatalf("POST did not share runtime refusal: %d", post.Code)
	}

	ready := admissionFixture(t, functionalLedgerTestConfig(t))
	ready.srv.runs.mu.Lock()
	ready.srv.runs.active = maxConcurrentRuns
	ready.srv.runs.mu.Unlock()
	_, projection, _ = readAdmission(t, ready, admissionAuthProfile)
	if projection.Launchable || projection.ReasonCode != string(functionalConcurrent) {
		t.Fatalf("concurrency cap not projected: %+v", projection)
	}
	ready.srv.runs.mu.Lock()
	ready.srv.runs.active = 0
	ready.srv.runs.lastStart = time.Now()
	ready.srv.runs.mu.Unlock()
	_, projection, _ = readAdmission(t, ready, admissionAuthProfile)
	if projection.Launchable || projection.ReasonCode != string(functionalRateLimited) {
		t.Fatalf("rate limit not projected: %+v", projection)
	}
}

func TestFunctionalAdmissionScopeAndProfileAreCheckedBeforeState(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "run-events.jsonl"), []byte("{private-invalid-ledger\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/runs/functional/admission",
		"/api/runs/functional/admission?profile=",
		admissionAuthProfile + "&profile=limited-v1-voice-recovery",
		admissionAuthProfile + "&profile=%GG",
		admissionAuthProfile + "&other=ignored",
		admissionAuthProfile + "&bad=%ZZ",
		"/api/runs/functional/admission?profile=unknown-profile",
	} {
		f := admissionFixture(t, cfg)
		code, _, body := readAdmission(t, f, path)
		if code != http.StatusBadRequest || strings.Contains(body, "RETAINED_STATE_UNAVAILABLE") || strings.Contains(body, "private-invalid") {
			t.Fatalf("invalid profile reached state: %q code=%d body=%s", path, code, body)
		}
	}
	withBody := admissionFixture(t, cfg)
	bodyResponse := withBody.do(withBody.albReqAs(t, http.MethodGet, admissionAuthProfile, `{"profile":"limited-v1-voice-recovery"}`, "op"))
	if bodyResponse.Code != http.StatusBadRequest || strings.Contains(bodyResponse.Body.String(), "RETAINED_STATE_UNAVAILABLE") {
		t.Fatalf("GET body was accepted or reached global state: code=%d body=%s", bodyResponse.Code, bodyResponse.Body.String())
	}
	for _, tc := range []struct {
		name  string
		grant SubjectGrant
	}{
		{"investor", investorGrant("op", []string{"vllm"}, []string{wildcardScope})},
		{"owner", ownerGrant("op", []string{"vllm"})},
		{"wrong-tenant", operatorGrant("op", []string{"voice"}, []string{wildcardScope})},
		{"wrong-target", operatorGrant("op", []string{"vllm"}, []string{"other-target"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthFixture(t, cfg, tc.grant)
			code, _, body := readAdmission(t, f, admissionAuthProfile)
			if code != http.StatusForbidden || strings.Contains(body, "RETAINED_STATE_UNAVAILABLE") || strings.Contains(body, "private-invalid") {
				t.Fatalf("out-of-scope request reached state: code=%d body=%s", code, body)
			}
		})
	}
}
