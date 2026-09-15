package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestM167AuthenticatedHTTPPersistenceBoundary(t *testing.T) {
	for _, mode := range []string{"positive", "intent-path-not-directory", "outcome-path-fails-after-effect", "transport-unknown", "unconfigured"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			sink, audit := filepath.Join(root, "outcomes.jsonl"), filepath.Join(root, "manager.jsonl")
			if err := os.WriteFile(audit, []byte("manager-owned\n"), 0o400); err != nil {
				t.Fatal(err)
			}
			calls := 0
			if mode == "intent-path-not-directory" {
				blocker := filepath.Join(root, "blocked")
				if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				sink = filepath.Join(blocker, "outcomes.jsonl")
			}
			cfg := Config{HarnessDir: root, AuditPath: audit, MutationAuditPath: sink, Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
				if bin != "kubectl" || !strings.Contains(strings.Join(args, " "), "patch phorvexpolicy") {
					return "", errors.New("unexpected executor request")
				}
				calls++
				if mode == "outcome-path-fails-after-effect" {
					if err := os.Mkdir(sink, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "transport-unknown" {
					return "request timed out", errors.New("timeout after dispatch")
				}
				return "phorvexpolicy.phorvex.ai/p patched", nil
			}}
			if mode == "unconfigured" {
				cfg.HarnessDir = ""
				cfg.AuditPath = ""
				cfg.MutationAuditPath = ""
			}
			f := newAuthFixture(t, cfg, operatorGrant("operator", []string{wildcardScope}, []string{wildcardScope}))
			f.srv = NewServer(cfg)
			f.srv.EnableAuth(f.auth)
			f.h = f.srv.Handler()
			body := `{"namespace":"tenant-a","name":"p","mode":"active"}`
			denied := f.do(httptest.NewRequest(http.MethodPost, "/api/policy/edit", strings.NewReader(body)))
			if denied.Code != 401 || calls != 0 {
				t.Fatalf("unauthenticated status=%d calls=%d", denied.Code, calls)
			}
			response := f.do(f.albReqAs(t, http.MethodPost, "/api/policy/edit", body, "operator"))
			var got map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "positive":
				if response.Code != 200 || got["ok"] != true || calls != 1 {
					t.Fatalf("response=%s calls=%d", response.Body.String(), calls)
				}
				restarted := NewServer(cfg)
				records := auditEntries(t, restarted.cfg.mutationAuditPath())
				if len(records) != 1 || records[0].Verdict != "applied" {
					t.Fatalf("records=%+v", records)
				}
			case "intent-path-not-directory", "unconfigured":
				if response.Code != 503 || calls != 0 {
					t.Fatalf("response=%s calls=%d", response.Body.String(), calls)
				}
				diagnostics := f.do(f.albReqAs(t, http.MethodGet, "/api/diagnostics", "", "operator"))
				var status map[string]any
				if err := json.Unmarshal(diagnostics.Body.Bytes(), &status); err != nil {
					t.Fatal(err)
				}
				if diagnostics.Code != http.StatusOK || status["stateAvailable"] != false || status["stateError"] == "" || calls != 0 {
					t.Fatalf("diagnostics=%s calls=%d", diagnostics.Body.String(), calls)
				}
				if mode == "unconfigured" {
					if _, err := os.Stat(filepath.Join(root, "mutation-intents.jsonl")); !os.IsNotExist(err) {
						t.Fatal("relative intent leaked")
					}
				}
			case "outcome-path-fails-after-effect":
				if response.Code < 500 || got["applied"] != true || got["unsafeToRetry"] != true || calls != 1 {
					t.Fatalf("response=%s calls=%d", response.Body.String(), calls)
				}
			case "transport-unknown":
				if response.Code != 502 || got["effectUnknown"] != true || got["unsafeToRetry"] != true || calls != 1 {
					t.Fatalf("response=%s calls=%d", response.Body.String(), calls)
				}
			}
			b, err := os.ReadFile(audit)
			if err != nil || string(b) != "manager-owned\n" {
				t.Fatalf("manager audit changed: %q %v", b, err)
			}
		})
	}
}

func TestConsoleStateSurvivesServerRecreationAndDoesNotTouchDecisionAudit(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "manager", "live.jsonl")
	if err := os.MkdirAll(filepath.Dir(audit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(audit, []byte("manager-owned\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: filepath.Join(dir, "console"), AuditPath: audit}
	if err := cfg.ValidateStateDir(); err != nil {
		t.Fatal(err)
	}
	s1 := NewServer(cfg)
	if err := s1.auditConsoleMutation(consoleMutation{Actor: "test", Verdict: "applied"}); err != nil {
		t.Fatal(err)
	}
	s2 := NewServer(cfg)
	b, err := os.ReadFile(s2.cfg.mutationAuditPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"verdict":"applied"`) {
		t.Fatalf("missing retained record: %s", b)
	}
	manager, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if string(manager) != "manager-owned\n" {
		t.Fatalf("manager audit changed: %q", manager)
	}
}

func TestPolicyEditRefusesBeforeEffectWhenIntentCannotPersist(t *testing.T) {
	var calls atomic.Int32
	cfg := Config{StateDir: t.TempDir(), Exec: func(time.Duration, string, ...string) (string, error) { calls.Add(1); return "patched", nil },
		StateAppend: func(string, []byte) error { return errors.New("disk full") }}
	s := NewServer(cfg)
	r := httptest.NewRequest("POST", "/api/policy/edit", strings.NewReader(`{"namespace":"tenant-a","name":"p","mode":"active"}`))
	w := httptest.NewRecorder()
	s.policyEdit(w, r)
	if w.Code != 503 || calls.Load() != 0 || !strings.Contains(w.Body.String(), "refused-evidence-unavailable") {
		t.Fatalf("code=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
	}
}

func TestUnconfiguredServerDoesNotWriteRelativeIntentOrDispatch(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	if err = os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	var calls atomic.Int32
	s := NewServer(Config{Exec: func(time.Duration, string, ...string) (string, error) { calls.Add(1); return "patched", nil }})
	r := httptest.NewRequest("POST", "/api/policy/edit", strings.NewReader(`{"namespace":"tenant-a","name":"p","mode":"active"}`))
	w := httptest.NewRecorder()
	s.policyEdit(w, r)
	if w.Code != 503 || calls.Load() != 0 {
		t.Fatalf("code=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
	}
	entries, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unconfigured server wrote relative files: %v", entries)
	}
}

func TestPolicyEditReportsAppliedPartialWithoutDuplicateEffect(t *testing.T) {
	var writes, calls atomic.Int32
	cfg := Config{StateDir: t.TempDir(), Exec: func(time.Duration, string, ...string) (string, error) { calls.Add(1); return "patched", nil },
		StateAppend: func(path string, b []byte) error {
			if writes.Add(1) == 2 {
				return errors.New("sync failed")
			}
			return appendState(path, b)
		}}
	s := NewServer(cfg)
	r := httptest.NewRequest("POST", "/api/policy/edit", strings.NewReader(`{"namespace":"tenant-a","name":"p","mode":"active"}`))
	w := httptest.NewRecorder()
	s.policyEdit(w, r)
	if w.Code != 500 || calls.Load() != 1 || !strings.Contains(w.Body.String(), `"unsafeToRetry":true`) || !strings.Contains(w.Body.String(), `"applied":true`) {
		t.Fatalf("code=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
	}
}

func TestAuthenticatedHTTPPolicyRefusesBeforeEffectOnStorageFailure(t *testing.T) {
	var calls atomic.Int32
	f := newAuthFixture(t, Config{StateDir: t.TempDir(), Exec: func(time.Duration, string, ...string) (string, error) { calls.Add(1); return "patched", nil }, StateAppend: func(string, []byte) error { return errors.New("read-only volume") }},
		operatorGrant("op", []string{"tenant-a"}, []string{defaultTargetID}))
	w := f.do(f.albReqAs(t, "POST", "/api/policy/edit", `{"namespace":"tenant-a","name":"p","mode":"active"}`, "op"))
	if w.Code != 503 || calls.Load() != 0 || !strings.Contains(w.Body.String(), "refused-evidence-unavailable") {
		t.Fatalf("code=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
	}
}

func TestAppendStateRejectsOversizedRecordWithoutDamagingLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := appendState(path, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = appendState(path, make([]byte, consoleStateRecordLimit)); err == nil {
		t.Fatal("oversized record accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("valid ledger changed after rejected record: before=%q after=%q", before, after)
	}
}

func TestMalformedRetainedUptimeIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phorvex-uptime.jsonl")
	if err := os.WriteFile(path, []byte("{broken}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUptimeSamples(path); err == nil || !strings.Contains(err.Error(), "malformed retained uptime") {
		t.Fatalf("error=%v", err)
	}
}

func TestUptimeWriterReturnsStorageFailure(t *testing.T) {
	s := NewServer(Config{StateDir: t.TempDir(), StateAppend: func(string, []byte) error { return errors.New("volume full") }})
	err := s.persistUptimeSamples([]uptimeSample{{T: time.Now().UTC().Format(time.RFC3339Nano), NS: "tenant-a", Workload: "app", Desired: 1, Ready: 1}})
	if err == nil || !strings.Contains(err.Error(), "volume full") {
		t.Fatalf("error=%v", err)
	}
}

func TestRunStatusSurvivesManagerRecreation(t *testing.T) {
	cfg := Config{StateDir: t.TempDir()}
	rm := NewRunManager(cfg)
	st := &RunStatus{ID: "run-7", Config: "fpprobe", State: "done", Owner: "issuer#subject", ScopeTenant: "tenant-a"}
	if err := rm.persistStatus(st, "run-7"); err != nil {
		t.Fatal(err)
	}
	reloaded := NewRunManager(cfg)
	got, ok := reloaded.Status("run-7")
	if !ok || got.State != "done" || got.Owner != "issuer#subject" {
		t.Fatalf("reloaded=%+v ok=%v err=%v", got, ok, reloaded.loadErr)
	}
}
