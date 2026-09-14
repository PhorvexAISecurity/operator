/*
 * Phorvex Console — the End-to-End pipeline's client against the REAL boundary (T1-E2E-AUTH).
 *
 * After the M-136 rollout the pipeline aborted at preflight: its client authorised itself with
 * `?lens=operator` and nothing else. This test anchors the caller repair to the actual server
 * contract rather than to a Python stand-in: the console handler with a real bearer verifier
 * and grant table is served over TLS, and End-to-End/pipeline/transport.py is driven as a real
 * subprocess (python3 -> /bin/sh -> curl) against it.
 *
 *   - the old caller (auth: none) reaches /api/health and is refused on /api/version: 401;
 *   - the configured caller carries a minted bearer through GET, POST and SSE and is
 *     authenticated, authorized against the grant and scoped by it;
 *   - the token never appears in the child's argv or environment.
 *
 * Skipped, not faked, when python3 or curl is absent.
 */

package console

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// e2eDriver is the Python the test runs: the pipeline's own Console/Transport, nothing else.
const e2eDriver = `
import json, os, sys
sys.path.insert(0, os.environ["E2E_PIPELINE"])
from transport import Console, ConsoleAccessError, Transport, TransportError
from capture import CaptureLimits

base, ca, token_file = os.environ["E2E_BASE"], os.environ["E2E_CA"], os.environ["E2E_TOKEN_FILE"]
out = {}

class Recording(Transport):
    def __init__(self):
        super().__init__({"kind": "local"}); self.argvs = []; self.envs = []
    def _command(self, command):
        argv, env = super()._command(command); self.argvs.append(argv); self.envs.append(env); return argv, env

t = Recording()
legacy = Console(t, {"mode": "http", "auth": "none", "base": base, "ca_file": ca})
out["legacyHealth"] = legacy.get_json("/api/health")
try:
    legacy.get_json("/api/version"); out["legacyVersion"] = "unexpected success"
except ConsoleAccessError as e:
    out["legacyVersion"] = str(e)
fired = []
try:
    legacy.stream_decisions(1, CaptureLimits(100000, 100), on_connected=lambda: fired.append(1))
    out["legacyStream"] = "unexpected success"
except ConsoleAccessError as e:
    out["legacyStream"] = str(e)
out["legacyFired"] = len(fired)

console = Console(t, {"mode": "http", "base": base, "ca_file": ca, "token_file": token_file})
out["version"] = console.get_json("/api/version")
out["session"] = console.get_json("/api/session")
out["stop"] = console.post_json("/api/runs/stop", {"id": "e2e-no-such-run"})
try:
    console.post_json("/api/workload/attack", {"namespace": "nats", "action": "foothold"})
    out["attackOutOfScope"] = "unexpected success"
except ConsoleAccessError as e:
    out["attackOutOfScope"] = str(e)
fired = []
got = console.stream_decisions(0.5, CaptureLimits(100000, 100), on_connected=lambda: fired.append(1))
out["streamFired"] = len(fired)
out["streamComplete"] = got.complete
out["streamPods"] = [r.get("pod") for r in got.records]
out["tokenInArgv"] = any(console.token in w for argv in t.argvs for w in argv)
out["tokenInEnv"] = any(console.token in v for env in t.envs for v in env.values())
out["tokenEnvScrubbed"] = all("PHORVEX_CONSOLE_TOKEN" not in env for env in t.envs)
print(json.dumps(out))
`

func TestE2EPipelineClientAgainstTheRealBearerBoundary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the pipeline transport drives /bin/sh and curl")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed; the pipeline client cannot be driven")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not installed; the pipeline client cannot be driven")
	}
	pipeline, err := filepath.Abs(filepath.Join("..", "..", "..", "End-to-End", "pipeline"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(pipeline, "transport.py")); err != nil {
		t.Skipf("End-to-End/pipeline is not checked out beside this module: %v", err)
	}
	// /api/version reads the deployed operator image through the default kubeconfig; this
	// test asserts the boundary, not a cluster, so none may be reachable.
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	audit := writeDecisionAudit(t, decisionRec("voice", "voice-a"), decisionRec("nats", "nats-a"))
	f := newAuthFixture(t, Config{AuditPath: audit},
		bearerOperatorGrant("e2e-ci", []string{"voice"}, []string{defaultTargetID}))
	srv := httptest.NewTLSServer(f.h)
	defer srv.Close()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(srv.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	token := f.bearer.mint(t, bearerTok{Sub: "e2e-ci"})
	tokenPath := filepath.Join(dir, "console-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(python, "-c", e2eDriver)
	cmd.Env = append(os.Environ(),
		"E2E_PIPELINE="+pipeline, "E2E_BASE="+srv.URL, "E2E_CA="+caPath, "E2E_TOKEN_FILE="+tokenPath,
		"PHORVEX_CONSOLE_TOKEN=", "PHORVEX_CONSOLE_BASE=", "PHORVEX_CONSOLE_CA_FILE=", "PHORVEX_CONSOLE_TOKEN_FILE=")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pipeline client failed: %v\n%s", err, raw)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var out struct {
		LegacyHealth     map[string]any `json:"legacyHealth"`
		LegacyVersion    string         `json:"legacyVersion"`
		LegacyStream     string         `json:"legacyStream"`
		LegacyFired      int            `json:"legacyFired"`
		Version          map[string]any `json:"version"`
		Session          map[string]any `json:"session"`
		Stop             map[string]any `json:"stop"`
		AttackOutOfScope string         `json:"attackOutOfScope"`
		StreamFired      int            `json:"streamFired"`
		StreamComplete   bool           `json:"streamComplete"`
		StreamPods       []string       `json:"streamPods"`
		TokenInArgv      bool           `json:"tokenInArgv"`
		TokenInEnv       bool           `json:"tokenInEnv"`
		TokenEnvScrubbed bool           `json:"tokenEnvScrubbed"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &out); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%s", err, raw)
	}
	if strings.Contains(string(raw), token) {
		t.Fatalf("the bearer token leaked into the client's output:\n%s", raw)
	}

	// The incident: the old caller is reachable and refused.
	if out.LegacyHealth["ok"] != true {
		t.Errorf("legacy caller must still reach the public health route: %v", out.LegacyHealth)
	}
	for name, msg := range map[string]string{"version": out.LegacyVersion, "stream": out.LegacyStream} {
		if !strings.Contains(msg, "HTTP 401") || !strings.Contains(msg, "no console credential") {
			t.Errorf("legacy %s must be reported as an unauthenticated 401, got: %s", name, msg)
		}
	}
	if out.LegacyFired != 0 {
		t.Errorf("the stimulus fired %d time(s) on an unauthenticated stream", out.LegacyFired)
	}

	// The repair: a real bearer, verified by the real Authenticator, authorized by the grant.
	if out.Version["console"] == nil {
		t.Errorf("authenticated /api/version did not answer: %v", out.Version)
	}
	if out.Session["subject"] != "e2e-ci" || out.Session["issuer"] != testBearerIss || out.Session["source"] != "bearer" {
		t.Errorf("session does not carry the verified bearer subject: %v", out.Session)
	}
	if out.Session["lens"] != "operator" {
		t.Errorf("the operator lens hint should narrow to operator for an operator grant: %v", out.Session)
	}
	// A control POST passes authentication and the operator role gate and reaches the run
	// resolver, which answers 404 for an unknown id; the client keeps that as a non-success.
	if out.Stop["ok"] != false || out.Stop["_httpStatus"] != float64(404) {
		t.Errorf("POST /api/runs/stop should reach the boundary's run resolution (404, ok=false): %v", out.Stop)
	}
	if !strings.Contains(out.AttackOutOfScope, "HTTP 403") || !strings.Contains(out.AttackOutOfScope, "tenant scope") {
		t.Errorf("a POST outside the granted tenant must be a 403 grant refusal: %s", out.AttackOutOfScope)
	}
	if out.StreamFired != 1 || !out.StreamComplete {
		t.Errorf("authenticated stream: fired=%d complete=%v", out.StreamFired, out.StreamComplete)
	}
	if strings.Join(out.StreamPods, ",") != "voice-a" {
		t.Errorf("the stream must carry exactly the granted tenant's decisions, got %v", out.StreamPods)
	}
	if out.TokenInArgv || out.TokenInEnv || !out.TokenEnvScrubbed {
		t.Errorf("credential hygiene: inArgv=%v inEnv=%v envScrubbed=%v", out.TokenInArgv, out.TokenInEnv, out.TokenEnvScrubbed)
	}
}
