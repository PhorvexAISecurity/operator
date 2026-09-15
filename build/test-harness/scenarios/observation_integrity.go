package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// observationTarget binds a post-state to the Pod selected during Execute. A
// replacement can still show a positive objective, but cannot establish that
// the original objective was removed by a defender.
func observationTarget(ctx context.Context, env *core.Env, app string, original types.UID) (*corev1.Pod, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("observation cancelled: %w", err)
	}
	pod, err := runningPodByApp(ctx, env, app)
	if err != nil {
		return nil, fmt.Errorf("observation target unavailable for app=%s: %w", app, err)
	}
	if original == "" {
		return nil, fmt.Errorf("observation target identity missing for app=%s", app)
	}
	return pod, nil
}

func observationExec(ctx context.Context, res core.ExecResult) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("observation cancelled: %w", err)
	}
	if res.Err != nil {
		return "", fmt.Errorf("observation exec unavailable: %w", res.Err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("observation exec failed: exit=%d stderr=%q", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	if strings.TrimSpace(res.Stdout) == "" {
		return "", fmt.Errorf("observation output empty or truncated")
	}
	return res.Stdout, nil
}

func stimulusExec(ctx context.Context, res core.ExecResult) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("stimulus cancelled: %w", err)
	}
	if res.Err != nil {
		return fmt.Errorf("stimulus exec unavailable: %w", res.Err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("stimulus exec failed: exit=%d stderr=%q", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

const observationAbsent = "R6TH-OBSERVED-ABSENT"

// Tests may remove only the post-stimulus wait; production keeps the original
// windows. The Pod polling path remains context bounded.
var observationPause = time.Sleep

// markerReadCommand distinguishes a measured missing marker from an empty or
// failed exec. It does not change the stimulus or create a marker.
func markerReadCommand(path string) []string {
	return []string{"sh", "-c", fmt.Sprintf("if test -f %s; then cat %s; else printf '%s'; fi", path, path, observationAbsent)}
}

func observedMarker(ctx context.Context, res core.ExecResult, marker string) (bool, error) {
	out, err := observationExec(ctx, res)
	if err != nil {
		return false, err
	}
	if strings.Contains(out, marker) {
		return true, nil
	}
	if strings.TrimSpace(out) == observationAbsent {
		return false, nil
	}
	return false, fmt.Errorf("observation marker output malformed or truncated")
}

// This parses only the mock's reported body; its fixed responder does not
// authenticate the header or demonstrate credential validity/revocation.
func mockResponderAuthorization(response string) (bool, error) {
	var body struct {
		Authorized *bool `json:"authorized"`
	}
	if err := json.Unmarshal([]byte(response), &body); err != nil || body.Authorized == nil {
		return false, fmt.Errorf("mock authorization response missing or malformed")
	}
	return *body.Authorized, nil
}

const replayDigestPrefix = "R6TH-REPLAY-SHA256="

// The in-Pod command emits a digest of the same shell variable it presents to
// the in-namespace mock API. Only this digest, never the fake value, crosses
// the observation boundary or enters raw logs.
func capturedMockReplay(output, captured string) (string, error) {
	line, response, ok := strings.Cut(output, "\n")
	if !ok || !strings.HasPrefix(line, replayDigestPrefix) || strings.TrimSpace(response) == "" {
		return "", fmt.Errorf("mock replay output missing digest or response")
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(captured)))
	if strings.TrimPrefix(line, replayDigestPrefix) != want {
		return "", fmt.Errorf("mock replay presented value differs from captured trial value")
	}
	return strings.TrimSpace(response), nil
}

func mockReplayCommand(filePath, endpoint string) []string {
	// This single shell process reads once. The digest and HTTP header use the
	// same immutable shell variable; a later file change cannot swap the value.
	script := fmt.Sprintf("CRED=$(cat %s 2>/dev/null); if [ -z \"$CRED\" ]; then exit 17; fi; D=$(printf '%%s' \"$CRED\" | sha256sum | cut -d' ' -f1); for i in 1 2 3 4 5; do R=$(wget -T 3 -qO- --header=\"Authorization: $CRED\" http://%s:8082/authorize 2>/dev/null); if [ -n \"$R\" ]; then break; fi; sleep 1; done; printf '%s%%s\\n%%s' \"$D\" \"$R\"", filePath, endpoint, replayDigestPrefix)
	return []string{"sh", "-c", script}
}
