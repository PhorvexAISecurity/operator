package console

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// Real attacks arrive concurrently. Runs may only execute at the same time if they share no
// state that one can destroy for the other: the harness deletes its sandbox namespace at
// teardown, and each arm binds real operator ports. These pin both.

func TestSandboxNamespaceIsPerRunAndStaysInsideTheGeneratedPrefix(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		token := make([]byte, 6)
		if _, err := rand.Read(token); err != nil {
			t.Fatal(err)
		}
		ns := scenarioSandboxNamespaceFor(hex.EncodeToString(token))
		if seen[ns] {
			t.Fatalf("two runs derived the same sandbox %q; teardown of one would destroy the other", ns)
		}
		seen[ns] = true
		if !strings.HasPrefix(ns, scenarioSandboxNamespace+"-") {
			t.Fatalf("sandbox %q escaped the generated prefix", ns)
		}
		if len(ns) > 63 || !nsRe.MatchString(ns) {
			t.Fatalf("sandbox %q is not a usable namespace name", ns)
		}
	}
}

func TestSandboxNamespaceRejectsCallerControlledCharacters(t *testing.T) {
	// The caller never supplies this, but the sanitiser is the guarantee that a real
	// workload namespace can never be produced here — the harness would delete it.
	for _, hostile := range []string{"../../kube-system", "vllm", "A B/C", "", "....."} {
		ns := scenarioSandboxNamespaceFor(hostile)
		if ns != scenarioSandboxNamespace && !strings.HasPrefix(ns, scenarioSandboxNamespace+"-") {
			t.Fatalf("input %q produced %q outside the sandbox prefix", hostile, ns)
		}
		if !nsRe.MatchString(ns) {
			t.Fatalf("input %q produced an invalid namespace %q", hostile, ns)
		}
	}
}

func TestConcurrentRunsAreAllowed(t *testing.T) {
	if maxConcurrentRuns < 2 {
		t.Fatalf("maxConcurrentRuns=%d still serializes runs; concurrent attacks cannot be reproduced", maxConcurrentRuns)
	}
}
