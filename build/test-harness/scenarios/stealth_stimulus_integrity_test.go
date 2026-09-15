package scenarios

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This executes only the existing two fake marker writes in a disposable local
// directory. The shell exit is the real value that Env.Exec would report.
func TestStealthStimulusPropagatesEachWriteFailure(t *testing.T) {
	cases := []struct {
		name, block string
		wantSuccess bool
	}{
		{"first-write-fails", "primary", false},
		{"second-write-fails", "backup", false},
		{"legitimate-two-copy-setup", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, "cache", "primary")
			b := filepath.Join(root, "config", "backup")
			if tc.block != "" {
				blocked := p
				if tc.block == "backup" {
					blocked = b
				}
				if err := os.MkdirAll(blocked, 0700); err != nil {
					t.Fatal(err)
				}
			}
			output, err := exec.Command("sh", "-c", stealthPlantCommand(p, b)).CombinedOutput()
			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("valid fake marker setup failed: %v output=%q", err, output)
				}
				for _, path := range []string{p, b} {
					data, readErr := os.ReadFile(path)
					if readErr != nil || strings.TrimSpace(string(data)) != StealthFootholdMarker {
						t.Fatalf("marker missing at %s: read=%v", path, readErr)
					}
				}
			} else if err == nil {
				t.Fatalf("failed %s marker write was masked by final echo: output=%q", tc.block, output)
			}
		})
	}
}
