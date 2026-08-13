package decision

import (
	"bytes"
	"os"
	"testing"
)

// The supported ablation is a recon-profile A/B on CoverageEngine. P0 is not its baseline.
func TestAblationNeverReferencesDeprecatedP0Engine(t *testing.T) {
	source, err := os.ReadFile("ablation.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source, []byte("NewEngine")) {
		t.Fatal("ablation.go references NewEngine: the P1 recon-profile A/B silently became a P0-vs-P1 comparison")
	}
}
