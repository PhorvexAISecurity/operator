package console

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The joint Voice renderer installs these literal source files and stamps its
// SOURCE_SHA on the Pod. The memory console must admit that same source.
func TestVoiceMemorySourcePinMatchesRenderedBundle(t *testing.T) {
	root := filepath.Join("..", "..", "..", "build", "integrations", "voice-memory")
	bot, err := os.ReadFile(filepath.Join(root, "bot.py"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(root, "voice_memory_policy.py"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(bot)
	h.Write([]byte{0})
	h.Write(policy)
	actual := hex.EncodeToString(h.Sum(nil))

	renderer, err := os.ReadFile(filepath.Join(root, "render_activation.py"))
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^SOURCE_SHA = "([0-9a-f]{64})"$`).FindSubmatch(renderer)
	if len(match) != 2 {
		t.Fatal("renderer has no single reviewed Voice memory source pin")
	}
	if string(match[1]) != actual {
		t.Fatalf("renderer source pin %s differs from bundled source %s", match[1], actual)
	}
	if voiceMemorySourceSHA256 != actual {
		t.Fatalf("console source pin %s differs from renderer and bundled source %s", voiceMemorySourceSHA256, actual)
	}
}
