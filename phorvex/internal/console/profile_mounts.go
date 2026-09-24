package console

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"sigs.k8s.io/yaml"
)

const namedProfileMaxBytes = 64 << 10

// readPinnedNamedProfile accepts only exact operator-reviewed bytes at the
// server-owned suite path. The chart projects one ConfigMap key over that file.
func readPinnedNamedProfile(path, expectedSHA string) ([]byte, error) {
	if !mongoSHA.MatchString(expectedSHA) {
		return nil, errors.New("named suite reviewed profile hash unavailable")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("named suite reviewed profile unavailable")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > namedProfileMaxBytes {
		return nil, errors.New("named suite reviewed profile is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, namedProfileMaxBytes+1))
	if err != nil || int64(len(raw)) != before.Size() {
		return nil, errors.New("named suite reviewed profile changed while reading")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("named suite reviewed profile changed while reading")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expectedSHA {
		return nil, errors.New("named suite reviewed profile hash differs")
	}
	return raw, nil
}

// NATS template comments describe __SET_*__ replacements; only scalar values
// can become executable pins. Malformed YAML remains a refusal.
func natsProfileHasPlaceholder(raw []byte) bool {
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return true
	}
	var visit func(any) bool
	visit = func(value any) bool {
		switch v := value.(type) {
		case string:
			return strings.Contains(v, "__SET_")
		case map[string]any:
			for _, child := range v {
				if visit(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if visit(child) {
					return true
				}
			}
		}
		return false
	}
	return visit(doc)
}
