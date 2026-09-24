package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const podBoundSourceManifestSchema = "phorvex.manager-source-image.v1"
const podBoundSourceManifestMaxBytes = 8 << 10

var podBoundSourceCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// This is a reviewed deployment artifact. Its build and review references are
// evidence for an operator to inspect and pin, not claims that the running Go
// binary can prove its own source revision. The installed Pod image is checked
// independently against ManagerImageID at every current-manager check.
type podBoundTokenSourceManifest struct {
	Schema              string `json:"schema"`
	SourceCommit        string `json:"sourceCommit"`
	ManagerImageID      string `json:"managerImageID"`
	BuildEvidenceRef    string `json:"buildEvidenceRef"`
	BuildEvidenceSHA256 string `json:"buildEvidenceSHA256"`
	ReviewRecordRef     string `json:"reviewRecordRef"`
	ReviewRecordSHA256  string `json:"reviewRecordSHA256"`
}

var podBoundSourceManifestKeys = map[string]bool{
	"schema": true, "sourceCommit": true, "managerImageID": true,
	"buildEvidenceRef": true, "buildEvidenceSHA256": true,
	"reviewRecordRef": true, "reviewRecordSHA256": true,
}

func validPodBoundSourceRef(ref string) bool {
	return len(ref) > 0 && len(ref) <= 512 && strings.TrimSpace(ref) == ref &&
		!strings.Contains(ref, "__SET_") && !strings.ContainsAny(ref, "\x00\r\n")
}

// verifyPodBoundTokenSourceManifest reads only the path in the server-owned
// profile. The profile hash pins the exact bytes reviewed outside this process;
// build evidence and review records must actually be checked by the operator.
func verifyPodBoundTokenSourceManifest(p podBoundTokenProfile) (podBoundTokenSourceManifest, error) {
	f := p.Fixture
	path := f.SourceManifestPath
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !mongoSHA.MatchString(f.SourceManifestSHA256) ||
		!mongoPinnedImage.MatchString(f.ManagerImageID) {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest pin unavailable")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest unavailable")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > podBoundSourceManifestMaxBytes {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, podBoundSourceManifestMaxBytes+1))
	if err != nil || int64(len(raw)) != before.Size() {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest changed while reading")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest changed while reading")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != f.SourceManifestSHA256 {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest hash differs from reviewed pin")
	}
	if err := strictNATSResponseJSON(raw, podBoundSourceManifestKeys); err != nil {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest fields are incomplete or ambiguous")
	}
	var manifest podBoundTokenSourceManifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&manifest); err != nil {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token source manifest is malformed")
	}
	if manifest.Schema != podBoundSourceManifestSchema || !podBoundSourceCommit.MatchString(manifest.SourceCommit) ||
		!mongoPinnedImage.MatchString(manifest.ManagerImageID) || manifest.ManagerImageID != f.ManagerImageID ||
		!validPodBoundSourceRef(manifest.BuildEvidenceRef) || !mongoSHA.MatchString(manifest.BuildEvidenceSHA256) ||
		!validPodBoundSourceRef(manifest.ReviewRecordRef) || !mongoSHA.MatchString(manifest.ReviewRecordSHA256) ||
		manifest.BuildEvidenceRef == manifest.ReviewRecordRef {
		return podBoundTokenSourceManifest{}, errors.New("Pod-bound token reviewed source-to-image authority differs")
	}
	return manifest, nil
}
