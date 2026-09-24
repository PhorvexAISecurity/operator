package console

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPodBoundSourceManifest(p podBoundTokenProfile) podBoundTokenSourceManifest {
	return podBoundTokenSourceManifest{
		Schema: podBoundSourceManifestSchema, SourceCommit: strings.Repeat("a", 40),
		ManagerImageID:      p.Fixture.ManagerImageID,
		BuildEvidenceRef:    "workflow/evidence/reviewed-build-log.json",
		BuildEvidenceSHA256: strings.Repeat("b", 64),
		ReviewRecordRef:     "workflow/evidence/external-build-review.md",
		ReviewRecordSHA256:  strings.Repeat("c", 64),
	}
}

func pinPodBoundSource(t *testing.T, p *podBoundTokenProfile, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	p.Fixture.SourceManifestPath = path
	p.Fixture.SourceManifestSHA256 = hex.EncodeToString(sum[:])
}

func TestPodBoundSourceManifestBindsReviewedBuildToInstalledImage(t *testing.T) {
	p := testPodBoundTokenProfile()
	path := filepath.Join(t.TempDir(), "source-manifest.json")
	manifest := testPodBoundSourceManifest(p)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pinPodBoundSource(t, &p, path, raw)
	got, err := verifyPodBoundTokenSourceManifest(p)
	if err != nil || got != manifest {
		t.Fatalf("reviewed source/image join refused: %v %+v", err, got)
	}

	// A changed file cannot silently replace the reviewed source-to-image join.
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPodBoundTokenSourceManifest(p); err == nil {
		t.Fatal("changed source manifest accepted against old profile hash")
	}
}

func TestPodBoundSourceManifestRejectsUnreviewedOrAmbiguousAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source-manifest.json")
	for _, tc := range []struct {
		name   string
		mutate func(*podBoundTokenSourceManifest)
	}{
		{"source revision missing", func(m *podBoundTokenSourceManifest) { m.SourceCommit = "" }},
		{"source revision abbreviated", func(m *podBoundTokenSourceManifest) { m.SourceCommit = strings.Repeat("a", 12) }},
		{"different image digest", func(m *podBoundTokenSourceManifest) {
			m.ManagerImageID = "registry.example/phorvex@sha256:" + strings.Repeat("d", 64)
		}},
		{"build evidence absent", func(m *podBoundTokenSourceManifest) { m.BuildEvidenceRef = "" }},
		{"build evidence hash absent", func(m *podBoundTokenSourceManifest) { m.BuildEvidenceSHA256 = "" }},
		{"review record absent", func(m *podBoundTokenSourceManifest) { m.ReviewRecordRef = "" }},
		{"review record hash absent", func(m *podBoundTokenSourceManifest) { m.ReviewRecordSHA256 = "" }},
		{"placeholder review", func(m *podBoundTokenSourceManifest) { m.ReviewRecordRef = "__SET_REVIEW__" }},
		{"same evidence and review", func(m *podBoundTokenSourceManifest) { m.ReviewRecordRef = m.BuildEvidenceRef }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPodBoundTokenProfile()
			m := testPodBoundSourceManifest(p)
			tc.mutate(&m)
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			pinPodBoundSource(t, &p, path, raw)
			if _, err := verifyPodBoundTokenSourceManifest(p); err == nil {
				t.Fatal("unreviewed source/image authority accepted")
			}
		})
	}
	p := testPodBoundTokenProfile()
	m := testPodBoundSourceManifest(p)
	raw, _ := json.Marshal(m)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate image key", []byte(strings.Replace(string(raw), `"managerImageID":`, `"managerImageID":"wrong","managerImageID":`, 1))},
		{"case alias image key", []byte(strings.Replace(string(raw), `"managerImageID":`, `"ManagerImageID":"wrong","managerImageID":`, 1))},
		{"unknown source claim", []byte(strings.Replace(string(raw), `"schema":`, `"gitProvenAtRuntime":true,"schema":`, 1))},
		{"trailing data", append(append([]byte(nil), raw...), []byte(`{}`)...)},
		{"oversize", []byte(strings.Repeat("x", podBoundSourceManifestMaxBytes+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinPodBoundSource(t, &p, path, tc.raw)
			if _, err := verifyPodBoundTokenSourceManifest(p); err == nil {
				t.Fatal("ambiguous or oversized manifest accepted")
			}
		})
	}
}

func TestPodBoundSourceManifestRequiresServerLocalRegularFile(t *testing.T) {
	p := testPodBoundTokenProfile()
	dir := t.TempDir()
	path := filepath.Join(dir, "source-manifest.json")
	raw, err := json.Marshal(testPodBoundSourceManifest(p))
	if err != nil {
		t.Fatal(err)
	}
	pinPodBoundSource(t, &p, path, raw)
	linked := filepath.Join(dir, "linked-manifest.json")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	p.Fixture.SourceManifestPath = linked
	if _, err := verifyPodBoundTokenSourceManifest(p); err == nil {
		t.Fatal("symlink source manifest accepted")
	}
	p.Fixture.SourceManifestPath = "source-manifest.json"
	if _, err := verifyPodBoundTokenSourceManifest(p); err == nil {
		t.Fatal("relative source manifest accepted")
	}
	p.Fixture.SourceManifestPath = dir
	if _, err := verifyPodBoundTokenSourceManifest(p); err == nil {
		t.Fatal("directory source manifest accepted")
	}
}
