package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleasePathsRejectSymlinkAncestorsLeavesEscapesAndHardLinks(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	outside := t.TempDir()
	for _, directory := range []string{inside, filepath.Join(root, "real")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	realFile := filepath.Join(root, "real", "values.yaml")
	if err := os.WriteFile(realFile, []byte("image: old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "escape.yaml")
	if err := os.WriteFile(outsideFile, []byte("escape\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "relative-parent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "absolute-parent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFile, filepath.Join(root, "leaf.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(realFile, filepath.Join(root, "hardlink.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"relative-parent/values.yaml",
		"absolute-parent/escape.yaml",
		"leaf.yaml",
		"real/values.yaml",
		"../escape.yaml",
	} {
		t.Run(path, func(t *testing.T) {
			if _, err := safeRepoPath(root, path, false); err == nil {
				t.Fatalf("unsafe path %q was accepted", path)
			}
		})
	}

	linkParent := t.TempDir()
	linkedRoot := filepath.Join(linkParent, "repo")
	if err := os.Symlink(root, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := safeRoot(linkedRoot); err == nil || !strings.Contains(err.Error(), "symlinks") {
		t.Fatalf("symlinked repository root error = %v", err)
	}
}

func TestAtomicWriteRejectsSymlinkSwapAtRenameBoundary(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "batch.json")
	escape := filepath.Join(t.TempDir(), "escape.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(escape, []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeAtomicReplace = func(target string) {
		if err := os.Rename(target, target+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(escape, target); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeAtomicReplace = nil })
	if err := writeAtomicFile(path, []byte("new\n")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink swap error = %v", err)
	}
	raw, err := os.ReadFile(escape)
	if err != nil || string(raw) != "outside\n" {
		t.Fatalf("escape target changed: %q, %v", raw, err)
	}
}

func TestCommittedStagingParentSymlinkCannotCompleteBatch(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	batch := r.ensureBatch()
	r.commit("pin batch")
	r.record("manager", "1.0.0", "a")
	r.commit("record manager")
	staging := filepath.Join(r.root, "deploy", "environments", "staging")
	r.git("mv", "deploy/environments/staging", "deploy/shadow")
	if err := os.Symlink("../shadow", staging); err != nil {
		t.Fatal(err)
	}
	r.commit("redirect staging through committed symlink")

	if _, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err == nil || !strings.Contains(err.Error(), "symlinks") {
		t.Fatalf("symlinked staging pending error = %v", err)
	}
	r.git("tag", "brain-v1.0.0", batch.Source)
	err := RecordRelease(r.root, r.releaseDir, "HEAD", ReleaseEnvironment, "brain",
		ReleaseRegistry+"/phorvex/brain", "1.0.0", "sha256:"+strings.Repeat("b", 64), batch.Source)
	if err == nil || !strings.Contains(err.Error(), "symlinks") {
		t.Fatalf("symlinked staging record error = %v", err)
	}
	committed := r.git("show", "HEAD:release/batch.json")
	if strings.Contains(committed, `"releases": {\n    "brain":`) || !strings.Contains(committed, `"status": "partial"`) {
		t.Fatalf("rejected symlink record changed committed completion:\n%s", committed)
	}
}

func TestEveryReleaseAuthorityAncestorAndLeafSymlinkFailsClosed(t *testing.T) {
	tests := []struct {
		name, path string
		buildPath  bool
	}{
		{"batch leaf", "release/batch.json", false},
		{"release directory ancestor", "release", false},
		{"application route leaf", deploymentManifest, false},
		{"ordered values leaf", "deploy/environments/staging/phorvex.yaml", false},
		{"writable values leaf", "deploy/environments/staging/brain.yaml", false},
		{"chart directory ancestor", "deploy/charts/phorvex-brain", false},
		{"chart template leaf", "deploy/charts/phorvex-brain/templates/deployment.yaml", false},
		{"Dockerfile leaf", "deploy/docker/service.Dockerfile", true},
		{"Docker context ignore leaf", ".dockerignore", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newBatchTestRepo(t, batchVersions())
			r.ensureBatch()
			r.commit("pin batch")
			path := filepath.Join(r.root, filepath.FromSlash(test.path))
			target := path + ".real"
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(target), path); err != nil {
				t.Fatal(err)
			}
			r.commit("replace authority with symlink")
			var err error
			if test.buildPath {
				err = VerifyBuildPaths(r.root, "deploy/docker/service.Dockerfile", ".")
			} else {
				_, err = PendingReleases(r.root, filepath.Join(r.root, "release"), "HEAD")
			}
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("%s symlink error = %v", test.path, err)
			}
		})
	}
}

func TestVerifyStagedRequiresTheExactReleaseAllowlistAndNoOtherMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*batchTestRepo)
	}{
		{"extra staged file", func(r *batchTestRepo) {
			_ = os.WriteFile(filepath.Join(r.root, "extra"), []byte("extra\n"), 0o644)
			r.git("add", "release/batch.json", "extra")
		}},
		{"unexpected untracked file", func(r *batchTestRepo) {
			r.git("add", "release/batch.json")
			_ = os.WriteFile(filepath.Join(r.root, "untracked"), []byte("extra\n"), 0o644)
		}},
		{"mutation outside staged allowlist", func(r *batchTestRepo) {
			r.git("add", "release/batch.json")
			_ = os.WriteFile(filepath.Join(r.root, "deploy/environments/staging/brain.yaml"), []byte(fixtureValues("runtimeImage")), 0o644)
		}},
		{"missing expected batch file", func(_ *batchTestRepo) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newBatchTestRepo(t, batchVersions())
			r.ensureBatch()
			test.mutate(r)
			if _, err := VerifyStaged(r.root, r.releaseDir, "HEAD", ""); err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}

	r := newBatchTestRepo(t, batchVersions())
	r.ensureBatch()
	r.git("add", "release/batch.json")
	if files, err := VerifyStaged(r.root, r.releaseDir, "HEAD", ""); err != nil || len(files) != 1 || files[0] != "release/batch.json" {
		t.Fatalf("exact staging = %v, %v", files, err)
	}
}

func TestCommittedHeadVerificationIsIndependentOfMutableWorkingTree(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	r.ensureBatch()
	r.commit("pin batch")
	detached := filepath.Join(t.TempDir(), "committed")
	r.git("worktree", "add", "--detach", detached, "HEAD")
	t.Cleanup(func() { r.git("worktree", "remove", "--force", detached) })
	if err := os.WriteFile(filepath.Join(r.root, "deploy/environments/staging/brain.yaml"), []byte(fixtureValues("runtimeImage")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCommitted(r.root, r.releaseDir, "HEAD"); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("mutable working tree verify error = %v", err)
	}
	if _, err := VerifyCommitted(detached, filepath.Join(detached, "release"), "HEAD"); err != nil {
		t.Fatalf("clean detached committed HEAD failed verification: %v", err)
	}
}
