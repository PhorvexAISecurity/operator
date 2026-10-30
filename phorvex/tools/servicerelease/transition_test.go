package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func transitionWorktrees(t *testing.T, r *batchTestRepo, expected, latest string) (string, string) {
	t.Helper()
	parent := t.TempDir()
	expectedRoot := filepath.Join(parent, "expected")
	latestRoot := filepath.Join(parent, "latest")
	r.git("worktree", "add", "--detach", expectedRoot, expected)
	r.git("worktree", "add", "--detach", latestRoot, latest)
	t.Cleanup(func() {
		r.git("worktree", "remove", "--force", latestRoot)
		r.git("worktree", "remove", "--force", expectedRoot)
	})
	return expectedRoot, latestRoot
}

func validateTestTransition(t *testing.T, r *batchTestRepo, expected, latest string) (*Batch, *Batch, error) {
	t.Helper()
	expectedRoot, latestRoot := transitionWorktrees(t, r, expected, latest)
	return ValidateBatchTransition(expectedRoot, latestRoot, "release", expected, latest)
}

func TestTransitionRejectsMalformedExpectedEvenWhenDescendantRepairsIt(t *testing.T) {
	r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
	r.ensureBatch()
	valid, err := os.ReadFile(filepath.Join(r.releaseDir, BatchFile))
	if err != nil {
		t.Fatal(err)
	}
	r.commit("pin valid batch")
	if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), []byte("{ definitely-not-json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	expected := r.commit("malformed authoritative batch")
	if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	latest := r.commit("repair descendant batch")

	if _, _, err := validateTestTransition(t, r, expected, latest); err == nil || !strings.Contains(err.Error(), "expected endpoint") {
		t.Fatalf("malformed expected endpoint error = %v", err)
	}
}

func TestTransitionRejectsSemanticallyInvalidExpectedEvenWhenDescendantRepairsIt(t *testing.T) {
	r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
	batch := r.ensureBatch()
	valid, err := os.ReadFile(filepath.Join(r.releaseDir, BatchFile))
	if err != nil {
		t.Fatal(err)
	}
	r.commit("pin valid batch")
	batch.Status = "complete"
	if err := writeBatch(r.releaseDir, batch); err != nil {
		t.Fatal(err)
	}
	expected := r.commit("semantically invalid authoritative batch")
	if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	latest := r.commit("repair semantic batch corruption")

	if _, _, err := validateTestTransition(t, r, expected, latest); err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("semantically invalid expected endpoint error = %v", err)
	}
}

func TestTransitionAcceptsMonotonicCompletionAndIdempotentDescendants(t *testing.T) {
	t.Run("partial to complete", func(t *testing.T) {
		r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0", "brain": "1.0.0"})
		r.ensureBatch()
		r.commit("pin batch")
		r.record("manager", "1.0.0", "a")
		expected := r.commit("record manager")
		r.record("brain", "1.0.0", "b")
		latest := r.commit("record brain")

		previous, current, err := validateTestTransition(t, r, expected, latest)
		if err != nil {
			t.Fatal(err)
		}
		if previous.Status != "partial" || current.Status != "complete" || len(previous.Releases) != 1 || len(current.Releases) != 2 {
			t.Fatalf("transition = %#v -> %#v", previous, current)
		}
	})

	t.Run("complete through unrelated descendant", func(t *testing.T) {
		r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
		r.ensureBatch()
		r.commit("pin batch")
		r.record("manager", "1.0.0", "a")
		expected := r.commit("complete batch")
		if err := os.WriteFile(filepath.Join(r.root, "unrelated"), []byte("descendant\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		latest := r.commit("unrelated descendant")

		previous, current, err := validateTestTransition(t, r, expected, latest)
		if err != nil {
			t.Fatal(err)
		}
		if previous.Status != "complete" || current.Status != "complete" || !reflectBatchReleaseEqual(previous, current) {
			t.Fatalf("idempotent transition = %#v -> %#v", previous, current)
		}
	})
}

func reflectBatchReleaseEqual(a, b *Batch) bool {
	if len(a.Releases) != len(b.Releases) {
		return false
	}
	for name, released := range a.Releases {
		if b.Releases[name] != released {
			return false
		}
	}
	return true
}

func TestTransitionRejectsEveryReleaseStateRewrite(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *batchTestRepo, *Batch)
	}{
		{"delete component set member", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			delete(batch.Versions, "brain")
			delete(batch.Releases, "brain")
			batch.ExpectedComponents = batch.ExpectedComponents[:1]
			batch.Components = batch.Components[:1]
			batch.Status = "complete"
		}},
		{"replace component contract", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			batch.Components[0] = batch.Components[1]
		}},
		{"reorder component set", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			slices.Reverse(batch.ExpectedComponents)
			slices.Reverse(batch.Components)
		}},
		{"change source", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			batch.Source = strings.Repeat("f", 40)
		}},
		{"change component metadata", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			batch.Components[0].Build.Target = "replacement"
		}},
		{"replace recorded digest", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			released := batch.Releases["manager"]
			released.Digest = "sha256:" + strings.Repeat("c", 64)
			batch.Releases["manager"] = released
			if err := Deploy(r.root, ReleaseEnvironment, "manager", released.Repository, "1.0.0", released.Digest, batch.Source); err != nil {
				t.Fatal(err)
			}
		}},
		{"replace recorded repository", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			released := batch.Releases["manager"]
			released.Repository = ReleaseRegistry + "/phorvex/sensor"
			batch.Releases["manager"] = released
			if err := Deploy(r.root, ReleaseEnvironment, "manager", released.Repository, "1.0.0", released.Digest, batch.Source); err != nil {
				t.Fatal(err)
			}
		}},
		{"change recorded deployment pin", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			released := batch.Releases["manager"]
			if err := Deploy(r.root, ReleaseEnvironment, "manager", released.Repository, "1.0.0", "sha256:"+strings.Repeat("d", 64), batch.Source); err != nil {
				t.Fatal(err)
			}
		}},
		{"roll recorded back to pending", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			delete(batch.Releases, "manager")
			batch.Status = "partial"
		}},
		{"downgrade schema", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			batch.Schema = 1
		}},
		{"swap release records", func(t *testing.T, r *batchTestRepo, batch *Batch) {
			batch.Releases["manager"], batch.Releases["brain"] = batch.Releases["brain"], batch.Releases["manager"]
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0", "brain": "1.0.0"})
			r.ensureBatch()
			r.commit("pin batch")
			r.record("manager", "1.0.0", "a")
			r.record("brain", "1.0.0", "b")
			expected := r.commit("complete valid batch")
			batch, err := readBatch(r.releaseDir)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, r, batch)
			if err := writeBatch(r.releaseDir, batch); err != nil {
				t.Fatal(err)
			}
			latest := r.commit("rewrite release state")

			if _, _, err := validateTestTransition(t, r, expected, latest); err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}
}

func TestTransitionRejectsMissingNonAncestorMalformedLatestAndMutableEndpoints(t *testing.T) {
	t.Run("missing expected path", func(t *testing.T) {
		r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
		r.ensureBatch()
		valid, err := os.ReadFile(filepath.Join(r.releaseDir, BatchFile))
		if err != nil {
			t.Fatal(err)
		}
		r.commit("pin batch")
		if err := os.Remove(filepath.Join(r.releaseDir, BatchFile)); err != nil {
			t.Fatal(err)
		}
		expected := r.commit("remove expected batch")
		if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), valid, 0o644); err != nil {
			t.Fatal(err)
		}
		latest := r.commit("restore latest batch")
		if _, _, err := validateTestTransition(t, r, expected, latest); err == nil {
			t.Fatal("missing expected batch was accepted")
		}
	})

	t.Run("malformed latest", func(t *testing.T) {
		r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
		r.ensureBatch()
		expected := r.commit("pin valid batch")
		if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), []byte("{\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		latest := r.commit("malform latest batch")
		if _, _, err := validateTestTransition(t, r, expected, latest); err == nil || !strings.Contains(err.Error(), "latest endpoint") {
			t.Fatalf("malformed latest endpoint error = %v", err)
		}
	})

	t.Run("non ancestor", func(t *testing.T) {
		r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
		r.ensureBatch()
		base := r.commit("pin valid batch")
		if err := os.WriteFile(filepath.Join(r.root, "expected-side"), []byte("expected\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		expected := r.commit("expected side")
		r.git("switch", "--detach", base)
		if err := os.WriteFile(filepath.Join(r.root, "latest-side"), []byte("latest\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		latest := r.commit("latest side")
		if _, _, err := validateTestTransition(t, r, expected, latest); err == nil || !strings.Contains(err.Error(), "not an ancestor") {
			t.Fatalf("non-ancestor error = %v", err)
		}
	})

	t.Run("attached mutable roots", func(t *testing.T) {
		r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
		r.ensureBatch()
		head := r.commit("pin batch")
		if _, _, err := ValidateBatchTransition(r.root, r.root, "release", head, head); err == nil || !strings.Contains(err.Error(), "attached to mutable ref") {
			t.Fatalf("attached endpoint error = %v", err)
		}
	})
}

func TestTransitionRejectsExpectedAndLatestGitObjectSymlinkEscapes(t *testing.T) {
	for _, endpoint := range []string{"expected", "latest"} {
		t.Run(endpoint, func(t *testing.T) {
			r := newBatchTestRepo(t, map[string]string{"manager": "1.0.0"})
			r.ensureBatch()
			valid, err := os.ReadFile(filepath.Join(r.releaseDir, BatchFile))
			if err != nil {
				t.Fatal(err)
			}
			base := r.commit("pin valid batch")
			if err := os.WriteFile(filepath.Join(r.root, "batch.real.json"), valid, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(r.releaseDir, BatchFile)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../batch.real.json", filepath.Join(r.releaseDir, BatchFile)); err != nil {
				t.Fatal(err)
			}
			symlinkCommit := r.commit("replace batch object with escaping symlink")
			var expected, latest string
			if endpoint == "expected" {
				expected = symlinkCommit
				if err := os.Remove(filepath.Join(r.releaseDir, BatchFile)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), valid, 0o644); err != nil {
					t.Fatal(err)
				}
				latest = r.commit("restore regular latest batch")
			} else {
				expected = base
				latest = symlinkCommit
			}
			if _, _, err := validateTestTransition(t, r, expected, latest); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("%s symlink endpoint error = %v", endpoint, err)
			}
		})
	}
}
