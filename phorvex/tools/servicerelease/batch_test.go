package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type batchTestRepo struct {
	t          *testing.T
	root       string
	releaseDir string
	source     string
}

func batchVersions() map[string]string {
	return map[string]string{
		"manager": "1.0.0", "brain": "1.0.0", "sensor": "1.0.0",
		"actuator": "1.0.0", "console": "1.0.0", "attacks": "1.0.0",
	}
}

func newBatchTestRepo(t *testing.T, versions map[string]string) *batchTestRepo {
	t.Helper()
	r := &batchTestRepo{t: t, root: t.TempDir()}
	r.releaseDir = filepath.Join(r.root, "release")
	if err := os.MkdirAll(r.releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r.writeVersions(versions)
	envDir := filepath.Join(r.root, "deploy", "environments", ReleaseEnvironment)
	if err := os.MkdirAll(envDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range Components {
		if seen[c.Deploy.File] {
			continue
		}
		seen[c.Deploy.File] = true
		if err := os.WriteFile(filepath.Join(envDir, c.Deploy.File+".yaml"), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r.git("init", "-q", "-b", "main")
	r.source = r.commit("prepare release")
	return r
}

func (r *batchTestRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.root
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *batchTestRepo) commit(message string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", message)
	return r.git("rev-parse", "HEAD")
}

func (r *batchTestRepo) writeVersions(versions map[string]string) {
	r.t.Helper()
	raw, err := json.MarshalIndent(versions, "", "  ")
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.releaseDir, VersionsFile), append(raw, '\n'), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *batchTestRepo) ensureBatch() *Batch {
	r.t.Helper()
	batch, _, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment)
	if err != nil {
		r.t.Fatal(err)
	}
	return batch
}

func (r *batchTestRepo) record(component, version, digestByte string) {
	r.t.Helper()
	batch, err := readBatch(r.releaseDir)
	if err != nil {
		r.t.Fatal(err)
	}
	r.git("tag", component+"-v"+version, batch.Source)
	err = RecordRelease(r.root, r.releaseDir, "HEAD", ReleaseEnvironment, component,
		"registry.example/phorvex/"+component, version, "sha256:"+strings.Repeat(digestByte, 64), batch.Source)
	if err != nil {
		r.t.Fatal(err)
	}
}

func pendingNames(pending []Pending) []string {
	names := make([]string, 0, len(pending))
	for _, release := range pending {
		names = append(names, release.Component)
	}
	return names
}

func TestPartialReleaseRetryKeepsThePreparedSource(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	batchA := r.ensureBatch()
	if batchA.Source != r.source {
		t.Fatalf("batch source = %s, want prepared SHA A %s", batchA.Source, r.source)
	}
	r.commit("pin SHA A")
	r.record("manager", "1.0.0", "a")
	recordHead := r.commit("record manager success")
	if err := os.WriteFile(filepath.Join(r.root, "main-advance"), []byte("SHA B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shaB := r.commit("advance main to SHA B")
	if shaB == batchA.Source || recordHead == batchA.Source {
		t.Fatal("record/main advance did not move beyond SHA A")
	}

	for _, retry := range []string{"workflow rerun", "manual dispatch"} {
		t.Run(retry, func(t *testing.T) {
			batch, err := LoadBatch(r.root, r.releaseDir, "HEAD", true)
			if err != nil {
				t.Fatal(err)
			}
			if batch.Source != r.source {
				t.Fatalf("retry recovered %s, want SHA A %s", batch.Source, r.source)
			}
			pending, err := PendingReleases(r.root, r.releaseDir, "HEAD")
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"brain", "sensor", "actuator", "console", "attacks"}
			if got := pendingNames(pending); !slices.Equal(got, want) {
				t.Fatalf("pending = %v, want %v", got, want)
			}
		})
	}
}

func TestBatchRejectsMissingMalformedAndMismatchedPins(t *testing.T) {
	t.Run("missing after partial publication", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.ensureBatch()
		r.commit("pin batch")
		r.record("manager", "1.0.0", "a")
		r.commit("record manager")
		if err := os.Remove(filepath.Join(r.releaseDir, BatchFile)); err != nil {
			t.Fatal(err)
		}
		r.commit("tamper away source pin")
		if _, _, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment); err == nil || !strings.Contains(err.Error(), "partially tagged") {
			t.Fatalf("missing pin error = %v", err)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.ensureBatch()
		r.commit("pin batch")
		if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), []byte("{\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r.commit("malform pin")
		if _, err := LoadBatch(r.root, r.releaseDir, "HEAD", true); err == nil {
			t.Fatal("malformed batch pin was accepted")
		}
	})

	t.Run("source ref and prepared source mismatch", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		batch := r.ensureBatch()
		r.commit("pin batch")
		batch.Source = strings.Repeat("a", 40)
		if err := writeBatch(r.releaseDir, batch); err != nil {
			t.Fatal(err)
		}
		r.commit("tamper source")
		if _, err := LoadBatch(r.root, r.releaseDir, "HEAD", true); err == nil || !strings.Contains(err.Error(), "does not resolve") {
			t.Fatalf("unresolved source error = %v", err)
		}
	})

	t.Run("valid but wrong source commit", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.ensureBatch()
		r.commit("pin batch")
		if err := os.WriteFile(filepath.Join(r.root, "advance"), []byte("B\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		shaB := r.commit("advance without changing versions")
		batch, err := readBatch(r.releaseDir)
		if err != nil {
			t.Fatal(err)
		}
		batch.Source = shaB
		if err := writeBatch(r.releaseDir, batch); err != nil {
			t.Fatal(err)
		}
		r.commit("point record at SHA B")
		if _, err := LoadBatch(r.root, r.releaseDir, "HEAD", true); err == nil || !strings.Contains(err.Error(), "did not introduce") {
			t.Fatalf("wrong prepared source error = %v", err)
		}
	})
}

func TestBatchRejectsMixedTagsDigestsAndRecordSource(t *testing.T) {
	t.Run("mixed tag provenance", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.ensureBatch()
		r.commit("pin batch")
		r.record("manager", "1.0.0", "a")
		r.commit("record manager")
		if err := os.WriteFile(filepath.Join(r.root, "advance"), []byte("B\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		shaB := r.commit("advance")
		r.git("tag", "brain-v1.0.0", shaB)
		if _, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err == nil || !strings.Contains(err.Error(), "batch source") {
			t.Fatalf("mixed tag error = %v", err)
		}
	})

	t.Run("mixed digest pin", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.ensureBatch()
		r.commit("pin batch")
		r.record("manager", "1.0.0", "a")
		r.commit("record manager")
		if err := Deploy(r.root, ReleaseEnvironment, "manager", "registry.example/phorvex/manager", "1.0.0", "sha256:"+strings.Repeat("b", 64), r.source); err != nil {
			t.Fatal(err)
		}
		r.commit("tamper digest")
		if _, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("mixed digest error = %v", err)
		}
	})

	t.Run("record source mismatch", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.ensureBatch()
		r.commit("pin batch")
		r.git("tag", "manager-v1.0.0", r.source)
		err := RecordRelease(r.root, r.releaseDir, "HEAD", ReleaseEnvironment, "manager", "registry.example/phorvex/manager",
			"1.0.0", "sha256:"+strings.Repeat("a", 64), strings.Repeat("b", 40))
		if err == nil || !strings.Contains(err.Error(), "does not match batch source") {
			t.Fatalf("record mismatch error = %v", err)
		}
	})
}

func TestBatchCreationIsIdempotentAndRejectsConcurrentNextBatch(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	first := r.ensureBatch()
	r.commit("pin batch")
	second, changed, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment)
	if err != nil || changed || second.Source != first.Source {
		t.Fatalf("same batch retry = source %v changed %v err %v", second, changed, err)
	}
	r.record("manager", "1.0.0", "a")
	r.commit("partial manager")
	next := batchVersions()
	next["manager"] = "1.0.1"
	r.writeVersions(next)
	r.commit("concurrent next batch")
	if _, _, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment); err == nil || !strings.Contains(err.Error(), "refusing concurrent batch creation") {
		t.Fatalf("concurrent batch error = %v", err)
	}
}

func TestCompleteBatchAndTerminalNextBatch(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	r.ensureBatch()
	r.commit("pin batch")
	for i, c := range Components {
		r.record(c.Name, "1.0.0", string(rune('a'+i)))
	}
	r.commit("record full batch")
	batch, err := LoadBatch(r.root, r.releaseDir, "HEAD", true)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Status != "complete" || len(batch.Releases) != len(Components) {
		t.Fatalf("complete batch = %#v", batch)
	}
	if pending, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err != nil || len(pending) != 0 {
		t.Fatalf("pending after full batch = %v, %v", pending, err)
	}

	next := batchVersions()
	for name := range next {
		next[name] = "1.0.1"
	}
	r.writeVersions(next)
	shaB := r.commit("prepare next terminal batch")
	nextBatch, changed, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment)
	if err != nil || !changed || nextBatch.Source != shaB || nextBatch.Status != "prepared" || len(nextBatch.Releases) != 0 {
		t.Fatalf("next batch = %#v changed=%v err=%v", nextBatch, changed, err)
	}
}

func TestLegacyCompleteBatchImportsOnlyUnanimousProvenance(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	for i, c := range Components {
		r.git("tag", c.Name+"-v1.0.0", r.source)
		if err := Deploy(r.root, ReleaseEnvironment, c.Name, "registry.example/phorvex/"+c.Name, "1.0.0",
			"sha256:"+strings.Repeat(string(rune('a'+i)), 64), r.source); err != nil {
			t.Fatal(err)
		}
	}
	r.commit("legacy complete pins")
	batch, changed, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment)
	if err != nil || !changed || batch.Status != "complete" || batch.Source != r.source {
		t.Fatalf("legacy import = %#v changed=%v err=%v", batch, changed, err)
	}
}

func TestBatchCommandsRejectDirtyLocalSource(t *testing.T) {
	t.Run("untracked before source pin", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		if err := os.WriteFile(filepath.Join(r.root, "untracked"), []byte("dirty\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := EnsureBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment); err == nil || !strings.Contains(err.Error(), "dirty") {
			t.Fatalf("dirty ensure error = %v", err)
		}
	})

	t.Run("tracked before retry", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.ensureBatch()
		r.commit("pin batch")
		if err := os.WriteFile(filepath.Join(r.releaseDir, VersionsFile), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err == nil || !strings.Contains(err.Error(), "dirty") {
			t.Fatalf("dirty pending error = %v", err)
		}
	})
}
