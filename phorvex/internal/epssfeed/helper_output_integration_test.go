package epssfeed

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// CI supplies the compiled standalone helper TEST binary, then executes this
// compiled suite as UID/GID 65532. No loader implementation is copied or changed.
func TestHelperOutputWithUnchangedLoader(t *testing.T) {
	binary := os.Getenv("EPSS_AUTH_TEST_BINARY")
	if binary == "" {
		t.Skip("requires CI's standalone helper test binary and UID fixture")
	}
	if os.Getuid() != 65532 || os.Getgid() != 65532 {
		t.Fatal("integration requires UID/GID 65532")
	}
	dir := t.TempDir()
	cmd := exec.Command(binary, "-test.run=^TestEmitLoaderFixture$")
	cmd.Env = append(os.Environ(), "EPSS_AUTH_TEST_DIRECTORY="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper fixture failed: %v %s", err, out)
	}
	path := filepath.Join(dir, "config.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Sys().(*syscall.Stat_t).Uid != 65532 {
		t.Fatal("real helper output violates mode/owner/name contract")
	}
	hosts := []string{"753556437180.dkr.ecr.us-east-2.amazonaws.com", "602401143452.dkr.ecr.us-east-2.amazonaws.com"}
	now := time.Now().UTC()
	horizon := 4200 * time.Second
	auth, err := LoadDockerConfigAuth(path, hosts, now, horizon)
	if err != nil {
		t.Fatalf("unchanged loader rejected helper output: %v", err)
	}
	for _, host := range hosts {
		directory, authenticated, err := auth.DockerConfigFor(host+"/allowed@sha256:"+strings.Repeat("a", 64), now, 10*time.Minute)
		if err != nil || !authenticated || directory != dir {
			t.Fatal("loader did not authenticate exact registry")
		}
	}
	if _, _, err := auth.DockerConfigFor("111111111111.dkr.ecr.us-east-2.amazonaws.com/foreign:tag", now, time.Minute); err == nil {
		t.Fatal("foreign image host accepted")
	}
	for _, mode := range []os.FileMode{0o600, 0o460} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDockerConfigAuth(path, hosts, now, horizon); err == nil {
			t.Fatal("writable config accepted")
		}
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDockerConfigAuth(path, hosts, now, horizon); err != nil {
		t.Fatal("permitted group read rejected")
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(dir, "wrong.json")
	if err := os.Rename(path, wrong); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDockerConfigAuth(wrong, hosts, now, horizon); err == nil {
		t.Fatal("wrong filename accepted")
	}
	if err := os.Rename(wrong, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config dockerAuthFile
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	foreign := "111111111111.dkr.ecr.us-east-2.amazonaws.com"
	config.Auths[foreign] = config.Auths[hosts[0]]
	config.Phorvex.ExpiresAt[foreign] = config.Phorvex.ExpiresAt[hosts[0]]
	delete(config.Auths, hosts[0])
	delete(config.Phorvex.ExpiresAt, hosts[0])
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDockerConfigAuth(path, hosts, now, horizon); err == nil {
		t.Fatal("foreign config host accepted")
	}
}
