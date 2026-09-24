package console

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func profileDigest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func TestReviewedNamedProfileRequiresBoundedRegularExactBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.yaml")
	raw := []byte("context: reviewed-cluster\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPinnedNamedProfile(path, profileDigest(raw)); err != nil || string(got) != string(raw) {
		t.Fatalf("regular exact profile refused: %q %v", got, err)
	}
	for _, bad := range []string{"", strings.Repeat("A", 64), strings.Repeat("0", 64)} {
		if _, err := readPinnedNamedProfile(path, bad); err == nil {
			t.Fatalf("unreviewed hash accepted: %q", bad)
		}
	}
	if _, err := readPinnedNamedProfile(filepath.Join(dir, "missing"), profileDigest(raw)); err == nil {
		t.Fatal("missing profile accepted")
	}
	if _, err := readPinnedNamedProfile(dir, profileDigest(raw)); err == nil {
		t.Fatal("directory accepted as profile")
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinnedNamedProfile(link, profileDigest(raw)); err == nil {
		t.Fatal("symlink accepted as profile")
	}
	large := make([]byte, namedProfileMaxBytes+1)
	if err := os.WriteFile(path, large, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinnedNamedProfile(path, profileDigest(large)); err == nil {
		t.Fatal("oversized profile accepted")
	}
}

func TestGuardrailStaticProfileMountAdmissionAndLaunchByteBinding(t *testing.T) {
	dir := t.TempDir()
	raw := pinnedStaticProfile(t)
	path := filepath.Join(dir, allowedConfigs[guardrailStaticConfig].File)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: filepath.Join(dir, "state"), HarnessDir: dir, GuardrailStaticProfileSHA256: profileDigest(raw)}
	rm := &RunManager{cfg: cfg}
	if _, err := rm.SuiteDestination(guardrailStaticConfig); err == nil {
		t.Fatal("default-off static profile admitted")
	}
	if item := cfg.guardrailStaticCatalogueItem(); item.Available {
		t.Fatal("default-off static profile advertised as available")
	}
	rm.cfg.GuardrailStaticEnabled = true
	if dest, err := rm.SuiteDestination(guardrailStaticConfig); err != nil || dest.ScopeTarget != "reviewed-cluster" {
		t.Fatalf("reviewed static profile refused: %+v %v", dest, err)
	}
	if item := rm.cfg.guardrailStaticCatalogueItem(); !item.Available || item.RuntimeContext != "reviewed-cluster" {
		t.Fatalf("reviewed static profile not advertised correctly: %+v", item)
	}
	old, _ := rm.SuiteDestination(guardrailStaticConfig)
	if err := os.MkdirAll(filepath.Join(rm.cfg.runsDir(), "configs"), 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := rm.prepareSuite("run-1", allowedConfigs[guardrailStaticConfig], old.SuiteSHA256)
	if err != nil || prepared.Namespace != "vllm" {
		t.Fatalf("same authorized bytes were not prepared: %+v %v", prepared, err)
	}
	if _, err := os.Stat(prepared.File); err != nil {
		t.Fatalf("prepared run-private config missing: %v", err)
	}
	changed := []byte(strings.Replace(string(raw), "reviewed-cluster", "another-cluster", 1))
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.SuiteDestination(guardrailStaticConfig); err == nil {
		t.Fatal("post-admission profile hash drift accepted")
	}
	if item := rm.cfg.guardrailStaticCatalogueItem(); item.Available {
		t.Fatal("changed static profile advertised as available")
	}
	rm.cfg.GuardrailStaticProfileSHA256 = profileDigest(changed)
	if _, err := rm.prepareSuite("run-2", allowedConfigs[guardrailStaticConfig], old.SuiteSHA256); err == nil || !strings.Contains(err.Error(), "authorized suite bytes changed before launch") {
		t.Fatalf("authorized SuiteSHA256 drift did not reach exact launch barrier: %v", err)
	}
	placeholder := []byte(strings.Replace(string(raw), "reviewed-cluster", "__SET_LOGICAL_CLUSTER_TARGET__", 1))
	if err := os.WriteFile(path, placeholder, 0600); err != nil {
		t.Fatal(err)
	}
	rm.cfg.GuardrailStaticProfileSHA256 = profileDigest(placeholder)
	if _, err := rm.SuiteDestination(guardrailStaticConfig); err == nil {
		t.Fatal("placeholder profile accepted despite matching owner hash")
	}
}

func TestNATSProfileMountAdmissionAndLaunchByteBinding(t *testing.T) {
	for _, tc := range []struct {
		name, filename string
		response       bool
	}{
		{natsBaselineConfig, "config.nats-exposure-baseline.yaml", false},
		{natsResponseConfig, "config.nats-client-response.yaml", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			shipped, err := os.ReadFile(filepath.Join("../../../build/test-harness", tc.filename))
			if err != nil {
				t.Fatal(err)
			}
			raw := strings.ReplaceAll(string(shipped), "__SET_LOGICAL_CLUSTER_TARGET__", "reviewed-cluster")
			for pin, value := range map[string]string{
				"REVIEWED_KUBE_SYSTEM_UID":         "00000000-0000-4000-8000-000000000001",
				"REVIEWED_NATS_CONFIG_SHA256":      strings.Repeat("a", 64),
				"REVIEWED_HEALTHY_NODE_NAME":       "reviewed-node-1",
				"INSTALLED_CONSOLE_IMAGE_DIGEST":   "registry.example/console@sha256:" + strings.Repeat("b", 64),
				"REVIEWED_NATS_IMAGE_ID_DIGEST":    "docker-pullable://nats@sha256:" + strings.Repeat("c", 64),
				"REVIEWED_MANAGER_IMAGE_ID_DIGEST": "docker-pullable://phorvex@sha256:" + strings.Repeat("d", 64),
			} {
				raw = strings.ReplaceAll(raw, "__SET_"+pin+"__", value)
			}
			path := filepath.Join(dir, tc.filename)
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := Config{HarnessDir: dir, StateDir: filepath.Join(dir, "state")}
			setHash := func(raw []byte) {
				if tc.response {
					cfg.NATSClientResponseProfileSHA256 = profileDigest(raw)
				} else {
					cfg.NATSExposureProfileSHA256 = profileDigest(raw)
				}
			}
			setHash([]byte(raw))
			rm := &RunManager{cfg: cfg}
			if _, err := rm.SuiteDestination(tc.name); err == nil {
				t.Fatal("default-off NATS suite admitted")
			}
			if tc.response {
				rm.cfg.NATSClientResponseEnabled = true
			}
			if _, err := rm.SuiteDestination(tc.name); err == nil {
				t.Fatal("response admitted without baseline enable")
			}
			rm.cfg.NATSExposureEnabled = true
			if tc.response {
				rm.cfg.NATSClientResponseEnabled = true
			}
			dest, err := rm.SuiteDestination(tc.name)
			if err != nil || dest.ScopeTarget != "reviewed-cluster" || dest.SuiteSHA256 != profileDigest([]byte(raw)) {
				t.Fatalf("reviewed NATS profile refused: %+v %v", dest, err)
			}
			if err := os.MkdirAll(filepath.Join(rm.cfg.runsDir(), "configs"), 0700); err != nil {
				t.Fatal(err)
			}
			prepared, err := rm.prepareSuite("run-1", allowedConfigs[tc.name], dest.SuiteSHA256)
			if err != nil || prepared.Namespace != natsFixtureNamespace {
				t.Fatalf("same authorized bytes not prepared: %+v %v", prepared, err)
			}
			changed := []byte(strings.Replace(raw, "reviewed-cluster", "other-cluster", 1))
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := rm.SuiteDestination(tc.name); err == nil {
				t.Fatal("profile hash drift accepted")
			}
			if tc.response {
				rm.cfg.NATSClientResponseProfileSHA256 = profileDigest(changed)
			} else {
				rm.cfg.NATSExposureProfileSHA256 = profileDigest(changed)
			}
			if _, err := rm.prepareSuite("run-2", allowedConfigs[tc.name], dest.SuiteSHA256); err == nil || !strings.Contains(err.Error(), "authorized suite bytes changed before launch") {
				t.Fatalf("authorized byte barrier absent: %v", err)
			}
			placeholder := []byte(strings.Replace(raw, "reviewed-cluster", "__SET_LOGICAL_CLUSTER_TARGET__", 1))
			if err := os.WriteFile(path, placeholder, 0600); err != nil {
				t.Fatal(err)
			}
			if tc.response {
				rm.cfg.NATSClientResponseProfileSHA256 = profileDigest(placeholder)
			} else {
				rm.cfg.NATSExposureProfileSHA256 = profileDigest(placeholder)
			}
			if _, err := rm.SuiteDestination(tc.name); err == nil {
				t.Fatal("matching-hash placeholder admitted")
			}
		})
	}
}
