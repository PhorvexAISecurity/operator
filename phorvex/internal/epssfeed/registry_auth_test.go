package epssfeed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testECR1 = "111111111111.dkr.ecr.us-east-1.amazonaws.com"
	testECR2 = "222222222222.dkr.ecr.us-west-2.amazonaws.com"
	testPass = "test-token-value-not-a-real-credential"
)

func authJSON(t *testing.T, hosts []string, now time.Time, mutate func(map[string]any)) []byte {
	t.Helper()
	auths, expiries := map[string]any{}, map[string]any{}
	for _, host := range hosts {
		auths[host] = map[string]any{"auth": base64.StdEncoding.EncodeToString([]byte("AWS:" + testPass))}
		expiries[host] = now.Add(time.Hour).UTC().Format(time.RFC3339)
	}
	value := map[string]any{
		"auths":     auths,
		"x-phorvex": map[string]any{"schemaVersion": RegistryAuthSchemaV1, "expiresAt": expiries},
	}
	if mutate != nil {
		mutate(value)
	}
	raw, err := jsonMarshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Kept tiny so the test's schema fixtures cannot accidentally use a custom
// encoder or bypass the same standard JSON surface consumed by production.
func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func writeAuthFile(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDockerConfigAuthExactHostsExpiryAndImmutableSnapshot(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	path := writeAuthFile(t, authJSON(t, []string{testECR1, testECR2}, now, nil))
	provider, err := LoadDockerConfigAuth(path, []string{testECR1, testECR2}, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dir, authenticated, err := provider.DockerConfigFor(testECR1+"/repo@sha256:"+strings.Repeat("a", 64), now, 10*time.Minute)
	if err != nil || !authenticated || dir != filepath.Dir(path) {
		t.Fatalf("matching auth = (%q,%t,%v)", dir, authenticated, err)
	}
	if dir, authenticated, err = provider.DockerConfigFor("docker.io/library/alpine@sha256:"+strings.Repeat("b", 64), now, 10*time.Minute); err != nil || authenticated || dir != "" {
		t.Fatalf("public auth = (%q,%t,%v)", dir, authenticated, err)
	}
	if _, _, err = provider.DockerConfigFor("333333333333.dkr.ecr.us-east-1.amazonaws.com/repo@sha256:"+strings.Repeat("c", 64), now, 10*time.Minute); err == nil {
		t.Fatal("foreign ECR host did not refuse")
	}
	if _, _, err = provider.DockerConfigFor(strings.ToUpper(testECR1)+"/repo@sha256:"+strings.Repeat("c", 64), now, 10*time.Minute); err == nil {
		t.Fatal("non-canonical ECR host did not refuse")
	}
	if _, _, err = provider.DockerConfigFor(testECR1+"/repo@sha256:"+strings.Repeat("c", 64), now.Add(51*time.Minute), 10*time.Minute); err == nil {
		t.Fatal("credential that cannot cover the scan horizon did not refuse")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = provider.DockerConfigFor(testECR1+"/repo@sha256:"+strings.Repeat("d", 64), now, 10*time.Minute); err == nil {
		t.Fatal("mutated snapshot did not refuse")
	}
}

func TestRegistryAuthConfigurationDefaultIsUnauthenticated(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	provider, err := LoadRegistryAuthConfiguration("", "", now, time.Minute)
	if err != nil || provider != nil {
		t.Fatalf("default registry auth = %+v, %v", provider, err)
	}
	for _, tc := range [][2]string{{"/secret/config.json", ""}, {"", testECR1}} {
		if _, err := LoadRegistryAuthConfiguration(tc[0], tc[1], now, time.Minute); err == nil {
			t.Fatal("half-configured registry authentication accepted")
		}
	}
}

func TestRegistryAuthConfigurationNilWiresScannerWithoutTypedNil(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	provider, err := LoadRegistryAuthConfiguration("", "", now, time.Minute)
	if err != nil || provider != nil {
		t.Fatalf("default registry auth = %#v, %v", provider, err)
	}
	public := writeScanner(t, `printf '{"Results":[]}'`)
	scanner := TrivyScanner{Path: public, CacheDir: t.TempDir(), Timeout: time.Minute, RegistryAuth: provider, Now: func() time.Time { return now }}
	if _, err := scanner.Scan(context.Background(), "docker.io/library/alpine@sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatalf("public default scan: %v", err)
	}
	scanner.Path = "/must/not/execute"
	if _, err := scanner.Scan(context.Background(), testECR1+"/repo@sha256:"+strings.Repeat("b", 64)); err == nil {
		t.Fatal("private default scan did not refuse before execution")
	}
}

func TestDockerConfigAuthProjectedSecretPinsVersion(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	mount := t.TempDir()
	version := "..2026_09_21_12_00_00.000000001"
	if err := os.Mkdir(filepath.Join(mount, version), 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(mount, version, "config.json")
	if err := os.WriteFile(config, authJSON(t, []string{testECR1}, now, nil), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(version, filepath.Join(mount, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "config.json"), filepath.Join(mount, "config.json")); err != nil {
		t.Fatal(err)
	}
	provider, err := LoadDockerConfigAuth(filepath.Join(mount, "config.json"), []string{testECR1}, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if provider.directory != filepath.Join(mount, version) {
		t.Fatalf("pinned directory = %q", provider.directory)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.DockerConfigFor(testECR1+"/r@sha256:"+strings.Repeat("a", 64), now, time.Minute); err == nil {
		t.Fatal("removed pinned version did not refuse")
	}
}

func TestDockerConfigAuthRejectsNonstandardProjectedSecretLinks(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	mount := t.TempDir()
	outside := writeAuthFile(t, authJSON(t, []string{testECR1}, now, nil))
	if err := os.Symlink(outside, filepath.Join(mount, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDockerConfigAuth(filepath.Join(mount, "config.json"), []string{testECR1}, now, time.Minute); err == nil {
		t.Fatal("arbitrary credential symlink accepted")
	}
}

func TestDockerConfigAuthRejectsMalformedStaleForeignAndUnsafeFiles(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		raw   []byte
		hosts []string
		mode  os.FileMode
	}{
		{name: "unknown top-level", raw: authJSON(t, []string{testECR1}, now, func(v map[string]any) { v["credsStore"] = "ambient" }), hosts: []string{testECR1}},
		{name: "host-set mismatch", raw: authJSON(t, []string{testECR1}, now, nil), hosts: []string{testECR1, testECR2}},
		{name: "foreign allowlist", raw: authJSON(t, []string{testECR1}, now, nil), hosts: []string{"registry.example"}},
		{name: "writable", raw: authJSON(t, []string{testECR1}, now, nil), hosts: []string{testECR1}, mode: 0o600},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeAuthFile(t, tc.raw)
			if tc.mode != 0 {
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadDockerConfigAuth(path, tc.hosts, now, 10*time.Minute); err == nil {
				t.Fatal("invalid registry authentication accepted")
			}
		})
	}

	t.Run("direct file wrong basename", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "credentials.json")
		if err := os.WriteFile(path, authJSON(t, []string{testECR1}, now, nil), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDockerConfigAuth(path, []string{testECR1}, now, time.Minute); err == nil {
			t.Fatal("validated a file Trivy would not read as config.json")
		}
	})

	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"top-level", `{"auths":{},"auths":{},"x-phorvex":{"schemaVersion":"phorvex.epss-registry-auth.v1","expiresAt":{}}}`},
		{"nested auth", `{"auths":{"` + testECR1 + `":{"auth":"QQ==","auth":"Qg=="}},"x-phorvex":{"schemaVersion":"phorvex.epss-registry-auth.v1","expiresAt":{"` + testECR1 + `":"2026-09-21T13:00:00Z"}}}`},
		{"nested expiry", `{"auths":{"` + testECR1 + `":{"auth":"QVdTOnRlc3Q="}},"x-phorvex":{"schemaVersion":"phorvex.epss-registry-auth.v1","expiresAt":{"` + testECR1 + `":"2026-09-21T13:00:00Z","` + testECR1 + `":"2026-09-21T14:00:00Z"}}}`},
	} {
		t.Run("duplicate "+tc.name, func(t *testing.T) {
			if _, err := LoadDockerConfigAuth(writeAuthFile(t, []byte(tc.raw)), []string{testECR1}, now, time.Minute); err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("duplicate JSON error = %v", err)
			}
		})
	}

	t.Run("stale member rejects whole set", func(t *testing.T) {
		raw := authJSON(t, []string{testECR1, testECR2}, now, func(v map[string]any) {
			v["x-phorvex"].(map[string]any)["expiresAt"].(map[string]any)[testECR2] = now.Add(time.Minute).Format(time.RFC3339)
		})
		if _, err := LoadDockerConfigAuth(writeAuthFile(t, raw), []string{testECR1, testECR2}, now, 10*time.Minute); err == nil {
			t.Fatal("stale required credential accepted")
		}
	})

	t.Run("control character", func(t *testing.T) {
		raw := authJSON(t, []string{testECR1}, now, func(v map[string]any) {
			v["auths"].(map[string]any)[testECR1] = map[string]any{"auth": base64.StdEncoding.EncodeToString([]byte("AWS:bad\nsecret"))}
		})
		if _, err := LoadDockerConfigAuth(writeAuthFile(t, raw), []string{testECR1}, now, time.Minute); err == nil {
			t.Fatal("control-bearing token accepted")
		}
	})
}

func writeScanner(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanner")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTrivyScannerUsesRemoteOnlyPinnedDockerConfigAndMinimalEnvironment(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	path := writeAuthFile(t, authJSON(t, []string{testECR1}, now, nil))
	provider, err := LoadDockerConfigAuth(path, []string{testECR1}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-must-not-pass")
	t.Setenv("TRIVY_USERNAME", "ambient-must-not-pass")
	t.Setenv("GITHUB_TOKEN", "ambient-must-not-pass")
	t.Setenv("DOCKER_CONFIG", "/ambient/must-not-pass")
	t.Setenv("DOCKER_AUTH_CONFIG", "ambient-must-not-pass")
	t.Setenv("REGISTRY_AUTH_FILE", "/ambient/must-not-pass")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/ambient")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/ambient/token")
	cacheDir := t.TempDir()
	staleWork := filepath.Join(cacheDir, "phorvex-work")
	if err := os.Mkdir(staleWork, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleWork, "trivy.yaml"), []byte("registry:\n  mirrors:\n    - ambient.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	private := writeScanner(t, `
case " $* " in *" --image-src remote "*) ;; *) exit 41;; esac
[ "${AWS_EC2_METADATA_DISABLED:-}" = true ] || exit 42
[ "${DOCKER_CONFIG:-}" != "" ] || exit 43
[ -f "$DOCKER_CONFIG/config.json" ] || exit 44
[ -z "${AWS_ACCESS_KEY_ID+x}" ] || exit 45
[ -z "${TRIVY_USERNAME+x}" ] || exit 46
[ -z "${GITHUB_TOKEN+x}" ] || exit 47
[ -z "${DOCKER_AUTH_CONFIG+x}" ] || exit 48
[ -z "${REGISTRY_AUTH_FILE+x}" ] || exit 49
[ -z "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI+x}" ] || exit 50
[ -z "${AWS_WEB_IDENTITY_TOKEN_FILE+x}" ] || exit 51
[ "$HOME" = "$PWD" ] || exit 52
[ "$XDG_CONFIG_HOME" = "$PWD" ] || exit 53
[ ! -e "$PWD/trivy.yaml" ] || exit 54
printf '{"Results":[]}'
`)
	scanner := TrivyScanner{Path: private, CacheDir: cacheDir, Timeout: time.Minute, RegistryAuth: provider, Now: func() time.Time { return now }}
	if got, err := scanner.Scan(context.Background(), testECR1+"/repo@sha256:"+strings.Repeat("a", 64)); err != nil || len(got) != 0 {
		t.Fatalf("private scan = %v, %v", got, err)
	}

	public := writeScanner(t, `
[ -z "${DOCKER_CONFIG+x}" ] || exit 51
[ -z "${AWS_ACCESS_KEY_ID+x}" ] || exit 52
printf '{"Results":[]}'
`)
	scanner.Path = public
	if _, err := scanner.Scan(context.Background(), "docker.io/library/alpine@sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatalf("public scan: %v", err)
	}
}

func TestTrivyScannerAuthenticatedFailureNeverExposesCredential(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	provider, err := LoadDockerConfigAuth(writeAuthFile(t, authJSON(t, []string{testECR1}, now, nil)), []string{testECR1}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	script := writeScanner(t, fmt.Sprintf("printf 'failure %s %s' >&2\nexit 9\n", testPass, base64.StdEncoding.EncodeToString([]byte("AWS:"+testPass))))
	scanner := TrivyScanner{Path: script, CacheDir: t.TempDir(), Timeout: time.Minute, RegistryAuth: provider, Now: func() time.Time { return now }}
	_, err = scanner.Scan(context.Background(), testECR1+"/repo@sha256:"+strings.Repeat("a", 64))
	if err == nil || strings.Contains(err.Error(), testPass) || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString([]byte("AWS:"+testPass))) {
		t.Fatalf("authenticated failure was not generic: %v", err)
	}
}

func TestTrivyScannerAuthenticatedMalformedSuccessIsGeneric(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	provider, err := LoadDockerConfigAuth(writeAuthFile(t, authJSON(t, []string{testECR1}, now, nil)), []string{testECR1}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	script := writeScanner(t, fmt.Sprintf("printf 'not-json-%s'\n", testPass))
	scanner := TrivyScanner{Path: script, CacheDir: t.TempDir(), Timeout: time.Minute, RegistryAuth: provider, Now: func() time.Time { return now }}
	_, err = scanner.Scan(context.Background(), testECR1+"/repo@sha256:"+strings.Repeat("a", 64))
	if err == nil || strings.Contains(err.Error(), testPass) || !strings.Contains(err.Error(), "invalid report") {
		t.Fatalf("authenticated malformed report error = %v", err)
	}
}

func TestTrivyScannerRefusesPrivateECRWithoutProvider(t *testing.T) {
	scanner := TrivyScanner{Path: "/does/not/run", CacheDir: t.TempDir(), Timeout: time.Minute}
	if _, err := scanner.Scan(context.Background(), testECR1+"/repo@sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Fatal("private ECR scan fell back without configured credentials")
	}
}

func TestRegistryAuthenticatedScansRequireCompleteSetBeforeApply(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	image1 := testECR1 + "/repo@sha256:" + strings.Repeat("a", 64)
	image2 := testECR2 + "/repo@sha256:" + strings.Repeat("b", 64)
	report := `printf '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","CVSS":{"nvd":{"V3Score":8}}}]}]}'`
	script := writeScanner(t, report)
	run := func(t *testing.T, hosts []string) (Result, error, *corev1.ConfigMap) {
		t.Helper()
		provider, err := LoadDockerConfigAuth(writeAuthFile(t, authJSON(t, hosts, now, nil)), hosts, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		client := fake.NewSimpleClientset(
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cache", Namespace: "ns"}, Data: map[string]string{"cache.json": `{}`}},
			runningPod("one", image1), runningPod("two", image2),
		)
		result, runErr := Run(context.Background(), Options{
			Client:  client,
			Scanner: &TrivyScanner{Path: script, CacheDir: t.TempDir(), Timeout: time.Minute, RegistryAuth: provider, Now: func() time.Time { return now }},
			EPSS:    fakeEPSS{"CVE-2026-0001": .4}, Namespace: "ns", ConfigMapName: "cache", ConfigMapKey: "cache.json", Apply: true, Now: func() time.Time { return now },
		})
		cm, getErr := client.CoreV1().ConfigMaps("ns").Get(context.Background(), "cache", metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		return result, runErr, cm
	}

	t.Run("complete exact set applies", func(t *testing.T) {
		result, err, cm := run(t, []string{testECR1, testECR2})
		if err != nil || result.Mode != "applied" || result.ScannedImages != 2 || result.FailedImages != 0 || cm.Data["cache.json"] == `{}` {
			t.Fatalf("complete apply result=%+v err=%v cache=%s", result, err, cm.Data["cache.json"])
		}
	})

	t.Run("missing foreign host refuses apply", func(t *testing.T) {
		result, err, cm := run(t, []string{testECR1})
		if err == nil || result.Mode != "rejected-partial" || result.ScannedImages != 1 || result.FailedImages != 1 || cm.Data["cache.json"] != `{}` {
			t.Fatalf("incomplete apply result=%+v err=%v cache=%s", result, err, cm.Data["cache.json"])
		}
	})
}

func TestBoundedScannerOutputNeverGrowsPastLimit(t *testing.T) {
	b := boundedOutput{limit: 4}
	if n, err := b.Write([]byte("123456")); err != nil || n != 6 || !b.overflow || b.String() != "1234" {
		t.Fatalf("bounded write = n=%d err=%v overflow=%t body=%q", n, err, b.overflow, b.String())
	}
	if n, err := b.Write([]byte("789")); err != nil || n != 3 || b.String() != "1234" {
		t.Fatalf("discard after bound = n=%d err=%v body=%q", n, err, b.String())
	}
}
