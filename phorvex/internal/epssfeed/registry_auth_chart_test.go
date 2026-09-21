package epssfeed

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	kyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func registryAuthHelm(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	helm := os.Getenv("HELM_BIN")
	if helm == "" {
		var err error
		helm, err = exec.LookPath("helm")
		if err != nil {
			t.Skip("helm binary unavailable; final preflight must execute this chart contract")
		}
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate chart")
	}
	chart := filepath.Join(filepath.Dir(file), "..", "..", "charts", "phorvex")
	args := []string{"template", "auth-test", chart,
		"--set", "phorvex.epss.enabled=true", "--set", "phorvex.epss.feed.enabled=true"}
	for _, set := range sets {
		args = append(args, "--set-string", set)
	}
	cmd := exec.Command(helm, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String() + "\n" + stderr.String(), err
	}
	return stdout.String(), nil
}

func renderedObjectsOfKind(t *testing.T, rendered, kind string) []string {
	t.Helper()
	decoder := kyaml.NewYAMLOrJSONDecoder(strings.NewReader(rendered), 4096)
	var names []string
	for {
		var object struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		err := decoder.Decode(&object)
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("decode Helm stdout: %v", err)
		}
		if object.Kind == kind {
			names = append(names, object.Metadata.Name)
		}
	}
}

func TestRegistryAuthChartDefaultsToNoCredentialMount(t *testing.T) {
	out, err := registryAuthHelm(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, forbidden := range []string{"--epss-feed-registry-auth-file", "--epss-feed-registry-auth-registries", "name: registry-auth"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("default chart exposed registry auth %q", forbidden)
		}
	}
}

func TestRegistryAuthChartOptInProjectsExactSecretAndHosts(t *testing.T) {
	baseline, err := registryAuthHelm(t)
	if err != nil {
		t.Fatalf("helm template baseline: %v\n%s", err, baseline)
	}
	out, err := registryAuthHelm(t,
		"phorvex.epss.feed.registryAuth.enabled=true",
		"phorvex.epss.feed.registryAuth.secretName=feed-auth",
		"phorvex.epss.feed.registryAuth.secretKey=docker-config.json",
		"phorvex.epss.feed.registryAuth.registries[0]="+testECR1,
		"phorvex.epss.feed.registryAuth.registries[1]="+testECR2,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, required := range []string{
		"--epss-feed-registry-auth-file=/var/run/secrets/phorvex-epss-registry-auth/config.json",
		"--epss-feed-registry-auth-registries=" + testECR1 + "," + testECR2,
		`secretName: "feed-auth"`, `key: "docker-config.json"`, "path: config.json", "defaultMode: 0440",
		"mountPath: /var/run/secrets/phorvex-epss-registry-auth", "readOnly: true",
	} {
		if !strings.Contains(out, required) {
			t.Errorf("enabled chart missing %q", required)
		}
	}
	if strings.Contains(out, "AWS_ACCESS_KEY") || strings.Contains(out, "TRIVY_PASSWORD") {
		t.Fatal("chart generated or exposed credential material")
	}
	if before, after := renderedObjectsOfKind(t, baseline, "Secret"), renderedObjectsOfKind(t, out, "Secret"); !reflect.DeepEqual(before, after) {
		t.Fatalf("registry auth opt-in generated or changed Secret objects: before=%v after=%v", before, after)
	}
}

func TestRegistryAuthChartRejectsIncompleteOptIn(t *testing.T) {
	for _, sets := range [][]string{
		{"phorvex.epss.feed.registryAuth.enabled=true"},
		{"phorvex.epss.feed.registryAuth.enabled=true", "phorvex.epss.feed.registryAuth.secretName=feed-auth"},
		{"phorvex.epss.feed.registryAuth.secretName=feed-auth"},
	} {
		out, err := registryAuthHelm(t, sets...)
		if err == nil || !strings.Contains(out, "registry authentication") {
			t.Fatalf("incomplete registry auth rendered: err=%v output=%s", err, out)
		}
	}
}
