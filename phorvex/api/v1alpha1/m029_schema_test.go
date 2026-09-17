package v1alpha1_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"

	"sigs.k8s.io/yaml"
)

func m029PackagedCRD(t *testing.T, archive string) []byte {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == "phorvex/crds/phorvex.ai_phorvexpolicies.yaml" {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
	t.Fatal("packaged PhorvexPolicy CRD missing")
	return nil
}

func m029Map(t *testing.T, value any, key string) map[string]any {
	t.Helper()
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", key, value)
	}
	next, ok := m[key]
	if !ok {
		t.Fatalf("object missing %s", key)
	}
	out, ok := next.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", key, next)
	}
	return out
}

func m029CRDProperty(t *testing.T, data []byte, property string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	spec := m029Map(t, root, "spec")
	versions, ok := spec["versions"].([]any)
	if !ok || len(versions) != 1 {
		t.Fatalf("versions=%T/%d, want one", spec["versions"], len(versions))
	}
	version, ok := versions[0].(map[string]any)
	if !ok {
		t.Fatalf("version is %T", versions[0])
	}
	schema := m029Map(t, version, "schema")
	openapi := m029Map(t, schema, "openAPIV3Schema")
	rootProperties := m029Map(t, openapi, "properties")
	policySpec := m029Map(t, rootProperties, "spec")
	specProperties := m029Map(t, policySpec, "properties")
	return m029Map(t, specProperties, property)
}

func TestM029EventAgeHorizonSchemaChartAndPackageStayIdentical(t *testing.T) {
	source, err := os.ReadFile("../../config/crd/bases/phorvex.ai_phorvexpolicies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	chart, err := os.ReadFile("../../charts/phorvex/crds/phorvex.ai_phorvexpolicies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	packaged := m029PackagedCRD(t, "../../../deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz")
	if !bytes.Equal(source, chart) || !bytes.Equal(chart, packaged) {
		t.Fatal("source, chart, and packaged PhorvexPolicy CRDs differ")
	}

	triggers := m029CRDProperty(t, source, "triggers")
	triggerProperties := m029Map(t, triggers, "properties")
	horizon := m029Map(t, triggerProperties, "eventAgeHorizon")
	if horizon["type"] != "string" || horizon["default"] != "1h" {
		t.Fatalf("eventAgeHorizon schema type/default=%v/%v", horizon["type"], horizon["default"])
	}
	validations, ok := horizon["x-kubernetes-validations"].([]any)
	if !ok || len(validations) != 2 {
		t.Fatalf("eventAgeHorizon validations=%T/%d, want two", horizon["x-kubernetes-validations"], len(validations))
	}

	trust := m029CRDProperty(t, source, "trust")
	trustProperties := m029Map(t, trust, "properties")
	peers := m029Map(t, trustProperties, "peerPolicies")
	items := m029Map(t, peers, "items")
	if items["minLength"] != float64(1) {
		t.Fatalf("peerPolicies nonempty validation lost: %+v", items)
	}
}
