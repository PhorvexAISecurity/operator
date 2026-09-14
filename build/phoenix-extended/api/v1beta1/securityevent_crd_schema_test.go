/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package v1beta1

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// V3-M164 regression: the SecurityEvent CRD shipped by the Phoenix chart (and its
// vendored copy in the phorvex-stack umbrella) must be the canonical generated
// schema. The chart copy used to lack spec.anomalyScore/metrics/evidence, so an
// API server installed from it PRUNED the fields the detector integrators write;
// their strict delivery proof then reports every such delivery as a conflict.
// Schema parity is what makes "stored == delivered" possible on the shipped path.

const (
	generatedCRD = "../../config/crd/bases/amtd.r6security.com_securityevents.yaml"
	chartCRD     = "../../charts/phoenix/templates/crds/securityevents_crd.yaml"
	vendoredTGZ  = "../../../../deploy/helm/phorvex-stack/charts/phoenix-0.1.4.tgz"
	vendoredCRD  = "phoenix/templates/crds/securityevents_crd.yaml"
)

// emitterSpecFields are the optional spec members written by the Falco/Prometheus
// integrators and the drift detector; the shipped schema must declare them.
var emitterSpecFields = []string{"anomalyScore", "metrics", "evidence"}

func readFile(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return data
}

func TestSecurityEventChartCRDMatchesGeneratedSchema(t *testing.T) {
	generated := readFile(t, generatedCRD)
	chart := readFile(t, chartCRD)
	if !bytes.Equal(generated, chart) {
		t.Fatalf("%s differs from %s: copy the generated CRD into the chart and repack the vendored archive (helm package charts/phoenix -d deploy/helm/phorvex-stack/charts/)", chartCRD, generatedCRD)
	}
	assertEmitterFieldsDeclared(t, chartCRD, chart)
}

func TestSecurityEventVendoredChartCRDMatchesSource(t *testing.T) {
	chart := readFile(t, chartCRD)
	vendored := extractFromTGZ(t, vendoredTGZ, vendoredCRD)
	if !bytes.Equal(chart, vendored) {
		t.Fatalf("%s inside %s differs from %s: repack with helm package charts/phoenix -d deploy/helm/phorvex-stack/charts/", vendoredCRD, vendoredTGZ, chartCRD)
	}
	assertEmitterFieldsDeclared(t, vendoredTGZ, vendored)
}

// assertEmitterFieldsDeclared parses the CRD and requires every emitter field
// under spec.versions[v1beta1].schema.openAPIV3Schema.properties.spec.properties.
func assertEmitterFieldsDeclared(t *testing.T, origin string, raw []byte) {
	t.Helper()
	jsonBytes, err := yaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatalf("%s is not YAML: %v", origin, err)
	}
	var crd struct {
		Spec struct {
			Scope    string `json:"scope"`
			Versions []struct {
				Name   string `json:"name"`
				Schema struct {
					OpenAPIV3Schema struct {
						Properties map[string]struct {
							Properties map[string]json.RawMessage `json:"properties"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(jsonBytes, &crd); err != nil {
		t.Fatalf("%s: %v", origin, err)
	}
	if crd.Spec.Scope != "Cluster" {
		t.Fatalf("%s: SecurityEvent must stay Cluster scoped, got %q", origin, crd.Spec.Scope)
	}
	var specProps map[string]json.RawMessage
	for _, v := range crd.Spec.Versions {
		if v.Name == "v1beta1" {
			specProps = v.Schema.OpenAPIV3Schema.Properties["spec"].Properties
		}
	}
	if specProps == nil {
		t.Fatalf("%s: no v1beta1 spec schema", origin)
	}
	for _, field := range emitterSpecFields {
		if _, ok := specProps[field]; !ok {
			t.Errorf("%s: spec.%s is not declared; an API server using this schema prunes it", origin, field)
		}
	}
}

func extractFromTGZ(t *testing.T, archive, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Clean(archive))
	if err != nil {
		t.Fatalf("open %s: %v", archive, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip %s: %v", archive, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read %s: %v", archive, err)
		}
		if hdr.Name == name {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read %s from %s: %v", name, archive, err)
			}
			return data
		}
	}
	t.Fatalf("%s does not contain %s", archive, name)
	return nil
}
