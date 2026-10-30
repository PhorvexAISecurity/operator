package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const deploymentManifest = "deploy/argocd/services/applicationset.yaml"

var renderAPIVersions = []string{
	"monitoring.coreos.com/v1/PodMonitor",
	"monitoring.coreos.com/v1/PrometheusRule",
}

// FileDigest binds one render input to the exact source-batch contents. The
// release values file is canonicalized with only its release fields redacted,
// so recording an earlier component is permitted but every other value/layout
// change fails closed.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ImageConsumer is one standard Kubernetes workload container whose image is
// selected by a component's release values. The complete sorted set is pinned
// in the batch contract; adding, removing, renaming or shadowing one is drift.
type ImageConsumer struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	Section            string `json:"section"`
	Container          string `json:"container"`
	FieldPath          string `json:"fieldPath"`
	Component          string `json:"component"`
	ExpectedRepository string `json:"expectedRepository"`
	ImageSource        string `json:"imageSource"`
}

func (c ImageConsumer) key() string {
	return strings.Join([]string{c.APIVersion, c.Kind, c.Namespace, c.Name, c.FieldPath, c.Container}, "\x00")
}

type deploymentRoute struct {
	Manifest       string
	ManifestDigest string
	Chart          string
	ChartDigest    string
	ReleaseName    string
	Namespace      string
	ValuesFiles    []string
	ValuesDigests  []FileDigest
}

func cleanRepoPath(path string) (string, error) {
	path = filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if path == "." || filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../") {
		return "", fmt.Errorf("repository path %q is not a clean relative path", path)
	}
	return path, nil
}

func rejectYAMLHazards(node *yaml.Node, path string) error {
	if node == nil {
		return fmt.Errorf("%s: nil YAML node", path)
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s: YAML aliases are not permitted in release render inputs", path)
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, child := range node.Content {
			if err := rejectYAMLHazards(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("%s: malformed YAML mapping", path)
		}
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "" {
				return fmt.Errorf("%s: release mappings require non-empty string keys", path)
			}
			if key.Value == "<<" {
				return fmt.Errorf("%s: YAML merge aliases are not permitted in release render inputs", path)
			}
			if seen[key.Value] {
				return fmt.Errorf("%s: duplicate YAML key %q", path, key.Value)
			}
			seen[key.Value] = true
			if err := rejectYAMLHazards(node.Content[i+1], path+"."+key.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseYAMLDocument(raw []byte, path string) (*yaml.Node, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var trailing yaml.Node
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%s: multiple YAML documents are not permitted", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("%s: not one YAML document", path)
	}
	if err := rejectYAMLHazards(&doc, path); err != nil {
		return nil, err
	}
	return &doc, nil
}

func exactMapping(m *yaml.Node, key, path string) (*yaml.Node, error) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected mapping before key %q", path, key)
	}
	var found *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%s: duplicate YAML key %q", path, key)
		}
		found = m.Content[i+1]
	}
	if found == nil {
		return nil, fmt.Errorf("%s: missing required key %q", path, key)
	}
	return found, nil
}

func imageValuesNode(doc *yaml.Node, target ComponentDeploy, path string) (*yaml.Node, error) {
	node := doc.Content[0]
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: top level must be a mapping", path)
	}
	for _, key := range target.Path {
		var err error
		node, err = exactMapping(node, key, path)
		if err != nil {
			return nil, fmt.Errorf("%s: image path %s: %w", path, strings.Join(target.Path, "."), err)
		}
		if node.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s: image path %s must be a mapping", path, strings.Join(target.Path, "."))
		}
	}
	return node, nil
}

func imageValueNodes(doc *yaml.Node, target ComponentDeploy, path string) (map[string]*yaml.Node, error) {
	node, err := imageValuesNode(doc, target, path)
	if err != nil {
		return nil, err
	}
	values := map[string]*yaml.Node{}
	for _, key := range []string{target.RepositoryKey, target.TagKey, target.DigestKey, target.SourceKey} {
		if key == "" {
			continue
		}
		value, err := exactMapping(node, key, path)
		if err != nil {
			return nil, fmt.Errorf("%s: release image value: %w", path, err)
		}
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "" {
			return nil, fmt.Errorf("%s: release image value %q must be a non-empty string scalar", path, key)
		}
		values[key] = value
	}
	return values, nil
}

func pinValuesRaw(raw []byte, target ComponentDeploy) (map[string]string, error) {
	doc, err := parseYAMLDocument(raw, target.ValuesFile)
	if err != nil {
		return nil, err
	}
	nodes, err := imageValueNodes(doc, target, target.ValuesFile)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for key, node := range nodes {
		values[key] = node.Value
	}
	return values, nil
}

// mutateDeploymentValues changes only existing release-critical scalar fields.
// It never creates a key, parent mapping or replacement shape.
func mutateDeploymentValues(raw []byte, target ComponentDeploy, repository, tag, digest, source string) ([]byte, error) {
	doc, err := parseYAMLDocument(raw, target.ValuesFile)
	if err != nil {
		return nil, err
	}
	nodes, err := imageValueNodes(doc, target, target.ValuesFile)
	if err != nil {
		return nil, err
	}
	updates := map[string]string{
		target.RepositoryKey: repository,
		target.TagKey:        tag,
		target.DigestKey:     digest,
	}
	if target.SourceKey != "" {
		updates[target.SourceKey] = source
	}
	for key, value := range updates {
		if value == "" {
			return nil, fmt.Errorf("%s: release image value %q cannot be set empty", target.ValuesFile, key)
		}
		node := nodes[key]
		node.Value = value
		node.Tag = "!!str"
		node.Style = yaml.DoubleQuotedStyle
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func canonicalNode(node *yaml.Node) any {
	switch node.Kind {
	case yaml.DocumentNode:
		return canonicalNode(node.Content[0])
	case yaml.MappingNode:
		out := make([]any, 0, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			out = append(out, []any{node.Content[i].Value, canonicalNode(node.Content[i+1])})
		}
		return map[string]any{"mapping": out}
	case yaml.SequenceNode:
		out := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			out = append(out, canonicalNode(child))
		}
		return map[string]any{"sequence": out}
	default:
		return []string{node.Tag, node.Value}
	}
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func yamlDigest(raw []byte, path string, target *ComponentDeploy) (string, error) {
	doc, err := parseYAMLDocument(raw, path)
	if err != nil {
		return "", err
	}
	if target != nil {
		nodes, err := imageValueNodes(doc, *target, path)
		if err != nil {
			return "", err
		}
		for _, node := range nodes {
			node.Value = "<release-value>"
			node.Tag = "!!str"
		}
	}
	canonical, err := json.Marshal(canonicalNode(doc))
	if err != nil {
		return "", err
	}
	return digestBytes(canonical), nil
}

func chartDigest(root, chart string) (string, error) {
	chart, err := cleanRepoPath(chart)
	if err != nil {
		return "", err
	}
	base, err := safeRepoPath(root, chart, true)
	if err != nil {
		return "", err
	}
	var files []string
	if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlinks are not permitted in a release chart", path)
		}
		if info.Mode().IsRegular() {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("chart %s has no files", chart)
	}
	sort.Strings(files)
	hash := sha256.New()
	for _, path := range files {
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return "", err
		}
		raw, err := readRegularFile(path)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(rel))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(raw)
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func stringMap(value any) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	return m, ok
}

func anySlice(value any) ([]any, bool) {
	s, ok := value.([]any)
	return s, ok
}

func nestedMap(root map[string]any, keys ...string) (map[string]any, error) {
	current := root
	for _, key := range keys {
		next, ok := stringMap(current[key])
		if !ok {
			return nil, fmt.Errorf("%s: expected mapping", strings.Join(keys, "."))
		}
		current = next
	}
	return current, nil
}

func templateValue(value, environment, service string) (string, error) {
	value = strings.ReplaceAll(value, "{{.environment}}", environment)
	value = strings.ReplaceAll(value, "{{.service}}", service)
	if strings.Contains(value, "{{") || strings.Contains(value, "}}") {
		return "", fmt.Errorf("unresolved deployment template value %q", value)
	}
	return value, nil
}

func findElement(generators []any, key, want string) (map[string]any, error) {
	var found map[string]any
	var visit func([]any) error
	visit = func(items []any) error {
		for _, item := range items {
			generator, ok := stringMap(item)
			if !ok {
				continue
			}
			if list, ok := stringMap(generator["list"]); ok {
				if elements, ok := anySlice(list["elements"]); ok {
					for _, raw := range elements {
						element, ok := stringMap(raw)
						if !ok || element[key] != want {
							continue
						}
						if found != nil {
							return fmt.Errorf("deployment manifest has duplicate %s %q", key, want)
						}
						found = element
					}
				}
			}
			if matrix, ok := stringMap(generator["matrix"]); ok {
				if nested, ok := anySlice(matrix["generators"]); ok {
					if err := visit(nested); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := visit(generators); err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("deployment manifest has no %s %q", key, want)
	}
	return found, nil
}

func resolveDeploymentRoute(root, environment, service string, target ComponentDeploy) (deploymentRoute, error) {
	raw, err := readRepoFile(root, deploymentManifest)
	if err != nil {
		return deploymentRoute{}, err
	}
	manifestDigest, err := yamlDigest(raw, deploymentManifest, nil)
	if err != nil {
		return deploymentRoute{}, err
	}
	var manifest map[string]any
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		return deploymentRoute{}, fmt.Errorf("%s: %w", deploymentManifest, err)
	}
	spec, err := nestedMap(manifest, "spec")
	if err != nil {
		return deploymentRoute{}, err
	}
	generators, ok := anySlice(spec["generators"])
	if !ok {
		return deploymentRoute{}, fmt.Errorf("%s: spec.generators must be a list", deploymentManifest)
	}
	serviceElement, err := findElement(generators, "service", service)
	if err != nil {
		return deploymentRoute{}, err
	}
	environmentElement, err := findElement(generators, "environment", environment)
	if err != nil {
		return deploymentRoute{}, err
	}
	chart, ok := serviceElement["chart"].(string)
	if !ok || chart == "" {
		return deploymentRoute{}, fmt.Errorf("deployment service %s has no chart", service)
	}
	chart, err = cleanRepoPath(chart)
	if err != nil {
		return deploymentRoute{}, err
	}
	if chart != target.Chart {
		return deploymentRoute{}, fmt.Errorf("component %s deployment chart %q, immutable component chart is %q", service, chart, target.Chart)
	}
	releaseName, ok := environmentElement["release"].(string)
	if !ok || releaseName == "" {
		return deploymentRoute{}, fmt.Errorf("deployment environment %s has no release", environment)
	}
	namespace, ok := environmentElement["namespace"].(string)
	if !ok || namespace == "" {
		return deploymentRoute{}, fmt.Errorf("deployment environment %s has no namespace", environment)
	}
	templateSpec, err := nestedMap(spec, "template", "spec")
	if err != nil {
		return deploymentRoute{}, err
	}
	sources, ok := anySlice(templateSpec["sources"])
	if !ok {
		return deploymentRoute{}, fmt.Errorf("%s: template.spec.sources must be a list", deploymentManifest)
	}
	var chartSource map[string]any
	for _, rawSource := range sources {
		source, ok := stringMap(rawSource)
		if !ok || source["path"] != "{{.chart}}" {
			continue
		}
		if chartSource != nil {
			return deploymentRoute{}, fmt.Errorf("%s: ambiguous chart sources", deploymentManifest)
		}
		chartSource = source
	}
	if chartSource == nil {
		return deploymentRoute{}, fmt.Errorf("%s: no authoritative chart source", deploymentManifest)
	}
	helm, ok := stringMap(chartSource["helm"])
	if !ok {
		return deploymentRoute{}, fmt.Errorf("%s: chart source has no helm contract", deploymentManifest)
	}
	if helm["releaseName"] != "{{.release}}" || helm["skipCrds"] != true {
		return deploymentRoute{}, fmt.Errorf("%s: chart source releaseName/skipCrds contract changed", deploymentManifest)
	}
	rawValues, ok := anySlice(helm["valueFiles"])
	if !ok || len(rawValues) == 0 {
		return deploymentRoute{}, fmt.Errorf("%s: chart source has no valueFiles", deploymentManifest)
	}
	valuesFiles := make([]string, 0, len(rawValues))
	seenTarget := false
	for _, rawValue := range rawValues {
		value, ok := rawValue.(string)
		if !ok || !strings.HasPrefix(value, "$values/") {
			return deploymentRoute{}, fmt.Errorf("%s: value file %v is not repository-backed", deploymentManifest, rawValue)
		}
		value, err = templateValue(strings.TrimPrefix(value, "$values/"), environment, service)
		if err != nil {
			return deploymentRoute{}, err
		}
		value, err = cleanRepoPath(value)
		if err != nil {
			return deploymentRoute{}, err
		}
		valuesFiles = append(valuesFiles, value)
		seenTarget = seenTarget || value == target.ValuesFile
	}
	if !seenTarget {
		return deploymentRoute{}, fmt.Errorf("component %s authoritative values %s are not consumed by its deployment manifest", service, target.ValuesFile)
	}
	chartSHA, err := chartDigest(root, chart)
	if err != nil {
		return deploymentRoute{}, err
	}
	digests := make([]FileDigest, 0, len(valuesFiles))
	for _, valueFile := range valuesFiles {
		valueRaw, err := readRepoFile(root, valueFile)
		if err != nil {
			return deploymentRoute{}, err
		}
		var redact *ComponentDeploy
		if valueFile == target.ValuesFile {
			redact = &target
		}
		valueSHA, err := yamlDigest(valueRaw, valueFile, redact)
		if err != nil {
			return deploymentRoute{}, err
		}
		digests = append(digests, FileDigest{Path: valueFile, SHA256: valueSHA})
	}
	return deploymentRoute{
		Manifest: deploymentManifest, ManifestDigest: manifestDigest, Chart: chart, ChartDigest: chartSHA,
		ReleaseName: releaseName, Namespace: namespace, ValuesFiles: valuesFiles, ValuesDigests: digests,
	}, nil
}

func helmPath() (string, error) {
	for _, name := range []string{os.Getenv("HELM_BIN"), os.Getenv("HELM"), "helm"} {
		if name == "" {
			continue
		}
		path, err := exec.LookPath(name)
		if err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("helm is required for release consumer verification")
}

func renderChart(root string, route deploymentRoute, overridePath string, overrideRaw []byte) ([]byte, error) {
	helm, err := helmPath()
	if err != nil {
		return nil, err
	}
	helmBefore, err := pathSnapshot(helm, false)
	if err != nil {
		return nil, fmt.Errorf("helm executable: %w", err)
	}
	chartPath, err := safeRepoPath(root, route.Chart, true)
	if err != nil {
		return nil, err
	}
	chartBefore, err := chartDigest(root, route.Chart)
	if err != nil {
		return nil, err
	}
	var tempPath string
	if overridePath != "" {
		file, err := os.CreateTemp(root, ".servicerelease-values-*.yaml")
		if err != nil {
			return nil, err
		}
		tempPath = file.Name()
		defer os.Remove(tempPath)
		if _, err := file.Write(overrideRaw); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		if _, err := pathSnapshot(tempPath, false); err != nil {
			return nil, err
		}
	}
	args := []string{"template", route.ReleaseName, chartPath, "--namespace", route.Namespace, "--skip-crds"}
	valueSnapshots := map[string][]pathIdentity{}
	for _, apiVersion := range renderAPIVersions {
		args = append(args, "--api-versions", apiVersion)
	}
	for _, valueFile := range route.ValuesFiles {
		path, err := safeRepoPath(root, valueFile, false)
		if err != nil {
			return nil, err
		}
		if valueFile == overridePath {
			path = tempPath
		}
		valueSnapshots[path], err = pathSnapshot(path, false)
		if err != nil {
			return nil, err
		}
		args = append(args, "--values", path)
	}
	cmd, commandCleanup, err := pinnedCommand(helm, args...)
	if err != nil {
		return nil, err
	}
	defer commandCleanup()
	cmd.Dir = root
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		diagnostic := strings.TrimSpace(stderr.String())
		if diagnostic == "" {
			diagnostic = strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("helm render %s: %w\n%s", route.Chart, err, diagnostic)
	}
	helmAfter, err := pathSnapshot(helm, false)
	if err != nil || !reflect.DeepEqual(helmBefore, helmAfter) {
		return nil, fmt.Errorf("helm executable identity changed during render")
	}
	chartAfter, err := chartDigest(root, route.Chart)
	if err != nil || chartAfter != chartBefore {
		return nil, fmt.Errorf("chart %s changed during render", route.Chart)
	}
	for path, before := range valueSnapshots {
		after, err := pathSnapshot(path, false)
		if err != nil || !reflect.DeepEqual(before, after) {
			return nil, fmt.Errorf("values file %s changed during render", path)
		}
	}
	return stdout.Bytes(), nil
}

var renderReleaseChart = renderChart

func mapValue(m map[string]any, keys ...string) (map[string]any, bool) {
	current := m
	for _, key := range keys {
		next, ok := stringMap(current[key])
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

type podSpecLocation struct {
	path string
	pod  map[string]any
}

func podSpecLocations(value any, path string) []podSpecLocation {
	var found []podSpecLocation
	switch current := value.(type) {
	case map[string]any:
		isPodSpec := false
		for _, section := range []string{"containers", "initContainers", "ephemeralContainers"} {
			if _, exists := current[section]; exists {
				isPodSpec = true
			}
		}
		if isPodSpec {
			found = append(found, podSpecLocation{path: path, pod: current})
		}
		for key, child := range current {
			if isPodSpec && (key == "containers" || key == "initContainers" || key == "ephemeralContainers") {
				continue
			}
			found = append(found, podSpecLocations(child, path+"/"+key)...)
		}
	case []any:
		for i, child := range current {
			found = append(found, podSpecLocations(child, fmt.Sprintf("%s/%d", path, i))...)
		}
	}
	return found
}

func workloadImages(rendered []byte) (map[string]string, map[string]ImageConsumer, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(rendered))
	images := map[string]string{}
	consumers := map[string]ImageConsumer{}
	for document := 0; ; document++ {
		var doc yaml.Node
		if err := decoder.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("rendered manifest %d: %w", document, err)
		}
		if len(doc.Content) == 0 || (doc.Content[0].Kind == yaml.ScalarNode && doc.Content[0].Tag == "!!null") {
			continue
		}
		if err := rejectYAMLHazards(&doc, fmt.Sprintf("rendered manifest %d", document)); err != nil {
			return nil, nil, err
		}
		var object map[string]any
		if err := doc.Decode(&object); err != nil {
			return nil, nil, err
		}
		locations := podSpecLocations(object, "")
		if len(locations) == 0 {
			continue
		}
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		metadata, _ := stringMap(object["metadata"])
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if namespace == "" {
			namespace = "default"
		}
		if apiVersion == "" || kind == "" || name == "" {
			return nil, nil, fmt.Errorf("rendered pod template has no complete apiVersion/kind/name identity")
		}
		for _, location := range locations {
			for _, section := range []string{"containers", "initContainers", "ephemeralContainers"} {
				rawEntries, exists := location.pod[section]
				if !exists {
					continue
				}
				entries, ok := anySlice(rawEntries)
				if !ok || len(entries) == 0 {
					return nil, nil, fmt.Errorf("rendered %s/%s %s must be a non-empty list", kind, name, section)
				}
				seenNames := map[string]bool{}
				for i, rawContainer := range entries {
					container, ok := stringMap(rawContainer)
					if !ok {
						return nil, nil, fmt.Errorf("rendered %s/%s %s entry is not a mapping", kind, name, section)
					}
					containerName, _ := container["name"].(string)
					image, _ := container["image"].(string)
					if containerName == "" || image == "" {
						return nil, nil, fmt.Errorf("rendered %s/%s %s has no name/image", kind, name, section)
					}
					if seenNames[containerName] {
						return nil, nil, fmt.Errorf("rendered %s/%s has duplicate %s container %q", kind, name, section, containerName)
					}
					seenNames[containerName] = true
					fieldPath := fmt.Sprintf("%s/%s/%d/image", location.path, section, i)
					consumer := ImageConsumer{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name, Section: section, Container: containerName, FieldPath: fieldPath}
					key := consumer.key()
					if _, duplicate := images[key]; duplicate {
						return nil, nil, fmt.Errorf("rendered workload consumer %s is duplicated or ambiguous", strings.ReplaceAll(key, "\x00", "/"))
					}
					images[key] = image
					consumers[key] = consumer
				}
			}
		}
	}
	return images, consumers, nil
}

func expectedRenderedImage(repository, tag, digest string) string {
	return repository + ":" + tag + "@" + digest
}

func imageRepository(image string) string {
	if at := strings.IndexByte(image, '@'); at >= 0 {
		image = image[:at]
	}
	slash := strings.LastIndexByte(image, '/')
	if colon := strings.LastIndexByte(image, ':'); colon > slash {
		image = image[:colon]
	}
	return image
}

func authoritativeComponent(consumer ImageConsumer, image string) string {
	if componentByName(consumer.Container) != nil {
		return consumer.Container
	}
	repository := imageRepository(image)
	for _, candidate := range Components {
		if repository == candidate.Repository || strings.HasSuffix(repository, "/"+candidate.Repository) {
			return candidate.Name
		}
	}
	return ""
}

func probeConsumers(root string, route deploymentRoute, target ComponentDeploy, component string, overrideRaw []byte) ([]ImageConsumer, map[string]string, error) {
	baselineOverride := ""
	if overrideRaw != nil {
		baselineOverride = target.ValuesFile
	}
	baseline, err := renderReleaseChart(root, route, baselineOverride, overrideRaw)
	if err != nil {
		return nil, nil, err
	}
	baseImages, _, err := workloadImages(baseline)
	if err != nil {
		return nil, nil, err
	}
	targetRaw := overrideRaw
	if targetRaw == nil {
		targetRaw, err = readRepoFile(root, target.ValuesFile)
		if err != nil {
			return nil, nil, err
		}
	}
	probeRepository := "release.invalid/phorvex-consumer-probe/" + component
	probeTag := "0.0.0-probe"
	probeDigest := "sha256:" + strings.Repeat("f", 64)
	probeRaw, err := mutateDeploymentValues(targetRaw, target, probeRepository, probeTag, probeDigest, strings.Repeat("f", 40))
	if err != nil {
		return nil, nil, err
	}
	probeRender, err := renderReleaseChart(root, route, target.ValuesFile, probeRaw)
	if err != nil {
		return nil, nil, err
	}
	probeImages, probeSlots, err := workloadImages(probeRender)
	if err != nil {
		return nil, nil, err
	}
	if len(baseImages) != len(probeImages) {
		return nil, nil, fmt.Errorf("component %s image values change the rendered workload set", component)
	}
	for key := range baseImages {
		if _, ok := probeImages[key]; !ok {
			return nil, nil, fmt.Errorf("component %s image values change workload identity %s", component, strings.ReplaceAll(key, "\x00", "/"))
		}
	}
	wantProbe := expectedRenderedImage(probeRepository, probeTag, probeDigest)
	definition := componentByName(component)
	if definition == nil {
		return nil, nil, fmt.Errorf("unknown release component %s", component)
	}
	expectedRepository := ReleaseRegistry + "/" + definition.Repository
	imageSource := target.ValuesFile + "#" + strings.Join(target.Path, ".")
	var consumers []ImageConsumer
	primary := false
	for key, before := range baseImages {
		after := probeImages[key]
		slot := probeSlots[key]
		authoritative := authoritativeComponent(slot, before)
		if before == after {
			if authoritative != "" {
				if authoritative != component {
					return nil, nil, fmt.Errorf("component %s chart contains cross-component %s consumer %s", component, authoritative, strings.ReplaceAll(key, "\x00", "/"))
				}
			}
			// A release chart is an authority boundary, not a general application
			// chart. Every rendered Pod-spec image must therefore be bound to the
			// one persisted component image source. Unknown repositories and
			// container names are deliberately not treated as an exclusion.
			return nil, nil, fmt.Errorf("component %s has unbound authoritative rendered consumer %s selecting %q", component, strings.ReplaceAll(key, "\x00", "/"), before)
		}
		if authoritative != "" && authoritative != component {
			return nil, nil, fmt.Errorf("component %s values control cross-component %s consumer %s", component, authoritative, strings.ReplaceAll(key, "\x00", "/"))
		}
		if after != wantProbe {
			return nil, nil, fmt.Errorf("component %s values ambiguously render %q at %s, want %q", component, after, strings.ReplaceAll(key, "\x00", "/"), wantProbe)
		}
		consumer := slot
		consumer.Component = component
		consumer.ExpectedRepository = expectedRepository
		consumer.ImageSource = imageSource
		consumers = append(consumers, consumer)
		primary = primary || (consumer.Kind == "Deployment" && consumer.Section == "containers" && consumer.Container == component)
	}
	if len(consumers) == 0 {
		return nil, nil, fmt.Errorf("component %s release values path exists but is not consumed by a rendered workload image", component)
	}
	if !primary {
		return nil, nil, fmt.Errorf("component %s release values do not select its authoritative Deployment container", component)
	}
	sort.Slice(consumers, func(i, j int) bool { return consumers[i].key() < consumers[j].key() })
	return consumers, baseImages, nil
}

func buildComponentDeployment(root, environment string, c *Component, target ComponentDeploy, prove bool) (ComponentDeploy, error) {
	route, err := resolveDeploymentRoute(root, environment, c.Name, target)
	if err != nil {
		return ComponentDeploy{}, err
	}
	target.Application = route.Manifest
	target.ApplicationDigest = route.ManifestDigest
	target.ChartDigest = route.ChartDigest
	target.ReleaseName = route.ReleaseName
	target.Namespace = route.Namespace
	target.ValuesFiles = append([]string(nil), route.ValuesFiles...)
	target.ValuesDigests = append([]FileDigest(nil), route.ValuesDigests...)
	if prove {
		consumers, _, err := probeConsumers(root, route, target, c.Name, nil)
		if err != nil {
			return ComponentDeploy{}, err
		}
		target.Consumers = consumers
	}
	return target, nil
}

func routeFromContract(target ComponentDeploy) deploymentRoute {
	return deploymentRoute{
		Manifest: target.Application, ManifestDigest: target.ApplicationDigest, Chart: target.Chart, ChartDigest: target.ChartDigest,
		ReleaseName: target.ReleaseName, Namespace: target.Namespace, ValuesFiles: append([]string(nil), target.ValuesFiles...),
		ValuesDigests: append([]FileDigest(nil), target.ValuesDigests...),
	}
}

func validateDeploymentConsumer(root string, batch *Batch, contract *BatchComponent, released *Released, overrideRaw []byte) error {
	current, err := resolveDeploymentRoute(root, batch.Environment, contract.Component, contract.Deploy)
	if err != nil {
		return fmt.Errorf("component %s deployment consumer: %w", contract.Component, err)
	}
	want := routeFromContract(contract.Deploy)
	if !reflect.DeepEqual(current, want) {
		return fmt.Errorf("component %s deployment chart/values consumer drifted from pinned source", contract.Component)
	}
	consumers, images, err := probeConsumers(root, current, contract.Deploy, contract.Component, overrideRaw)
	if err != nil {
		return fmt.Errorf("component %s deployment consumer: %w", contract.Component, err)
	}
	if !reflect.DeepEqual(consumers, contract.Deploy.Consumers) {
		return fmt.Errorf("component %s rendered image consumers drifted from pinned source", contract.Component)
	}
	if released == nil {
		return nil
	}
	wantImage := expectedRenderedImage(released.Repository, contract.Image.Tag, released.Digest)
	for _, consumer := range consumers {
		if got := images[consumer.key()]; got != wantImage {
			return fmt.Errorf("component %s rendered consumer %s selects %q, want verified image %q", contract.Component, strings.ReplaceAll(consumer.key(), "\x00", "/"), got, wantImage)
		}
	}
	return nil
}

// validateReleasedDeploymentConsumer checks one component of a complete batch at a later
// head. The batch is then a historical record: the chart, helpers and values may have
// changed since its source, and the next version set pins them anew. What must still hold
// is that every image consumer rendered through the current route is bound to the
// component's values source and selects exactly the released image.
func validateReleasedDeploymentConsumer(root string, batch *Batch, contract *BatchComponent, released Released, overrideRaw []byte) error {
	current, err := resolveDeploymentRoute(root, batch.Environment, contract.Component, contract.Deploy)
	if err != nil {
		return fmt.Errorf("component %s deployment consumer: %w", contract.Component, err)
	}
	consumers, images, err := probeConsumers(root, current, contract.Deploy, contract.Component, overrideRaw)
	if err != nil {
		return fmt.Errorf("component %s deployment consumer: %w", contract.Component, err)
	}
	if len(consumers) == 0 {
		return fmt.Errorf("component %s renders no image consumer", contract.Component)
	}
	wantImage := expectedRenderedImage(released.Repository, contract.Image.Tag, released.Digest)
	for _, consumer := range consumers {
		if got := images[consumer.key()]; got != wantImage {
			return fmt.Errorf("component %s rendered consumer %s selects %q, want verified image %q", contract.Component, strings.ReplaceAll(consumer.key(), "\x00", "/"), got, wantImage)
		}
	}
	return nil
}

func gitShow(root, source, path string) ([]byte, error) {
	path, err := cleanRepoPath(path)
	if err != nil {
		return nil, err
	}
	out, err := git(root, "show", source+":"+path)
	if err != nil {
		return nil, fmt.Errorf("git show %s:%s: %w", source, path, err)
	}
	return []byte(out), nil
}

func sourceReleaseTree(root, source, environment string) (string, func(), error) {
	rawManifest, err := gitShow(root, source, deploymentManifest)
	if err != nil {
		return "", nil, err
	}
	var manifest map[string]any
	if _, err := parseYAMLDocument(rawManifest, deploymentManifest); err != nil {
		return "", nil, err
	}
	if err := yaml.Unmarshal(rawManifest, &manifest); err != nil {
		return "", nil, err
	}
	spec, err := nestedMap(manifest, "spec")
	if err != nil {
		return "", nil, err
	}
	generators, ok := anySlice(spec["generators"])
	if !ok {
		return "", nil, fmt.Errorf("%s: spec.generators must be a list", deploymentManifest)
	}
	paths := []string{".dockerignore", deploymentManifest, filepath.ToSlash(filepath.Join("deploy", "environments", environment))}
	for _, component := range Components {
		element, err := findElement(generators, "service", component.Name)
		if err != nil {
			return "", nil, err
		}
		chart, ok := element["chart"].(string)
		if !ok {
			return "", nil, fmt.Errorf("deployment service %s has no chart", component.Name)
		}
		chart, err = cleanRepoPath(chart)
		if err != nil {
			return "", nil, err
		}
		paths = append(paths, chart, component.Dockerfile)
	}
	sort.Strings(paths)
	paths = slicesCompact(paths)
	temp, err := os.MkdirTemp(root, ".servicerelease-source-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(temp) }
	args := append([]string{"archive", "--format=tar", source, "--"}, paths...)
	gitPath, err := exec.LookPath("git")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	gitBefore, err := pathSnapshot(gitPath, false)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	cmd, commandCleanup, err := pinnedCommand(gitPath, args...)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer commandCleanup()
	cmd.Dir = root
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cleanup()
		return "", nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cleanup()
		return "", nil, err
	}
	reader := tar.NewReader(stdout)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			_ = cmd.Wait()
			return "", nil, err
		}
		name, err := cleanRepoPath(header.Name)
		if err != nil {
			cleanup()
			_ = cmd.Wait()
			return "", nil, err
		}
		destination := filepath.Join(temp, filepath.FromSlash(name))
		rel, err := filepath.Rel(temp, destination)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			cleanup()
			_ = cmd.Wait()
			return "", nil, fmt.Errorf("git archive path escapes source tree: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		case tar.TypeDir:
			if err := os.MkdirAll(destination, 0o755); err != nil {
				cleanup()
				_ = cmd.Wait()
				return "", nil, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
				cleanup()
				_ = cmd.Wait()
				return "", nil, err
			}
			file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(header.Mode)&0o777)
			if err != nil {
				cleanup()
				_ = cmd.Wait()
				return "", nil, err
			}
			_, copyErr := io.Copy(file, reader)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				cleanup()
				_ = cmd.Wait()
				return "", nil, errors.Join(copyErr, closeErr)
			}
		default:
			cleanup()
			_ = cmd.Wait()
			return "", nil, fmt.Errorf("git archive contains unsupported entry %q", header.Name)
		}
	}
	if err := cmd.Wait(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git archive %s: %w: %s", source, err, strings.TrimSpace(stderr.String()))
	}
	gitAfter, err := pathSnapshot(gitPath, false)
	if err != nil || !reflect.DeepEqual(gitBefore, gitAfter) {
		cleanup()
		return "", nil, fmt.Errorf("git executable identity changed during source archive")
	}
	if _, err := safeRoot(temp); err != nil {
		cleanup()
		return "", nil, err
	}
	return temp, cleanup, nil
}

func slicesCompact(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
