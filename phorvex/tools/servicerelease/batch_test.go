package main

import (
	"encoding/json"
	"errors"
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

func fakeReleaseRenderer(root string, route deploymentRoute, overridePath string, overrideRaw []byte) ([]byte, error) {
	var component *Component
	for i := range Components {
		if Components[i].Chart == route.Chart {
			component = &Components[i]
			break
		}
	}
	if component == nil {
		return nil, errors.New("unknown fixture chart " + route.Chart)
	}
	target := ComponentDeploy{
		Chart: route.Chart, ValuesFile: filepath.ToSlash(filepath.Join("deploy", "environments", ReleaseEnvironment, component.Deploy.File+".yaml")),
		Path: append([]string(nil), component.Deploy.Path...), RepositoryKey: component.Deploy.Repository,
		TagKey: component.Deploy.Tag, DigestKey: component.Deploy.Digest, SourceKey: component.Deploy.Source,
	}
	raw := overrideRaw
	if overridePath == "" {
		var err error
		raw, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(target.ValuesFile)))
		if err != nil {
			return nil, err
		}
	}
	values, err := pinValuesRaw(raw, target)
	if err != nil {
		return nil, err
	}
	image := expectedRenderedImage(values[target.RepositoryKey], values[target.TagKey], values[target.DigestKey])
	rendered := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: " + route.ReleaseName + "-" + component.Name + "\n  namespace: " + route.Namespace + "\nspec:\n  template:\n    spec:\n      containers:\n      - name: " + component.Name + "\n        image: \"" + image + "\"\n"
	return []byte(rendered), nil
}

func newBatchTestRepo(t *testing.T, versions map[string]string) *batchTestRepo {
	t.Helper()
	previousRenderer := renderReleaseChart
	renderReleaseChart = fakeReleaseRenderer
	t.Cleanup(func() { renderReleaseChart = previousRenderer })
	r := &batchTestRepo{t: t, root: t.TempDir()}
	write := func(path, content string) {
		t.Helper()
		path = filepath.Join(r.root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r.releaseDir = filepath.Join(r.root, "release")
	if err := os.MkdirAll(r.releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r.writeVersions(versions)
	write(".dockerignore", ".git\n")
	write("deploy/docker/operator.Dockerfile", "FROM scratch\n")
	write("deploy/docker/service.Dockerfile", "FROM scratch\n")
	write("deploy/docker/console.Dockerfile", "FROM scratch\n")
	write("deploy/environments/staging/phorvex.yaml", "{}\n")
	write("deploy/environments/staging/catalogue-family.yaml", "{}\n")
	var services strings.Builder
	for _, c := range Components {
		services.WriteString("          - service: " + c.Name + "\n            chart: " + c.Chart + "\n")
		var values strings.Builder
		for depth, key := range c.Deploy.Path {
			values.WriteString(strings.Repeat("  ", depth) + key + ":\n")
		}
		indent := strings.Repeat("  ", len(c.Deploy.Path))
		values.WriteString(indent + c.Deploy.Repository + ": \"old.invalid/" + c.Repository + "\"\n")
		values.WriteString(indent + c.Deploy.Tag + ": \"0.0.1\"\n")
		values.WriteString(indent + c.Deploy.Digest + ": \"sha256:" + strings.Repeat("0", 64) + "\"\n")
		if c.Deploy.Source != "" {
			values.WriteString(indent + c.Deploy.Source + ": \"" + strings.Repeat("0", 40) + "\"\n")
		}
		write("deploy/environments/staging/"+c.Deploy.File+".yaml", values.String())
		write(c.Chart+"/Chart.yaml", "apiVersion: v2\nname: "+c.Name+"\nversion: 0.1.0\n")
		write(c.Chart+"/values.yaml", "{}\n")
		value := ".Values." + strings.Join(c.Deploy.Path, ".")
		template := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}-" + c.Name + "\n  namespace: {{ .Release.Namespace }}\nspec:\n  selector:\n    matchLabels:\n      app: " + c.Name + "\n  template:\n    metadata:\n      labels:\n        app: " + c.Name + "\n    spec:\n      containers:\n      - name: " + c.Name + "\n        image: \"{{ " + value + "." + c.Deploy.Repository + " }}:{{ " + value + "." + c.Deploy.Tag + " }}@{{ " + value + "." + c.Deploy.Digest + " }}\"\n"
		write(c.Chart+"/templates/deployment.yaml", template)
	}
	write(deploymentManifest, "apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nspec:\n  generators:\n  - matrix:\n      generators:\n      - list:\n          elements:\n          - environment: staging\n            namespace: phorvex-staging\n            release: staging\n      - list:\n          elements:\n"+services.String()+"  template:\n    spec:\n      sources:\n      - path: '{{.chart}}'\n        helm:\n          releaseName: '{{.release}}'\n          skipCrds: true\n          valueFiles:\n          - '$values/deploy/environments/{{.environment}}/phorvex.yaml'\n          - '$values/deploy/environments/{{.environment}}/{{.service}}.yaml'\n          - '$values/deploy/environments/{{.environment}}/catalogue-family.yaml'\n")
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
		ReleaseRegistry+"/phorvex/"+component, version, "sha256:"+strings.Repeat(digestByte, 64), batch.Source)
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

func TestPartialRetryRejectsRenamedBrainConsumerWithoutRecreatingOldKey(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	useRealReleaseRenderer(t)
	batchA := r.ensureBatch()
	r.commit("pin SHA A consumer contract")
	r.record("manager", "1.0.0", "a")
	r.commit("record manager at SHA A")

	var brain Component
	for _, component := range Components {
		if component.Name == "brain" {
			brain = component
			break
		}
	}
	chartPath := filepath.Join(r.root, filepath.FromSlash(brain.Chart), "templates", "deployment.yaml")
	template := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}-brain\n  namespace: {{ .Release.Namespace }}\nspec:\n  selector:\n    matchLabels:\n      app: brain\n  template:\n    metadata:\n      labels:\n        app: brain\n    spec:\n      containers:\n      - name: brain\n        image: \"{{ .Values.runtimeImage.repository }}:{{ .Values.runtimeImage.tag }}@{{ .Values.runtimeImage.digest }}\"\n"
	if err := os.WriteFile(chartPath, []byte(template), 0o644); err != nil {
		t.Fatal(err)
	}
	valuesPath := filepath.Join(r.root, "deploy", "environments", ReleaseEnvironment, "brain.yaml")
	runtimeValues := "runtimeImage:\n  repository: \"old.invalid/phorvex/brain\"\n  tag: \"0.0.1\"\n  digest: \"sha256:" + strings.Repeat("0", 64) + "\"\n"
	if err := os.WriteFile(valuesPath, []byte(runtimeValues), 0o644); err != nil {
		t.Fatal(err)
	}
	shaB := r.commit("rename brain chart consumer at SHA B")
	if shaB == batchA.Source {
		t.Fatal("main did not advance beyond SHA A")
	}

	before, err := os.ReadFile(valuesPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err == nil ||
		(!strings.Contains(err.Error(), "drifted from pinned source") && !strings.Contains(err.Error(), "missing required key")) {
		t.Fatalf("renamed destination consumer pending error = %v", err)
	}
	r.git("tag", "brain-v1.0.0", batchA.Source)
	err = RecordRelease(r.root, r.releaseDir, "HEAD", ReleaseEnvironment, "brain", ReleaseRegistry+"/phorvex/brain",
		"1.0.0", "sha256:"+strings.Repeat("b", 64), batchA.Source)
	if err == nil || (!strings.Contains(err.Error(), "drifted from pinned source") && !strings.Contains(err.Error(), "missing required key")) {
		t.Fatalf("renamed destination consumer record error = %v", err)
	}
	after, err := os.ReadFile(valuesPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || strings.Contains(string(after), "\nimage:") {
		t.Fatalf("rejected record recreated obsolete image key:\n%s", after)
	}
	batch, err := readBatch(r.releaseDir)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Status != "partial" || len(batch.Releases) != 1 || batch.Releases["manager"].Digest == "" {
		t.Fatalf("rejected record changed batch completion: %#v", batch)
	}
}

func TestMainAdvancementCannotRedirectBrainToSensor(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	batchA := r.ensureBatch()
	r.commit("pin complete SHA A contract")
	r.record("manager", "1.0.0", "a")
	r.commit("record manager at SHA A")
	if err := os.WriteFile(filepath.Join(r.root, "main-advance"), []byte("SHA B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shaB := r.commit("advance main to SHA B")
	if shaB == batchA.Source {
		t.Fatal("main did not advance beyond SHA A")
	}

	// This is the reviewed black-box defect in deterministic form: a later-main
	// helper changes brain's repository and pin target to sensor. The old code
	// emitted and accepted that current table against the unchanged SHA-A batch.
	original := Components
	changed := append([]Component(nil), Components...)
	for i := range changed {
		if changed[i].Name == "brain" {
			changed[i].Repository = "phorvex/sensor"
			changed[i].Deploy = serviceImage("sensor")
		}
	}
	Components = changed
	defer func() { Components = original }()
	if source, err := BootstrapSource(r.root, r.releaseDir, "HEAD"); err != nil || source != batchA.Source {
		t.Fatalf("minimal bootstrap source = %q, %v; want SHA A %s", source, err, batchA.Source)
	}
	if _, err := PendingReleases(r.root, r.releaseDir, "HEAD"); err == nil ||
		(!strings.Contains(err.Error(), "pinned-source contract") && !strings.Contains(err.Error(), "not consumed by its deployment manifest")) {
		t.Fatalf("later-main helper metadata was not rejected: %v", err)
	}

	// The helper compiled from SHA A has the original table and consumes the
	// persisted contract. It continues with brain's SHA-A build/repo/pin data.
	Components = original
	pending, err := PendingReleases(r.root, r.releaseDir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	brain := pending[0]
	if brain.Component != "brain" || brain.Source != batchA.Source || brain.Image.Repository != "phorvex/brain" ||
		brain.Deploy.ValuesFile != "deploy/environments/staging/brain.yaml" || brain.Identity.Service != "brain" {
		t.Fatalf("SHA-A brain contract drifted: %#v", brain)
	}
	r.git("tag", brain.Record.GitTag, batchA.Source)
	before, err := os.ReadFile(filepath.Join(r.root, "deploy/environments/staging/sensor.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	err = RecordRelease(r.root, r.releaseDir, "HEAD", ReleaseEnvironment, "brain",
		ReleaseRegistry+"/phorvex/sensor", brain.Version, "sha256:"+strings.Repeat("b", 64), batchA.Source)
	if err == nil || !strings.Contains(err.Error(), "immutable batch repository") {
		t.Fatalf("brain -> sensor repository drift was accepted: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(r.root, "deploy/environments/staging/sensor.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected brain record changed the sensor deployment pin")
	}
}

func TestBatchRejectsEveryComponentMetadataClassTamper(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BatchComponent)
	}{
		{"canonical component", func(c *BatchComponent) { c.Component = "renamed" }},
		{"service identity", func(c *BatchComponent) { c.Identity.Service = "sensor" }},
		{"command identity", func(c *BatchComponent) { c.Identity.Command = "/sensor" }},
		{"validation image lookup", func(c *BatchComponent) { c.Identity.ValidationImage = "sensor" }},
		{"alias lookup", func(c *BatchComponent) { c.Identity.Aliases = append(c.Identity.Aliases, "manager-old") }},
		{"component source", func(c *BatchComponent) { c.Source = strings.Repeat("f", 40) }},
		{"component version", func(c *BatchComponent) { c.Version = "1.0.1" }},
		{"dockerfile", func(c *BatchComponent) { c.Build.Dockerfile = "deploy/docker/service.Dockerfile" }},
		{"build context", func(c *BatchComponent) { c.Build.Context = "phorvex" }},
		{"build target", func(c *BatchComponent) { c.Build.Target = "sensor" }},
		{"build argument", func(c *BatchComponent) { c.Build.Args[0] = "GIT_SHA=" + strings.Repeat("f", 40) }},
		{"image registry", func(c *BatchComponent) { c.Image.Registry = "registry.example" }},
		{"image repository", func(c *BatchComponent) { c.Image.Repository = "phorvex/sensor" }},
		{"image tag", func(c *BatchComponent) { c.Image.Tag = "1.0.1" }},
		{"deployment application", func(c *BatchComponent) { c.Deploy.Application = "deploy/other.yaml" }},
		{"deployment application digest", func(c *BatchComponent) { c.Deploy.ApplicationDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"chart", func(c *BatchComponent) { c.Deploy.Chart = "deploy/charts/phorvex-sensor" }},
		{"chart digest", func(c *BatchComponent) { c.Deploy.ChartDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"release name", func(c *BatchComponent) { c.Deploy.ReleaseName = "other" }},
		{"namespace", func(c *BatchComponent) { c.Deploy.Namespace = "other" }},
		{"values files", func(c *BatchComponent) { c.Deploy.ValuesFiles[0] = "deploy/environments/staging/other.yaml" }},
		{"values digest", func(c *BatchComponent) { c.Deploy.ValuesDigests[0].SHA256 = "sha256:" + strings.Repeat("f", 64) }},
		{"values file", func(c *BatchComponent) { c.Deploy.ValuesFile = "deploy/environments/staging/sensor.yaml" }},
		{"values path", func(c *BatchComponent) { c.Deploy.Path = []string{"sensor", "image"} }},
		{"repository key", func(c *BatchComponent) { c.Deploy.RepositoryKey = "sensorRepository" }},
		{"tag key", func(c *BatchComponent) { c.Deploy.TagKey = "sensorTag" }},
		{"digest key", func(c *BatchComponent) { c.Deploy.DigestKey = "sensorDigest" }},
		{"source key", func(c *BatchComponent) { c.Deploy.SourceKey = "sensorSource" }},
		{"rendered consumer", func(c *BatchComponent) { c.Deploy.Consumers[0].Container = "other" }},
		{"batch record file", func(c *BatchComponent) { c.Record.BatchFile = "release/other.json" }},
		{"release record key", func(c *BatchComponent) { c.Record.ReleaseKey = "sensor" }},
		{"git tag", func(c *BatchComponent) { c.Record.GitTag = "sensor-v1.0.0" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newBatchTestRepo(t, batchVersions())
			batch := r.ensureBatch()
			test.mutate(&batch.Components[0])
			if err := writeBatch(r.releaseDir, batch); err != nil {
				t.Fatal(err)
			}
			r.commit("tamper " + test.name)
			if _, err := LoadBatch(r.root, r.releaseDir, "HEAD", true); err == nil {
				t.Fatalf("tampered %s was accepted", test.name)
			}
		})
	}
}

func TestBatchRejectsStructuralContractCorruption(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Batch)
	}{
		{"schema version mismatch", func(b *Batch) { b.Schema++ }},
		{"environment mismatch", func(b *Batch) { b.Environment = "production" }},
		{"version set tamper", func(b *Batch) { b.Versions["brain"] = "1.0.1" }},
		{"status tamper", func(b *Batch) { b.Status = "complete" }},
		{"missing component", func(b *Batch) { b.Components = b.Components[:len(b.Components)-1] }},
		{"extra component", func(b *Batch) {
			b.Components = append(b.Components, b.Components[0])
			b.Components[len(b.Components)-1].Component = "extra"
		}},
		{"duplicate component", func(b *Batch) { b.Components[len(b.Components)-1] = b.Components[0] }},
		{"reordered components", func(b *Batch) { b.Components[0], b.Components[1] = b.Components[1], b.Components[0] }},
		{"partial component", func(b *Batch) { b.Components[0].Build = ComponentBuild{} }},
		{"extra release record", func(b *Batch) {
			b.Releases["extra"] = Released{Repository: "registry.example/extra", Digest: "sha256:" + strings.Repeat("a", 64)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newBatchTestRepo(t, batchVersions())
			batch := r.ensureBatch()
			test.mutate(batch)
			if err := writeBatch(r.releaseDir, batch); err != nil {
				t.Fatal(err)
			}
			r.commit("corrupt " + test.name)
			if _, err := LoadBatch(r.root, r.releaseDir, "HEAD", true); err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}

	for _, test := range []struct {
		name string
		raw  string
	}{
		{"truncated JSON", "{\n"},
		{"unknown field", `{"schema":2,"unknown":true}`},
		{"partial manifest", `{"schema":2,"status":"prepared"}`},
		{"trailing document", `{"schema":2} {"schema":2}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newBatchTestRepo(t, batchVersions())
			r.ensureBatch()
			if err := os.WriteFile(filepath.Join(r.releaseDir, BatchFile), []byte(test.raw), 0o644); err != nil {
				t.Fatal(err)
			}
			r.commit("corrupt manifest")
			if _, err := LoadBatch(r.root, r.releaseDir, "HEAD", true); err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}
}

func TestBootstrapReadsOnlyPointerAndPinnedToolValidatesContract(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	batch := r.ensureBatch()
	r.commit("pin batch")
	batch.Components[1].Image.Repository = "phorvex/sensor"
	if err := writeBatch(r.releaseDir, batch); err != nil {
		t.Fatal(err)
	}
	r.commit("tamper non-pointer metadata")
	if source, err := BootstrapSource(r.root, r.releaseDir, "HEAD"); err != nil || source != r.source {
		t.Fatalf("bootstrap source = %q, %v; want %s", source, err, r.source)
	}
	if _, err := LoadBatch(r.root, r.releaseDir, "HEAD", true); err == nil {
		t.Fatal("authoritative pinned helper accepted metadata bootstrap deliberately ignored")
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
		if err := Deploy(r.root, ReleaseEnvironment, "manager", ReleaseRegistry+"/phorvex/manager", "1.0.0", "sha256:"+strings.Repeat("b", 64), r.source); err != nil {
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
		err := RecordRelease(r.root, r.releaseDir, "HEAD", ReleaseEnvironment, "manager", ReleaseRegistry+"/phorvex/manager",
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
		if err := Deploy(r.root, ReleaseEnvironment, c.Name, ReleaseRegistry+"/phorvex/"+c.Name, "1.0.0",
			"sha256:"+strings.Repeat(string(rune('a'+i)), 64), r.source); err != nil {
			t.Fatal(err)
		}
	}
	r.commit("legacy complete pins")
	batch, err := ImportTerminalBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment)
	if err != nil || batch.Status != "complete" || batch.Source != r.source {
		t.Fatalf("legacy import = %#v err=%v", batch, err)
	}
}

func TestLegacyTerminalImportRejectsConsumerDrift(t *testing.T) {
	r := newBatchTestRepo(t, batchVersions())
	useRealReleaseRenderer(t)
	for i, component := range Components {
		r.git("tag", component.Name+"-v1.0.0", r.source)
		if err := Deploy(r.root, ReleaseEnvironment, component.Name, ReleaseRegistry+"/phorvex/"+component.Name, "1.0.0",
			"sha256:"+strings.Repeat(string(rune('a'+i)), 64), r.source); err != nil {
			t.Fatal(err)
		}
	}
	brainChart := filepath.Join(r.root, "deploy", "charts", "phorvex-brain", "templates", "deployment.yaml")
	raw, err := os.ReadFile(brainChart)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(brainChart, []byte(strings.ReplaceAll(string(raw), ".Values.image", ".Values.runtimeImage")), 0o644); err != nil {
		t.Fatal(err)
	}
	r.commit("legacy pins with disconnected brain consumer")
	if _, err := ImportTerminalBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment); err == nil ||
		(!strings.Contains(err.Error(), "drifted from pinned source") && !strings.Contains(err.Error(), "runtimeImage")) {
		t.Fatalf("terminal import consumer drift error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.releaseDir, BatchFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal import wrote a batch after consumer drift: %v", err)
	}
}

func TestLegacyTerminalImportCannotAuthorizeComponentWork(t *testing.T) {
	t.Run("untagged", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		if _, err := ImportTerminalBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment); err == nil || !strings.Contains(err.Error(), "not terminal") {
			t.Fatalf("untagged terminal import error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(r.releaseDir, BatchFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("terminal import wrote a work-authorizing batch: %v", err)
		}
	})

	t.Run("partial tags", func(t *testing.T) {
		r := newBatchTestRepo(t, batchVersions())
		r.git("tag", "manager-v1.0.0", r.source)
		if _, err := ImportTerminalBatch(r.root, r.releaseDir, "HEAD", ReleaseEnvironment); err == nil || !strings.Contains(err.Error(), "partially tagged") {
			t.Fatalf("partial terminal import error = %v", err)
		}
	})
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
