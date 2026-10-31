package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeConsumerFixture(t *testing.T, root, path, content string) {
	t.Helper()
	path = filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixtureRoute() deploymentRoute {
	return deploymentRoute{
		Chart: "chart", ReleaseName: "staging", Namespace: "phorvex-staging",
		ValuesFiles: []string{"values.yaml"},
	}
}

func fixtureTarget(path ...string) ComponentDeploy {
	return ComponentDeploy{
		Chart: "chart", ValuesFile: "values.yaml", Path: path,
		RepositoryKey: "repository", TagKey: "tag", DigestKey: "digest",
	}
}

func fixtureValues(path string) string {
	return path + ":\n  repository: \"old.invalid/phorvex/brain\"\n  tag: \"0.1.0\"\n  digest: \"sha256:" + strings.Repeat("0", 64) + "\"\n"
}

func fixtureDeployment(image string) string {
	return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: staging-brain\nspec:\n  selector:\n    matchLabels:\n      app: brain\n  template:\n    metadata:\n      labels:\n        app: brain\n    spec:\n      containers:\n      - name: brain\n        image: '" + image + "'\n"
}

func useRealReleaseRenderer(t *testing.T) {
	t.Helper()
	previous := renderReleaseChart
	renderReleaseChart = renderChart
	t.Cleanup(func() { renderReleaseChart = previous })
}

func TestConsumerProbeFollowsHelperTemplateIndirection(t *testing.T) {
	useRealReleaseRenderer(t)
	t.Setenv("KUBECONFIG", "/dev/null")
	root := t.TempDir()
	writeConsumerFixture(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: brain\nversion: 0.1.0\n")
	writeConsumerFixture(t, root, "chart/values.yaml", "{}\n")
	writeConsumerFixture(t, root, "values.yaml", fixtureValues("image"))
	writeConsumerFixture(t, root, "chart/templates/_helpers.tpl", "{{- define \"brain.releaseImage\" -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}{{- end -}}\n")
	writeConsumerFixture(t, root, "chart/templates/deployment.yaml", fixtureDeployment(`{{ include "brain.releaseImage" . }}`))
	consumers, _, err := probeConsumers(root, fixtureRoute(), fixtureTarget("image"), "brain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(consumers) != 1 || consumers[0].Container != "brain" || consumers[0].Kind != "Deployment" {
		t.Fatalf("helper consumers = %#v", consumers)
	}
	if consumers[0].Component != "brain" || consumers[0].FieldPath != "/spec/template/spec/containers/0/image" ||
		consumers[0].ExpectedRepository != ReleaseRegistry+"/phorvex/brain" ||
		consumers[0].ImageSource != "values.yaml#image" {
		t.Fatalf("incomplete explicit consumer contract = %#v", consumers[0])
	}
}

func TestConsumerProbeFollowsSubchartGlobalValues(t *testing.T) {
	useRealReleaseRenderer(t)
	root := t.TempDir()
	writeConsumerFixture(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: parent\nversion: 0.1.0\ndependencies:\n- name: child\n  version: 0.1.0\n  repository: file://charts/child\n")
	writeConsumerFixture(t, root, "chart/values.yaml", "{}\n")
	writeConsumerFixture(t, root, "chart/charts/child/Chart.yaml", "apiVersion: v2\nname: child\nversion: 0.1.0\n")
	writeConsumerFixture(t, root, "chart/charts/child/values.yaml", "{}\n")
	writeConsumerFixture(t, root, "chart/charts/child/templates/deployment.yaml", fixtureDeployment("{{ .Values.global.releaseImage.repository }}:{{ .Values.global.releaseImage.tag }}@{{ .Values.global.releaseImage.digest }}"))
	writeConsumerFixture(t, root, "values.yaml", "global:\n  "+strings.ReplaceAll(fixtureValues("releaseImage"), "\n", "\n  "))
	consumers, _, err := probeConsumers(root, fixtureRoute(), fixtureTarget("global", "releaseImage"), "brain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(consumers) != 1 || consumers[0].Container != "brain" {
		t.Fatalf("subchart consumers = %#v", consumers)
	}
}

func TestConsumerProbeRejectsUnusedAndShadowedImagePaths(t *testing.T) {
	useRealReleaseRenderer(t)
	for _, test := range []struct {
		name     string
		values   string
		template string
		contains string
	}{
		{
			name:     "path exists but is not consumed",
			values:   fixtureValues("image") + strings.Replace(fixtureValues("runtimeImage"), "old.invalid/phorvex/brain", "other.invalid/phorvex/brain", 1),
			template: fixtureDeployment("{{ .Values.runtimeImage.repository }}:{{ .Values.runtimeImage.tag }}@{{ .Values.runtimeImage.digest }}"),
			contains: "unbound authoritative",
		},
		{
			name:     "chart retains an old digest",
			values:   fixtureValues("image"),
			template: fixtureDeployment("{{ .Values.image.repository }}:{{ .Values.image.tag }}@sha256:" + strings.Repeat("0", 64)),
			contains: "ambiguously render",
		},
		{
			name:   "second consumer shadows the release path",
			values: fixtureValues("image") + fixtureValues("runtimeImage"),
			template: fixtureDeployment("{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}") + "---\n" +
				strings.ReplaceAll(strings.ReplaceAll(fixtureDeployment("{{ .Values.runtimeImage.repository }}:{{ .Values.runtimeImage.tag }}@{{ .Values.runtimeImage.digest }}"), "staging-brain", "staging-shadow"), "name: brain\n", "name: shadow\n"),
			contains: "unbound authoritative",
		},
		{
			name:     "duplicate workload consumer identity",
			values:   fixtureValues("image"),
			template: fixtureDeployment("{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}") + "---\n" + fixtureDeployment("{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}"),
			contains: "duplicated or ambiguous",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeConsumerFixture(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: brain\nversion: 0.1.0\n")
			writeConsumerFixture(t, root, "chart/values.yaml", "{}\n")
			writeConsumerFixture(t, root, "chart/templates/deployment.yaml", test.template)
			writeConsumerFixture(t, root, "values.yaml", test.values)
			_, _, err := probeConsumers(root, fixtureRoute(), fixtureTarget("image"), "brain", nil)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("consumer error = %v, want %q", err, test.contains)
			}
		})
	}
}

func extraConsumerManifest(kind, name, section, container string) string {
	image := "alternate.invalid/phorvex/brain:0.0.1@sha256:" + strings.Repeat("e", 64)
	pod := "      " + section + ":\n      - name: " + container + "\n        image: '" + image + "'\n"
	switch kind {
	case "Pod":
		return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\nspec:\n" + strings.ReplaceAll(pod, "      ", "  ")
	case "Job":
		return "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: " + name + "\nspec:\n  template:\n    spec:\n      restartPolicy: Never\n" + pod
	case "CronJob":
		return "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: " + name + "\nspec:\n  schedule: '* * * * *'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n" + strings.ReplaceAll(pod, "      ", "          ")
	case "BrainFleet":
		return "apiVersion: example.invalid/v1\nkind: BrainFleet\nmetadata:\n  name: " + name + "\nspec:\n  podTemplate:\n    spec:\n" + pod
	default:
		return "apiVersion: apps/v1\nkind: " + kind + "\nmetadata:\n  name: " + name + "\nspec:\n  selector:\n    matchLabels:\n      app: " + name + "\n  template:\n    metadata:\n      labels:\n        app: " + name + "\n    spec:\n" + pod
	}
}

func TestConsumerProbeRejectsEveryUnboundAuthoritativeWorkloadAndContainerClass(t *testing.T) {
	useRealReleaseRenderer(t)
	cases := []struct {
		name, manifest string
	}{
		{"alternate repository deployment", extraConsumerManifest("Deployment", "alternate", "containers", "brain")},
		{"second sidecar", extraConsumerManifest("Deployment", "sidecar", "containers", "sidecar")},
		{"unrelated repository and container", strings.Replace(extraConsumerManifest("Deployment", "unknown", "containers", "helper"), "alternate.invalid/phorvex/brain", "registry.invalid/unrelated/tool", 1)},
		{"init container", extraConsumerManifest("Deployment", "init", "initContainers", "bootstrap")},
		{"ephemeral container", extraConsumerManifest("Deployment", "debug", "ephemeralContainers", "debugger")},
		{"statefulset", extraConsumerManifest("StatefulSet", "stateful", "containers", "brain")},
		{"daemonset", extraConsumerManifest("DaemonSet", "daemon", "containers", "brain")},
		{"job", extraConsumerManifest("Job", "job", "containers", "brain")},
		{"cronjob", extraConsumerManifest("CronJob", "cron", "containers", "brain")},
		{"hook job", strings.Replace(extraConsumerManifest("Job", "hook", "containers", "brain"), "metadata:\n", "metadata:\n  annotations:\n    helm.sh/hook: test\n", 1)},
		{"pod", extraConsumerManifest("Pod", "pod", "containers", "brain")},
		{"custom controller pod template", extraConsumerManifest("BrainFleet", "fleet", "containers", "brain")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeConsumerFixture(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: brain\nversion: 0.1.0\n")
			writeConsumerFixture(t, root, "chart/values.yaml", "{}\n")
			writeConsumerFixture(t, root, "values.yaml", fixtureValues("image"))
			writeConsumerFixture(t, root, "chart/templates/workloads.yaml", fixtureDeployment("{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}")+"---\n"+test.manifest)
			_, _, err := probeConsumers(root, fixtureRoute(), fixtureTarget("image"), "brain", nil)
			if err == nil || (!strings.Contains(err.Error(), "unbound authoritative") && !strings.Contains(err.Error(), "cross-component")) {
				t.Fatalf("unbound %s error = %v", test.name, err)
			}
		})
	}
}

func TestExactIsolatedStagingConsumerIsTheOnlyExternalConsumerAllowed(t *testing.T) {
	consumer := ImageConsumer{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: "p6-demo", Name: "agent-sim",
		Section: "containers", Container: "agent-sim", FieldPath: "/spec/template/spec/containers/0/image",
	}
	image := ReleaseRegistry + "/" + StagingRepositoryPrefix + "agent-sim@sha256:" + strings.Repeat("a", 64)
	if !exactIsolatedStagingConsumer("attacks", consumer, image) {
		t.Fatal("exact isolated staging consumer was rejected")
	}
	for _, test := range []struct {
		name, component, image string
		consumer               ImageConsumer
	}{
		{"wrong component", "manager", image, consumer},
		{"wrong namespace", "attacks", image, func() ImageConsumer { changed := consumer; changed.Namespace = "default"; return changed }()},
		{"shared repository", "attacks", ReleaseRegistry + "/phorvex/agent-sim@sha256:" + strings.Repeat("a", 64), consumer},
		{"mutable tag", "attacks", ReleaseRegistry + "/" + StagingRepositoryPrefix + "agent-sim:latest", consumer},
	} {
		t.Run(test.name, func(t *testing.T) {
			if exactIsolatedStagingConsumer(test.component, test.consumer, test.image) {
				t.Fatal("non-exact isolated staging consumer was accepted")
			}
		})
	}
}

func TestWorkloadImagesRejectsImageVolumes(t *testing.T) {
	imageVolume := "volumes:\n- name: rogue\n  image:\n    reference: alternate.invalid/phorvex/brain:shared\n"
	for _, test := range []struct {
		name, manifest string
	}{
		{
			name: "pod with container",
			manifest: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: image-volume\nspec:\n  " +
				strings.ReplaceAll(imageVolume, "\n", "\n  ") +
				"containers:\n  - name: brain\n    image: alternate.invalid/phorvex/brain:shared\n",
		},
		{
			name: "nested volume-only template",
			manifest: "apiVersion: example.invalid/v1\nkind: BrainFleet\nmetadata:\n  name: image-volume-only\nspec:\n  podTemplate:\n    spec:\n      " +
				strings.ReplaceAll(imageVolume, "\n", "\n      "),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := workloadImages([]byte(test.manifest))
			if err == nil || !strings.Contains(err.Error(), "image volume") ||
				!strings.Contains(err.Error(), "unsupported by the release consumer contract") {
				t.Fatalf("image-volume consumer error = %v", err)
			}
		})
	}
}

func TestConsumerProbeRejectsConsumersAddedOrRemovedBetweenRenderPhases(t *testing.T) {
	primary := fixtureDeployment("old.invalid/phorvex/brain:0.1.0@sha256:" + strings.Repeat("0", 64))
	extra := "---\n" + extraConsumerManifest("Deployment", "dynamic", "containers", "brain")
	for _, test := range []struct {
		name   string
		render [][]byte
	}{
		{"added", [][]byte{[]byte(primary), []byte(primary + extra)}},
		{"removed", [][]byte{[]byte(primary + extra), []byte(primary)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeConsumerFixture(t, root, "values.yaml", fixtureValues("image"))
			previous := renderReleaseChart
			calls := 0
			renderReleaseChart = func(string, deploymentRoute, string, []byte) ([]byte, error) {
				result := test.render[min(calls, len(test.render)-1)]
				calls++
				return result, nil
			}
			t.Cleanup(func() { renderReleaseChart = previous })
			_, _, err := probeConsumers(root, fixtureRoute(), fixtureTarget("image"), "brain", nil)
			if err == nil || !strings.Contains(err.Error(), "rendered workload set") {
				t.Fatalf("dynamic %s consumer error = %v", test.name, err)
			}
		})
	}
}

func TestAllSixStagingDeploymentsRenderTheVerifiedImage(t *testing.T) {
	useRealReleaseRenderer(t)
	root, err := git(".", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatal(err)
	}
	root = strings.TrimSpace(root)
	for i := range Components {
		component := &Components[i]
		t.Run(component.Name, func(t *testing.T) {
			target := ComponentDeploy{
				Chart:      component.Chart,
				ValuesFile: filepath.ToSlash(filepath.Join("deploy", "environments", ReleaseEnvironment, component.Deploy.File+".yaml")),
				Path:       append([]string(nil), component.Deploy.Path...), RepositoryKey: component.Deploy.Repository,
				TagKey: component.Deploy.Tag, DigestKey: component.Deploy.Digest, SourceKey: component.Deploy.Source,
			}
			contract, err := buildComponentDeployment(root, ReleaseEnvironment, component, target, true)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(contract.ValuesFile)))
			if err != nil {
				t.Fatal(err)
			}
			repository := ReleaseRegistry + "/" + component.Repository
			tag := "9.9.9"
			digest := "sha256:" + strings.Repeat(string(rune('a'+i)), 64)
			candidate, err := mutateDeploymentValues(raw, contract, repository, tag, digest, strings.Repeat("a", 40))
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := pinValuesRaw(candidate, contract)
			if err != nil {
				t.Fatal(err)
			}
			if persisted[contract.RepositoryKey] != repository || persisted[contract.TagKey] != tag || persisted[contract.DigestKey] != digest {
				t.Fatalf("candidate release metadata = %#v", persisted)
			}
			if contract.SourceKey != "" && persisted[contract.SourceKey] != strings.Repeat("a", 40) {
				t.Fatalf("candidate source metadata = %#v", persisted)
			}
			consumers, images, err := probeConsumers(root, routeFromContract(contract), contract, component.Name, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(consumers, contract.Consumers) {
				t.Fatalf("candidate consumers = %#v, source consumers = %#v", consumers, contract.Consumers)
			}
			want := expectedRenderedImage(repository, tag, digest)
			for _, consumer := range consumers {
				if got := images[consumer.key()]; got != want {
					t.Fatalf("%s renders %q, want %q", strings.ReplaceAll(consumer.key(), "\x00", "/"), got, want)
				}
			}
		})
	}
}
