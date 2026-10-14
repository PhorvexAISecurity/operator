package console

import (
	"context"
	"encoding/json"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func drainComponentFixture(component string) (appsv1.Deployment, appsv1.ReplicaSetList, corev1.PodList, DrainComponentRelease) {
	one := int32(1)
	yes := true
	a := DrainComponentRelease{"repo.invalid/" + component + ":reviewed", "repo.invalid/" + component + "@sha256:" + strings.Repeat("b", 64), strings.Repeat("a", 40)}
	name := "phorvex-phorvex"
	sa := "phorvex-phorvex-manager"
	if component == "console" {
		name += "-console"
		sa = "phorvex-phorvex-console"
	}
	d := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "phorvex-system", UID: types.UID(component + "-dep"), Generation: 7}, Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: sa, Containers: []corev1.Container{{Name: component, Image: a.TemplateImage}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 7, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}}
	r := appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: component + "-rs", Namespace: "phorvex-system", UID: types.UID(component + "-rs"), Generation: 1, OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: &yes}}}, Spec: appsv1.ReplicaSetSpec{Replicas: &one, Template: d.Spec.Template}, Status: appsv1.ReplicaSetStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}}
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: component + "-pod", Namespace: "phorvex-system", UID: types.UID(component + "-pod"), OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: r.Name, UID: r.UID, Controller: &yes}}}, Spec: d.Spec.Template.Spec, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: component, Ready: true, ContainerID: "containerd://current", ImageID: a.Image, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Unix(1, 0))}}}}}}
	return d, appsv1.ReplicaSetList{Items: []appsv1.ReplicaSet{r}}, corev1.PodList{Items: []corev1.Pod{p}}, a
}
func TestDrainV2ProfileOwnerPinsAndUnchangedV1(t *testing.T) {
	old := drainTestProfile()
	b, _ := json.Marshal(old)
	if _, e := parseDrainLiveProfile(b); e != nil {
		t.Fatal(e)
	}
	p := old
	p.Schema = "live-request-drain-v2"
	p.ManagerDeploymentName = "phorvex-phorvex"
	p.ManagerDeploymentUID = old.ManagerPodUID
	p.ManagerPodName = ""
	p.ManagerPodUID = ""
	p.ManagerContainerID = ""
	p.ManagerImageID = ""
	p.ConsoleImageID = ""
	b, _ = json.Marshal(p)
	if _, e := parseDrainLiveProfile(b); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*drainLiveProfile){func(p *drainLiveProfile) { p.ManagerPodUID = old.ManagerPodUID }, func(p *drainLiveProfile) { p.ManagerImageID = old.ManagerImageID }, func(p *drainLiveProfile) { p.ConsoleImageID = old.ConsoleImageID }, func(p *drainLiveProfile) { p.ManagerDeploymentUID = "" }, func(p *drainLiveProfile) { p.ProxyImageID = "" }, func(p *drainLiveProfile) { p.PodUID = "" }, func(p *drainLiveProfile) { p.DrainEngineSourceSHA256 = "" }} {
		q := p
		change(&q)
		b, _ = json.Marshal(q)
		if _, e := parseDrainLiveProfile(b); e == nil {
			t.Fatal("mixed/missing authority accepted")
		}
	}
	old.ManagerDeploymentUID = p.ManagerDeploymentUID
	b, _ = json.Marshal(old)
	if _, e := parseDrainLiveProfile(b); e == nil {
		t.Fatal("v1 changed")
	}
}
func TestDrainComponentReplacementAndNegativeGates(t *testing.T) {
	d, r, p, a := drainComponentFixture("manager")
	before, e := drainValidateComponent(d, r, p, d.Name, string(d.UID), "manager", a, "", "")
	if e != nil {
		t.Fatal(e)
	}
	p.Items[0].UID = "new"
	p.Items[0].Status.ContainerStatuses[0].ContainerID = "containerd://new"
	after, e := drainValidateComponent(d, r, p, d.Name, string(d.UID), "manager", a, "", "")
	if e != nil || before == after {
		t.Fatal("replacement refused or hidden", e)
	}

	// A later reviewed component publication changes authority and owner runtime
	// identities, while the stable target profile keeps the same Deployment UID.
	a.TemplateImage = "repo.invalid/manager:later-reviewed"
	a.Image = "repo.invalid/manager@sha256:" + strings.Repeat("c", 64)
	a.SourceSHA = strings.Repeat("d", 40)
	d.Generation++
	d.Status.ObservedGeneration = d.Generation
	d.Spec.Template.Spec.Containers[0].Image = a.TemplateImage
	r.Items[0].Spec.Template = *d.Spec.Template.DeepCopy()
	p.Items[0].Spec = *d.Spec.Template.Spec.DeepCopy()
	p.Items[0].Status.ContainerStatuses[0].ImageID = a.Image
	if _, e := drainValidateComponent(d, r, p, d.Name, string(d.UID), "manager", a, "", ""); e != nil {
		t.Fatal("reviewed release still requires profile refresh", e)
	}
	for _, change := range []func(*appsv1.Deployment, *appsv1.ReplicaSetList, *corev1.PodList, *DrainComponentRelease){func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		d.Status.ObservedGeneration--
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		p.Items = append(p.Items, *p.Items[0].DeepCopy())
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		p.Items[0].OwnerReferences[0].UID = "old"
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		p.Items[0].Spec.ServiceAccountName = "foreign"
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		a.Image = a.TemplateImage
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		a.SourceSHA = ""
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		p.Items[0].Status.ContainerStatuses[0].ImageID = "unknown"
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		p.Items[0].Spec.Containers = append(p.Items[0].Spec.Containers, corev1.Container{Name: "sidecar"})
	}, func(d *appsv1.Deployment, r *appsv1.ReplicaSetList, p *corev1.PodList, a *DrainComponentRelease) {
		p.Items[0].Status.ContainerStatuses[0].ImageID = "repo.invalid/manager@sha256:" + strings.Repeat("e", 64)
	}} {
		d, r, p, a := drainComponentFixture("manager")
		change(&d, &r, &p, &a)
		if _, e := drainValidateComponent(d, r, p, d.Name, string(d.UID), "manager", a, "", ""); e == nil {
			t.Fatal("bad binding accepted")
		}
	}
}
func TestDrainComponentArchived399Bindings(t *testing.T) {
	root := os.Getenv("PHORVEX_DRAIN_ARCHIVE_399")
	if root == "" {
		t.Skip("private originals supplied by review")
	}
	read := func(name string, v any) {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b, v); e != nil {
			t.Fatal(e)
		}
	}
	var deps appsv1.DeploymentList
	var sets appsv1.ReplicaSetList
	var pods corev1.PodList
	read("final-deployments.json", &deps)
	read("final-replicasets.json", &sets)
	read("final-pods.json", &pods)
	var report struct {
		Components map[string]struct {
			TemplateImage string `json:"templateImage"`
			ActualImageID string `json:"actualImageID"`
			SourceSHA     string `json:"sourceSHA"`
			PodName       string `json:"podName"`
			PodUID        string `json:"podUID"`
		}
	}
	read("INDEPENDENT-RELEASE-REVIEW.json", &report)
	for _, d := range deps.Items {
		component := "manager"
		if strings.HasSuffix(d.Name, "-console") {
			component = "console"
		}
		c := report.Components[component]
		if _, e := drainValidateComponent(d, sets, pods, d.Name, string(d.UID), component, DrainComponentRelease{c.TemplateImage, c.ActualImageID, c.SourceSHA}, c.PodName, c.PodUID); e != nil {
			t.Fatalf("actual %s399 refused: %v", component, e)
		}
	}
}
func TestDrainComponentBarrierRejectsActualReplacement(t *testing.T) {
	md, mr, mp, ma := drainComponentFixture("manager")
	cd, cr, cp, ca := drainComponentFixture("console")
	root := t.TempDir()
	out := t.TempDir()
	sets := appsv1.ReplicaSetList{Items: append(mr.Items, cr.Items...)}
	pods := corev1.PodList{Items: append(mp.Items, cp.Items...)}
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		if e := os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("sets", sets)
	write("pods", pods)
	write("manager", md)
	write("console", cd)
	script := "#!/bin/sh\ncase \"$*\" in\n*'get replicasets'*) cat '" + root + "/sets';;\n*'get pods'*) cat '" + root + "/pods';;\n*'get deployment phorvex-phorvex-console'*) cat '" + root + "/console';;\n*'get deployment phorvex-phorvex'*) cat '" + root + "/manager';;\n*) exit 2;;\nesac\n"
	if e := os.WriteFile(filepath.Join(root, "kubectl"), []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PHORVEX_CONSOLE_POD_NAME", cp.Items[0].Name)
	t.Setenv("PHORVEX_CONSOLE_POD_UID", string(cp.Items[0].UID))
	p := drainLiveProfile{Schema: "live-request-drain-v2", ManagerDeploymentName: md.Name, ManagerDeploymentUID: string(md.UID), ConsoleDeploymentName: cd.Name, ConsoleDeploymentUID: string(cd.UID), release: DrainReleaseAuthority{ma, ca}}
	s := &Server{}
	captured, e := s.drainComponents(context.Background(), out, p, "captured")
	if e != nil {
		t.Fatal(e)
	}
	p.components = &captured
	if e = s.drainComponentBarrier(context.Background(), out, p, "pre-event"); e != nil {
		t.Fatal(e)
	}
	pods.Items[0].UID = "new"
	pods.Items[0].Status.ContainerStatuses[0].ContainerID = "containerd://new"
	write("pods", pods)
	if e = s.drainComponentBarrier(context.Background(), out, p, "closing"); e == nil {
		t.Fatal("mid-run replacement recaptured")
	}
}

func TestDrainComponentAuditBuildAuthorityAndSanitizedEvidence(t *testing.T) {
	_, _, _, a := drainComponentFixture("manager")
	_, _, _, c := drainComponentFixture("console")
	p := drainLiveProfile{Schema: "live-request-drain-v2", release: DrainReleaseAuthority{a, c}}
	d := &decisionEvidence{BrainImage: a.TemplateImage, GitSHA: a.SourceSHA}
	if !drainDecisionReleaseMatches(d, p) {
		t.Fatal("reviewed build refused")
	}
	d.GitSHA = strings.Repeat("e", 40)
	if drainDecisionReleaseMatches(d, p) {
		t.Fatal("other source accepted")
	}
	d.GitSHA = a.SourceSHA
	d.BrainImage = "repo.invalid/manager:unreviewed"
	if drainDecisionReleaseMatches(d, p) {
		t.Fatal("other template accepted")
	}
	// Run the actual bounded producer read, not a rendering helper, against
	// secret-like spec/status/metadata fields. Originals remain in memory only.
	root := t.TempDir()
	out := t.TempDir()
	payload := `{"items":[{"metadata":{"name":"manager","uid":"current","annotations":{"private":"private-token"}},"spec":{"containers":[{"env":[{"name":"TOKEN","value":"private-token"}]}]},"status":{"phase":"Running","message":"private-token","containerStatuses":[{"name":"manager","ready":true,"imageID":"reviewed","containerID":"current","lastState":{"terminated":{"message":"private-token"}}}]}}]}`
	if e := os.WriteFile(filepath.Join(root, "payload"), []byte(payload), 0600); e != nil {
		t.Fatal(e)
	}
	script := "#!/bin/sh\ncat '" + root + "/payload'\n"
	if e := os.WriteFile(filepath.Join(root, "kubectl"), []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := &Server{}
	raw, e := s.drainReadKube(context.Background(), out, "captured-component-pods", false, "get", "pods")
	if e != nil || !strings.Contains(string(raw), "private-token") {
		t.Fatal("original source absent", e)
	}
	saved, e := os.ReadFile(filepath.Join(out, "captured-component-pods.json"))
	if e != nil || strings.Contains(string(saved), "private-token") || !strings.Contains(string(saved), "specSHA256") {
		t.Fatal("private source was persisted or hash lost", e)
	}
}

func TestDrainCompletionDuringComponentBarrierHasNoEventOverlap(t *testing.T) {
	stream := &drainStreamRun{done: make(chan error, 1), final: make(chan drainStreamRow, 1)}
	r := &attackRecord{DrainLiveProbe: &drainLiveProbeResult{}}
	out := t.TempDir()
	if ended, err := drainNoOverlapIfCompleted(out, r, stream); ended || err != nil {
		t.Fatal("live producer refused", err)
	}
	// The actual stream producer finishes while component authority is resolved.
	stream.final <- drainStreamRow{Original: []byte(`{"stage":"final","done":true}`), Done: true}
	stream.done <- nil
	if ended, err := drainNoOverlapIfCompleted(out, r, stream); !ended || err != nil || r.DrainLiveProbe.Status != "NO_DISCRIMINATING_OVERLAP" {
		t.Fatal("completed stream remained eligible", err)
	}
	if r.StimulusEvidence != nil {
		t.Fatal("event evidence fabricated")
	}
}

func TestDrainComponentRejectsMountedVolumeSubstitution(t *testing.T) {
	d, r, p, a := drainComponentFixture("manager")
	volume := corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "reviewed"}}}}
	d.Spec.Template.Spec.Volumes = []corev1.Volume{volume}
	r.Items[0].Spec.Template = *d.Spec.Template.DeepCopy()
	p.Items[0].Spec = *d.Spec.Template.Spec.DeepCopy()
	if _, err := drainValidateComponent(d, r, p, d.Name, string(d.UID), "manager", a, "", ""); err != nil {
		t.Fatal(err)
	}
	p.Items[0].Spec.Volumes[0].ConfigMap.Name = "substituted"
	if _, err := drainValidateComponent(d, r, p, d.Name, string(d.UID), "manager", a, "", ""); err == nil {
		t.Fatal("same container with different mounted source accepted")
	}
}

func TestDrainComponentNativeMetricsSidecarRestriction(t *testing.T) {
	profile, snap, _ := revalidationFixture(t)
	workload := leaseTestServingPod(profile, snap.Pods[0])
	leaseTestAddNativeMetrics(&workload)
	service := &corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "vllm"}}}
	if !endpointLeaseReadyPod(&workload, profile, service) {
		t.Fatal("vllm workload with a native metrics init sidecar refused")
	}
	for _, component := range []string{"manager", "console"} {
		for _, gate := range []string{"deployment-template", "admitted-pod"} {
			t.Run(component+"/"+gate, func(t *testing.T) {
				dep, sets, pods, release := drainComponentFixture(component)
				selfName, selfUID := pods.Items[0].Name, string(pods.Items[0].UID)
				// Keep volumes equal at both zero-init gates so an unrelated mount
				// mismatch cannot explain the refusal of the added init container.
				dep.Spec.Template.Spec.Volumes = leaseTestMetricsVolumes()
				sets.Items[0].Spec.Template = *dep.Spec.Template.DeepCopy()
				pods.Items[0].Spec = *dep.Spec.Template.Spec.DeepCopy()
				// The same vllm workload is outside this component's owner graph.
				pods.Items = append(pods.Items, workload)
				before, err := drainValidateComponent(dep, sets, pods, dep.Name, string(dep.UID), component, release, selfName, selfUID)
				if err != nil {
					t.Fatalf("reviewed zero-init phorvex-system %s refused: %v", component, err)
				}
				if before.PodUID != selfUID || before.ContainerID != "containerd://current" || before.ImageID != release.Image {
					t.Fatalf("component authority escaped phorvex-system: %+v", before)
				}
				metrics := leaseTestMetricsSidecar()
				if gate == "deployment-template" {
					dep.Spec.Template.Spec.InitContainers = []corev1.Container{metrics}
					sets.Items[0].Spec.Template = *dep.Spec.Template.DeepCopy()
					pods.Items[0].Spec = *dep.Spec.Template.Spec.DeepCopy()
				} else {
					pods.Items[0].Spec.InitContainers = []corev1.Container{metrics}
				}
				pods.Items[0].Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: metrics.Name, Ready: true,
					ContainerID: "containerd://metrics", ImageID: metrics.Image, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
				if _, err := drainValidateComponent(dep, sets, pods, dep.Name, string(dep.UID), component, release, selfName, selfUID); err == nil {
					t.Fatalf("%s accepted an init sidecar at its %s zero-init gate", component, gate)
				}
				if !endpointLeaseReadyPod(&workload, profile, service) {
					t.Fatal("component init restriction contaminated vllm workload acceptance")
				}
			})
		}
	}
}
