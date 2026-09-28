package console

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These literal values come from the reviewed release's GitOps configuration,
// separately from the target profile. Neither API callers nor discovered tags
// can authorize an image. Actual runtime imageIDs must match the published index.
type DrainComponentRelease struct {
	TemplateImage string `json:"templateImage"`
	Image         string `json:"image"`
	SourceSHA     string `json:"sourceSHA"`
}
type DrainReleaseAuthority struct {
	Manager DrainComponentRelease `json:"manager"`
	Console DrainComponentRelease `json:"console"`
}
type drainReleaseAuthority = DrainReleaseAuthority

var drainSourceSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var drainImageTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

func (r DrainComponentRelease) valid() bool {
	if !mongoPinnedImage.MatchString(r.Image) || !drainSourceSHA.MatchString(r.SourceSHA) {
		return false
	}
	repo, _, ok := strings.Cut(r.Image, "@sha256:")
	return ok && (r.TemplateImage == r.Image || (strings.HasPrefix(r.TemplateImage, repo+":") && drainImageTag.MatchString(strings.TrimPrefix(r.TemplateImage, repo+":"))))
}
func (r DrainReleaseAuthority) valid() bool { return r.Manager.valid() && r.Console.valid() }

type drainComponentIdentity struct {
	DeploymentName       string `json:"deploymentName"`
	DeploymentUID        string `json:"deploymentUID"`
	DeploymentGeneration int64  `json:"deploymentGeneration"`
	TemplateSHA256       string `json:"templateSHA256"`
	ReplicaSetUID        string `json:"replicaSetUID"`
	PodName              string `json:"podName"`
	PodUID               string `json:"podUID"`
	ContainerID          string `json:"containerID"`
	ImageID              string `json:"imageID"`
}
type drainComponentSnapshot struct {
	Schema        string                 `json:"schema"`
	Release       DrainReleaseAuthority  `json:"release"`
	ReleaseSHA256 string                 `json:"releaseSHA256"`
	Manager       drainComponentIdentity `json:"manager"`
	Console       drainComponentIdentity `json:"console"`
}

func drainOwnedBy(refs []metav1.OwnerReference, kind, name, uid string) bool {
	n := 0
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			n++
			if r.Kind != kind || r.Name != name || string(r.UID) != uid {
				return false
			}
		}
	}
	return n == 1
}
func drainTemplateEqual(a, b corev1.PodTemplateSpec) bool {
	// The Deployment controller adds exactly this one label to its ReplicaSet.
	a = *a.DeepCopy()
	b = *b.DeepCopy()
	delete(a.Labels, "pod-template-hash")
	delete(b.Labels, "pod-template-hash")
	return reflect.DeepEqual(a, b)
}

// Kubernetes adds only the standard ServiceAccount projection when automount is enabled.
func drainAdmittedContainerMatches(actual, want corev1.Container, volumes []corev1.Volume) bool {
	if reflect.DeepEqual(actual, want) {
		return true
	}
	copy := *actual.DeepCopy()
	copy.VolumeMounts = nil
	for _, mount := range actual.VolumeMounts {
		known := false
		for _, m := range want.VolumeMounts {
			if reflect.DeepEqual(mount, m) {
				known = true
			}
		}
		if known {
			copy.VolumeMounts = append(copy.VolumeMounts, mount)
			continue
		}
		if mount.MountPath != "/var/run/secrets/kubernetes.io/serviceaccount" || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" || mount.MountPropagation != nil || mount.RecursiveReadOnly != nil || !strings.HasPrefix(mount.Name, "kube-api-access-") {
			return false
		}
		valid := false
		for _, v := range volumes {
			if v.Name != mount.Name || v.Projected == nil {
				continue
			}
			p := v.Projected
			if p.DefaultMode == nil || *p.DefaultMode != 420 || len(p.Sources) != 3 {
				continue
			}
			t, c, d := p.Sources[0], p.Sources[1], p.Sources[2]
			valid = t.ServiceAccountToken != nil && t.ConfigMap == nil && t.DownwardAPI == nil && t.Secret == nil && t.ServiceAccountToken.Path == "token" && t.ServiceAccountToken.Audience == "" && t.ServiceAccountToken.ExpirationSeconds != nil && *t.ServiceAccountToken.ExpirationSeconds == 3607 && c.ConfigMap != nil && c.ServiceAccountToken == nil && c.DownwardAPI == nil && c.Secret == nil && c.ConfigMap.Name == "kube-root-ca.crt" && c.ConfigMap.Optional == nil && len(c.ConfigMap.Items) == 1 && c.ConfigMap.Items[0].Key == "ca.crt" && c.ConfigMap.Items[0].Path == "ca.crt" && d.DownwardAPI != nil && d.ConfigMap == nil && d.ServiceAccountToken == nil && d.Secret == nil && len(d.DownwardAPI.Items) == 1 && d.DownwardAPI.Items[0].Path == "namespace" && d.DownwardAPI.Items[0].FieldRef != nil && d.DownwardAPI.Items[0].FieldRef.APIVersion == "v1" && d.DownwardAPI.Items[0].FieldRef.FieldPath == "metadata.namespace"
			if valid {
				break
			}
		}
		if !valid {
			return false
		}
	}
	return reflect.DeepEqual(copy, want)
}

func drainAdmittedVolumesMatch(actual, want []corev1.Volume) bool {
	if len(actual) < len(want) || len(actual) > len(want)+1 {
		return false
	}
	matched := make(map[string]bool)
	extra := 0
	for _, volume := range actual {
		if matched[volume.Name] {
			return false
		}
		matched[volume.Name] = true
		known := false
		for _, expected := range want {
			if volume.Name == expected.Name {
				if !reflect.DeepEqual(volume, expected) {
					return false
				}
				known = true
			}
		}
		if known {
			continue
		}
		extra++
		mount := corev1.VolumeMount{Name: volume.Name, MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true}
		if !drainAdmittedContainerMatches(corev1.Container{VolumeMounts: []corev1.VolumeMount{mount}}, corev1.Container{}, []corev1.Volume{volume}) {
			return false
		}
	}
	return len(matched)-extra == len(want)
}

func drainValidateComponent(dep appsv1.Deployment, sets appsv1.ReplicaSetList, pods corev1.PodList, name, uid, component string, release DrainComponentRelease, selfName, selfUID string) (drainComponentIdentity, error) {
	bad := drainLiveStaticIssue("component incarnation drift")
	if !release.valid() || dep.Name != name || string(dep.UID) != uid || dep.Namespace != "phorvex-system" || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || dep.Status.ObservedGeneration != dep.Generation || dep.Status.Replicas != 1 || dep.Status.UpdatedReplicas != 1 || dep.Status.ReadyReplicas != 1 || dep.Status.AvailableReplicas != 1 || dep.Status.UnavailableReplicas != 0 {
		return drainComponentIdentity{}, bad
	}
	expectedSA := "phorvex-phorvex-manager"
	if component == "console" {
		expectedSA = "phorvex-phorvex-console"
	}
	if dep.Spec.Template.Spec.ServiceAccountName != expectedSA || len(dep.Spec.Template.Spec.Containers) != 1 || len(dep.Spec.Template.Spec.InitContainers) != 0 || dep.Spec.Template.Spec.HostNetwork || dep.Spec.Template.Spec.HostPID || dep.Spec.Template.Spec.HostIPC {
		return drainComponentIdentity{}, bad
	}
	count := 0
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == component {
			count++
			if c.Image != release.TemplateImage || len(c.Command) != 0 {
				return drainComponentIdentity{}, bad
			}
		}
	}
	if count != 1 {
		return drainComponentIdentity{}, bad
	}
	var selected *appsv1.ReplicaSet
	for i := range sets.Items {
		r := &sets.Items[i]
		if !drainOwnedBy(r.OwnerReferences, "Deployment", name, uid) {
			continue
		}
		if r.Namespace != "phorvex-system" || r.DeletionTimestamp != nil {
			if r.Spec.Replicas != nil && *r.Spec.Replicas > 0 {
				return drainComponentIdentity{}, bad
			}
			continue
		}
		if r.Spec.Replicas != nil && *r.Spec.Replicas > 0 {
			if selected != nil || *r.Spec.Replicas != 1 || r.Status.ObservedGeneration != r.Generation || r.Status.Replicas != 1 || r.Status.ReadyReplicas != 1 || r.Status.AvailableReplicas != 1 || !drainTemplateEqual(dep.Spec.Template, r.Spec.Template) {
				return drainComponentIdentity{}, bad
			}
			selected = r
		}
	}
	if selected == nil {
		return drainComponentIdentity{}, bad
	}
	var selectedPod *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		belongs := false
		for _, r := range sets.Items {
			if drainOwnedBy(r.OwnerReferences, "Deployment", name, uid) && drainOwnedBy(p.OwnerReferences, "ReplicaSet", r.Name, string(r.UID)) {
				belongs = true
				break
			}
		}
		if !belongs {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if selectedPod != nil || p.Namespace != "phorvex-system" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || !drainOwnedBy(p.OwnerReferences, "ReplicaSet", selected.Name, string(selected.UID)) || p.Spec.ServiceAccountName != expectedSA {
			return drainComponentIdentity{}, bad
		}
		selectedPod = p
	}
	if selectedPod == nil || selectedPod.UID == "" || (component == "console" && (selectedPod.Name != selfName || string(selectedPod.UID) != selfUID)) {
		return drainComponentIdentity{}, bad
	}
	ready := false
	for _, c := range selectedPod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready || !drainAdmittedVolumesMatch(selectedPod.Spec.Volumes, selected.Spec.Template.Spec.Volumes) || len(selectedPod.Spec.Containers) != 1 || len(selectedPod.Spec.InitContainers) != 0 || len(selectedPod.Spec.EphemeralContainers) != 0 || selectedPod.Spec.HostNetwork || selectedPod.Spec.HostPID || selectedPod.Spec.HostIPC {
		return drainComponentIdentity{}, bad
	}
	// Admission-injected projected volumes do not redefine image authority. The
	// container itself must exactly originate from the current ReplicaSet template.
	count = 0
	for _, c := range selectedPod.Spec.Containers {
		if c.Name == component {
			count++
			found := false
			for _, t := range selected.Spec.Template.Spec.Containers {
				if t.Name == component && drainAdmittedContainerMatches(c, t, selectedPod.Spec.Volumes) {
					found = true
				}
			}
			if !found {
				return drainComponentIdentity{}, bad
			}
		}
	}
	if count != 1 {
		return drainComponentIdentity{}, bad
	}
	var status *corev1.ContainerStatus
	for i := range selectedPod.Status.ContainerStatuses {
		c := &selectedPod.Status.ContainerStatuses[i]
		if c.Name == component {
			if status != nil {
				return drainComponentIdentity{}, bad
			}
			status = c
		}
	}
	if status == nil || !status.Ready || status.State.Running == nil || status.State.Running.StartedAt.IsZero() || status.ContainerID == "" || status.ImageID != release.Image {
		return drainComponentIdentity{}, bad
	}
	return drainComponentIdentity{name, uid, dep.Generation, availabilityHash(drainJSON(dep.Spec.Template)), string(selected.UID), selectedPod.Name, string(selectedPod.UID), status.ContainerID, status.ImageID}, nil
}
func (s *Server) drainComponents(ctx context.Context, out string, p drainLiveProfile, phase string) (drainComponentSnapshot, error) {
	bad := drainLiveStaticIssue("component incarnation drift")
	if !p.release.valid() {
		return drainComponentSnapshot{}, drainLiveStaticIssue("component release authority unavailable")
	}
	var sets appsv1.ReplicaSetList
	var pods corev1.PodList
	read := func(label string, dst any, args ...string) error {
		raw, e := s.drainReadKube(ctx, out, phase+"-"+label, false, args...)
		if e != nil {
			return bad
		}
		if json.Unmarshal(raw, dst) != nil {
			return bad
		}
		return nil
	}
	if err := read("component-replicasets", &sets, "-n", "phorvex-system", "get", "replicasets", "-l", "app.kubernetes.io/instance=phorvex,app.kubernetes.io/component in (manager,console)", "-o", "json"); err != nil {
		return drainComponentSnapshot{}, err
	}
	if err := read("component-pods", &pods, "-n", "phorvex-system", "get", "pods", "-l", "app.kubernetes.io/instance=phorvex,app.kubernetes.io/component in (manager,console)", "-o", "json"); err != nil {
		return drainComponentSnapshot{}, err
	}
	if len(sets.Items) > 128 || len(pods.Items) > 128 {
		return drainComponentSnapshot{}, bad
	}
	var manager, console appsv1.Deployment
	if err := read("manager-deployment", &manager, "-n", "phorvex-system", "get", "deployment", p.ManagerDeploymentName, "-o", "json"); err != nil {
		return drainComponentSnapshot{}, err
	}
	if err := read("console-deployment", &console, "-n", "phorvex-system", "get", "deployment", p.ConsoleDeploymentName, "-o", "json"); err != nil {
		return drainComponentSnapshot{}, err
	}
	m, e := drainValidateComponent(manager, sets, pods, p.ManagerDeploymentName, p.ManagerDeploymentUID, "manager", p.release.Manager, "", "")
	if e != nil {
		return drainComponentSnapshot{}, e
	}
	c, e := drainValidateComponent(console, sets, pods, p.ConsoleDeploymentName, p.ConsoleDeploymentUID, "console", p.release.Console, os.Getenv("PHORVEX_CONSOLE_POD_NAME"), os.Getenv("PHORVEX_CONSOLE_POD_UID"))
	if e != nil {
		return drainComponentSnapshot{}, e
	}
	return drainComponentSnapshot{"drain-component-snapshot-v1", p.release, availabilityHash(drainJSON(p.release)), m, c}, nil
}
func (s *Server) drainComponentBarrier(ctx context.Context, out string, p drainLiveProfile, phase string) error {
	if p.Schema != "live-request-drain-v2" {
		return nil
	}
	current, err := s.drainComponents(ctx, out, p, phase)
	if err != nil {
		return err
	}
	if p.components == nil || current != *p.components {
		return drainLiveStaticIssue("component incarnation drift")
	}
	return publishMongoAuditFile(out, phase+"-component-snapshot.json", drainJSON(current), 16<<10)
}

func drainDecisionReleaseMatches(d *decisionEvidence, p drainLiveProfile) bool {
	if p.Schema != "live-request-drain-v2" {
		return true
	}
	return d != nil && p.release.valid() && d.BrainImage == p.release.Manager.TemplateImage && d.GitSHA == p.release.Manager.SourceSHA
}
