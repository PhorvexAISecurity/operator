package ingest

import (
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/phorvex/phorvex/internal/model"
)

// bindPodBoundKubeAPIAuth recognizes only the admitted, mounted default-API-
// audience projection of a currently Running Pod. Kubernetes binds projected
// service-account tokens to that Pod's UID; this metadata is still only a
// potential capability, not proof a bearer was issued or stolen. A ServiceAccount
// created at or after the Pod may be a replacement for the account that issued
// its token, so its UID cannot be used as a positive current identity witness.
func bindPodBoundKubeAPIAuth(pods []model.Pod, objects []corev1.Pod, accounts []corev1.ServiceAccount) {
	byAccount := make(map[string]*corev1.ServiceAccount, len(accounts))
	duplicates := make(map[string]bool)
	for i := range accounts {
		sa := &accounts[i]
		key := sa.Namespace + "/" + sa.Name
		if _, exists := byAccount[key]; exists {
			duplicates[key] = true
		}
		byAccount[key] = sa
	}
nextPod:
	for i := range pods {
		pod := &objects[i]
		projected := &pods[i]
		projected.PodBoundKubeAPIAuth = nil // a refresh cannot retain a former identity witness
		key := pod.Namespace + "/" + projected.ServiceAccount
		if duplicates[key] {
			continue
		}
		sa := byAccount[key]
		if sa == nil || sa.UID == "" || sa.ResourceVersion == "" || sa.DeletionTimestamp != nil ||
			pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil ||
			pod.CreationTimestamp.IsZero() || sa.CreationTimestamp.IsZero() ||
			!sa.CreationTimestamp.Time.Before(pod.CreationTimestamp.Time) ||
			pod.Status.Phase != corev1.PodRunning || projected.UID != string(pod.UID) ||
			projected.PodResourceVersion != pod.ResourceVersion || projected.ServiceAccount != sa.Name {
			continue
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.Projected == nil || volume.Name == "" {
				continue
			}
			var defaultAPITokenPaths []string
			for _, source := range volume.Projected.Sources {
				token := source.ServiceAccountToken
				if token != nil && token.Audience == "" && validRelativeTokenPath(token.Path) {
					defaultAPITokenPaths = append(defaultAPITokenPaths, token.Path)
				}
			}
			if len(defaultAPITokenPaths) == 0 {
				continue
			}
			for _, container := range pod.Spec.Containers {
				if !startedTokenContainer(pod.Status.ContainerStatuses, container.Name) {
					continue
				}
				for mountIndex, mount := range container.VolumeMounts {
					if mount.Name != volume.Name || !path.IsAbs(mount.MountPath) || !mount.ReadOnly ||
						mount.SubPath != "" || mount.SubPathExpr != "" {
						continue
					}
					unshadowed := false
					for _, tokenPath := range defaultAPITokenPaths {
						if !tokenPathShadowed(container.VolumeMounts, mountIndex, tokenPath) {
							unshadowed = true
							break
						}
					}
					if !unshadowed {
						continue
					}
					projected.PodBoundKubeAPIAuth = &model.PodBoundKubeAPIAuthProjection{
						PodUID: string(pod.UID), PodResourceVersion: pod.ResourceVersion,
						ServiceAccountName: sa.Name, ServiceAccountUID: string(sa.UID),
						VolumeName: volume.Name, MountedContainer: container.Name,
						AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount",
					}
					continue nextPod
				}
			}
		}
	}
}

func validRelativeTokenPath(tokenPath string) bool {
	if tokenPath == "" || path.IsAbs(tokenPath) || path.Clean(tokenPath) == "." {
		return false
	}
	for _, part := range strings.Split(tokenPath, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// Another mount at the projection root or between it and the token file can
// hide the token while the projected volume itself remains mounted. A sibling
// mount does not. This is a conservative structural check, not a filesystem
// read or proof that the kubelet has issued a token.
func tokenPathShadowed(mounts []corev1.VolumeMount, projectedIndex int, tokenPath string) bool {
	root := path.Clean(mounts[projectedIndex].MountPath)
	target := path.Join(root, tokenPath)
	for index, mount := range mounts {
		if index == projectedIndex || mount.MountPath == "" {
			continue
		}
		other := path.Clean(mount.MountPath)
		if pathWithin(root, other) && pathWithin(other, target) {
			return true
		}
	}
	return false
}

func pathWithin(parent, child string) bool {
	return child == parent || strings.HasPrefix(child, strings.TrimSuffix(parent, "/")+"/")
}

func startedTokenContainer(statuses []corev1.ContainerStatus, name string) bool {
	for _, status := range statuses {
		if status.Name == name {
			return status.Started != nil && *status.Started && status.State.Running != nil
		}
	}
	return false
}
