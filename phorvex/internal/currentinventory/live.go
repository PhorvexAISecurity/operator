package currentinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/phorvex/phorvex/internal/model"
)

func ConfigMapBytes(cm *corev1.ConfigMap, key string) ([]byte, error) {
	text, textOK := cm.Data[key]
	binary, binaryOK := cm.BinaryData[key]
	if textOK == binaryOK {
		return nil, errors.New("current inventory key must exist exactly once")
	}
	if textOK {
		binary = []byte(text)
	}
	if len(binary) == 0 || len(binary) > MaxPayloadBytes {
		return nil, errors.New("current inventory bytes empty or oversized")
	}
	return append([]byte(nil), binary...), nil
}

func BindingFor(pod *corev1.Pod, cm *corev1.ConfigMap, key, volumeName, containerName, mountPath, projectedPath string) (model.CurrentInventorySourceBinding, error) {
	if pod == nil || cm == nil || pod.Namespace == "" || pod.Namespace != cm.Namespace {
		return model.CurrentInventorySourceBinding{}, errors.New("Pod and ConfigMap namespace binding mismatch")
	}
	bytes, err := ConfigMapBytes(cm, key)
	if err != nil {
		return model.CurrentInventorySourceBinding{}, err
	}
	var source *corev1.ConfigMapVolumeSource
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == volumeName {
			source = pod.Spec.Volumes[i].ConfigMap
			break
		}
	}
	if source == nil || source.Name != cm.Name || (source.Optional != nil && *source.Optional) {
		return model.CurrentInventorySourceBinding{}, errors.New("Pod does not mount exact ConfigMap volume")
	}
	mapped := key
	if len(source.Items) > 0 {
		mapped = ""
		seenKeys := map[string]struct{}{}
		seenPaths := map[string]struct{}{}
		for _, item := range source.Items {
			if _, exists := seenKeys[item.Key]; exists {
				return model.CurrentInventorySourceBinding{}, errors.New("duplicate ConfigMap key projection")
			}
			if _, exists := seenPaths[item.Path]; exists {
				return model.CurrentInventorySourceBinding{}, errors.New("duplicate ConfigMap destination projection")
			}
			seenKeys[item.Key] = struct{}{}
			seenPaths[item.Path] = struct{}{}
			if item.Key == key {
				mapped = item.Path
			}
		}
	}
	if mapped == "" || path.Clean(mapped) != projectedPath {
		return model.CurrentInventorySourceBinding{}, errors.New("ConfigMap key projection mismatch")
	}
	mounted := false
	projectedFile := path.Join(mountPath, projectedPath)
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name != containerName {
			continue
		}
		for _, m := range c.VolumeMounts {
			if m.Name == volumeName && m.MountPath == mountPath && m.ReadOnly && m.SubPath == "" && m.SubPathExpr == "" {
				if mounted {
					return model.CurrentInventorySourceBinding{}, errors.New("target container has ambiguous exact ConfigMap mounts")
				}
				mounted = true
				continue
			}
			// A second mount at the projected file or any of its parent directories
			// shadows the bytes from the asserted ConfigMap mount. A sibling or a
			// descendant below the file cannot replace that exact file.
			other := path.Clean(m.MountPath)
			if other == "/" || other == projectedFile || strings.HasPrefix(projectedFile, other+"/") {
				return model.CurrentInventorySourceBinding{}, errors.New("another volume mount shadows projected ConfigMap file")
			}
		}
	}
	if !mounted {
		return model.CurrentInventorySourceBinding{}, errors.New("target container lacks exact read-only mount")
	}
	sum := sha256.Sum256(bytes)
	return model.CurrentInventorySourceBinding{ConfigMap: model.ObjectIdentity{APIVersion: "v1", Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name, UID: string(cm.UID)}, ResourceVersion: cm.ResourceVersion, Key: key, VolumeName: volumeName, ContainerName: containerName, MountPath: mountPath, ProjectedPath: projectedPath, Bytes: int64(len(bytes)), SHA256: hex.EncodeToString(sum[:])}, nil
}

func SameBinding(a, b model.CurrentInventorySourceBinding) bool {
	return a == b
}
