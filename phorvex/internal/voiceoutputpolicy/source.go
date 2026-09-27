package voiceoutputpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const SourceConfigMapAnnotation = "phorvex.ai/voice-output-source-configmap"
const SourceSHAAnnotation = "phorvex.ai/voice-output-source-sha256"

var sourceFiles = [...]string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"}

type SourceEvidence struct {
	ConfigMapName string
	ConfigMapUID  string
	SourceSHA256  string
	BundleSHA256  string
}

// SourceHashes derives the app's output-source digest and the shared immutable
// bundle name from the exact four files projected into every serving Voice Pod.
func SourceHashes(cm *corev1.ConfigMap) (string, string, error) {
	if cm == nil || cm.Immutable == nil || !*cm.Immutable || cm.DeletionTimestamp != nil ||
		len(cm.Data) != len(sourceFiles) || len(cm.BinaryData) != 0 {
		return "", "", errors.New("Voice output source ConfigMap must be immutable and exact")
	}
	var values [len(sourceFiles)]string
	for i, name := range sourceFiles {
		value, ok := cm.Data[name]
		if !ok || value == "" {
			return "", "", fmt.Errorf("Voice output source %s missing", name)
		}
		values[i] = value
	}
	join := func(count int) string {
		h := sha256.New()
		for i := 0; i < count; i++ {
			if i != 0 {
				_, _ = h.Write([]byte{0})
			}
			_, _ = h.Write([]byte(values[i]))
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	return join(3), join(4), nil
}

func sourceMount(spec corev1.PodSpec, sourceName string) (corev1.Container, bool) {
	if sourceName == "" {
		return corev1.Container{}, false
	}
	volumeName := ""
	for _, volume := range spec.Volumes {
		if volume.ConfigMap == nil || volume.ConfigMap.Name != sourceName {
			continue
		}
		if volumeName != "" || volume.ConfigMap.Optional != nil && *volume.ConfigMap.Optional ||
			len(volume.ConfigMap.Items) != 0 {
			return corev1.Container{}, false
		}
		volumeName = volume.Name
	}
	if volumeName == "" {
		return corev1.Container{}, false
	}
	var bot corev1.Container
	count := 0
	for _, container := range spec.Containers {
		if container.Name == "bot" {
			bot = container
			count++
		}
	}
	if count != 1 {
		return corev1.Container{}, false
	}
	if len(bot.Command) != 3 || bot.Command[0] != "python3" || bot.Command[1] != "-B" ||
		bot.Command[2] != "/app/bot.py" || len(bot.Args) != 0 {
		return corev1.Container{}, false
	}
	seen := map[string]bool{}
	for _, mount := range bot.VolumeMounts {
		if !strings.HasPrefix(mount.MountPath, "/app/") && mount.Name != volumeName {
			continue
		}
		valid := false
		for _, name := range sourceFiles {
			if mount.MountPath == "/app/"+name && mount.Name == volumeName && mount.ReadOnly && mount.SubPath == name && !seen[name] {
				seen[name] = true
				valid = true
				break
			}
		}
		if !valid {
			return corev1.Container{}, false
		}
	}
	return bot, len(seen) == len(sourceFiles)
}

// VerifySource binds the observed source to a current Deployment, Pod and
// immutable ConfigMap. It does not infer source authority from annotations.
func VerifySource(ctx context.Context, reader client.Reader, pod *corev1.Pod, dep *appsv1.Deployment) (SourceEvidence, error) {
	var evidence SourceEvidence
	if reader == nil || pod == nil || dep == nil || pod.Namespace != Namespace || dep.Namespace != Namespace ||
		pod.DeletionTimestamp != nil || dep.DeletionTimestamp != nil || !ValidUID(string(dep.UID)) ||
		pod.Annotations[SourceConfigMapAnnotation] == "" || pod.Annotations[SourceSHAAnnotation] == "" {
		return evidence, errors.New("Voice output source authority incomplete")
	}
	name := pod.Annotations[SourceConfigMapAnnotation]
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: name}, cm); err != nil {
		return evidence, err
	}
	return VerifySourceObjects(pod, dep, cm)
}

// VerifySourceObjects is the same source proof for callers that already have
// authenticated typed API snapshots. It never trusts the event's source claim.
func VerifySourceObjects(pod *corev1.Pod, dep *appsv1.Deployment, cm *corev1.ConfigMap) (SourceEvidence, error) {
	var evidence SourceEvidence
	if pod == nil || dep == nil || cm == nil || pod.Namespace != Namespace || dep.Namespace != Namespace ||
		cm.Namespace != Namespace || pod.DeletionTimestamp != nil || dep.DeletionTimestamp != nil ||
		!ValidUID(string(dep.UID)) || pod.Annotations[SourceConfigMapAnnotation] == "" ||
		pod.Annotations[SourceSHAAnnotation] == "" {
		return evidence, errors.New("Voice output source authority incomplete")
	}
	name := pod.Annotations[SourceConfigMapAnnotation]
	if cm.Name != name {
		return evidence, errors.New("Voice output source ConfigMap name changed")
	}
	if dep.Spec.Template.Annotations[SourceConfigMapAnnotation] != name ||
		dep.Spec.Template.Annotations[SourceSHAAnnotation] != pod.Annotations[SourceSHAAnnotation] {
		return evidence, errors.New("Voice output Deployment source annotations changed")
	}
	bot, ok := sourceMount(pod.Spec, name)
	templateBot, templateOK := sourceMount(dep.Spec.Template.Spec, name)
	if !ok || !templateOK || bot.Image == "" || bot.Image != templateBot.Image ||
		!slices.Equal(bot.Command, templateBot.Command) || !slices.Equal(bot.Args, templateBot.Args) {
		return evidence, errors.New("Voice output source mount or bot command changed")
	}
	if !ValidUID(string(cm.UID)) || cm.ResourceVersion == "" || len(cm.OwnerReferences) != 1 {
		return evidence, errors.New("Voice output source ConfigMap identity incomplete")
	}
	owner := cm.OwnerReferences[0]
	if owner.Controller == nil || !*owner.Controller || owner.APIVersion != "apps/v1" || owner.Kind != "Deployment" ||
		owner.Name != dep.Name || owner.UID != dep.UID {
		return evidence, errors.New("Voice output source ConfigMap owner changed")
	}
	sourceSHA, bundleSHA, err := SourceHashes(cm)
	if err != nil || name != "voice-memory-source-"+bundleSHA[:12] || sourceSHA != pod.Annotations[SourceSHAAnnotation] {
		return evidence, errors.New("Voice output source bytes or bundle name changed")
	}
	return SourceEvidence{ConfigMapName: name, ConfigMapUID: string(cm.UID), SourceSHA256: sourceSHA, BundleSHA256: bundleSHA}, nil
}
