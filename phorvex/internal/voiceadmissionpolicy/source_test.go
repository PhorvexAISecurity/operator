package voiceadmissionpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type sourceFixture struct {
	pod                  *corev1.Pod
	dep                  *appsv1.Deployment
	source, legacy, rule *corev1.ConfigMap
	ingress              *networkingv1.Ingress
	code, image          string
}

func reviewedSourceFixture(t *testing.T) sourceFixture {
	t.Helper()
	yes := true
	uid := types.UID(testUID)
	sha := strings.Repeat("a", 64)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: "voice-bot", UID: uid}}
	owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: uid, Controller: &yes}
	cm := func(name string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: name, UID: uid, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{owner}}, Immutable: &yes, Data: map[string]string{}}
	}
	legacy := cm("")
	files := []string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"}
	parts := []string{}
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "build", "integrations", "voice-memory", name))
		if err != nil {
			t.Fatal(err)
		}
		legacy.Data[name] = string(b)
		parts = append(parts, string(b))
	}
	legacySHA := Digest([]byte(strings.Join(parts, "\x00")))
	legacy.Name = "voice-memory-source-" + legacySHA[:12]
	profile := AuthProfile{Version: 1, DeploymentUID: testUID, PublicHost: "voicebot.phorvex.ai", WebsocketSigningURLs: []string{"wss://voicebot.phorvex.ai/ws"}, WebhookSigningURL: "https://voicebot.phorvex.ai/", TwilioSecretName: "voice-secrets", AuthTokenSHA256: sha}
	source := cm("")
	source.Data = map[string]string{"entry.py": "reviewed entry fixture\n", "policy.py": "reviewed policy fixture\n", "auth-profile.json": string(profile.Bytes())}
	code, bundle, profileSHA, err := SourceHashes(source)
	if err != nil {
		t.Fatal(err)
	}
	source.Name = "voice-admission-source-" + bundle[:12]
	r := testRule()
	r.AdmissionSourceSHA256 = code
	r.LegacyBundleSHA256 = legacySHA
	r.AuthProfileSHA256 = profileSHA
	rule := cm(ConfigMapName)
	rule.Immutable = nil
	rule.Data = map[string]string{RuleKey: string(r.Bytes())}
	image := "registry.example/voice-sdk@sha256:" + sha
	c := corev1.Container{Name: "bot", Image: image, Command: []string{"python3", "-B", WrapperPath + "/entry.py"}, WorkingDir: "/app", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "voice-secrets"}}}}}
	for name, value := range map[string]string{"PUBLIC_HOST": profile.PublicHost, "VOICE_ADMISSION_SOURCE_SHA256": code, "VOICE_ADMISSION_DEPLOYMENT_UID": testUID, "VOICE_ADMISSION_POLICY_CM_UID": testUID, "VOICE_ADMISSION_SECURITY_POLICY_UID": testUID, "VOICE_ADMISSION_WRAPPER_CM_UID": testUID, "VOICE_ADMISSION_AUTH_PROFILE_SHA256": profileSHA, "VOICE_ADMISSION_LEGACY_BUNDLE_SHA256": legacySHA, "VOICE_MEMORY_POLICY_REQUIRED": "true", "VOICE_REFUND_POLICY_REQUIRED": "true", "VOICE_MCP_POLICY_REQUIRED": "true", "VOICE_OUTPUT_POLICY_REQUIRED": "true"} {
		c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
	}
	for name, value := range map[string]string{"VOICE_MEMORY_POLICY_DIR": "/etc/phorvex/voice-memory-policy", "VOICE_REFUND_POLICY_DIR": "/etc/phorvex/voice-refund-policy", "VOICE_MCP_POLICY_DIR": "/etc/phorvex/voice-mcp-tool-policy", "VOICE_OUTPUT_POLICY_DIR": "/etc/phorvex/voice-output-policy", "VOICE_MEMORY_STATE_DIR": "/var/lib/phorvex-voice-memory", "VOICE_MEMORY_STATE_TOKEN_FILE": "/etc/phorvex/voice-memory-state-token/token"} {
		c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
	}
	c.Env = append(c.Env, corev1.EnvVar{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}})
	spec := corev1.PodSpec{Containers: []corev1.Container{c}, ServiceAccountName: "voice-bot-admission-reader", AutomountServiceAccountToken: &yes}
	for _, v := range []struct{ name, cm, path string }{{"source", source.Name, WrapperPath}, {"legacy", legacy.Name, ""}, {"memory", "voice-memory-policy", "/etc/phorvex/voice-memory-policy"}, {"refund", "voice-refund-policy", "/etc/phorvex/voice-refund-policy"}, {"mcp", "voice-mcp-tool-policy", "/etc/phorvex/voice-mcp-tool-policy"}, {"output", "voice-output-policy", "/etc/phorvex/voice-output-policy"}} {
		spec.Volumes = append(spec.Volumes, corev1.Volume{Name: v.name, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: v.cm}}}})
		if v.path != "" {
			spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: v.name, MountPath: v.path, ReadOnly: true})
		}
	}
	for _, name := range files {
		spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "legacy", MountPath: "/app/" + name, SubPath: name, ReadOnly: true})
	}
	spec.Volumes = append(spec.Volumes, corev1.Volume{Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-memory-state-token"}}}, corev1.Volume{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true}, corev1.VolumeMount{Name: "state", MountPath: "/var/lib/phorvex-voice-memory"})
	annotations := map[string]string{WrapperConfigMapAnnotation: source.Name, SourceSHAAnnotation: code, AuthProfileSHAAnnotation: profileSHA, LegacyBundleSHAAnnotation: legacySHA, PolicyConfigMapAnnotation: ConfigMapName}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: "voice-bot", UID: uid, Annotations: annotations}, Spec: spec}
	dep.Spec.Template = corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}, Spec: *spec.DeepCopy()}
	class := "alb"
	pathType := networkingv1.PathTypePrefix
	ingress := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: "voice-bot-public", Annotations: map[string]string{"alb.ingress.kubernetes.io/scheme": "internet-facing", "alb.ingress.kubernetes.io/ssl-redirect": "443"}}, Spec: networkingv1.IngressSpec{IngressClassName: &class, Rules: []networkingv1.IngressRule{{Host: profile.PublicHost, IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &pathType, Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "voice-bot", Port: networkingv1.ServiceBackendPort{Number: 8080}}}}}}}}}}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "bot", Ready: true, ImageID: "docker-pullable://" + image, ContainerID: "containerd://fixture", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}
	return sourceFixture{pod, dep, source, legacy, rule, ingress, code, image}
}

func (f sourceFixture) verify() error {
	_, err := verifySourceObjects(f.pod, f.dep, f.source, f.legacy, f.rule, f.ingress, f.code, f.image, "")
	return err
}

func TestWrapperExecutionRequiresReviewedBytesImageAndUnchangedGuards(t *testing.T) {
	if err := reviewedSourceFixture(t).verify(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(sourceFixture){
		"token override": func(f sourceFixture) {
			f.pod.Spec.Containers[0].Env = append(f.pod.Spec.Containers[0].Env, corev1.EnvVar{Name: "TWILIO_AUTH_TOKEN", Value: "attacker"})
		},
		"extra env source": func(f sourceFixture) {
			f.pod.Spec.Containers[0].EnvFrom = append(f.pod.Spec.Containers[0].EnvFrom, corev1.EnvFromSource{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "overrides"}}})
		},
		"guard disabled": func(f sourceFixture) {
			for i := range f.pod.Spec.Containers[0].Env {
				if f.pod.Spec.Containers[0].Env[i].Name == "VOICE_OUTPUT_POLICY_REQUIRED" {
					f.pod.Spec.Containers[0].Env[i].Value = "false"
				}
			}
		},
		"policy path override": func(f sourceFixture) {
			f.pod.Spec.Containers[0].Env = append(f.pod.Spec.Containers[0].Env, corev1.EnvVar{Name: "VOICE_MEMORY_POLICY_DIR", Value: "/tmp/unguarded"})
		},
		"mount shadow": func(f sourceFixture) {
			f.pod.Spec.Containers[0].VolumeMounts = append(f.pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "state", MountPath: "/app"})
		},
		"changed production route": func(f sourceFixture) { f.ingress.Spec.Rules[0].Host = "attacker.example" },
		"changed image all claims": func(f sourceFixture) {
			f.pod.Spec.Containers[0].Image = "attacker/image:latest"
			f.dep.Spec.Template.Spec.Containers[0].Image = "attacker/image:latest"
		},
		"wrong running image": func(f sourceFixture) {
			f.pod.Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + strings.Repeat("c", 64)
		},
		"missing running context": func(f sourceFixture) { f.pod.Status.ContainerStatuses[0].State.Running = nil },
		"changed legacy bytes":    func(f sourceFixture) { f.legacy.Data["bot.py"] += "\n# changed\n" },
	} {
		t.Run(name, func(t *testing.T) {
			f := reviewedSourceFixture(t)
			change(f)
			if f.verify() == nil {
				t.Fatal("changed execution authority accepted")
			}
		})
	}
}

func TestSelfConsistentUnreviewedWrapperStillRejected(t *testing.T) {
	f := reviewedSourceFixture(t)
	f.source.Data["entry.py"] += "unreviewed code\n"
	code, bundle, _, _ := SourceHashes(f.source)
	oldName := f.source.Name
	f.source.Name = "voice-admission-source-" + bundle[:12]
	for _, spec := range []*corev1.PodSpec{&f.pod.Spec, &f.dep.Spec.Template.Spec} {
		for i := range spec.Volumes {
			if spec.Volumes[i].ConfigMap != nil && spec.Volumes[i].ConfigMap.Name == oldName {
				spec.Volumes[i].ConfigMap.Name = f.source.Name
			}
		}
		for i := range spec.Containers[0].Env {
			if spec.Containers[0].Env[i].Name == "VOICE_ADMISSION_SOURCE_SHA256" {
				spec.Containers[0].Env[i].Value = code
			}
		}
	}
	f.pod.Annotations[WrapperConfigMapAnnotation] = f.source.Name
	f.pod.Annotations[SourceSHAAnnotation] = code
	r, _ := Parse(f.rule.Data[RuleKey])
	r.AdmissionSourceSHA256 = code
	f.rule.Data[RuleKey] = string(r.Bytes())
	if f.verify() == nil {
		t.Fatal("self-consistent attacker source passed reviewed byte authority")
	}
	if _, err := VerifySourceObjects(f.pod, f.dep, f.source, f.legacy, f.rule, f.ingress); err == nil {
		t.Fatal("public verifier accepted test fixture execution authority")
	}
}
