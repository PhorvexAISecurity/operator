package voiceadmissionpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReviewedAdmissionSourceSHA256 is finalized from the separately reviewed
// entry.py + NUL + policy.py; unset source authority always fails closed.
const ReviewedAdmissionSourceSHA256 = "5a4d59555a37b6990cb6e78c03d2768445c0809ca797bb50fdbdc1d8d61b2d23"

// ReviewedAdmissionImage is the immutable reviewed SDK overlay image reference.
const ReviewedAdmissionImage = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:7a20c69d1ab15b56afac6a74c42a3de605e8a99e8db26c6e803bd80feb2f6f26"

// ReviewedAdmissionPlatformSHA256 is accepted only when its relation to the
// published index was independently verified; empty adds no alternate digest.
const ReviewedAdmissionPlatformSHA256 = "66547aea8c753e683fd57f3340fa0e1e42c73fe406a0fe34a7c0521d00975d31"

const ReviewedLegacyBundleSHA256 = "e3cfcb87456b299f2b021bce70fb565e699f81b39d3b7bc3bd985b0f56f1f899"

const (
	WrapperPath                = "/opt/voice-admission"
	WrapperConfigMapAnnotation = "phorvex.ai/voice-admission-wrapper-configmap"
	SourceSHAAnnotation        = "phorvex.ai/voice-admission-source-sha256"
	AuthProfileSHAAnnotation   = "phorvex.ai/voice-admission-auth-profile-sha256"
	LegacyBundleSHAAnnotation  = "phorvex.ai/voice-admission-legacy-bundle-sha256"
	PolicyConfigMapAnnotation  = "phorvex.ai/voice-admission-policy-configmap"
	EventCreatorAnnotation     = "phorvex.ai/voice-admission-event-creator"
)

type AuthProfile struct {
	Version              int      `json:"version"`
	DeploymentUID        string   `json:"deploymentUID"`
	PublicHost           string   `json:"publicHost"`
	WebsocketSigningURLs []string `json:"websocketSigningURLs"`
	WebhookSigningURL    string   `json:"webhookSigningURL"`
	TwilioSecretName     string   `json:"twilioSecretName"`
	AuthTokenSHA256      string   `json:"authTokenSHA256"`
}

func (p AuthProfile) Bytes() []byte {
	b, _ := json.Marshal(map[string]any{"version": p.Version, "deploymentUID": p.DeploymentUID, "publicHost": p.PublicHost, "websocketSigningURLs": p.WebsocketSigningURLs, "webhookSigningURL": p.WebhookSigningURL, "twilioSecretName": p.TwilioSecretName, "authTokenSHA256": p.AuthTokenSHA256})
	return b
}
func ParseProfile(raw string) (AuthProfile, error) {
	var p AuthProfile
	if ExactDecode([]byte(raw), &p) != nil || p.Version != 1 || !ValidUID(p.DeploymentUID) || p.PublicHost != "voicebot.phorvex.ai" || len(p.WebsocketSigningURLs) != 1 || p.WebsocketSigningURLs[0] != "wss://"+p.PublicHost+"/ws" || p.WebhookSigningURL != "https://"+p.PublicHost+"/" || p.TwilioSecretName != "voice-secrets" || !ValidSHA(p.AuthTokenSHA256) || raw != string(p.Bytes()) {
		return AuthProfile{}, errors.New("Voice admission auth profile invalid or noncanonical")
	}
	return p, nil
}

type SourceEvidence struct {
	ConfigMapName      string
	ConfigMapUID       string
	SourceSHA256       string
	BundleSHA256       string
	AuthProfileSHA256  string
	LegacyBundleSHA256 string
	LegacyConfigMapUID string
}

func LegacyCommand(c corev1.Container) bool {
	return slices.Equal(c.Command, []string{"python3", "-B", "/app/bot.py"}) && len(c.Args) == 0
}
func WrapperCommand(c corev1.Container) bool {
	return slices.Equal(c.Command, []string{"python3", "-B", WrapperPath + "/entry.py"}) && len(c.Args) == 0
}
func UsesWrapper(p *corev1.Pod) bool {
	if p == nil {
		return false
	}
	for _, c := range p.Spec.Containers {
		if c.Name == "bot" {
			return WrapperCommand(c)
		}
	}
	return false
}

// HasWrapperAuthority prevents an annotated alternative command from falling
// through a legacy verifier; attestation must succeed before it executes.
func HasWrapperAuthority(p *corev1.Pod) bool {
	return p != nil && (UsesWrapper(p) || p.Annotations[WrapperConfigMapAnnotation] != "")
}

func owned(cm *corev1.ConfigMap, dep *appsv1.Deployment) bool {
	if cm == nil || dep == nil || cm.Namespace != Namespace || cm.DeletionTimestamp != nil || !ValidUID(string(cm.UID)) || cm.ResourceVersion == "" || len(cm.OwnerReferences) != 1 {
		return false
	}
	o := cm.OwnerReferences[0]
	return o.APIVersion == "apps/v1" && o.Kind == "Deployment" && o.Name == dep.Name && o.UID == dep.UID && o.Controller != nil && *o.Controller
}
func OwnedConfigMap(cm *corev1.ConfigMap, dep *appsv1.Deployment) bool { return owned(cm, dep) }
func hashes(cm *corev1.ConfigMap) (string, string, string, error) {
	if cm == nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 3 || len(cm.BinaryData) != 0 || cm.Data["entry.py"] == "" || cm.Data["policy.py"] == "" || cm.Data["auth-profile.json"] == "" {
		return "", "", "", errors.New("Voice admission source requires exact immutable three-file bundle")
	}
	code := cm.Data["entry.py"] + "\x00" + cm.Data["policy.py"]
	return Digest([]byte(code)), Digest([]byte(code + "\x00" + cm.Data["auth-profile.json"])), Digest([]byte(cm.Data["auth-profile.json"])), nil
}
func SourceHashes(cm *corev1.ConfigMap) (string, string, string, error) { return hashes(cm) }

func botContainer(spec corev1.PodSpec) (corev1.Container, bool) {
	var bot corev1.Container
	count := 0
	for _, c := range spec.Containers {
		if c.Name == "bot" {
			bot = c
			count++
		}
	}
	return bot, count == 1
}
func envLiteral(c corev1.Container, name, value string) bool {
	count := 0
	for _, e := range c.Env {
		if e.Name == name {
			if e.ValueFrom != nil || e.Value != value {
				return false
			}
			count++
		}
	}
	return count == 1
}
func wrapperMounts(spec corev1.PodSpec, sourceName string, profile AuthProfile, ruleCMUID, codeSHA, legacySHA, profileSHA string) bool {
	c, ok := botContainer(spec)
	if !ok || !WrapperCommand(c) || c.Image == "" || c.WorkingDir != "/app" || !legacyPolicyMounts(spec) {
		return false
	}
	for _, e := range c.Env {
		if e.Name == "PYTHONPATH" || e.Name == "PYTHONHOME" {
			return false
		}
	}
	for name, value := range map[string]string{"PUBLIC_HOST": profile.PublicHost, "VOICE_ADMISSION_SOURCE_SHA256": codeSHA, "VOICE_ADMISSION_DEPLOYMENT_UID": profile.DeploymentUID, "VOICE_ADMISSION_POLICY_CM_UID": ruleCMUID, "VOICE_ADMISSION_WRAPPER_CM_UID": "", "VOICE_ADMISSION_AUTH_PROFILE_SHA256": profileSHA, "VOICE_ADMISSION_LEGACY_BUNDLE_SHA256": legacySHA} {
		if name == "VOICE_ADMISSION_WRAPPER_CM_UID" {
			continue
		}
		if !envLiteral(c, name, value) {
			return false
		}
	}
	podUID := 0
	for _, e := range c.Env {
		if e.Name == "POD_UID" {
			if e.Value != "" || e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "metadata.uid" {
				return false
			}
			podUID++
		}
	}
	if podUID != 1 {
		return false
	}
	volumeName := ""
	for _, v := range spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == sourceName {
			if volumeName != "" || v.ConfigMap.Optional != nil && *v.ConfigMap.Optional || len(v.ConfigMap.Items) != 0 {
				return false
			}
			volumeName = v.Name
		}
	}
	if volumeName == "" {
		return false
	}
	mountCount := 0
	for _, m := range c.VolumeMounts {
		if m.MountPath == WrapperPath {
			if m.Name != volumeName || !m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" {
				return false
			}
			mountCount++
		} else if m.Name == volumeName || m.MountPath == "/" || m.MountPath == "/opt" || strings.HasPrefix(m.MountPath, WrapperPath+"/") || m.MountPath == "/app" {
			return false
		}
	}
	if mountCount != 1 {
		return false
	}
	// The inherited token must come from the pinned production Secret. Literal or
	// additional same-name env sources are rejected; no test auth bypass exists.
	tokenSources := 0
	for _, e := range c.Env {
		if e.Name == "TWILIO_AUTH_TOKEN" {
			if e.Value != "" || e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil || e.ValueFrom.SecretKeyRef.Name != profile.TwilioSecretName || e.ValueFrom.SecretKeyRef.Key != "TWILIO_AUTH_TOKEN" {
				return false
			}
			tokenSources++
		}
	}
	for _, f := range c.EnvFrom {
		if f.Prefix != "" {
			continue
		}
		if f.SecretRef == nil || f.SecretRef.Name != profile.TwilioSecretName || f.ConfigMapRef != nil {
			return false
		}
		tokenSources++
	}
	return tokenSources == 1 && spec.ServiceAccountName == "voice-bot-admission-reader" && spec.AutomountServiceAccountToken != nil && *spec.AutomountServiceAccountToken
}

func VerifySource(ctx context.Context, reader client.Reader, pod *corev1.Pod, dep *appsv1.Deployment) (SourceEvidence, error) {
	if reader == nil || pod == nil || dep == nil {
		return SourceEvidence{}, errors.New("Voice admission source reader unavailable")
	}
	wrapper := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: pod.Annotations[WrapperConfigMapAnnotation]}, wrapper); err != nil {
		return SourceEvidence{}, err
	}
	_, err := ParseProfile(wrapper.Data["auth-profile.json"])
	if err != nil {
		return SourceEvidence{}, err
	}
	legacy := &corev1.ConfigMap{}
	if err = reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: pod.Annotations["phorvex.ai/voice-output-source-configmap"]}, legacy); err != nil {
		return SourceEvidence{}, err
	}
	ingress := &networkingv1.Ingress{}
	if err = reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "voice-bot-public"}, ingress); err != nil {
		return SourceEvidence{}, err
	}
	policyCM := &corev1.ConfigMap{}
	if err = reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ConfigMapName}, policyCM); err != nil {
		return SourceEvidence{}, err
	}
	return VerifySourceObjects(pod, dep, wrapper, legacy, policyCM, ingress)
}

func VerifySourceObjects(pod *corev1.Pod, dep *appsv1.Deployment, wrapper, legacy, policyCM *corev1.ConfigMap, ingress *networkingv1.Ingress) (SourceEvidence, error) {
	return verifySourceObjects(pod, dep, wrapper, legacy, policyCM, ingress, ReviewedAdmissionSourceSHA256, ReviewedAdmissionImage, ReviewedAdmissionPlatformSHA256)
}

// expectedCode/image are private test fixtures; the public execution authority
// always supplies compile-time reviewed pins.
func verifySourceObjects(pod *corev1.Pod, dep *appsv1.Deployment, wrapper, legacy, policyCM *corev1.ConfigMap, ingress *networkingv1.Ingress, expectedCode, expectedImage, expectedPlatform string) (SourceEvidence, error) {
	var ev SourceEvidence
	if pod == nil || dep == nil || pod.Namespace != Namespace || dep.Namespace != Namespace || pod.DeletionTimestamp != nil || dep.DeletionTimestamp != nil || !ValidUID(string(dep.UID)) || !owned(wrapper, dep) || !owned(legacy, dep) {
		return ev, errors.New("Voice admission source ownership incomplete")
	}
	code, bundle, profileSHA, err := hashes(wrapper)
	if err != nil {
		return ev, err
	}
	if !ValidSHA(expectedCode) || code != expectedCode {
		return ev, errors.New("Voice admission wrapper bytes are not reviewed execution authority")
	}
	profile, err := ParseProfile(wrapper.Data["auth-profile.json"])
	if err != nil || profile.DeploymentUID != string(dep.UID) || wrapper.Name != "voice-admission-source-"+bundle[:12] {
		return ev, errors.New("Voice admission source/profile identity changed")
	}
	if legacy.Immutable == nil || !*legacy.Immutable || len(legacy.Data) != 4 || len(legacy.BinaryData) != 0 {
		return ev, errors.New("Voice admission legacy bundle must remain immutable and exact")
	}
	parts := []string{}
	for _, name := range []string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"} {
		if legacy.Data[name] == "" {
			return ev, errors.New("Voice admission legacy file absent")
		}
		parts = append(parts, legacy.Data[name])
	}
	legacySHA := Digest([]byte(strings.Join(parts, "\x00")))
	if legacySHA != ReviewedLegacyBundleSHA256 || legacy.Name != "voice-memory-source-"+legacySHA[:12] {
		return ev, errors.New("Voice admission legacy source name differs from bytes")
	}
	for name, value := range map[string]string{WrapperConfigMapAnnotation: wrapper.Name, SourceSHAAnnotation: code, AuthProfileSHAAnnotation: profileSHA, LegacyBundleSHAAnnotation: legacySHA, PolicyConfigMapAnnotation: ConfigMapName} {
		if pod.Annotations[name] != value || dep.Spec.Template.Annotations[name] != value {
			return ev, fmt.Errorf("Voice admission annotation %s differs from live source", name)
		}
	}
	policyCMUID := ""
	for _, c := range pod.Spec.Containers {
		if c.Name == "bot" {
			for _, e := range c.Env {
				if e.Name == "VOICE_ADMISSION_POLICY_CM_UID" {
					policyCMUID = e.Value
				}
			}
		}
	}
	if !ValidUID(policyCMUID) || !owned(policyCM, dep) || policyCM.Name != ConfigMapName || string(policyCM.UID) != policyCMUID || len(policyCM.Data) != 1 || len(policyCM.BinaryData) != 0 {
		return ev, errors.New("Voice admission policy ConfigMap UID unbound")
	}
	rule, err := Parse(policyCM.Data[RuleKey])
	if err != nil || rule.DeploymentUID != string(dep.UID) || rule.WrapperCMUID != string(wrapper.UID) || rule.AdmissionSourceSHA256 != code || rule.LegacyBundleSHA256 != legacySHA || rule.AuthProfileSHA256 != profileSHA {
		return ev, errors.New("Voice admission current rule/source authority differs")
	}
	if !envLiteralForSpec(pod.Spec, "VOICE_ADMISSION_SECURITY_POLICY_UID", rule.SecurityPolicyUID) || !envLiteralForSpec(dep.Spec.Template.Spec, "VOICE_ADMISSION_SECURITY_POLICY_UID", rule.SecurityPolicyUID) || !legacyMounts(pod.Spec, legacy.Name) || !legacyMounts(dep.Spec.Template.Spec, legacy.Name) || !wrapperMounts(pod.Spec, wrapper.Name, profile, policyCMUID, code, legacySHA, profileSHA) || !wrapperMounts(dep.Spec.Template.Spec, wrapper.Name, profile, policyCMUID, code, legacySHA, profileSHA) {
		return ev, errors.New("Voice admission execution or mounts differ")
	}
	bot, _ := botContainer(pod.Spec)
	template, _ := botContainer(dep.Spec.Template.Spec)
	if expectedImage == "" || bot.Image != expectedImage || bot.Image != template.Image || !runningImageApproved(pod, expectedImage, expectedPlatform) || !envLiteral(bot, "VOICE_ADMISSION_WRAPPER_CM_UID", string(wrapper.UID)) || !envLiteral(template, "VOICE_ADMISSION_WRAPPER_CM_UID", string(wrapper.UID)) {
		return ev, errors.New("Voice admission wrapper execution UID/image differs")
	}
	if ingress == nil || ingress.Namespace != Namespace || ingress.Name != "voice-bot-public" || ingress.DeletionTimestamp != nil || ingress.Spec.IngressClassName == nil || *ingress.Spec.IngressClassName != "alb" || ingress.Annotations["alb.ingress.kubernetes.io/scheme"] != "internet-facing" || ingress.Annotations["alb.ingress.kubernetes.io/ssl-redirect"] != "443" {
		return ev, errors.New("Voice admission production ingress authority differs")
	}
	matched := 0
	for _, r := range ingress.Spec.Rules {
		if r.Host == profile.PublicHost && r.HTTP != nil {
			for _, p := range r.HTTP.Paths {
				if p.Path == "/" && p.Backend.Service != nil && p.Backend.Service.Name == "voice-bot" && p.Backend.Service.Port.Number == 8080 {
					matched++
				}
			}
		}
	}
	if matched != 1 {
		return ev, errors.New("Voice admission canonical public route differs")
	}
	return SourceEvidence{ConfigMapName: wrapper.Name, ConfigMapUID: string(wrapper.UID), SourceSHA256: code, BundleSHA256: bundle, AuthProfileSHA256: profileSHA, LegacyBundleSHA256: legacySHA, LegacyConfigMapUID: string(legacy.UID)}, nil
}

func envLiteralForSpec(spec corev1.PodSpec, name, value string) bool {
	c, ok := botContainer(spec)
	return ok && envLiteral(c, name, value)
}
func legacyMounts(spec corev1.PodSpec, name string) bool {
	c, ok := botContainer(spec)
	if !ok {
		return false
	}
	volumeName := ""
	for _, v := range spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == name {
			if volumeName != "" || len(v.ConfigMap.Items) != 0 || (v.ConfigMap.Optional != nil && *v.ConfigMap.Optional) {
				return false
			}
			volumeName = v.Name
		}
	}
	if volumeName == "" {
		return false
	}
	seen := map[string]bool{}
	for _, m := range c.VolumeMounts {
		if m.Name != volumeName && !strings.HasPrefix(m.MountPath, "/app/") {
			continue
		}
		valid := false
		for _, f := range []string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"} {
			if m.MountPath == "/app/"+f && m.Name == volumeName && m.SubPath == f && m.SubPathExpr == "" && m.ReadOnly && !seen[f] {
				seen[f] = true
				valid = true
				break
			}
		}
		if !valid {
			return false
		}
	}
	return len(seen) == 4
}

// Wrapped execution retains all four mandatory guards and their original inputs.
func legacyPolicyMounts(spec corev1.PodSpec) bool {
	c, ok := botContainer(spec)
	if !ok {
		return false
	}
	for _, name := range []string{"VOICE_MEMORY_POLICY_REQUIRED", "VOICE_REFUND_POLICY_REQUIRED", "VOICE_MCP_POLICY_REQUIRED", "VOICE_OUTPUT_POLICY_REQUIRED"} {
		if !envLiteral(c, name, "true") {
			return false
		}
	}
	paths := map[string]string{"VOICE_MEMORY_POLICY_DIR": "/etc/phorvex/voice-memory-policy", "VOICE_REFUND_POLICY_DIR": "/etc/phorvex/voice-refund-policy", "VOICE_MCP_POLICY_DIR": "/etc/phorvex/voice-mcp-tool-policy", "VOICE_OUTPUT_POLICY_DIR": "/etc/phorvex/voice-output-policy", "VOICE_MEMORY_STATE_DIR": "/var/lib/phorvex-voice-memory", "VOICE_MEMORY_STATE_TOKEN_FILE": "/etc/phorvex/voice-memory-state-token/token"}
	for name, path := range paths {
		if !envLiteral(c, name, path) {
			return false
		}
	}
	inputs := map[string]string{"/etc/phorvex/voice-memory-policy": "voice-memory-policy", "/etc/phorvex/voice-refund-policy": "voice-refund-policy", "/etc/phorvex/voice-mcp-tool-policy": "voice-mcp-tool-policy", "/etc/phorvex/voice-output-policy": "voice-output-policy", "/etc/phorvex/voice-memory-state-token": "voice-memory-state-token"}
	for path, name := range inputs {
		count := 0
		for _, m := range c.VolumeMounts {
			if m.MountPath == path {
				count++
				if !m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" {
					return false
				}
				matches := 0
				for _, v := range spec.Volumes {
					if v.Name != m.Name {
						continue
					}
					if name == "voice-memory-state-token" {
						if v.Secret != nil && v.Secret.SecretName == name && len(v.Secret.Items) == 0 {
							matches++
						}
					} else if v.ConfigMap != nil && v.ConfigMap.Name == name && len(v.ConfigMap.Items) == 0 {
						matches++
					}
				}
				if matches != 1 {
					return false
				}
			} else if m.MountPath == "/etc" || m.MountPath == "/etc/phorvex" || strings.HasPrefix(m.MountPath, path+"/") {
				return false
			}
		}
		if count != 1 {
			return false
		}
	}
	count := 0
	for _, m := range c.VolumeMounts {
		if m.MountPath == "/var/lib/phorvex-voice-memory" {
			count++
			if m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" {
				return false
			}
			valid := false
			for _, v := range spec.Volumes {
				if v.Name == m.Name && v.EmptyDir != nil {
					valid = true
				}
			}
			if !valid {
				return false
			}
		} else if m.MountPath == "/var" || m.MountPath == "/var/lib" || strings.HasPrefix(m.MountPath, "/var/lib/phorvex-voice-memory/") {
			return false
		}
	}
	return count == 1
}

func runningImageApproved(pod *corev1.Pod, expectedImage, expectedPlatform string) bool {
	index := strings.LastIndex(expectedImage, "@sha256:")
	if index <= 0 || !ValidSHA(expectedImage[index+8:]) {
		return false
	}
	digests := []string{expectedImage[index+8:]}
	if expectedPlatform != "" {
		if !ValidSHA(expectedPlatform) {
			return false
		}
		digests = append(digests, expectedPlatform)
	}
	count := 0
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != "bot" {
			continue
		}
		count++
		if !status.Ready || status.State.Running == nil || status.State.Running.StartedAt.IsZero() || status.ContainerID == "" || len(status.ContainerID) > 256 || strings.ContainsRune(status.ContainerID, '\x00') {
			return false
		}
		approved := false
		for _, digest := range digests {
			ref := expectedImage[:index] + "@sha256:" + digest
			for _, value := range []string{ref, "docker-pullable://" + ref, "containerd://" + ref, "sha256:" + digest, "containerd://sha256:" + digest} {
				if status.ImageID == value {
					approved = true
				}
			}
		}
		if !approved {
			return false
		}
	}
	return count == 1
}
