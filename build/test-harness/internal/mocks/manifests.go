// Package mocks provides the SHARED, containment-safe stand-ins the category-3
// scenarios use: a mock IMDS (169.254.169.254 stand-in), a mock C2/exfil sink, a
// mock OCI registry, a mock CI/CD pipeline runner, and a CPU-BOUNDED miner.
//
// EVERYTHING here is in-cluster and confined to the sandbox namespace. The
// harness NEVER touches a real cloud metadata endpoint, a real registry, real
// credentials, or a real mining pool. The credentials/tokens issued by these
// mocks are FAKE and only ever accepted by the matching mock.
package mocks

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// BusyboxImage is the tiny, ubiquitous base image used for stand-in workloads so
// the harness pulls nothing exotic and works on an air-gapped-ish kind node that
// already has it cached. It is overridable via the env in a future config knob.
const BusyboxImage = "busybox:1.36"

// hardenedSecurityContext returns a deliberately MINIMAL container security
// context for benign stand-ins (target workloads). Privileged stand-ins (the
// admission-bypass scenario) override this on purpose, within the sandbox only.
func hardenedSecurityContext() *corev1.SecurityContext {
	t := true
	f := false
	uid := int64(65534) // nobody
	return &corev1.SecurityContext{
		RunAsNonRoot:             &t,
		RunAsUser:                &uid,
		AllowPrivilegeEscalation: &f,
		ReadOnlyRootFilesystem:   &f, // attackers need to write their backdoor marker
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}

// PodBuilder assembles a sandbox-confined pod with the standard owner labels. It
// is the shared low-level builder every scenario/mock uses so labels, namespace
// and resource bounds are consistent.
type PodBuilder struct {
	env    *core.Env
	name   string
	labels map[string]string
	pod    *corev1.Pod
}

// NewPod starts a pod builder in the sandbox namespace with owner labels.
func NewPod(env *core.Env, name string, extraLabels map[string]string) *PodBuilder {
	labels := env.OwnedLabels(extraLabels)
	pb := &PodBuilder{
		env:    env,
		name:   name,
		labels: labels,
		pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: env.Config.Namespace,
				Labels:    labels,
			},
			Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever,
			},
		},
	}
	return pb
}

// WithBusyboxLoop adds a busybox container running an indefinite sleep loop with
// a CPU/memory limit. cmd, if non-empty, overrides the default sleep loop.
func (b *PodBuilder) WithBusyboxLoop(container string, cmd []string, cpuMillis, memMi int64) *PodBuilder {
	if len(cmd) == 0 {
		cmd = []string{"sh", "-c", "while true; do sleep 3600; done"}
	}
	c := corev1.Container{
		Name:            container,
		Image:           BusyboxImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         cmd,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    *resource.NewMilliQuantity(cpuMillis, resource.DecimalSI),
				corev1.ResourceMemory: *resource.NewQuantity(memMi*1024*1024, resource.BinarySI),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    *resource.NewMilliQuantity(cpuMillis/4+1, resource.DecimalSI),
				corev1.ResourceMemory: *resource.NewQuantity(memMi*1024*1024/2, resource.BinarySI),
			},
		},
		SecurityContext: hardenedSecurityContext(),
	}
	b.pod.Spec.Containers = append(b.pod.Spec.Containers, c)
	return b
}

// WithContainer appends a fully-specified container (caller owns the spec). Used
// by the mocks that need a custom command + ports.
func (b *PodBuilder) WithContainer(c corev1.Container) *PodBuilder {
	b.pod.Spec.Containers = append(b.pod.Spec.Containers, c)
	return b
}

// WithServiceAccount sets the pod's service account (cred-theft scenarios).
func (b *PodBuilder) WithServiceAccount(sa string) *PodBuilder {
	b.pod.Spec.ServiceAccountName = sa
	return b
}

// WithRestartPolicy overrides the restart policy.
func (b *PodBuilder) WithRestartPolicy(p corev1.RestartPolicy) *PodBuilder {
	b.pod.Spec.RestartPolicy = p
	return b
}

// WithVolume adds a volume + a mount on the first container.
func (b *PodBuilder) WithVolume(vol corev1.Volume, mount corev1.VolumeMount) *PodBuilder {
	b.pod.Spec.Volumes = append(b.pod.Spec.Volumes, vol)
	if len(b.pod.Spec.Containers) > 0 {
		b.pod.Spec.Containers[0].VolumeMounts = append(b.pod.Spec.Containers[0].VolumeMounts, mount)
	}
	return b
}

// MutateSpec gives the caller direct access to the PodSpec for scenario-specific
// shaping (privileged context, hostPath, injected sidecar) — confined to the
// sandbox pod being built.
func (b *PodBuilder) MutateSpec(fn func(*corev1.PodSpec)) *PodBuilder {
	fn(&b.pod.Spec)
	return b
}

// Build returns the assembled pod object (not yet created).
func (b *PodBuilder) Build() *corev1.Pod {
	return b.pod
}

// LabelMap is a tiny helper to merge label maps.
func LabelMap(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
