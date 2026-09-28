package console

import (
	"context"
	"errors"

	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func voiceConsoleUsesWrapper(pod *corev1.Pod) bool {
	return pod != nil && (pod.Annotations[voiceadmissionpolicy.WrapperConfigMapAnnotation] != "" || voiceadmissionpolicy.UsesWrapper(pod))
}

// The wrapper is a separately attested entry point. No legacy policy digest or
// operation history is repinned when its authentication boundary is installed.
func voiceConsoleWrapperSource(ctx context.Context, pod *corev1.Pod, dep *appsv1.Deployment) error {
	if !voiceConsoleUsesWrapper(pod) {
		return nil
	}
	config, e := restConfigFor("")
	if e != nil {
		return e
	}
	reader, e := client.New(config, client.Options{Scheme: scheme.Scheme})
	if e != nil {
		return e
	}
	_, e = voiceadmissionpolicy.VerifySource(ctx, reader, pod, dep)
	if e != nil {
		return errors.New("reviewed admission wrapper authority unavailable")
	}
	return nil
}
