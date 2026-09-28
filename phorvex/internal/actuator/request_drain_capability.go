package actuator

import (
	"context"
	"strconv"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/servingcontext"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This preselection probe performs only current authenticated reads. An absent
// next generation means unavailable (idle, full, or otherwise not creatable),
// not a failed drain. Enact still independently checks fresh native authority.
func requestDrainCapability(ctx context.Context, reader client.Reader, t Target, security *ServingSecurityConfig) (bool, string) {
	const prefix = "request-drain-capability: "
	if reader == nil || t.Namespace == "" || t.Pod == "" || t.UID == "" || t.PolicyName == "" || t.PolicyUID == "" || security == nil || security.Mode() != ServingSecuritySecureRequired {
		return false, prefix + "exact secure target authority unavailable"
	}
	probe, cancel := context.WithTimeout(ctx, protectedServingCapabilityTimeout)
	defer cancel()
	req := Request{Action: model.ActionRequestDrain, Namespace: t.Namespace, Pod: t.Pod, TargetUID: t.UID, PolicyName: t.PolicyName, PolicyUID: t.PolicyUID}
	pod, snapshot, err := security.prepare(probe, reader, req, t.UID)
	if err != nil || normalizeServiceAccount(pod.Spec.ServiceAccountName) != normalizeServiceAccount(t.ServiceAccount) {
		return false, prefix + "current policy or authenticated binding unavailable"
	}
	ec := EnactCtx{Reader: reader, ServingSecurity: security, ServingAttempt: snapshot}
	ep, err := servingEndpointForPod(probe, ec, req, pod)
	if err != nil {
		return false, prefix + "current authenticated endpoint unavailable"
	}
	capability, err := (&httpVLLM{}).DrainV11Capability(probe, ep)
	if err != nil {
		return false, prefix + "authenticated v11 readiness unavailable"
	}
	if capability.PodUID != t.UID || drainV11SourceBinding(pod, capability.ProxySource, capability.EngineSource) != nil {
		return false, prefix + "target or reviewed source differs from v11 readiness"
	}
	before, err := drainV11OperatorBinding(pod, capability.RawSHA256, capability.IncarnationDigest)
	if err != nil {
		return false, prefix + "current operator incarnation unavailable"
	}
	fresh := &corev1.Pod{}
	if reader.Get(probe, client.ObjectKeyFromObject(pod), fresh) != nil || string(fresh.UID) != t.UID ||
		normalizeServiceAccount(fresh.Spec.ServiceAccountName) != normalizeServiceAccount(t.ServiceAccount) ||
		snapshot.selector == nil || snapshot.selector.Empty() || !snapshot.selector.Matches(labels.Set(fresh.Labels)) || !servingcontext.FromAnnotations(fresh.Annotations).Declared() ||
		secureDrainEndpointConfigDigest(fresh) != secureDrainEndpointConfigDigest(pod) || drainV11SourceBinding(fresh, capability.ProxySource, capability.EngineSource) != nil {
		return false, prefix + "target source or endpoint changed during readiness read"
	}
	after, err := drainV11OperatorBinding(fresh, capability.RawSHA256, capability.IncarnationDigest)
	if err != nil || before != after {
		return false, prefix + "operator incarnation changed during readiness read"
	}
	if capability.Admission != "OPEN" || capability.NextOperationGeneration == "" {
		return false, prefix + "no new operation is currently advertised"
	}
	high, highErr := strconv.ParseUint(capability.GenerationHighWater, 10, 64)
	next, nextErr := strconv.ParseUint(capability.NextOperationGeneration, 10, 64)
	if highErr != nil || nextErr != nil || next == 0 || high != next-1 {
		return false, prefix + "advertised generation is not the exact next operation"
	}
	return true, ""
}
