package recon

import (
	"strings"

	"github.com/phorvex/phorvex/internal/model"
)

func detectorAdapter(p *model.Pod, name string) {
	if p.UID == "" {
		p.UID = "synthetic-pod-uid"
	}
	p.SuspectAdapter = name
	p.AdapterObservation = &model.AdapterObservation{EventName: "detected", EventUID: "synthetic-event-uid",
		CreatorIdentity: "system:serviceaccount:ns:detector", TargetPodUID: p.UID, AdapterName: name}
}

// detectorConfigObject binds a trusted config-object-drift observation (observed hash != trusted
// snapshot hash) to the pod, the fixture that mints FactConfigObjectIntegrity -> k8s-object-revert
// cover.
func detectorConfigObject(p *model.Pod) {
	if p.UID == "" {
		p.UID = "synthetic-pod-uid"
	}
	p.SuspectConfigObject = "agent-config"
	p.K8sObjectRevertObservation = &model.K8sObjectRevertObservation{EventName: "cfg-detected", EventUID: "synthetic-config-event-uid",
		CreatorIdentity: "system:serviceaccount:ns:detector", TargetPodUID: p.UID, ConfigMapName: "agent-config",
		ObservedSHA256: "sha256:" + strings.Repeat("b", 64), TrustedSHA256: "sha256:" + strings.Repeat("a", 64)}
}
