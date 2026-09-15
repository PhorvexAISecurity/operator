package recon

import "github.com/phorvex/phorvex/internal/model"

func detectorAdapter(p *model.Pod, name string) {
	if p.UID == "" {
		p.UID = "synthetic-pod-uid"
	}
	p.SuspectAdapter = name
	p.AdapterObservation = &model.AdapterObservation{EventName: "detected", EventUID: "synthetic-event-uid",
		CreatorIdentity: "system:serviceaccount:ns:detector", TargetPodUID: p.UID, AdapterName: name}
}
