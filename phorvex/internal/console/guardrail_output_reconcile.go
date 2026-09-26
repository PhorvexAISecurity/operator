package console

import (
	"context"
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// Lost create replies are reconciled by the exact candidate name at most
// three times. A recovered event is cleaned up, while the run stays UNKNOWN.
func (w *outputWorker) reconcileAmbiguousOutputEvent(candidate *attackStimulusEvidence) error {
	if candidate == nil || candidate.EventName == "" || candidate.Correlation == "" ||
		candidate.TargetUID != w.profile.Fixture.PodUID || candidate.EventRule != guardrailOutputEventType {
		return errors.New("ambiguous output event candidate identity unavailable")
	}
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	rc, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("ambiguous output event cluster authority unavailable")
	}
	client, err := dynamic.NewForConfig(rc)
	if err != nil {
		return errors.New("ambiguous output event readback client unavailable")
	}
	if err = w.reconcileAmbiguousGuardrailEventWithClient(ctx, client, candidate); err != nil {
		return err
	}
	if w.event == nil {
		return errors.New("ambiguous output event exact identity unavailable")
	}
	obj, err := client.Resource(securityEventGVR).Get(ctx, candidate.EventName, metav1.GetOptions{})
	if err != nil {
		w.event = nil
		return errors.New("ambiguous output event observation unavailable")
	}
	notes := availabilityMap(availabilityMeta(obj.Object)["annotations"])
	if notes["phorvex.ai/console-target-pod-uid"] != w.profile.Fixture.PodUID ||
		availabilityString(notes, "phorvex.ai/sensitive-output-observation-v1") == "" {
		w.event = nil
		return errors.New("ambiguous output event observation differs")
	}
	return nil
}
