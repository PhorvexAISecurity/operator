package runner

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	"k8s.io/client-go/tools/record"
)

func TestM013TruthfulNotifications(t *testing.T) {
	target := actuationEventTarget(&model.WorkloadView{Pod: model.Pod{Namespace: "tenant", Name: "pod", UID: "original-uid"}})
	if target.UID != "original-uid" || target.APIVersion != "v1" || target.Kind != "Pod" || len(target.OwnerReferences) != 0 {
		t.Fatal(target)
	}
	secret := "TOKEN=private https://internal/another-tenant"
	for _, tc := range []struct {
		name   string
		res    actuator.Result
		err    error
		reason string
	}{
		{name: "emitted", res: actuator.Result{Emitted: true, Note: secret}, reason: "PhorvexActuationEmitted"},
		{name: "refused", res: actuator.Result{Actuator: "native", NoEffect: actuator.NoEffectRefused, Note: secret}, reason: "PhorvexActuationNotEmitted"},
		{name: "reconciled", res: actuator.Result{NoEffect: actuator.NoEffectReconciled, Note: secret}, reason: "PhorvexActuationReconciled"},
		{name: "declared", res: actuator.Result{NoEffect: actuator.NoEffectDeclared, MutationKind: "declared", Note: secret}, reason: "PhorvexActuationDeclaredOnly"},
		{name: "unknown", res: actuator.Result{Note: secret}, reason: "PhorvexActuationOutcomeUnknown"},
		{name: "contradictory-refused-emitted", res: actuator.Result{Emitted: true, NoEffect: actuator.NoEffectRefused, Note: secret}, reason: "PhorvexActuationOutcomeUnknown"},
		{name: "partial-error", res: actuator.Result{Emitted: true, ObjectsTouched: []string{secret}}, err: errors.New(secret), reason: "PhorvexActuationOutcomeUnknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := record.NewFakeRecorder(2)
			m := &Manager{ActuationRecorder: r, Log: logr.Discard()}
			m.notifyActuation(target, model.ActionRotate, tc.res, tc.err)
			msg := <-r.Events
			if !strings.Contains(msg, tc.reason) || strings.Contains(msg, secret) || len(msg) > 250 {
				t.Fatal(msg)
			}
		})
	}
	r := record.NewFakeRecorder(2)
	m := &Manager{ActuationRecorder: r, Log: logr.Discard()}
	m.notifyActuation(nil, model.ActionRotate, actuator.Result{Emitted: true}, nil)
	if len(r.Events) != 0 {
		t.Fatal("missing UID fabricated notification")
	}
	m.notifyActuation(target, model.Action(secret), actuator.Result{Emitted: true}, nil)
	if msg := <-r.Events; strings.Contains(msg, secret) {
		t.Fatal(msg)
	}
}
