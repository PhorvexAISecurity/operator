package actuator

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// Recovery only reads an existing prepared intent and the durable policy. It
// never creates an event, dispatches a new decision, or repeats a policy CAS.
func recoverEndpointLeaseOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	cm := &corev1.ConfigMap{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: endpointlease.JournalName}, cm)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	doc, err := endpointLeaseReadJournal(cm)
	if err != nil {
		return []RecoveryEvent{{Receipt: endpointlease.JournalName, Kind: string(model.ActionEndpointLeaseRevoke), Outcome: "refused", Err: err}}, nil
	}
	out := []RecoveryEvent{}
	for _, r := range doc.Receipts {
		if r.Phase != "prepared" {
			continue
		}
		ev := RecoveryEvent{Receipt: endpointlease.JournalName, Kind: string(model.ActionEndpointLeaseRevoke), Phase: r.Phase,
			PolicyNamespace: r.Namespace, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.TargetPodName, TargetUID: r.TargetPodUID, Outcome: "refused"}
		if allow != nil && !allow(model.ActionEndpointLeaseRevoke) {
			ev.Err = errors.New("endpoint lease recovery routed away from native")
		} else {
			ev.Err = recoverPreparedEndpointLease(ctx, ec, r, &ev)
		}
		if ev.Err == nil {
			ev.Outcome = "confirmed"
			ev.Effect = "same-decision durable caller revoke and old/current proxy drain confirmed; no repeated policy CAS"
		}
		out = append(out, ev)
	}
	return out, nil
}

func recoverPreparedEndpointLease(ctx context.Context, ec EnactCtx, r endpointLeaseReceipt, ev *RecoveryEvent) error {
	if !endpointlease.ValidSHA(ec.EndpointLeaseApprovedSourceSHA256) || ec.EndpointLeaseApprovedSourceSHA256 != r.ProxySourceSHA256 ||
		ec.EndpointLeaseApprovedProxyImage == "" || ec.EndpointLeaseApprovedEngineImage == "" {
		return errors.New("endpoint lease recovery reviewed source/image authority unavailable")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: r.PolicyName}, policy); err != nil {
		return err
	}
	if string(policy.UID) != r.PolicyUID || policy.Generation != r.PolicyGeneration || policy.DeletionTimestamp != nil || policy.Spec.IsDryRun() ||
		!policyActionEnabled(policy, model.ActionEndpointLeaseRevoke) {
		return errors.New("endpoint lease recovery selecting policy epoch/action changed")
	}
	ev.Tenant = policy.EffectiveTenant()
	// Retained event may have aged out after a timed-out console run. If it
	// exists, it still has to be the exact originally selected event.
	event := &amtdv1beta1.SecurityEvent{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Name: r.EventName}, event)
	if err == nil {
		if string(event.UID) != r.EventUID || event.Spec.Rule.Type != endpointlease.RuleType || event.Spec.Rule.Source != "redteam" ||
			event.Annotations[model.ConsoleTargetPodUIDAnnotation] != r.TargetPodUID ||
			event.Annotations["phorvex.ai/creator-identity"] != endpointLeaseConsoleCreator {
			return errors.New("endpoint lease recovery original event identity changed")
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	if ec.EndpointLeaseStatusTransport == nil {
		if ec.ServingSecurity == nil || ec.ServingSecurity.mode != ServingSecuritySecureRequired {
			return errors.New("endpoint lease recovery secure admin binding unavailable")
		}
		req := Request{Action: model.ActionEndpointLeaseRevoke, Namespace: r.Namespace, Pod: r.TargetPodName, TargetUID: r.TargetPodUID,
			PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, PolicyGeneration: r.PolicyGeneration}
		_, snapshot, prepareErr := ec.ServingSecurity.prepare(ctx, ec.Reader, req, r.TargetPodUID)
		if prepareErr != nil {
			return prepareErr
		}
		ec.ServingAttempt = snapshot
	}
	// A prepared receipt with unchanged old policy is UNKNOWN, even if a lost
	// journal acknowledgement means this process knows it never sent a CAS.
	// Recovery cannot infer that after restart and must not send one.
	if err = endpointLeaseReadback(ctx, ec, r); err != nil {
		return fmt.Errorf("endpoint lease recovery effective readback pending: %w", err)
	}
	return endpointLeaseTerminal(ctx, ec, r)
}
