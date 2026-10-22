package actuator

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// recoverLiteLLMClientOperations resolves only previously protected prepared
// journals. It never creates an event, chooses an action, or repeats the policy
// CAS. Each invocation does one bounded current-state readback; later manager
// maintenance ticks may observe projected policy propagation.
func recoverLiteLLMClientOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	journal := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: ec.JournalNamespace, Name: litellmclient.JournalName}
	if e := ec.Reader.Get(ctx, key, journal); apierrors.IsNotFound(e) {
		return nil, nil
	} else if e != nil {
		return nil, e
	}
	journalDoc, e := litellmReadJournal(journal)
	if e != nil {
		return []RecoveryEvent{{Receipt: litellmclient.JournalName, Kind: string(model.ActionLiteLLMClientRevoke),
			Outcome: "refused", Err: e}}, nil
	}
	results := make([]RecoveryEvent, 0, len(journalDoc.Receipts))
	pending := 0
	for _, item := range journalDoc.Receipts {
		if item.Phase == "prepared" {
			pending++
		}
	}
	if pending > 1 {
		return []RecoveryEvent{{Receipt: litellmclient.JournalName, Kind: string(model.ActionLiteLLMClientRevoke),
			Outcome: "refused", Err: errors.New("owned-client multiple unresolved protected entries")}}, nil
	}
	for _, r := range journalDoc.Receipts {
		if r.Phase == "terminal-full" || r.Phase == "aborted" {
			continue
		}
		ev := RecoveryEvent{Receipt: litellmclient.JournalName, Kind: string(model.ActionLiteLLMClientRevoke),
			PolicyNamespace: litellmclient.Namespace, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID,
			TargetUID: r.TargetUID, Phase: r.Phase, Outcome: "refused"}
		if allow != nil && !allow(model.ActionLiteLLMClientRevoke) {
			e = errors.New("owned-client recovery routed away from native")
		} else {
			e = recoverPreparedLiteLLMClient(ctx, ec, journalDoc, r, &ev)
		}
		ev.Err = e
		if e == nil {
			ev.Outcome = "confirmed"
		}
		results = append(results, ev)
	}
	return results, nil
}

func recoverPreparedLiteLLMClient(ctx context.Context, ec EnactCtx,
	doc litellmRevokeJournal, r litellmRevokeReceipt, ev *RecoveryEvent) error {
	live, e := litellmclient.ValidateLive(ctx, ec.Reader, r.TargetUID, r.PeerUID)
	if e != nil || live.PolicyUID != r.ConfigMapUID || live.ServiceUID != r.ServiceUID ||
		live.SourceSHA256 != r.SourceSHA256 || live.ClientsUID != r.ClientsConfigMapUID ||
		live.SeedSHA256 != r.SeedSHA256 {
		return errors.New("owned-client prepared operation live authority differs")
	}
	entry, exists := live.State.Entry(r.ClientSHA256)
	if !exists || !entry.Active || entry.OperationID != r.OperationID {
		return errors.New("owned-client prepared operation has no matching committed policy entry; no second CAS")
	}
	activeReceipts := 0
	for _, prior := range doc.Receipts {
		joined, ok := live.State.Entry(prior.ClientSHA256)
		if prior.Phase == "aborted" {
			if ok {
				return errors.New("owned-client aborted receipt unexpectedly active")
			}
			continue
		}
		activeReceipts++
		if !ok || !joined.Active || joined.OperationID != prior.OperationID ||
			(prior.ClientSHA256 != r.ClientSHA256 && prior.Phase != "terminal-full") {
			return errors.New("owned-client prepared operation prior entries unjoined")
		}
	}
	if len(live.State.Entries) != activeReceipts {
		return errors.New("owned-client prepared operation differs from prior protected history")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: litellmclient.Namespace, Name: r.PolicyName}, policy); e != nil {
		return e
	}
	if string(policy.UID) != r.PolicyUID || policy.Generation != r.PolicyGeneration || policy.DeletionTimestamp != nil {
		return errors.New("owned-client prepared operation selecting policy changed")
	}
	enabled := false
	for _, action := range policy.Spec.Actions.Enabled {
		if string(action) == string(model.ActionLiteLLMClientRevoke) {
			enabled = true
		}
	}
	selector, e := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if e != nil || selector.Empty() || !enabled {
		return errors.New("owned-client prepared operation policy selector/action differs")
	}
	var target *litellmclient.Pod
	for i := range live.Pods {
		if live.Pods[i].UID == r.TargetUID {
			target = &live.Pods[i]
		}
	}
	if target == nil {
		return errors.New("owned-client prepared operation target absent")
	}
	pod := &corev1.Pod{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: litellmclient.Namespace, Name: target.Name}, pod); e != nil {
		return e
	}
	if string(pod.UID) != r.TargetUID || !selector.Matches(labels.Set(pod.Labels)) {
		return errors.New("owned-client prepared operation target left policy selector")
	}
	ev.TargetName = target.Name
	ev.Tenant = policy.EffectiveTenant()
	// A retained original event must still match the exact journal. Cleanup may
	// have removed it after the timed-out console run; only the protected journal
	// remains authoritative in that case.
	event := &amtdv1beta1.SecurityEvent{}
	e = ec.Reader.Get(ctx, client.ObjectKey{Name: r.EventName}, event)
	if e == nil {
		if string(event.UID) != r.EventUID || event.Spec.Rule.Type != litellmclient.RuleType ||
			event.Spec.Rule.Source != "redteam" || event.Annotations[model.ConsoleTargetPodUIDAnnotation] != r.TargetUID ||
			event.Annotations["phorvex.ai/creator-identity"] != eventtrust.Injector() {
			return errors.New("owned-client prepared operation original event differs")
		}
	} else if !apierrors.IsNotFound(e) {
		return e
	}
	if e = litellmReadback(ctx, ec, live, r.ClientSHA256, r.OperationID); e != nil {
		return fmt.Errorf("owned-client prepared operation effective readback pending: %w", e)
	}
	journal := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: ec.JournalNamespace, Name: litellmclient.JournalName}
	if e = ec.Reader.Get(ctx, key, journal); e != nil {
		return e
	}
	currentDoc, e := litellmReadJournal(journal)
	if e != nil {
		return e
	}
	index := currentDoc.index(r.ClientSHA256)
	if index < 0 || currentDoc.Receipts[index] != r || r.Phase != "prepared" {
		return errors.New("owned-client prepared journal entry changed during recovery")
	}
	r.Phase = "terminal-full"
	currentDoc.Receipts[index] = r
	journal.Data[litellmclient.JournalKey] = litellmJournalRaw(currentDoc)
	if e = ec.Client.Update(ctx, journal); e != nil {
		return e
	}
	ev.Effect = "same-operation client deny effective on both gateway Pods; no additional policy CAS"
	return nil
}
