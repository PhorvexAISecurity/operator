package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/model"
)

const identityJournalLabel = "phorvex.ai/identity-rotation-journal"
const identityOperationAnno = "phorvex.ai/identity-rotation-operation"

type identityReceipt struct {
	Version       int
	Request       Request
	Account       corev1.ServiceAccount // sanitized; never Secret data or bearer bytes
	Phase, NewUID string
	PreparedAt    time.Time
	CompletedAt   time.Time
	Cooldown      time.Duration
}

func identityRequestEligible(req Request) bool {
	o := req.IdentityRotationObservation
	if o == nil {
		return false
	}
	p := model.Pod{Namespace: req.Namespace, Name: req.Pod, UID: req.TargetUID,
		PodResourceVersion: o.PodResourceVersion, ServiceAccount: o.ServiceAccountName,
		PodBoundKubeAPIAuth: req.PodBoundKubeAPIAuth, IdentityRotationObservation: o}
	return req.Action == model.ActionIdentityRotate && p.IdentityRotationEligible(req.PolicyName, req.PolicyUID, req.PolicyGeneration)
}

func identityJournalName(req Request) string {
	o := req.IdentityRotationObservation
	sum := sha256.Sum256([]byte(o.NamespaceUID + "/" + o.ServiceAccountName))
	return "identity-rotation-" + hex.EncodeToString(sum[:20])
}

func identityWrite(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r identityReceipt) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	cm.Data = map[string]string{"receipt": string(b)}
	return ec.Client.Update(ctx, cm) // resourceVersion CAS is also the account fence
}

func identityDecode(cm *corev1.ConfigMap) (identityReceipt, error) {
	var r identityReceipt
	err := json.Unmarshal([]byte(cm.Data["receipt"]), &r)
	if err != nil || r.Version != 1 || !identityRequestEligible(r.Request) || r.Request.OperationID == "" || cm.Name != identityJournalName(r.Request) || cm.Labels[identityJournalLabel] != "v1" {
		return r, fmt.Errorf("identity-rotate: invalid protected journal")
	}
	o := r.Request.IdentityRotationObservation
	if r.Account.Namespace != o.Namespace || r.Account.Name != o.ServiceAccountName || r.Account.UID != "" || r.Account.ResourceVersion != "" || len(r.Account.Secrets) != 0 || r.Account.Annotations[identityOperationAnno] != r.Request.OperationID {
		return r, fmt.Errorf("identity-rotate: invalid account snapshot")
	}
	switch r.Phase {
	case "prepared", "delete-intent", "absent", "create-intent", "cleanup", "complete":
	default:
		return r, fmt.Errorf("identity-rotate: invalid phase")
	}
	return r, nil
}

const identityFirstDeleteMaxAge = 2 * time.Minute

func identityNow(ec EnactCtx) time.Time {
	if ec.IdentityNow != nil {
		return ec.IdentityNow()
	}
	return time.Now()
}

// Repair authority deliberately survives original Pod/policy retirement. Every
// mutation still requires the exact namespace and fresh global/namespace brakes.
func identitySafety(ctx context.Context, ec EnactCtx, req Request) error {
	if !identityRequestEligible(req) {
		return fmt.Errorf("%s", model.IdentityRotateUnsupportedReason)
	}
	if ec.DryRun {
		return errDryRunGuard
	}
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.OperationID == "" {
		return fmt.Errorf("identity-rotate: protected reader/client/journal/operation unavailable")
	}
	if ec.IdentityKillSwitch == nil || ec.IdentityKillSwitch(ctx) {
		return fmt.Errorf("identity-rotate: global kill-switch engaged or unavailable")
	}
	ns := &corev1.Namespace{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: req.Namespace}, ns); err != nil {
		return err
	}
	if string(ns.UID) != req.IdentityRotationObservation.NamespaceUID || ns.DeletionTimestamp != nil {
		return fmt.Errorf("identity-rotate: namespace identity changed")
	}
	if brake := actuationbrake.Namespace(ns.Annotations); brake.Engaged {
		return fmt.Errorf("identity-rotate: namespace dry-run: %s", brake.Cause)
	}
	return nil
}

func identityAuthorization(ctx context.Context, ec EnactCtx, req Request) error {
	verbs := IdentityRotationVerbs(RequiredVerbsForBackend(BackendNative, model.ActionIdentityRotate), req.IdentityRotationObservation)
	for i := range verbs {
		if verbs[i].OperatorScoped {
			verbs[i].Namespace = ec.JournalNamespace
		}
	}
	allowed, unknown, why := ec.IdentityAuthz.Allowed(ctx, req.Namespace, verbs)
	if unknown || !allowed {
		return fmt.Errorf("identity-rotate: affirmative complete-plan RBAC required: %s", why)
	}
	return nil
}

func identityFederationCheck(pod *corev1.Pod, sa *corev1.ServiceAccount) error {
	if _, present := sa.Annotations["eks.amazonaws.com/role-arn"]; present {
		return fmt.Errorf("identity-rotate: federated IRSA identity refused")
	}
	for _, v := range pod.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, source := range v.Projected.Sources {
			if source.ServiceAccountToken != nil && source.ServiceAccountToken.Audience != "" {
				return fmt.Errorf("identity-rotate: extra-audience/federated token refused")
			}
		}
	}
	checkEnv := func(env []corev1.EnvVar) error {
		for _, e := range env {
			switch e.Name {
			case "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE":
				return fmt.Errorf("identity-rotate: AWS federated/Pod Identity credential injection refused")
			}
		}
		return nil
	}
	for _, c := range append(append([]corev1.Container(nil), pod.Spec.Containers...), pod.Spec.InitContainers...) {
		if err := checkEnv(c.Env); err != nil {
			return err
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if err := checkEnv(c.Env); err != nil {
			return err
		}
	}
	return nil
}

// Destructive authority rechecks the current Pod, dedicated consumer inventory and
// policy. Kubernetes provides no multi-object transaction; admission stays exclusive.
func identityAuthority(ctx context.Context, ec EnactCtx, req Request, strict bool) (*corev1.Pod, *v1alpha1.PhorvexPolicy, error) {
	if err := identitySafety(ctx, ec, req); err != nil {
		return nil, nil, err
	}
	o := req.IdentityRotationObservation
	if req.Namespace == ec.JournalNamespace || req.Namespace == "phorvex-system" || req.Namespace == "default" || strings.HasPrefix(req.Namespace, "kube-") || o.ServiceAccountName == "default" || strings.HasPrefix(o.ServiceAccountName, "system:") || strings.HasPrefix(o.ServiceAccountName, "kube-") || strings.Contains(strings.ToLower(o.ServiceAccountName), "operator") || strings.Contains(strings.ToLower(o.ServiceAccountName), "phorvex") {
		return nil, nil, fmt.Errorf("identity-rotate: default/system/operator identity refused")
	}
	if !o.LegacyTokenInventoryComplete || !o.FederatedIdentityAbsent {
		return nil, nil, fmt.Errorf("identity-rotate: trusted complete legacy inventory and absence of federated identity required")
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		return nil, nil, err
	}
	if string(pod.UID) != req.TargetUID || pod.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != o.ServiceAccountName || pod.Status.Phase != corev1.PodRunning || (strict && (!podReady(pod) || pod.ResourceVersion != o.PodResourceVersion)) {
		return nil, nil, fmt.Errorf("identity-rotate: stale or unhealthy target")
	}
	sa := &corev1.ServiceAccount{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: o.ServiceAccountName}, sa); err != nil {
		return nil, nil, err
	}
	if err := identityFederationCheck(pod, sa); err != nil {
		return nil, nil, err
	}
	// Re-read the admitted volume and mount, not merely a producer's projection flag.
	projected := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == req.PodBoundKubeAPIAuth.VolumeName && v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.ServiceAccountToken != nil && s.ServiceAccountToken.Audience == "" {
					projected = true
				}
			}
		}
	}
	mounted := false
	for _, c := range pod.Spec.Containers {
		if c.Name == req.PodBoundKubeAPIAuth.MountedContainer {
			for _, m := range c.VolumeMounts {
				if m.Name == req.PodBoundKubeAPIAuth.VolumeName {
					mounted = true
				}
			}
		}
	}
	if !projected || !mounted {
		return nil, nil, fmt.Errorf("identity-rotate: admitted token projection missing")
	}
	var pods corev1.PodList
	if err := ec.Reader.List(ctx, &pods, client.InNamespace(req.Namespace)); err != nil {
		return nil, nil, err
	}
	consumers := 0
	for _, p := range pods.Items {
		if p.Spec.ServiceAccountName != o.ServiceAccountName || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		consumers++
		if p.UID != pod.UID || p.DeletionTimestamp != nil {
			return nil, nil, fmt.Errorf("identity-rotate: shared or ambiguous consumer")
		}
	}
	if consumers != 1 || pods.Continue != "" {
		return nil, nil, fmt.Errorf("identity-rotate: incomplete consumer inventory")
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, pol); err != nil {
		return nil, nil, err
	}
	selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) || string(pol.UID) != req.PolicyUID || pol.Generation != req.PolicyGeneration || pol.DeletionTimestamp != nil || pol.Spec.IsDryRun() || !pol.Spec.ActionEnabled(v1alpha1.ActionType(model.ActionIdentityRotate)) || (req.Tenant != "" && pol.EffectiveTenant() != req.Tenant) {
		return nil, nil, fmt.Errorf("identity-rotate: selecting policy changed or unauthorized")
	}
	return pod, pol, nil
}

func identityLegacyCheck(ctx context.Context, ec EnactCtx, req Request, sa *corev1.ServiceAccount) error {
	o := req.IdentityRotationObservation
	seen := map[string]bool{}
	for _, s := range o.LegacyTokenSecrets {
		if s.Name == "" || s.UID == "" || s.ResourceVersion == "" || seen[s.Name] {
			return fmt.Errorf("identity-rotate: ambiguous legacy inventory")
		}
		seen[s.Name] = true
		secret := &corev1.Secret{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: s.Name}, secret); err != nil {
			return err
		}
		if string(secret.UID) != s.UID || secret.ResourceVersion != s.ResourceVersion || secret.Type != corev1.SecretTypeServiceAccountToken || secret.Annotations[corev1.ServiceAccountNameKey] != sa.Name || secret.Annotations[corev1.ServiceAccountUIDKey] != o.ServiceAccountUID || secret.DeletionTimestamp != nil || len(secret.Finalizers) != 0 {
			return fmt.Errorf("identity-rotate: legacy token identity changed")
		}
	}
	// Refuse unlisted references instead of broadening Secret-read privileges.
	for _, ref := range sa.Secrets {
		if !seen[ref.Name] {
			return fmt.Errorf("identity-rotate: ambiguous SA Secret reference")
		}
	}
	return nil
}

func enactIdentityRotation(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if !identityRequestEligible(req) {
		return HandlerResult{}, fmt.Errorf("%s", model.IdentityRotateUnsupportedReason)
	}
	// Resume the exact protected operation before requiring new-decision authority:
	// an absent SA must also be repairable through a direct retry after Pod/policy drift.
	if err := identitySafety(ctx, ec, req); err != nil {
		return HandlerResult{}, err
	}
	name := identityJournalName(req)
	cm := &corev1.ConfigMap{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: name}, cm)
	if err == nil {
		r, e := identityDecode(cm)
		if e != nil {
			return HandlerResult{}, e
		}
		if r.Request.OperationID == req.OperationID {
			if !reflect.DeepEqual(r.Request, req) {
				return HandlerResult{}, fmt.Errorf("identity-rotate: operation binding differs")
			}
			return resumeIdentityRotation(ctx, ec, cm, r)
		}
		if r.Phase != "complete" || r.NewUID != req.IdentityRotationObservation.ServiceAccountUID || r.CompletedAt.IsZero() || identityNow(ec).Sub(r.CompletedAt) < r.Cooldown {
			return HandlerResult{}, fmt.Errorf("identity-rotate: account operation pending or cooling down")
		}
	} else if !apierrors.IsNotFound(err) {
		return HandlerResult{}, err
	}
	_, pol, err := identityAuthority(ctx, ec, req, true)
	if err != nil {
		return HandlerResult{}, err
	}
	if err := identityAuthorization(ctx, ec, req); err != nil {
		return HandlerResult{}, err
	}
	sa := &corev1.ServiceAccount{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.IdentityRotationObservation.ServiceAccountName}, sa); err != nil {
		return HandlerResult{}, err
	}
	o := req.IdentityRotationObservation
	if string(sa.UID) != o.ServiceAccountUID || sa.ResourceVersion != o.ServiceAccountResourceVersion || sa.DeletionTimestamp != nil || len(sa.Finalizers) != 0 || len(sa.OwnerReferences) != 0 {
		return HandlerResult{}, fmt.Errorf("identity-rotate: stale or controller-owned SA")
	}
	if err := identityLegacyCheck(ctx, ec, req, sa); err != nil {
		return HandlerResult{}, err
	}
	// Only allowlisted metadata/spec fields survive. UID/RV/timestamps/managedFields,
	// token Secret refs, finalizers and owners are never replayed.
	fresh := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa.Name, Namespace: sa.Namespace, Labels: sa.Labels, Annotations: sa.Annotations}, ImagePullSecrets: sa.ImagePullSecrets, AutomountServiceAccountToken: sa.AutomountServiceAccountToken}
	if fresh.Annotations == nil {
		fresh.Annotations = map[string]string{}
	}
	delete(fresh.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	fresh.Annotations[identityOperationAnno] = req.OperationID
	cooldown := pol.Spec.EffectiveAntiOverRotationWindow()
	if cooldown < 10*time.Minute {
		cooldown = 10 * time.Minute
	}
	r := identityReceipt{Version: 1, Request: req, Account: fresh, Phase: "prepared", PreparedAt: identityNow(ec).UTC(), Cooldown: cooldown}
	if cm.Name == "" {
		b, e := json.Marshal(r)
		if e != nil {
			return HandlerResult{}, e
		}
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ec.JournalNamespace, Labels: map[string]string{identityJournalLabel: "v1"}}, Data: map[string]string{"receipt": string(b)}}
		if err := ec.Client.Create(ctx, cm); err != nil {
			return HandlerResult{}, err
		}
	} else if err := identityWrite(ctx, ec, cm, r); err != nil {
		return HandlerResult{}, err
	}
	return resumeIdentityRotation(ctx, ec, cm, r)
}

func resumeIdentityRotation(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r identityReceipt) (HandlerResult, error) {
	req := r.Request
	o := req.IdentityRotationObservation
	result := HandlerResult{MutationKind: "partial", RollbackRef: cm.Name, Note: "protected forward recovery pending"}
	advance := func(phase string) error { r.Phase = phase; return identityWrite(ctx, ec, cm, r) }
	authority := func() error { _, _, err := identityAuthority(ctx, ec, req, false); return err }
	if err := identitySafety(ctx, ec, req); err != nil {
		return result, err
	}
	key := client.ObjectKey{Namespace: req.Namespace, Name: o.ServiceAccountName}
	if r.Phase == "prepared" {
		if err := advance("delete-intent"); err != nil {
			return result, err
		}
	}
	if r.Phase == "delete-intent" {
		sa := &corev1.ServiceAccount{}
		err := ec.Reader.Get(ctx, key, sa)
		if err == nil {
			if string(sa.UID) != o.ServiceAccountUID || sa.ResourceVersion != o.ServiceAccountResourceVersion || sa.DeletionTimestamp != nil {
				return result, fmt.Errorf("identity-rotate: old SA changed before deletion")
			}
			if err := authority(); err != nil {
				return result, err
			}
			// A receipt is not an indefinite license to begin destructive work.
			age := identityNow(ec).Sub(r.PreparedAt)
			if r.PreparedAt.IsZero() || age < 0 || age > identityFirstDeleteMaxAge {
				return result, fmt.Errorf("identity-rotate: first-delete authority expired")
			}
			if err := identityAuthorization(ctx, ec, req); err != nil {
				return result, err
			}
			if err := advance("delete-intent"); err != nil {
				return result, err
			}
			if err := identitySafety(ctx, ec, req); err != nil {
				return result, err
			}
			uid, rv := sa.UID, sa.ResourceVersion
			if err := ec.Client.Delete(ctx, sa, client.Preconditions{UID: &uid, ResourceVersion: &rv}, client.PropagationPolicy(metav1.DeletePropagationOrphan)); err != nil && !apierrors.IsNotFound(err) {
				return result, err
			}
			result.Emitted = true
		} else if !apierrors.IsNotFound(err) {
			return result, err
		}
		// A different UID is not equivalent to observing native 404. Never adopt it.
		if err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
			sa := &corev1.ServiceAccount{}
			err := ec.Reader.Get(ctx, key, sa)
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			if err != nil {
				return false, err
			}
			if string(sa.UID) != o.ServiceAccountUID {
				return false, fmt.Errorf("identity-rotate: unexpected successor before native absence")
			}
			return false, nil
		}); err != nil {
			return result, err
		}
		if err := advance("absent"); err != nil {
			return result, err
		}
	}
	if r.Phase == "absent" {
		if err := advance("create-intent"); err != nil {
			return result, err
		}
	}
	if r.Phase == "create-intent" {
		if err := identitySafety(ctx, ec, req); err != nil {
			return result, err
		}
		sa := &corev1.ServiceAccount{}
		err := ec.Reader.Get(ctx, key, sa)
		if apierrors.IsNotFound(err) {
			if err := identitySafety(ctx, ec, req); err != nil {
				return result, err
			}
			sa = r.Account.DeepCopy()
			if err := ec.Client.Create(ctx, sa); err != nil {
				return result, err
			}
			result.Emitted = true
			// Confirm through authoritative GET, including on the next recovery after
			// a lost Create acknowledgement. Marker alone never licenses deleting it.
			if err := ec.Reader.Get(ctx, key, sa); err != nil {
				return result, err
			}
		} else if err != nil {
			return result, err
		}
		if sa.UID == "" || string(sa.UID) == o.ServiceAccountUID || sa.DeletionTimestamp != nil || sa.Annotations[identityOperationAnno] != req.OperationID || !reflect.DeepEqual(sa.ImagePullSecrets, r.Account.ImagePullSecrets) || !reflect.DeepEqual(sa.AutomountServiceAccountToken, r.Account.AutomountServiceAccountToken) {
			return result, fmt.Errorf("identity-rotate: new SA identity unconfirmed")
		}
		r.NewUID = string(sa.UID)
		if err := advance("cleanup"); err != nil {
			return result, err
		}
	}
	if r.Phase == "cleanup" {
		for _, s := range o.LegacyTokenSecrets {
			if err := identitySafety(ctx, ec, req); err != nil {
				return result, err
			}
			secret := &corev1.Secret{}
			err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: s.Name}, secret)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return result, err
			}
			if string(secret.UID) != s.UID || secret.ResourceVersion != s.ResourceVersion || secret.Type != corev1.SecretTypeServiceAccountToken || secret.Annotations[corev1.ServiceAccountNameKey] != o.ServiceAccountName || secret.Annotations[corev1.ServiceAccountUIDKey] != o.ServiceAccountUID {
				return result, fmt.Errorf("identity-rotate: replacement legacy Secret refused")
			}
			// Same cleanup phase is CAS-persisted immediately before EACH deletion.
			if err := advance("cleanup"); err != nil {
				return result, err
			}
			if err := identitySafety(ctx, ec, req); err != nil {
				return result, err
			}
			uid, rv := secret.UID, secret.ResourceVersion
			if err := ec.Client.Delete(ctx, secret, client.Preconditions{UID: &uid, ResourceVersion: &rv}); err != nil && !apierrors.IsNotFound(err) {
				return result, err
			}
			result.Emitted = true
			if err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{}); !apierrors.IsNotFound(err) {
				return result, fmt.Errorf("identity-rotate: legacy Secret absence unconfirmed: %v", err)
			}
		}
		r.CompletedAt = identityNow(ec).UTC()
		if err := advance("complete"); err != nil {
			return result, err
		}
	}
	sa := &corev1.ServiceAccount{}
	if err := ec.Reader.Get(ctx, key, sa); err != nil {
		return result, err
	}
	if r.Phase != "complete" || string(sa.UID) != r.NewUID || sa.DeletionTimestamp != nil {
		return result, fmt.Errorf("identity-rotate: completion identity changed")
	}
	result.MutationKind = "forward-only"
	result.ObjectsTouched = []string{objRef("ServiceAccount", req.Namespace, o.ServiceAccountName), objRef("ConfigMap", ec.JournalNamespace, cm.Name)}
	for _, s := range o.LegacyTokenSecrets {
		result.ObjectsTouched = append(result.ObjectsTouched, objRef("Secret", req.Namespace, s.Name))
	}
	if !result.Emitted {
		result.NoEffect = NoEffectReconciled
	}
	result.Note = "SA UID replaced; legacy tokens removed; Pod retained; mounted-token recovery and revocation require independent authentication observation"
	return result, nil
}

func recoverIdentityRotations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	var list corev1.ConfigMapList
	if err := ec.Reader.List(ctx, &list, client.InNamespace(ec.JournalNamespace), client.MatchingLabels{identityJournalLabel: "v1"}); err != nil {
		return nil, err
	}
	var events []RecoveryEvent
	for i := range list.Items {
		cm := &list.Items[i]
		r, err := identityDecode(cm)
		ev := RecoveryEvent{Receipt: cm.Name, Kind: string(model.ActionIdentityRotate), Phase: r.Phase, Outcome: "refused"}
		if err == nil && r.Phase == "complete" {
			continue
		}
		if err == nil && allow != nil && !allow(model.ActionIdentityRotate) {
			err = fmt.Errorf("identity-rotate recovery: native route disabled")
		}
		if err == nil {
			ev.PolicyNamespace, ev.PolicyName, ev.PolicyUID, ev.TargetName, ev.TargetUID = r.Request.Namespace, r.Request.PolicyName, r.Request.PolicyUID, r.Request.Pod, r.Request.TargetUID
			hr, e := resumeIdentityRotation(ctx, ec, cm, r)
			err = e
			ev.Effect = hr.Note
			if err == nil {
				ev.Outcome = "confirmed"
			}
		}
		ev.Err = err
		events = append(events, ev)
	}
	return events, nil
}
