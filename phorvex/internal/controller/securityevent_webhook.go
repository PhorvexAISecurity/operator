/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// securityEventStampPath is the mutating endpoint that binds a SecurityEvent to the identity
// that actually created it.
const securityEventStampPath = "/stamp-amtd-r6security-com-v1beta1-securityevent"

// SecurityEventStamper closes the M-94 trust boundary at its only possible point.
//
// A SecurityEvent is cluster-scoped and its `spec.rule.source` is written by the creator, so
// nothing on the stored object says who made it: ingest could not tell a real detector from an
// injected event claiming to be one (the live campaign steered the brain ~25 times with
// `source: K3Detector`). The authenticated identity exists in exactly one place — the admission
// request's UserInfo — so this handler copies it onto the object and ingest allowlists THAT.
//
// The stamp is authoritative WHEN THIS HANDLER RUNS: generic events are stamped from each
// request. Dedicated completed disclosures bind creator, policy and owner at first admission;
// later updates must preserve that immutable admission authority.
//
// The webhook is registered failurePolicy=Ignore on purpose: it must never be able to block the
// cluster's security-event flow. That availability choice is NOT self-securing, and the earlier
// claim that a missed stamp simply leaves the event unstamped was wrong (M-94 outage residual):
// `Ignore` means the API server stores the object UNCHANGED, so an annotation the CLIENT wrote
// survives untouched and ingest reads it as an authenticated creator. What actually closes that
// is a separate, server-side ValidatingAdmissionPolicy + Deny binding
// (charts/phorvex/templates/securityevent-identity-policy.yaml): it is evaluated in-process by
// the API server, after mutation, so it has no endpoint that can be down, and it rejects any
// present creator-identity that does not equal the authenticated requester. An event with NO
// claim is still admitted and is untrusted at ingest — open on ingestion, closed on belief.
//
// So: this handler WRITES the identity, the policy GUARANTEES that a written identity is real.
// Neither alone is the trust boundary, and a binary-only deployment (no chart, no policy) does
// not have the guarantee.
type SecurityEventStamper struct {
	Reader client.Reader
	Now    func() time.Time
}

// Handle implements admission.Handler.
func (s SecurityEventStamper) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return admission.Allowed("no stamp needed")
	}
	var obj unstructured.Unstructured
	if err := json.Unmarshal(req.Object.Raw, &obj); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	raw, present := annotations[disclosure.Annotation]
	var oldEvent amtdv1beta1.SecurityEvent
	oldPresent := false
	if req.Operation == admissionv1.Update {
		var err error
		oldEvent, err = disclosureEvent(req.OldObject.Raw)
		if err != nil {
			return admission.Denied("completed disclosure rejected: old SecurityEvent is missing")
		}
		_, oldPresent = oldEvent.Annotations[disclosure.Annotation]
		if oldPresent && !present {
			return admission.Denied("completed disclosure rejected: completed-disclosure evidence cannot be removed")
		}
	}
	if present {
		canonical, admittedAt, creator, err := s.validateCompletedDisclosureAdmission(ctx, req, raw, oldEvent, oldPresent)
		if err != nil {
			return admission.Denied("completed disclosure rejected: " + err.Error())
		}
		annotations[disclosure.Annotation] = canonical
		annotations[disclosure.AdmissionTimeAnnotation] = admittedAt.Format(time.RFC3339Nano)
		annotations[disclosure.AdmissionContractAnnotation] = disclosure.BoundaryContract
		annotations[ingest.CreatorIdentityAnnotation] = creator
	} else if user := req.UserInfo.Username; user != "" {
		annotations[ingest.CreatorIdentityAnnotation] = user
	} else {
		// No authenticated user on the request: remove any client-supplied claim rather than
		// leave one standing. The event is then unstamped, i.e. untrusted at ingest. The
		// admission policy makes the same call independently — a missing username never
		// authorises a non-empty claim.
		delete(annotations, ingest.CreatorIdentityAnnotation)
	}
	obj.SetAnnotations(annotations)
	patched, err := json.Marshal(&obj)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, patched)
}

func disclosureEvent(raw []byte) (amtdv1beta1.SecurityEvent, error) {
	var event amtdv1beta1.SecurityEvent
	if len(raw) == 0 {
		return event, errors.New("SecurityEvent body is missing")
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return event, err
	}
	return event, nil
}

func (s SecurityEventStamper) validateCompletedDisclosureAdmission(ctx context.Context, req admission.Request, raw string, oldEvent amtdv1beta1.SecurityEvent, oldPresent bool) (string, time.Time, string, error) {
	payload, canonical, _, err := disclosure.Parse(raw)
	if err != nil {
		return "", time.Time{}, "", err
	}
	event, err := disclosureEvent(req.Object.Raw)
	if err != nil {
		return "", time.Time{}, "", err
	}
	if event.Spec.Rule.Type != model.CompletedDisclosureRuleType || event.Spec.Rule.Source != model.CompletedDisclosureSource ||
		event.Spec.Rule.ThreatLevel != "high" || len(event.Spec.Rule.Match) != 0 || event.Spec.Rule.ScoreThreshold != nil ||
		event.Spec.AnomalyScore != nil || len(event.Spec.Metrics) != 0 || event.Spec.Evidence != nil ||
		event.Spec.Description != model.CompletedDisclosureDescription {
		return "", time.Time{}, "", errors.New("unexpected completed-disclosure rule")
	}
	wantTarget := payload.DecisionAsset.Namespace + "/" + payload.DecisionAsset.Name
	if len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != wantTarget {
		return "", time.Time{}, "", errors.New("SecurityEvent target does not match disclosure target")
	}
	if oldPresent {
		oldRaw := oldEvent.Annotations[disclosure.Annotation]
		if oldRaw == "" || !disclosure.EqualPayload(oldRaw, raw) || len(oldEvent.Spec.Targets) != 1 ||
			oldEvent.Spec.Targets[0] != event.Spec.Targets[0] || !reflect.DeepEqual(oldEvent.Spec.Rule, event.Spec.Rule) {
			return "", time.Time{}, "", errors.New("completed-disclosure evidence is immutable")
		}
		admittedAt, err := time.Parse(time.RFC3339Nano, oldEvent.Annotations[disclosure.AdmissionTimeAnnotation])
		if err != nil || oldEvent.Annotations[disclosure.AdmissionContractAnnotation] != disclosure.BoundaryContract {
			return "", time.Time{}, "", errors.New("completed-disclosure admission authority is missing")
		}
		creator := oldEvent.Annotations[ingest.CreatorIdentityAnnotation]
		if creator == "" || creator != payload.Classification.ObserverIdentity || !ingest.CompletedDisclosureTrust().Allows(creator) {
			return "", time.Time{}, "", errors.New("completed-disclosure creator authority is invalid")
		}
		return string(canonical), admittedAt, creator, nil
	}
	if !ingest.CompletedDisclosureTrust().Allows(req.UserInfo.Username) {
		return "", time.Time{}, "", errors.New("authenticated creator is not an allowed loss observer")
	}
	if payload.Classification.ObserverIdentity != req.UserInfo.Username {
		return "", time.Time{}, "", errors.New("authenticated creator does not match disclosure observer identity")
	}
	if s.Reader == nil {
		return "", time.Time{}, "", errors.New("authoritative disclosure reader is unavailable")
	}
	var policy v1alpha1.PhorvexPolicy
	if err := s.Reader.Get(ctx, types.NamespacedName{Namespace: payload.PolicyEpoch.Namespace, Name: payload.PolicyEpoch.Name}, &policy); err != nil ||
		string(policy.UID) != payload.PolicyEpoch.UID || policy.Generation != payload.PolicyEpoch.Generation {
		return "", time.Time{}, "", errors.New("policy epoch is not current")
	}
	tenant := policy.Spec.Tenant
	if tenant == "" {
		tenant = policy.Namespace
	}
	if tenant != payload.ProtectedScope.Tenant {
		return "", time.Time{}, "", errors.New("policy tenant does not match protected scope")
	}
	immediate, stable, err := ingest.ResolveStableWorkloadOwner(ctx, s.Reader,
		payload.DecisionAsset.Namespace, payload.DecisionAsset.Name, payload.DecisionAsset.TargetUID)
	if err != nil || !sameDisclosureIdentity(immediate, payload.ImmediateController) || !sameDisclosureIdentity(stable, payload.StableWorkloadOwner) {
		return "", time.Time{}, "", errors.New("workload owner identity is not current")
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	if payload.Observation.CompletedAt.After(now) {
		return "", time.Time{}, "", errors.New("completed observation is after admission")
	}
	return string(canonical), now, req.UserInfo.Username, nil
}

func sameDisclosureIdentity(a, b model.ObjectIdentity) bool {
	return a.APIVersion == b.APIVersion && a.Kind == b.Kind && a.Namespace == b.Namespace &&
		a.Name == b.Name && a.UID == b.UID
}

// SetupSecurityEventWebhookWithManager registers the creator-identity stamp. It is a raw
// handler (not a CustomDefaulter) because only the admission REQUEST carries UserInfo — the
// object never does.
func SetupSecurityEventWebhookWithManager(mgr ctrl.Manager) error {
	mgr.GetWebhookServer().Register(securityEventStampPath, &webhook.Admission{Handler: SecurityEventStamper{Reader: mgr.GetAPIReader()}})
	return nil
}
