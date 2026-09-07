/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package controller

import (
	"context"
	"encoding/json"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/phorvex/phorvex/internal/ingest"
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
// The stamp is authoritative: whatever the client put in the annotation is OVERWRITTEN on every
// CREATE and UPDATE, so an identity cannot self-declare a trusted creator, and cannot keep a
// stale stamp by editing an event it did not create.
//
// The webhook is registered failurePolicy=Ignore on purpose: it must never be able to block the
// cluster's security-event flow. An event that misses the stamp is not trusted by ingest, so the
// failure direction is closed on the belief side, not on the API server.
type SecurityEventStamper struct{}

// Handle implements admission.Handler.
func (SecurityEventStamper) Handle(_ context.Context, req admission.Request) admission.Response {
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
	if user := req.UserInfo.Username; user != "" {
		annotations[ingest.CreatorIdentityAnnotation] = user
	} else {
		// No authenticated user on the request: remove any client-supplied claim rather than
		// leave one standing. The event is then unstamped, i.e. untrusted at ingest.
		delete(annotations, ingest.CreatorIdentityAnnotation)
	}
	obj.SetAnnotations(annotations)
	patched, err := json.Marshal(&obj)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, patched)
}

// SetupSecurityEventWebhookWithManager registers the creator-identity stamp. It is a raw
// handler (not a CustomDefaulter) because only the admission REQUEST carries UserInfo — the
// object never does.
func SetupSecurityEventWebhookWithManager(mgr ctrl.Manager) error {
	mgr.GetWebhookServer().Register(securityEventStampPath, &webhook.Admission{Handler: SecurityEventStamper{}})
	return nil
}
