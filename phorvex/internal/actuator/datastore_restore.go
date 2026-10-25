package actuator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/datastore"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// datastoreRestoreFreshness bounds how long after observation a restore may still enact. The
// persisted poison does not self-heal, but a stale observation must be re-detected rather than
// acted on; this is the self-limiting window of the datastore-restore steer.
const datastoreRestoreFreshness = 5 * time.Minute

// datastoreRestoreCapability gates offer-time: a reader, a target Pod, and a live datastore
// (app Service + app-facing store ConfigMap + an operator-owned trusted snapshot whose content
// hashes to its own recorded label) in the TARGET's own namespace (parametric — no app-namespace
// literal). There is no journal: the content hash is the idempotency record.
func datastoreRestoreCapability(ctx context.Context, reader client.Reader, t Target) (bool, string) {
	if reader == nil || t.Namespace == "" || t.UID == "" || t.Pod == "" {
		return false, "datastore-restore: reader or target unavailable"
	}
	live, e := datastore.ValidateLive(ctx, reader, t.Namespace, t.UID)
	if e != nil {
		return false, "datastore-restore: " + e.Error()
	}
	if live.TrustedSHA == "" || len(live.TrustedContent) == 0 {
		return false, "datastore-restore: no trusted snapshot available"
	}
	return true, ""
}

// datastoreRestoreAuthority re-establishes, against the authoritative reader, that this exact
// decision is still bound to a live datastore, the selecting policy (action enabled), the target
// Pod inside the selector, and a trusted admission-stamped SecurityEvent whose observation
// annotation matches the selection-time observation. Like agent-action-deny it does NOT pin a
// specific injector identity: any trusted creator is honored (the detector path stays
// reproducible inside an isolated lane), with the console-target-pod-UID binding still required.
func datastoreRestoreAuthority(ctx context.Context, ec EnactCtx, req Request) (datastore.Live, error) {
	o := req.DatastoreRestoreObservation
	if ec.Reader == nil || ec.Client == nil || req.Action != model.ActionDatastoreRestore ||
		req.Namespace == "" || req.TargetUID == "" || req.Pod == "" || req.PolicyName == "" ||
		req.PolicyUID == "" || req.PolicyGeneration < 1 ||
		o == nil || o.Namespace != req.Namespace || o.TargetPodUID != req.TargetUID ||
		o.EventUID == "" || o.EventName == "" || o.CreatorIdentity == "" ||
		o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration ||
		o.StoreName == "" || o.StoreConfigMapUID == "" || o.TrustedSnapshotConfigMapUID == "" || o.ServiceUID == "" ||
		!datastore.ValidSHA(o.PoisonedSHA256) || !datastore.ValidSHA(o.TrustedSHA256) || o.PoisonedSHA256 == o.TrustedSHA256 ||
		o.ObservedAt.IsZero() || time.Since(o.ObservedAt) < 0 || time.Since(o.ObservedAt) >= datastoreRestoreFreshness {
		return datastore.Live{}, errors.New("datastore-restore request/observation authority incomplete")
	}
	live, e := datastore.ValidateLive(ctx, ec.Reader, o.Namespace, o.TargetPodUID)
	if e != nil {
		return live, e
	}
	if live.ServiceUID != o.ServiceUID || live.StoreUID != o.StoreConfigMapUID || live.TrustedUID != o.TrustedSnapshotConfigMapUID {
		return live, errors.New("datastore-restore Service, store or trusted-snapshot identity drift")
	}
	if live.TrustedSHA != o.TrustedSHA256 {
		return live, errors.New("datastore-restore trusted snapshot changed since selection")
	}
	found := false
	for _, pod := range live.Pods {
		if pod.UID == req.TargetUID && pod.Name == req.Pod {
			found = true
		}
	}
	if !found {
		return live, errors.New("datastore-restore selected Pod name/UID differs")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, policy); e != nil {
		return live, e
	}
	if string(policy.UID) != req.PolicyUID || policy.Generation != req.PolicyGeneration || policy.DeletionTimestamp != nil {
		return live, errors.New("datastore-restore selecting policy epoch changed")
	}
	enabled := false
	for _, action := range policy.Spec.Actions.Enabled {
		if string(action) == string(model.ActionDatastoreRestore) {
			enabled = true
		}
	}
	if !enabled {
		return live, errors.New("datastore-restore action absent from selecting policy")
	}
	pod := &corev1.Pod{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); e != nil {
		return live, e
	}
	sel, e := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if e != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) || string(pod.UID) != req.TargetUID {
		return live, errors.New("datastore-restore target left policy selector")
	}
	event := &amtdv1beta1.SecurityEvent{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); e != nil {
		return live, e
	}
	if event.DeletionTimestamp != nil || string(event.UID) != o.EventUID || event.Spec.Rule.Type != datastore.RuleType ||
		event.Spec.Rule.Source == "" || !litellmEventTimeMatches(event.CreationTimestamp.Time, o.ObservedAt, time.Now()) ||
		event.Annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != req.TargetUID ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.Annotations[datastore.ObservationAnnotation] == "" {
		return live, errors.New("datastore-restore trusted exact SecurityEvent changed")
	}
	assertion, e := datastore.ParseObservation(event.Annotations[datastore.ObservationAnnotation])
	if e != nil || assertion.Namespace != o.Namespace || assertion.StoreName != o.StoreName ||
		assertion.StoreConfigMapUID != o.StoreConfigMapUID || assertion.TrustedSnapshotConfigMapUID != o.TrustedSnapshotConfigMapUID ||
		assertion.ServiceUID != o.ServiceUID || assertion.TargetPodUID != o.TargetPodUID ||
		assertion.PoisonedSHA256 != o.PoisonedSHA256 || assertion.TrustedSHA256 != o.TrustedSHA256 ||
		assertion.PolicyName != o.PolicyName || assertion.PolicyUID != o.PolicyUID || assertion.PolicyGeneration != o.PolicyGeneration {
		return live, errors.New("datastore-restore SecurityEvent assertion changed after selection")
	}
	return live, nil
}

type datastoreStoreHashResponse struct {
	SHA256 string `json:"sha256"`
}

// errDatastoreReadbackPending marks a restore that is written and API-confirmed (the store
// ConfigMap now canonicalizes to the trusted sha) but not yet observed reflected on every
// serving Pod's app endpoint. The store app re-reads the ConfigMap live per request, so this is
// normally transient.
var errDatastoreReadbackPending = errors.New("datastore-restore all-Pod effective readback deadline")

// datastoreRestoreReadback confirms every serving Pod's app reports the trusted store hash via
// its read-only hash endpoint. Success == all Pods serve the restored content.
func datastoreRestoreReadback(ctx context.Context, ec EnactCtx, live datastore.Live, wantSHA string) error {
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 0, DisableKeepAlives: true}
	hc := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("datastore-restore hash-endpoint redirect refused")
	}}
	for _, pod := range live.Pods {
		if net.ParseIP(pod.IP) == nil {
			return errors.New("datastore-restore Pod IP invalid")
		}
		url := "http://" + net.JoinHostPort(pod.IP, strconv.Itoa(datastore.ServingPort)) + datastore.ReadbackPath
		httpReq, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return e
		}
		resp, e := hc.Do(httpReq)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		if e != nil || resp.StatusCode != http.StatusOK {
			return errors.New("datastore-restore hash endpoint unavailable")
		}
		var st datastoreStoreHashResponse
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&st) != nil || !datastore.ValidSHA(st.SHA256) {
			return errors.New("datastore-restore hash response malformed")
		}
		if st.SHA256 != wantSHA {
			return errors.New("datastore-restore Pod does not yet serve the trusted hash")
		}
	}
	return nil
}

func datastoreAwaitReadback(ctx context.Context, ec EnactCtx, live datastore.Live, wantSHA string) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var last error
	for {
		if last = datastoreRestoreReadback(ctx, ec, live, wantSHA); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%w: %w", errDatastoreReadbackPending, last)
		case <-tick.C:
		}
	}
}

type datastoreRestoreHandler struct{}

func (datastoreRestoreHandler) Name() string { return string(model.ActionDatastoreRestore) }
func (datastoreRestoreHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	live, e := datastoreRestoreAuthority(ctx, ec, req)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	o := req.DatastoreRestoreObservation
	touched := []string{req.Namespace + "/" + datastore.StoreConfigMapName}

	// Idempotency: the store content hash is the record. If the live store already matches the
	// trusted snapshot, the restore has already landed; only confirm the all-Pod readback.
	if live.CurrentSHA == live.TrustedSHA {
		if e = datastoreAwaitReadback(ctx, ec, live, live.TrustedSHA); e != nil {
			if errors.Is(e, errDatastoreReadbackPending) {
				return HandlerResult{MutationKind: "partial", Emitted: true, ObjectsTouched: touched,
					Note: "datastore already at trusted snapshot; all-Pod hash readback pending"}, nil
			}
			return HandlerResult{MutationKind: "partial"}, e
		}
		return HandlerResult{MutationKind: "forward-only", NoEffect: NoEffectReconciled, ObjectsTouched: touched,
			Note: "datastore already matches trusted snapshot on all serving Pods"}, nil
	}

	// RECOMPUTE the canonical sha of the exact bytes we will write and require it == trusted sha.
	// The restore bytes come ONLY from the operator-owned snapshot, never from the event.
	restoreSHA, e := datastore.CanonicalSHA(live.TrustedContent)
	if e != nil || restoreSHA != live.TrustedSHA {
		return HandlerResult{}, RefusedWithoutEffect(errors.New("datastore-restore trusted content failed recomputed canonical sha check"))
	}

	// One exact resourceVersion CAS against the validated store ConfigMap. A lost acknowledgement
	// is ambiguous; the content-hash idempotency makes a later re-selection a safe no-op reconcile.
	cm := &corev1.ConfigMap{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: datastore.StoreConfigMapName}, cm); e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	if string(cm.UID) != live.StoreUID || cm.ResourceVersion != live.StoreRV {
		return HandlerResult{MutationKind: "partial"}, errors.New("datastore-restore pre-CAS store authority changed")
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[datastore.StoreKey] = string(live.TrustedContent)
	if e = ec.Client.Update(ctx, cm); e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}

	current, e := datastore.ValidateLive(ctx, ec.Reader, o.Namespace, o.TargetPodUID)
	if e != nil || current.StoreUID != live.StoreUID || current.TrustedUID != live.TrustedUID ||
		current.ServiceUID != live.ServiceUID || current.CurrentSHA != live.TrustedSHA {
		return HandlerResult{MutationKind: "partial"}, errors.New("datastore-restore post-CAS store hash not confirmed")
	}
	if e = datastoreAwaitReadback(ctx, ec, current, current.TrustedSHA); e != nil {
		if errors.Is(e, errDatastoreReadbackPending) {
			return HandlerResult{MutationKind: "partial", Emitted: true, ObjectsTouched: touched,
				Note: "datastore restored to trusted snapshot; all-Pod hash readback pending"}, nil
		}
		return HandlerResult{MutationKind: "partial"}, e
	}
	return HandlerResult{MutationKind: "forward-only", Emitted: true, ObjectsTouched: touched,
		Note: fmt.Sprintf("datastore restored to trusted snapshot; store hash == trusted (%s) on all serving Pods", current.TrustedSHA[:12])}, nil
}

func init() { HandlerRegistry.Register(datastoreRestoreHandler{}) }
