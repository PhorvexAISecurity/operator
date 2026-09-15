package actuator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const adapterHorizon = 15 * time.Minute

var adapterDetectorMu sync.RWMutex
var adapterDetectors = map[string]bool{}

// ConfigureAdapterDetectorIdentities receives the same normalized authenticated
// creator allowlist configured for ingest at startup. Empty fails closed.
func ConfigureAdapterDetectorIdentities(ids []string) {
	adapterDetectorMu.Lock()
	defer adapterDetectorMu.Unlock()
	adapterDetectors = map[string]bool{}
	for _, id := range ids {
		if id != "" {
			adapterDetectors[id] = true
		}
	}
}

func adapterCreatorAllowed(id string) bool {
	adapterDetectorMu.RLock()
	defer adapterDetectorMu.RUnlock()
	return adapterDetectors[id]
}

func validateAdapterDispatch(ctx context.Context, ec EnactCtx, req Request, podUID string) (string, error) {
	o := req.AdapterObservation
	if o == nil || req.TargetUID == "" || req.TargetUID != podUID || o.TargetPodUID != podUID ||
		o.EventUID == "" || o.EventName == "" || o.CreatorIdentity == "" || !adapterCreatorAllowed(o.CreatorIdentity) ||
		!validRuntimeAdapterName(o.AdapterName) {
		return "", fmt.Errorf("adapter-rotate unsupported: missing or mismatched trusted observation")
	}
	reader := ec.Reader
	if reader == nil {
		return "", fmt.Errorf("adapter-rotate unsupported: authoritative reader unavailable")
	}
	var fresh corev1.Pod
	if err := reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &fresh); err != nil {
		return "", fmt.Errorf("adapter-rotate unsupported: fresh Pod unavailable: %w", err)
	}
	if string(fresh.UID) != podUID || fresh.DeletionTimestamp != nil || fresh.Labels[labelLoRAEnabled] != "true" {
		return "", fmt.Errorf("adapter-rotate unsupported: fresh Pod identity or capability drifted")
	}
	se := &unstructured.Unstructured{}
	se.SetAPIVersion("amtd.r6security.com/v1beta1")
	se.SetKind("SecurityEvent")
	if err := reader.Get(ctx, client.ObjectKey{Name: o.EventName}, se); err != nil {
		return "", fmt.Errorf("adapter-rotate unsupported: detector event unavailable: %w", err)
	}
	created := se.GetCreationTimestamp()
	age := time.Since(created.Time)
	if string(se.GetUID()) != o.EventUID || created.IsZero() ||
		age < 0 || age >= adapterHorizon || se.GetDeletionTimestamp() != nil ||
		se.GetAnnotations()["phorvex.ai/creator-identity"] != o.CreatorIdentity ||
		se.GetAnnotations()["phorvex.ai/target-pod-uid"] != podUID ||
		se.GetAnnotations()["phorvex.ai/adapter-name"] != o.AdapterName {
		return "", fmt.Errorf("adapter-rotate unsupported: detector event identity or payload drifted")
	}
	typ, _, _ := unstructured.NestedString(se.Object, "spec", "rule", "type")
	if typ != model.AttackVectorAdapter {
		return "", fmt.Errorf("adapter-rotate unsupported: detector event type drifted")
	}
	source, _, _ := unstructured.NestedString(se.Object, "spec", "rule", "source")
	if source == RuleSource {
		return "", fmt.Errorf("adapter-rotate unsupported: self event cannot authenticate adapter")
	}
	targets, _, _ := unstructured.NestedStringSlice(se.Object, "spec", "targets")
	matched := false
	for _, target := range targets {
		if strings.TrimSpace(target) == req.Namespace+"/"+req.Pod {
			matched = true
		}
	}
	if !matched {
		return "", fmt.Errorf("adapter-rotate unsupported: detector event target drifted")
	}
	return o.AdapterName, nil
}

func validRuntimeAdapterName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
