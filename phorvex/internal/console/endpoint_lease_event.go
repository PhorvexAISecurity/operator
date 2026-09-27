package console

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const (
	endpointLeaseEventType       = "phorvex.attack.endpoint-lease-reuse"
	endpointLeaseEventAnnotation = "phorvex.ai/endpoint-lease-observation-v1"
)

func endpointLeaseObservation(p endpointLeaseProfile, snap endpointLeaseSnapshot, pod corev1.Pod,
	a, b endpointLeaseHTTPReceipt, observedAt time.Time) []byte {
	value := map[string]any{"version": 1, "scenarioId": endpointLeaseScenario,
		"acceptedStatus": a.Status, "acceptedResponseSHA256": a.ResponseSHA256,
		"retainedBaselineStatus": b.Status, "retainedBaselineResponseSHA256": b.ResponseSHA256,
		"evidenceSource": "TEST_INJECTED", "observedAt": observedAt.UTC().Format(time.RFC3339Nano),
		"policyConfigMapUID": snap.ConfigMapUID, "policyGeneration": p.PolicyGeneration,
		"policyName": p.PolicyName, "policyUID": p.PolicyUID, "priorRevision": snap.State.Revision,
		"proxySourceSHA256": p.ProxySourceSHA256, "retainedClientHMAC": p.ClientBHMAC,
		"revokedClientHMAC": p.ClientAHMAC, "secretUID": p.TenantSecretUID,
		"seedSHA256": p.SeedSHA256, "serviceUID": p.ServiceUID, "targetPodUID": string(pod.UID)}
	raw, _ := json.Marshal(value)
	return raw
}

func endpointLeaseDeleteEvent(name, uid string) error {
	if name == "" || uid == "" {
		return errors.New("endpoint lease exact event cleanup identity absent")
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("endpoint lease cleanup authority unavailable")
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return errors.New("endpoint lease cleanup client unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	precondition := types.UID(uid)
	err = client.Resource(securityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &precondition}})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.New("endpoint lease exact event deletion unresolved")
	}
	_, err = client.Resource(securityEventGVR).Get(ctx, name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		return errors.New("endpoint lease exact event absence unverified")
	}
	return nil
}

func endpointLeaseEventMatches(raw []byte, name, target, uid, creator, observation string) bool {
	var created vllmSecurityEvent
	return json.Unmarshal(raw, &created) == nil && created.Metadata.Name == name && created.Metadata.Namespace == "" &&
		created.Metadata.UID == uid && created.Metadata.CreationTimestamp != "" &&
		created.Metadata.Annotations["phorvex.ai/creator-identity"] == creator &&
		created.Metadata.Annotations[model.ConsoleTargetPodUIDAnnotation] == target &&
		created.Metadata.Annotations[endpointLeaseEventAnnotation] == observation &&
		len(created.Spec.Targets) == 1 && created.Spec.Rule.Type == endpointLeaseEventType
}

func (s *Server) createEndpointLeaseEvent(ctx context.Context, privateDir, run string, p endpointLeaseProfile,
	snap endpointLeaseSnapshot, pod corev1.Pod, a, b endpointLeaseHTTPReceipt, observedAt time.Time) (*attackStimulusEvidence, error) {
	if !a.ValidCompletion || a.Status != 200 || !b.ValidCompletion || b.Status != 200 ||
		observedAt.IsZero() || time.Since(observedAt) < 0 || time.Since(observedAt) >= 50*time.Second {
		return nil, errors.New("endpoint lease real A/B baseline unavailable or stale")
	}
	name := "endpoint-lease-" + run
	observation := endpointLeaseObservation(p, snap, pod, a, b, observedAt)
	object := map[string]any{"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name,
			"labels": map[string]string{"phorvex.ai/redteam": "true", "phorvex.ai/attack-correlation": run},
			"annotations": map[string]string{model.ConsoleTargetPodUIDAnnotation: string(pod.UID),
				endpointLeaseEventAnnotation: string(observation)}},
		"spec": map[string]any{"description": "test-generated signal after real public Service A and B completions; first A request remains accepted",
			"targets":      []string{"vllm/" + pod.Name},
			"rule":         map[string]any{"type": endpointLeaseEventType, "threatLevel": "critical", "source": "redteam"},
			"anomalyScore": "0.95"}}
	manifest, err := json.Marshal(object)
	if err != nil || publishMongoAuditFile(privateDir, "event-intent.json", manifest, 8192) != nil {
		return nil, errors.New("endpoint lease event intent not durable")
	}
	candidate := &attackStimulusEvidence{Kind: "test-injected-after-real-endpoint-lease-reuse", EventName: name,
		EventRule: endpointLeaseEventType, TargetUID: string(pod.UID), Correlation: run, BehavioralExecuted: true,
		Limitation: "owned A/B callers only; no natural detection, SSRF, extraction or first-request prevention claim"}
	candidate.createManifest = manifest
	file, err := os.CreateTemp("", "endpoint-lease-event-*.json")
	if err != nil {
		return candidate, errors.New("endpoint lease event manifest unavailable")
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(manifest)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return candidate, errors.New("endpoint lease event manifest unavailable")
	}
	raw, createErr := s.cfg.execText(10*time.Second, "kubectl", "create", "-f", file.Name(), "-o", "json")
	if createErr != nil || len(raw) == 0 || len(raw) > 65536 {
		// A lost create acknowledgement is ambiguous. A deterministic exact-name
		// read can recover the real admitted UID; a missing read stays UNKNOWN.
		raw, createErr = s.cfg.execText(8*time.Second, "kubectl", "get", "securityevent", name, "-o", "json")
	}
	if createErr != nil || len(raw) == 0 || len(raw) > 65536 {
		return candidate, errors.New("endpoint lease event admission unknown")
	}
	var created vllmSecurityEvent
	if json.Unmarshal([]byte(raw), &created) != nil || created.Metadata.UID == "" ||
		!endpointLeaseEventMatches([]byte(raw), name, string(pod.UID), created.Metadata.UID, p.EventCreator, string(observation)) ||
		created.Spec.Targets[0] != "vllm/"+pod.Name || created.Spec.Rule.Source != "redteam" {
		return candidate, errors.New("endpoint lease event creator or target admission differs")
	}
	candidate.EventUID, candidate.EventCreatedAt, candidate.Observed = created.Metadata.UID, created.Metadata.CreationTimestamp, true
	candidate.createReply = []byte(raw)
	if publishMongoAuditFile(privateDir, "event-created-original.json", []byte(raw), 65536) != nil {
		return candidate, errors.New("endpoint lease admitted event reply not durable")
	}
	_ = ctx
	return candidate, nil
}
