package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const experimentMarker = "phorvex.ai/console-experiment"

type experimentPolicy struct {
	Namespace, Name, UID, ResourceVersion, Mode, SpecHash, MetadataHash, Marker string
	SpecJSON                                                                    string
}

type experimentCluster interface {
	Policy(context.Context, string) (experimentPolicy, error)
	SetPolicyMode(context.Context, experimentPolicy, string, string, bool) (experimentPolicy, error)
	DeletePod(context.Context, string, string, string, string) error
	PodUID(context.Context, string, string) (string, bool, error)
	CreateEvent(context.Context, string, string, string, string) (string, error)
	EventIdentity(context.Context, string, string) (string, string, bool, error)
	DeleteEvent(context.Context, string, string, string) error
}

var securityEventGVR = schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents"}

func (d dynamicExperimentCluster) CreateEvent(ctx context.Context, name, token, ns, pod string) (string, error) {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1",
		"kind":       "SecurityEvent",
		"metadata": map[string]any{
			"name": name,
			"labels": map[string]any{
				"phorvex.ai/redteam":    "true",
				"phorvex.ai/experiment": "true",
			},
			"annotations": map[string]any{experimentMarker: token},
		},
		"spec": map[string]any{
			"description": "three-arm synthetic detector signal on " + pod,
			"targets":     []any{ns + "/" + pod},
			"rule": map[string]any{
				"type": "Panic", "threatLevel": "critical", "source": "ExternalDetector",
			},
		},
	}}
	c, err := d.client()
	if err != nil {
		return "", err
	}
	created, err := c.Resource(securityEventGVR).Create(ctx, u, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	if created.GetUID() == "" || created.GetAnnotations()[experimentMarker] != token {
		return "", fmt.Errorf("created signal identity unavailable or mismatched")
	}
	return string(created.GetUID()), nil
}

func (d dynamicExperimentCluster) PodUID(ctx context.Context, ns, name string) (string, bool, error) {
	c, e := d.client()
	if e != nil {
		return "", false, e
	}
	u, e := c.Resource(corePodGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		return "", false, nil
	}
	if e != nil {
		return "", false, e
	}
	if u.GetUID() == "" {
		return "", true, fmt.Errorf("pod UID unavailable")
	}
	return string(u.GetUID()), true, nil
}
func (d dynamicExperimentCluster) EventIdentity(ctx context.Context, _, name string) (string, string, bool, error) {
	c, e := d.client()
	if e != nil {
		return "", "", false, e
	}
	// SecurityEvent is cluster scoped. The namespace is carried in spec.targets and
	// remains part of the caller's authorization boundary; it is not an API path.
	u, e := c.Resource(securityEventGVR).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		return "", "", false, nil
	}
	if e != nil {
		return "", "", false, e
	}
	return string(u.GetUID()), u.GetAnnotations()[experimentMarker], true, nil
}
func (d dynamicExperimentCluster) DeleteEvent(ctx context.Context, _, name, uid string) error {
	c, e := d.client()
	if e != nil {
		return e
	}
	u := types.UID(uid)
	return c.Resource(securityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &u}})
}

type dynamicExperimentCluster struct{ cfg *rest.Config }

func (d dynamicExperimentCluster) client() (dynamic.Interface, error) {
	cfg := d.cfg
	if cfg == nil {
		var err error
		cfg, err = restConfigFor("")
		if err != nil {
			return nil, err
		}
	}
	return dynamic.NewForConfig(cfg)
}

func policyFromObject(u *unstructured.Unstructured) (experimentPolicy, error) {
	spec, ok := u.Object["spec"].(map[string]any)
	if !ok {
		return experimentPolicy{}, fmt.Errorf("policy spec unavailable")
	}
	b, err := json.Marshal(spec)
	if err != nil {
		return experimentPolicy{}, err
	}
	h := sha256.Sum256(b)
	marker := u.GetAnnotations()[experimentMarker]
	annotations := map[string]string{}
	for k, v := range u.GetAnnotations() {
		annotations[k] = v
	}
	delete(annotations, experimentMarker)
	meta, _ := json.Marshal(map[string]any{"labels": u.GetLabels(), "annotations": annotations})
	mh := sha256.Sum256(meta)
	mode, _, _ := unstructured.NestedString(u.Object, "spec", "mode")
	return experimentPolicy{Namespace: u.GetNamespace(), Name: u.GetName(), UID: string(u.GetUID()),
		ResourceVersion: u.GetResourceVersion(), Mode: mode, SpecHash: hex.EncodeToString(h[:]), MetadataHash: hex.EncodeToString(mh[:]), Marker: marker, SpecJSON: string(b)}, nil
}

func specHashWithMode(p experimentPolicy, mode string) string {
	var spec map[string]any
	if json.Unmarshal([]byte(p.SpecJSON), &spec) != nil {
		return ""
	}
	spec["mode"] = mode
	b, _ := json.Marshal(spec)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func supportsResettablePolicy(p experimentPolicy) error {
	if p.Marker != "" {
		return fmt.Errorf("policy is already owned by another experiment")
	}
	var spec struct {
		Actions struct {
			Enabled []string `json:"enabled"`
		} `json:"actions"`
	}
	if json.Unmarshal([]byte(p.SpecJSON), &spec) != nil || len(spec.Actions.Enabled) == 0 {
		return fmt.Errorf("policy must explicitly enable only the resettable rotate action")
	}
	for _, a := range spec.Actions.Enabled {
		if a != "rotate" {
			return fmt.Errorf("policy action %q has no verified reset contract", a)
		}
	}
	return nil
}

func policyMatchesOwnedState(live experimentPolicy, e experimentEvent) bool {
	return live.UID == e.Policy.UID && live.Marker == e.Operation &&
		live.Mode == e.OwnedMode && live.SpecHash == e.OwnedSpecHash &&
		live.MetadataHash == e.OwnedMetadataHash
}

func policyMatchesRestoredState(live experimentPolicy, e experimentEvent) bool {
	return live.UID == e.Policy.UID && live.Marker == "" &&
		live.Mode == e.OriginalMode &&
		live.SpecHash == specHashWithMode(e.Policy, e.OriginalMode) &&
		live.MetadataHash == e.OwnedMetadataHash
}

func policyMatchesPreparedState(live experimentPolicy, e experimentEvent) bool {
	return live.UID == e.Policy.UID && live.Marker == "" &&
		live.Mode == e.OriginalMode && live.SpecHash == e.Policy.SpecHash &&
		live.MetadataHash == e.Policy.MetadataHash
}

func restoredPolicyAcknowledged(restored, owned experimentPolicy, e experimentEvent) bool {
	return restored.UID == owned.UID && restored.Marker == "" &&
		restored.Mode == e.OriginalMode &&
		restored.SpecHash == specHashWithMode(owned, e.OriginalMode) &&
		restored.MetadataHash == owned.MetadataHash
}

func (d dynamicExperimentCluster) Policy(ctx context.Context, ns string) (experimentPolicy, error) {
	c, err := d.client()
	if err != nil {
		return experimentPolicy{}, err
	}
	list, err := c.Resource(phorvexPolicyGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return experimentPolicy{}, err
	}
	if len(list.Items) != 1 {
		return experimentPolicy{}, fmt.Errorf("expected exactly one PhorvexPolicy in %s, found %d", ns, len(list.Items))
	}
	return policyFromObject(&list.Items[0])
}

func (d dynamicExperimentCluster) SetPolicyMode(ctx context.Context, old experimentPolicy, mode, operation string, clear bool) (experimentPolicy, error) {
	c, err := d.client()
	if err != nil {
		return experimentPolicy{}, err
	}
	marker := any(operation)
	if clear {
		marker = nil
	}
	patch := map[string]any{"metadata": map[string]any{"resourceVersion": old.ResourceVersion, "annotations": map[string]any{experimentMarker: marker}}, "spec": map[string]any{"mode": mode}}
	b, _ := json.Marshal(patch)
	u, err := c.Resource(phorvexPolicyGVR).Namespace(old.Namespace).Patch(ctx, old.Name, types.MergePatchType, b, metav1.PatchOptions{})
	if err != nil {
		return experimentPolicy{}, err
	}
	if string(u.GetUID()) != old.UID {
		return experimentPolicy{}, fmt.Errorf("policy identity changed")
	}
	return policyFromObject(u)
}

func (d dynamicExperimentCluster) DeletePod(ctx context.Context, ns, name, uid, rv string) error {
	c, err := d.client()
	if err != nil {
		return err
	}
	u := types.UID(uid)
	return c.Resource(corePodGVR).Namespace(ns).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &u, ResourceVersion: &rv}})
}

var corePodGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

type experimentEvent struct {
	Operation         string           `json:"operation"`
	Phase             string           `json:"phase"`
	At                string           `json:"at"`
	Actor             string           `json:"actor"`
	Namespace         string           `json:"namespace"`
	Attack            string           `json:"attack"`
	Deployment        string           `json:"deployment"`
	DeploymentUID     string           `json:"deploymentUid"`
	Policy            experimentPolicy `json:"policy"`
	OriginalMode      string           `json:"originalMode"`
	OwnedMode         string           `json:"ownedMode"`
	OwnedSpecHash     string           `json:"ownedSpecHash"`
	OwnedMetadataHash string           `json:"ownedMetadataHash"`
	Error             string           `json:"error,omitempty"`
	Arm               *armEvidence     `json:"arm,omitempty"`
}

func experimentEventsPath(c Config) string { return c.statePath("experiment-events.jsonl") }

func (s *Server) experimentCluster() experimentCluster {
	if s.experimentAPI != nil {
		return s.experimentAPI
	}
	return dynamicExperimentCluster{cfg: s.cfg.ExperimentRESTConfig}
}

func (s *Server) appendExperiment(e experimentEvent) error {
	e.At = s.cfg.now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.cfg.appendState(experimentEventsPath(s.cfg), b)
}

func retainedExperimentEvents(cfg Config) (map[string]experimentEvent, error) {
	b, err := readStateLedgerHistory(experimentEventsPath(cfg))
	if err != nil {
		return nil, err
	}
	latest := map[string]experimentEvent{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e experimentEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil || e.Operation == "" {
			return nil, fmt.Errorf("malformed retained experiment journal")
		}
		latest[e.Operation] = e
	}
	return latest, nil
}

func (s *Server) unresolvedExperiments() map[string]experimentEvent {
	latest, err := retainedExperimentEvents(s.cfg)
	if err != nil {
		s.recordStateError(err)
		return map[string]experimentEvent{"corrupt": {Operation: "corrupt", Phase: "recovery-required", Error: err.Error()}}
	}
	for id, e := range latest {
		if e.Phase == "complete" || e.Phase == "incomplete-restored" || e.Phase == "no-effect" {
			delete(latest, id)
		}
	}
	return latest
}

func (s *Server) recoverExperiments() {
	for _, e := range s.unresolvedExperiments() {
		if e.Operation == "corrupt" {
			continue
		}
		var problems []string
		if e.Arm != nil && e.Arm.Event != "" {
			if cleanupErr := s.cleanupExperimentSignal(e.Namespace, experimentStimulusReceipt{Event: e.Arm.Event, EventUID: e.Arm.EventUID, Token: e.Operation}); cleanupErr != nil {
				problems = append(problems, cleanupErr.Error())
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		live, err := s.experimentCluster().Policy(ctx, e.Namespace)
		restored, noEffect := false, false
		if err == nil && policyMatchesOwnedState(live, e) {
			e.Phase = "restore-intent"
			if journalErr := s.appendExperiment(e); journalErr != nil {
				problems = append(problems, "persist restore intention: "+journalErr.Error())
			}
			var acknowledged experimentPolicy
			acknowledged, err = s.experimentCluster().SetPolicyMode(ctx, live, e.OriginalMode, e.Operation, true)
			if err == nil {
				if !restoredPolicyAcknowledged(acknowledged, live, e) {
					err = fmt.Errorf("policy restore acknowledgement mismatched intended state")
				} else {
					e.Policy = acknowledged
					e.OwnedMode = e.OriginalMode
					e.OwnedSpecHash = acknowledged.SpecHash
					e.OwnedMetadataHash = acknowledged.MetadataHash
					restored = true
				}
			}
		} else if err == nil && policyMatchesRestoredState(live, e) {
			e.Policy = live
			e.OwnedMode = e.OriginalMode
			e.OwnedSpecHash = live.SpecHash
			e.OwnedMetadataHash = live.MetadataHash
			restored = true
		} else if err == nil && e.Phase == "prepared" && policyMatchesPreparedState(live, e) {
			noEffect = true
		} else if err == nil && e.Phase == "transition-intent" && policyMatchesPreparedState(live, e) {
			noEffect = true
		} else if err == nil {
			err = fmt.Errorf("recovery ownership conflict")
		}
		cancel()
		if err != nil {
			problems = append(problems, err.Error())
		}
		if len(problems) == 0 {
			switch {
			case noEffect:
				e.Phase = "no-effect"
				e.Error = ""
			case restored:
				e.Phase = "incomplete-restored"
				e.Error = "process restarted before completed result was durable"
			default:
				e.Phase = "recovery-required"
				e.Error = "recovery did not establish a terminal policy state"
			}
		} else {
			e.Phase = "recovery-required"
			e.Error = strings.Join(problems, "; ")
		}
		if persistErr := s.appendExperiment(e); persistErr != nil {
			s.recordStateError(persistErr)
		}
	}
}
