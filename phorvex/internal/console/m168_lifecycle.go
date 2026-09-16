package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
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
}

type dynamicExperimentCluster struct{}

func (dynamicExperimentCluster) client() (dynamic.Interface, error) {
	cfg, err := restConfigFor("")
	if err != nil {
		return nil, err
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
	return dynamicExperimentCluster{}
}

func (s *Server) appendExperiment(e experimentEvent) error {
	e.At = s.cfg.now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.cfg.appendState(experimentEventsPath(s.cfg), b)
}

func (s *Server) unresolvedExperiments() map[string]experimentEvent {
	b, err := readStateLedgerHistory(experimentEventsPath(s.cfg))
	if err != nil {
		s.recordStateError(err)
		return nil
	}
	latest := map[string]experimentEvent{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e experimentEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil || e.Operation == "" {
			s.recordStateError(fmt.Errorf("malformed retained experiment journal"))
			return map[string]experimentEvent{"corrupt": {Operation: "corrupt", Phase: "recovery-required", Error: "malformed retained experiment journal"}}
		}
		latest[e.Operation] = e
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		live, err := s.experimentCluster().Policy(ctx, e.Namespace)
		if err == nil && live.UID == e.Policy.UID && live.Marker == e.Operation && live.Mode == e.OwnedMode && live.SpecHash == e.OwnedSpecHash && live.MetadataHash == e.OwnedMetadataHash {
			var restored experimentPolicy
			restored, err = s.experimentCluster().SetPolicyMode(ctx, live, e.OriginalMode, e.Operation, true)
			if err == nil {
				e.Policy = restored
				e.OwnedMode = e.OriginalMode
				e.Phase = "restored"
				err = s.appendExperiment(e)
			}
		} else if err == nil && live.Marker == "" && e.Phase == "prepared" {
			e.Phase = "no-effect"
			err = s.appendExperiment(e)
		} else if err == nil && live.Marker == "" && e.Phase == "transition-intent" && live.UID == e.Policy.UID && live.ResourceVersion == e.Policy.ResourceVersion && live.Mode == e.Policy.Mode {
			e.Phase = "no-effect"
			err = s.appendExperiment(e)
		} else if err == nil && live.Marker == "" && live.UID == e.Policy.UID && live.Mode == e.OriginalMode && live.SpecHash == e.Policy.SpecHash && live.MetadataHash == e.Policy.MetadataHash && (e.Phase == "restored" || e.Phase == "restore-intent") {
			e.Phase = "incomplete-restored"
			e.Error = "process restarted after restoration before completed result was durable"
			err = s.appendExperiment(e)
		} else if err == nil {
			err = fmt.Errorf("recovery ownership conflict")
		}
		cancel()
		if err != nil {
			e.Phase = "recovery-required"
			e.Error = err.Error()
			if persistErr := s.appendExperiment(e); persistErr != nil {
				s.recordStateError(persistErr)
			}
		}
	}
}
