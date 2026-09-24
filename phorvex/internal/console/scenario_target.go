package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
)

type scenarioFireRequest struct {
	Namespace string `json:"namespace"`
	Scenario  string `json:"scenario"`
	MITRE     string `json:"mitre"`
	Expected  string `json:"expected"`
	Action    string `json:"action"`
	TargetPod string `json:"targetPod"`
	TargetUID string `json:"targetUid"`
}

var scenarioTargetUIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Decode one bounded object and reject duplicate keys before any durable intent.
// json.Decoder's usual last-key-wins behavior is unsafe for namespace and target identity.
func decodeScenarioFireRequest(r *http.Request) (scenarioFireRequest, error) {
	var body scenarioFireRequest
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
	if err != nil || len(rawBody) > 16<<10 {
		return body, fmt.Errorf("request body is unavailable or too large")
	}
	d := json.NewDecoder(bytes.NewReader(rawBody))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return body, fmt.Errorf("request must be one JSON object")
	}
	seen := map[string]bool{}
	fields := map[string]json.RawMessage{}
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return body, fmt.Errorf("invalid request field: %w", err)
		}
		key, ok := keyToken.(string)
		folded := strings.ToLower(key)
		if !ok || seen[folded] {
			return body, fmt.Errorf("duplicate or malformed request field")
		}
		for _, canonical := range []string{"namespace", "scenario", "mitre", "expected", "action", "targetPod", "targetUid"} {
			if strings.EqualFold(key, canonical) && key != canonical {
				return body, fmt.Errorf("request field %q must use canonical spelling", key)
			}
		}
		seen[folded] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return body, fmt.Errorf("invalid request field %q: %w", key, err)
		}
		fields[key] = value
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return body, fmt.Errorf("request object is incomplete")
	}
	if _, err := d.Token(); err != io.EOF {
		return body, fmt.Errorf("request has trailing data")
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return body, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return body, fmt.Errorf("invalid request values: %w", err)
	}
	if seen["targetpod"] != seen["targetuid"] {
		return body, fmt.Errorf("targetPod and targetUid must be supplied together")
	}
	if seen["targetpod"] && (!nsRe.MatchString(body.TargetPod) || !scenarioTargetUIDPattern.MatchString(body.TargetUID)) {
		return body, fmt.Errorf("targetPod or targetUid is malformed")
	}
	return body, nil
}

type scenarioExactTarget struct {
	pod        corev1.Pod
	ownerName  string
	ownerUID   string
	policyUID  string
	policyGen  int64
	policyName string
}

func (s *Server) scenarioObject(ns, kind, name string, out any) error {
	args := []string{"-n", ns, "get", kind}
	if name != "" {
		args = append(args, name)
	}
	args = append(args, "-o", "json")
	raw, err := s.cfg.execText(6*time.Second, "kubectl", args...)
	if err != nil {
		return fmt.Errorf("read %s %s/%s: %w", kind, ns, name, err)
	}
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		return fmt.Errorf("decode %s %s/%s: %w", kind, ns, name, err)
	}
	return nil
}

func (s *Server) resolveScenarioExactTarget(ns, name, uid string) (scenarioExactTarget, error) {
	var t scenarioExactTarget
	if err := s.scenarioObject(ns, "pod", name, &t.pod); err != nil {
		return t, err
	}
	p := &t.pod
	if p.Namespace != ns || p.Name != name || string(p.UID) != uid || p.ResourceVersion == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Labels["phorvex.ai/quarantined"] != "" {
		return t, fmt.Errorf("exact target Pod identity or running state is unavailable")
	}
	ready := false
	for _, c := range p.Status.Conditions {
		ready = ready || c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue
	}
	if !ready {
		return t, fmt.Errorf("exact target Pod is not Ready")
	}
	if len(p.OwnerReferences) != 1 {
		return t, fmt.Errorf("exact target requires one ReplicaSet controller")
	}
	rsRef := metav1.GetControllerOf(p)
	if rsRef == nil || rsRef.APIVersion != "apps/v1" || rsRef.Kind != "ReplicaSet" || rsRef.UID == "" {
		return t, fmt.Errorf("exact target requires an authoritative ReplicaSet owner")
	}
	var rs appsv1.ReplicaSet
	if err := s.scenarioObject(ns, "replicaset", rsRef.Name, &rs); err != nil {
		return t, err
	}
	if rs.Namespace != ns || rs.Name != rsRef.Name || rs.UID != rsRef.UID || rs.ResourceVersion == "" || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
		return t, fmt.Errorf("exact target ReplicaSet identity changed")
	}
	depRef := metav1.GetControllerOf(&rs)
	if depRef == nil || depRef.APIVersion != "apps/v1" || depRef.Kind != "Deployment" || depRef.UID == "" {
		return t, fmt.Errorf("exact target requires an authoritative Deployment owner")
	}
	var dep appsv1.Deployment
	if err := s.scenarioObject(ns, "deployment", depRef.Name, &dep); err != nil {
		return t, err
	}
	if dep.Namespace != ns || dep.Name != depRef.Name || dep.UID != depRef.UID || dep.ResourceVersion == "" || dep.DeletionTimestamp != nil {
		return t, fmt.Errorf("exact target Deployment identity changed")
	}
	t.ownerName, t.ownerUID = dep.Name, string(dep.UID)
	var policies v1alpha1.PhorvexPolicyList
	if err := s.scenarioObject(ns, "phorvexpolicy", "", &policies); err != nil {
		return t, err
	}
	if policies.Continue != "" || policies.RemainingItemCount != nil {
		return t, fmt.Errorf("exact target policy inventory is incomplete")
	}
	for i := range policies.Items {
		policy := &policies.Items[i]
		if policy.Namespace != ns || policy.DeletionTimestamp != nil {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
		if err != nil {
			return t, fmt.Errorf("exact target policy selector is invalid")
		}
		if !selector.Matches(labels.Set(p.Labels)) {
			continue
		}
		if t.policyUID != "" {
			return t, fmt.Errorf("exact target matches multiple policies")
		}
		if policy.UID == "" || policy.ResourceVersion == "" || policy.Generation <= 0 || policy.Spec.EffectiveMode() != v1alpha1.ModeActive || policy.EffectiveTenant() != ns {
			return t, fmt.Errorf("exact target matching policy is not active for this tenant")
		}
		t.policyName, t.policyUID, t.policyGen = policy.Name, string(policy.UID), policy.Generation
	}
	if t.policyUID == "" {
		return t, fmt.Errorf("exact target has no matching active policy")
	}
	return t, nil
}

func (s *Server) recheckScenarioExactTarget(ns, name, uid string, original scenarioExactTarget) error {
	current, err := s.resolveScenarioExactTarget(ns, name, uid)
	if err != nil {
		return err
	}
	if current.ownerUID != original.ownerUID || current.ownerName != original.ownerName || current.policyUID != original.policyUID || current.policyName != original.policyName || current.policyGen != original.policyGen || current.pod.Labels["phorvex.ai/quarantined"] != "" {
		return fmt.Errorf("exact target owner or policy changed before signal creation")
	}
	return nil
}

func scenarioHasPVC(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim != nil && strings.TrimSpace(v.PersistentVolumeClaim.ClaimName) != "" {
			return true
		}
	}
	return false
}
