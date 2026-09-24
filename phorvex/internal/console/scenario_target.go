package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
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
	pod           corev1.Pod
	ownerKind     string
	ownerName     string
	ownerUID      string
	ownerGen      int64
	ownerRevision string
	policyUID     string
	policyGen     int64
	policyName    string
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
	return s.resolveScenarioExactTargetForTenant(ns, name, uid, ns)
}

// The named NATS response fixture uses a fresh, server-owned policy tenant to
// avoid colliding with another policy in its precreated namespace. All Pod,
// owner, selector and policy checks remain identical to ordinary exact mode.
func (s *Server) resolveScenarioExactTargetForTenant(ns, name, uid, tenant string) (scenarioExactTarget, error) {
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
		return t, fmt.Errorf("exact target requires one authoritative controller")
	}
	ownerRef := metav1.GetControllerOf(p)
	if ownerRef == nil || ownerRef.APIVersion != "apps/v1" || ownerRef.Name == "" || ownerRef.UID == "" {
		return t, fmt.Errorf("exact target requires an authoritative apps/v1 owner")
	}
	switch ownerRef.Kind {
	case "ReplicaSet":
		var rs appsv1.ReplicaSet
		if err := s.scenarioObject(ns, "replicaset", ownerRef.Name, &rs); err != nil {
			return t, err
		}
		if rs.Namespace != ns || rs.Name != ownerRef.Name || rs.UID != ownerRef.UID || rs.ResourceVersion == "" || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
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
		t.ownerKind, t.ownerName, t.ownerUID, t.ownerGen, t.ownerRevision = "Deployment", dep.Name, string(dep.UID), dep.Generation, string(rs.UID)
	case "StatefulSet":
		var set appsv1.StatefulSet
		if err := s.scenarioObject(ns, "statefulset", ownerRef.Name, &set); err != nil {
			return t, err
		}
		if set.Namespace != ns || set.Name != ownerRef.Name || set.UID != ownerRef.UID || set.ResourceVersion == "" || set.DeletionTimestamp != nil ||
			set.Generation <= 0 || set.Status.ObservedGeneration != set.Generation || set.Spec.Replicas == nil || *set.Spec.Replicas <= 0 ||
			set.Spec.ServiceName == "" || set.Spec.Selector == nil ||
			(len(set.Spec.Selector.MatchLabels) == 0 && len(set.Spec.Selector.MatchExpressions) == 0) {
			return t, fmt.Errorf("exact target StatefulSet identity or observed spec is unavailable")
		}
		selector, err := metav1.LabelSelectorAsSelector(set.Spec.Selector)
		if err != nil || !selector.Matches(labels.Set(p.Labels)) {
			return t, fmt.Errorf("exact target Pod is outside StatefulSet selector")
		}
		start := int64(0)
		if set.Spec.Ordinals != nil {
			start = int64(set.Spec.Ordinals.Start)
		}
		ordinal := strings.TrimPrefix(p.Name, set.Name+"-")
		parsed, parseErr := strconv.ParseInt(ordinal, 10, 32)
		if start < 0 || !strings.HasPrefix(p.Name, set.Name+"-") || parseErr != nil || strconv.FormatInt(parsed, 10) != ordinal ||
			parsed < start || parsed >= start+int64(*set.Spec.Replicas) ||
			p.Labels["statefulset.kubernetes.io/pod-name"] != p.Name {
			return t, fmt.Errorf("exact target Pod ordinal or name is outside StatefulSet")
		}
		if index := p.Labels["apps.kubernetes.io/pod-index"]; index != "" && index != ordinal {
			return t, fmt.Errorf("exact target Pod index differs from StatefulSet ordinal")
		}
		if set.Status.CurrentRevision == "" || set.Status.CurrentRevision != set.Status.UpdateRevision ||
			set.Status.Replicas <= 0 || set.Status.CurrentReplicas != set.Status.Replicas || set.Status.UpdatedReplicas != set.Status.Replicas ||
			p.Labels["controller-revision-hash"] != set.Status.CurrentRevision {
			return t, fmt.Errorf("exact target StatefulSet revision is ambiguous or Pod revision differs")
		}
		t.ownerKind, t.ownerName, t.ownerUID, t.ownerGen, t.ownerRevision = "StatefulSet", set.Name, string(set.UID), set.Generation, set.Status.CurrentRevision
	default:
		return t, fmt.Errorf("exact target owner kind is unsupported")
	}
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
		if policy.UID == "" || policy.ResourceVersion == "" || policy.Generation <= 0 || policy.Spec.EffectiveMode() != v1alpha1.ModeActive || policy.EffectiveTenant() != tenant {
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
	return s.recheckScenarioExactTargetForTenant(ns, name, uid, ns, original)
}

func (s *Server) recheckScenarioExactTargetForTenant(ns, name, uid, tenant string, original scenarioExactTarget) error {
	current, err := s.resolveScenarioExactTargetForTenant(ns, name, uid, tenant)
	if err != nil {
		return err
	}
	if current.ownerKind != original.ownerKind || current.ownerUID != original.ownerUID || current.ownerName != original.ownerName ||
		current.ownerGen != original.ownerGen || current.ownerRevision != original.ownerRevision ||
		current.policyUID != original.policyUID || current.policyName != original.policyName || current.policyGen != original.policyGen ||
		current.pod.Labels["phorvex.ai/quarantined"] != "" {
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
