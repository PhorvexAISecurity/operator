package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func outputObservation(p guardrailOutputProfile, observedAt time.Time) ([]byte, error) {
	f := p.Fixture
	return json.Marshal(struct {
		Version          int    `json:"version"`
		RuleID           string `json:"ruleId"`
		RuleSHA256       string `json:"ruleSHA256"`
		ConfigMapUID     string `json:"configMapUID"`
		PodUID           string `json:"podUID"`
		RequestPath      string `json:"requestPath"`
		PolicyName       string `json:"policyName"`
		PolicyUID        string `json:"policyUID"`
		PolicyGeneration int64  `json:"policyGeneration"`
		ObservedAt       string `json:"observedAt"`
	}{1, guardrailOutputRuleID, f.OutputPolicyRuleSHA256, f.OutputPolicyConfigMapUID, f.PodUID,
		guardrailOutputPath, f.PolicyName, f.PolicyUID, f.PolicyGeneration, observedAt.UTC().Format(time.RFC3339Nano)})
}

// Create only after the exact original guarded response and controls are
// sealed. The observation carries identities, never the private marker or its
// hash. The API admission stamp, not this manifest, supplies creator identity.
func (s *Server) createSensitiveOutputEvent(p guardrailOutputProfile, observedAt time.Time, privateMarker string) (*attackStimulusEvidence, error) {
	f := p.Fixture
	sequence := vllmEventSequence.Add(1)
	correlation := fmt.Sprintf("%x-%x", s.cfg.now().UnixNano(), sequence)
	name := "redteam-vllm-sensitive-output-" + correlation
	candidate := &attackStimulusEvidence{Kind: "synthetic-security-event", TargetUID: f.PodUID,
		EventName: name, EventRule: guardrailOutputEventType, Correlation: correlation,
		Limitation: "Explicitly injected after a measured application serializer disclosure; natural detection untested"}
	observation, err := outputObservation(p, observedAt)
	if err != nil {
		return candidate, err
	}
	object := map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name,
			"labels": map[string]string{"phorvex.ai/redteam": "true", "phorvex.ai/console-vllm": "true", "phorvex.ai/attack-correlation": correlation},
			"annotations": map[string]string{"phorvex.ai/console-target-pod-uid": f.PodUID,
				"phorvex.ai/sensitive-output-observation-v1": string(observation)}},
		"spec": map[string]any{"description": "injected signal after actual synthetic support application output disclosure",
			"targets":      []string{"vllm/" + f.PodName},
			"rule":         map[string]any{"type": guardrailOutputEventType, "threatLevel": "critical", "source": "redteam"},
			"anomalyScore": "0.95"},
	}
	manifest, err := json.Marshal(object)
	if err != nil {
		return candidate, err
	}
	if !outputMarkerPattern.MatchString(privateMarker) || strings.Contains(string(manifest), privateMarker) {
		return candidate, errors.New("marker-bearing output event manifest refused")
	}
	candidate.createManifest = append([]byte(nil), manifest...)
	file, err := os.CreateTemp("", "phorvex-output-event-*.json")
	if err != nil {
		return candidate, err
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
		return candidate, errors.New("private output event manifest unavailable")
	}
	stdout, err := s.cfg.execText(10*time.Second, "kubectl", "--context="+p.Context, "create", "-f", file.Name(), "-o", "json")
	if len(stdout) > 64<<10 {
		return candidate, errors.New("output event create reply exceeded bound; reconcile exact candidate")
	}
	candidate.createReply = []byte(stdout)
	if err != nil {
		return candidate, fmt.Errorf("output event create unresolved; reconcile exact candidate %s", name)
	}
	var event vllmSecurityEvent
	if availabilityDecode([]byte(stdout), &event) != nil || event.Metadata.Name != name || event.Metadata.UID == "" ||
		event.Metadata.CreationTimestamp == "" || event.Metadata.Labels["phorvex.ai/attack-correlation"] != correlation ||
		event.Metadata.Annotations["phorvex.ai/console-target-pod-uid"] != f.PodUID ||
		event.Metadata.Annotations["phorvex.ai/sensitive-output-observation-v1"] != string(observation) ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != "vllm/"+f.PodName ||
		event.Spec.Rule.Type != guardrailOutputEventType || event.Spec.Rule.Source != "redteam" {
		return candidate, fmt.Errorf("output event create reply incomplete; reconcile exact candidate %s", name)
	}
	candidate.Observed = true
	candidate.EventUID = event.Metadata.UID
	candidate.EventCreatedAt = event.Metadata.CreationTimestamp
	return candidate, nil
}
