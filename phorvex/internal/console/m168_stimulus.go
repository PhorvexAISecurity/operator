package console

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type experimentStimulusReceipt struct {
	AttackID string `json:"attackId"`
	Pod      string `json:"pod"`
	PodUID   string `json:"podUid"`
	Deploy   string `json:"deploy"`
	Event    string `json:"event"`
}

// executeResettableFoothold is deliberately narrow: voice is the shipped stateless,
// resettable positive comparison fixture. Sticky/stateful and vLLM mutations are refused
// by the experiment before policy mutation until they have an equally strong reset contract.
func (s *Server) executeResettableFoothold(actor, ns string) (experimentStimulusReceipt, error) {
	if ns != "voice" {
		return experimentStimulusReceipt{}, fmt.Errorf("three-arm comparison unsupported for %s: no verified reset contract", ns)
	}
	kctl := func(timeout time.Duration, args ...string) (string, error) {
		return s.cfg.execText(timeout, "kubectl", append([]string{"-n", ns}, args...)...)
	}
	pod, uid, err := s.resettableTarget(ns)
	if err != nil {
		return experimentStimulusReceipt{}, err
	}
	base := s.snapshotBaseline(ns, pod)
	event := "redteam-arms-" + strings.ToLower(strings.TrimPrefix(fmt.Sprintf("%x", s.cfg.now().UnixNano()), "-"))
	yaml := fmt.Sprintf(`apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: %s
  namespace: %s
  labels:
    phorvex.ai/redteam: "true"
    phorvex.ai/experiment: "true"
spec:
  description: "three-arm measured foothold signal on %s"
  targets: ["%s/%s"]
  rule:
    type: "Panic"
    threatLevel: "critical"
    source: "ExternalDetector"
`, event, ns, pod, ns, pod)
	f, err := os.CreateTemp("", "phorvex-arms-se-*.yaml")
	if err != nil {
		return experimentStimulusReceipt{}, err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(yaml); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return experimentStimulusReceipt{}, fmt.Errorf("write attack manifest: %w", err)
	}
	if err = s.persistEffectIntent("/api/availability-arms/run", actor, ns, "foothold"); err != nil {
		return experimentStimulusReceipt{}, fmt.Errorf("attack refused before effect: %w", err)
	}
	out, err := kctl(10*time.Second, "create", "-f", f.Name())
	if err != nil {
		return experimentStimulusReceipt{}, fmt.Errorf("create SecurityEvent: %w: %s", err, strings.TrimSpace(out))
	}
	id := s.startAttackRecord("", ns, ns, pod, "Container-escape foothold", "foothold", "T1611", "rotate", false, base)
	return experimentStimulusReceipt{AttackID: id, Pod: pod, PodUID: uid, Deploy: s.firstDeploy(ns), Event: event}, nil
}

func (s *Server) resettableTarget(ns string) (string, string, error) {
	if ns != "voice" {
		return "", "", fmt.Errorf("three-arm comparison unsupported for %s: no verified reset contract", ns)
	}
	kctl := func(timeout time.Duration, args ...string) (string, error) {
		return s.cfg.execText(timeout, "kubectl", append([]string{"-n", ns}, args...)...)
	}
	line, err := kctl(8*time.Second, "get", "pod", "-l", "r6th.io/rotation-target=true",
		"-o", `jsonpath={range .items[?(@.status.phase=="Running")]}{.metadata.name}|{.metadata.uid}{"\n"}{end}`)
	if err != nil {
		return "", "", fmt.Errorf("resolve attack target: %w: %s", err, strings.TrimSpace(line))
	}
	first := strings.Split(strings.TrimSpace(line), "\n")[0]
	parts := strings.Split(first, "|")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("no running identity-bound rotation target in %s", ns)
	}
	pod, uid := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if pvc, e := kctl(6*time.Second, "get", "pod", pod, "-o", "jsonpath={.spec.volumes[*].persistentVolumeClaim.claimName}"); e != nil || strings.TrimSpace(pvc) != "" {
		return "", "", fmt.Errorf("target is not a verified resettable stateless pod")
	}
	return pod, uid, nil
}

func (s *Server) resetExperimentStimulus(r experimentStimulusReceipt) error {
	out, err := s.cfg.execText(8*time.Second, "kubectl", "-n", "voice", "delete", "securityevent", r.Event, "--ignore-not-found=false")
	if err != nil {
		return fmt.Errorf("clear experiment signal: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}
