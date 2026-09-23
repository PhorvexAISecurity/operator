package console

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type experimentStimulusReceipt struct {
	AttackID    string    `json:"attackId"`
	Pod         string    `json:"pod"`
	PodUID      string    `json:"podUid"`
	PodRV       string    `json:"podResourceVersion"`
	Deploy      string    `json:"deploy"`
	Event       string    `json:"event"`
	EventUID    string    `json:"eventUid,omitempty"`
	Token       string    `json:"operationToken"`
	WindowStart time.Time `json:"-"`
	WindowEnd   time.Time `json:"-"`
	AcceptedAt  time.Time `json:"-"`
}

type resettableTargetInfo struct {
	Pod, UID, ResourceVersion, Deploy, OwnerUID string
}

// executeResettableFoothold is deliberately narrow: voice is the shipped stateless,
// resettable positive comparison fixture. Sticky/stateful and vLLM mutations are refused
// by the experiment before policy mutation until they have an equally strong reset contract.
func (s *Server) executeResettableFoothold(actor, ns, event string) (experimentStimulusReceipt, error) {
	target, err := s.resettableTarget(ns)
	if err != nil {
		return experimentStimulusReceipt{}, err
	}
	window := s.cfg.AttackWatchDuration
	if window <= 0 {
		window = 95 * time.Second
	}
	start := s.cfg.now()
	return s.executePreparedResettableSignal(actor, ns, event, target, "", start, start.Add(window))
}

func (s *Server) executePreparedResettableSignal(actor, ns, event string, target resettableTargetInfo, token string, windowStart, windowEnd time.Time) (experimentStimulusReceipt, error) {
	if ns != "voice" {
		return experimentStimulusReceipt{}, fmt.Errorf("three-arm comparison unsupported for %s: no verified reset contract", ns)
	}
	live, err := s.resettableTarget(ns)
	if err != nil {
		return experimentStimulusReceipt{}, err
	}
	if live.Pod != target.Pod || live.UID != target.UID || live.ResourceVersion != target.ResourceVersion || live.OwnerUID != target.OwnerUID {
		return experimentStimulusReceipt{}, fmt.Errorf("prepared target identity changed before signal")
	}
	pod, uid := target.Pod, target.UID
	base := s.snapshotBaseline(ns, pod)
	base.uid = uid
	if event == "" {
		event = "redteam-arms-" + strings.ToLower(strings.TrimPrefix(fmt.Sprintf("%x", s.cfg.now().UnixNano()), "-"))
	}
	if token == "" {
		token = event
	}
	window := s.cfg.AttackWatchDuration
	if window <= 0 {
		window = 95 * time.Second
	}
	if windowStart.IsZero() || !windowEnd.After(windowStart) || windowEnd.Sub(windowStart) != window {
		return experimentStimulusReceipt{}, fmt.Errorf("invalid pre-registered observation window")
	}
	if err = s.persistEffectIntent("/api/availability-arms/run", actor, ns, "foothold"); err != nil {
		return experimentStimulusReceipt{}, fmt.Errorf("attack refused before effect: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	created, err := s.experimentCluster().CreateEvent(ctx, event, token, ns, pod)
	cancel()
	if err != nil {
		return experimentStimulusReceipt{}, fmt.Errorf("create SecurityEvent: %w", err)
	}
	acceptedAt := s.cfg.now()
	receipt := experimentStimulusReceipt{Pod: pod, PodUID: uid, PodRV: target.ResourceVersion, Deploy: target.Deploy, Event: event, EventUID: created.UID, Token: token, WindowStart: windowStart, WindowEnd: windowEnd, AcceptedAt: acceptedAt}
	if !acceptedAt.Before(windowEnd) {
		return receipt, fmt.Errorf("signal acceptance exceeded the pre-registered observation window")
	}
	base.stimulus = &attackStimulusEvidence{Kind: "synthetic-security-event", Observed: true, TargetUID: uid,
		EventName: event, EventUID: created.UID, EventCreatedAt: created.CreatedAt.UTC().Format(time.RFC3339Nano),
		EventRule: "Panic", Correlation: token, BehavioralExecuted: false,
		Limitation: "synthetic detector signal is not a demonstrated exploit"}
	base.outcomeClass = "behavioral-oracle-unsupported"
	base.producerRoute = "/api/workload/attack"
	base.resultSchema = "synthetic-detector-signal-v2"
	id := s.startAttackRecordAtKind("", ns, ns, pod, "Synthetic detector signal", "foothold", "T1611", "rotate", false, base, windowStart, windowEnd, "synthetic-detector-signal", acceptedAt)
	receipt.AttackID = id
	return receipt, nil
}

func (s *Server) resettableTarget(ns string) (resettableTargetInfo, error) {
	if ns != "voice" {
		return resettableTargetInfo{}, fmt.Errorf("three-arm comparison unsupported for %s: no verified reset contract", ns)
	}
	kctl := func(timeout time.Duration, args ...string) (string, error) {
		return s.cfg.execText(timeout, "kubectl", append([]string{"-n", ns}, args...)...)
	}
	line, err := kctl(8*time.Second, "get", "pod", "-l", "r6th.io/rotation-target=true", "-o",
		`jsonpath={range .items[*]}{.metadata.name}|{.metadata.uid}|{.metadata.resourceVersion}|{.metadata.ownerReferences[0].kind}|{.metadata.ownerReferences[0].name}|{.metadata.ownerReferences[0].uid}|{.metadata.deletionTimestamp}|{.spec.volumes[*].persistentVolumeClaim.claimName}|{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`)
	if err != nil {
		return resettableTargetInfo{}, fmt.Errorf("resolve attack target: %w: %s", err, strings.TrimSpace(line))
	}
	var p []string
	for _, row := range strings.Split(strings.TrimSpace(line), "\n") {
		f := strings.Split(row, "|")
		if len(f) == 9 && f[0] != "" && f[1] != "" && f[2] != "" && f[3] == "ReplicaSet" && f[6] == "" && f[7] == "" && f[8] == "True" {
			p = f
			break
		}
	}
	if len(p) == 0 {
		return resettableTargetInfo{}, fmt.Errorf("no ready, nonterminating, stateless Deployment pod in %s", ns)
	}
	rs, err := kctl(6*time.Second, "get", "replicaset", p[4], "-o", `jsonpath={.metadata.uid}|{.metadata.ownerReferences[0].kind}|{.metadata.ownerReferences[0].name}|{.metadata.ownerReferences[0].uid}`)
	if err != nil {
		return resettableTargetInfo{}, fmt.Errorf("resolve target owner: %w", err)
	}
	r := strings.Split(strings.TrimSpace(rs), "|")
	if len(r) != 4 || r[0] != p[5] || r[1] != "Deployment" || r[2] == "" || r[3] == "" {
		return resettableTargetInfo{}, fmt.Errorf("target owner is not a stable Deployment chain")
	}
	dep, err := kctl(6*time.Second, "get", "deployment", r[2], "-o", `jsonpath={.metadata.uid}|{.metadata.generation}|{.status.observedGeneration}|{.spec.replicas}|{.status.replicas}|{.status.updatedReplicas}|{.status.readyReplicas}|{.status.availableReplicas}`)
	if err != nil {
		return resettableTargetInfo{}, fmt.Errorf("resolve deployment readiness: %w", err)
	}
	d := strings.Split(strings.TrimSpace(dep), "|")
	if len(d) != 8 || d[0] != r[3] {
		return resettableTargetInfo{}, fmt.Errorf("deployment identity/readiness is not stable")
	}
	generation, genErr := strconv.ParseInt(d[1], 10, 64)
	observed, observedErr := strconv.ParseInt(d[2], 10, 64)
	desired, desiredErr := strconv.Atoi(d[3])
	replicas, replicasErr := strconv.Atoi(d[4])
	updated, updatedErr := strconv.Atoi(d[5])
	ready, readyErr := strconv.Atoi(d[6])
	available, availableErr := strconv.Atoi(d[7])
	if genErr != nil || observedErr != nil || desiredErr != nil || replicasErr != nil || updatedErr != nil || readyErr != nil || availableErr != nil ||
		generation <= 0 || observed != generation || desired <= 0 || replicas != desired || updated != desired || ready != desired || available != desired {
		return resettableTargetInfo{}, fmt.Errorf("deployment identity/readiness is not stable")
	}
	return resettableTargetInfo{Pod: p[0], UID: p[1], ResourceVersion: p[2], Deploy: r[2], OwnerUID: r[3]}, nil
}

func (s *Server) resetExperimentStimulus(r experimentStimulusReceipt) error {
	return s.cleanupExperimentSignal("voice", r)
}

func (s *Server) cleanupExperimentSignal(ns string, r experimentStimulusReceipt) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	uid, token, found, err := s.experimentCluster().EventIdentity(ctx, ns, r.Event)
	if err != nil {
		return fmt.Errorf("resolve experiment signal %s: %w", r.Event, err)
	}
	if !found {
		return nil
	}
	if r.Token == "" || token != r.Token || (r.EventUID != "" && uid != r.EventUID) {
		return fmt.Errorf("experiment signal %s identity conflict", r.Event)
	}
	if uid == "" {
		return fmt.Errorf("experiment signal %s UID unavailable", r.Event)
	}
	if err = s.experimentCluster().DeleteEvent(ctx, ns, r.Event, uid); err != nil {
		return fmt.Errorf("delete experiment signal %s: %w", r.Event, err)
	}
	// A Kubernetes DELETE acknowledgement is not absence: a finalizer may retain the
	// exact object. Re-read the same UID/token for a short bounded interval and leave
	// the operation unresolved until absence is observed.
	for i := 0; i < 10; i++ {
		liveUID, liveToken, live, readErr := s.experimentCluster().EventIdentity(ctx, ns, r.Event)
		if readErr != nil {
			return fmt.Errorf("verify experiment signal %s cleanup: %w", r.Event, readErr)
		}
		if !live {
			return nil
		}
		if liveUID != uid || liveToken != r.Token {
			return fmt.Errorf("experiment signal %s identity changed during cleanup", r.Event)
		}
		if i < 9 {
			s.cfg.sleep(100 * time.Millisecond)
		}
	}
	return fmt.Errorf("experiment signal %s remains after delete acknowledgement", r.Event)
}
