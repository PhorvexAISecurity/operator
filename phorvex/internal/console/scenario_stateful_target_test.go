package console

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// These objects are returned through the same kubectl JSON seam used by the
// production fire-scenario handler. The test never injects a final resolver flag.
type statefulTargetExec struct {
	base      exactScenarioExec
	mu        sync.Mutex
	podName   string
	podReads  int
	setReads  int
	changePod func(*corev1.Pod, int)
	changeSet func(*appsv1.StatefulSet, int)
}

func statefulTargetPod() *corev1.Pod {
	control := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "owned-0", UID: types.UID("owned-uid"),
			ResourceVersion: "17", Labels: map[string]string{
				"app": "owned", "campaign.phorvex.ai/fixture": "nonce-1",
				"statefulset.kubernetes.io/pod-name": "owned-0", "apps.kubernetes.io/pod-index": "0",
				"controller-revision-hash": "owned-abc",
			}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "owned", UID: types.UID("set-uid"), Controller: &control}}},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-owned-0"}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func statefulTargetSet() *appsv1.StatefulSet {
	replicas := int32(2)
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "owned", UID: types.UID("set-uid"), ResourceVersion: "25", Generation: 3},
		Spec:       appsv1.StatefulSetSpec{Replicas: &replicas, ServiceName: "owned-headless", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "owned"}}},
		Status: appsv1.StatefulSetStatus{ObservedGeneration: 3, Replicas: 2, ReadyReplicas: 1,
			CurrentRevision: "owned-abc", UpdateRevision: "owned-abc", CurrentReplicas: 2, UpdatedReplicas: 2},
	}
}

func (f *statefulTargetExec) run(timeout time.Duration, bin string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	podName := f.podName
	if podName == "" {
		podName = "owned-0"
	}
	if strings.Contains(joined, "get pod "+podName+" -o json") && !strings.Contains(joined, "jsonpath") {
		f.mu.Lock()
		f.podReads++
		read := f.podReads
		f.base.podReads = read
		f.mu.Unlock()
		pod := statefulTargetPod()
		if f.changePod != nil {
			f.changePod(pod, read)
		}
		b, err := json.Marshal(pod)
		return string(b), err
	}
	if strings.Contains(joined, "get statefulset owned -o json") && !strings.Contains(joined, "jsonpath") {
		f.mu.Lock()
		f.setReads++
		read := f.setReads
		f.mu.Unlock()
		set := statefulTargetSet()
		if f.changeSet != nil {
			f.changeSet(set, read)
		}
		b, err := json.Marshal(set)
		return string(b), err
	}
	return f.base.run(timeout, bin, args...)
}

func statefulSignalServer(t *testing.T, fx *statefulTargetExec) *Server {
	t.Helper()
	dir, bin := catalogueHarness(t)
	line := `  - c2-persistence-evict [K8s] R6=C2 realism=real benign=false declared=[T0001] exercised=[] caps=[]`
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' '"+line+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: t.TempDir(), HarnessDir: dir, HarnessBin: bin, Exec: fx.run,
		AttackWatchDuration: 8 * time.Millisecond, AttackWatchInterval: 2 * time.Millisecond}
	return &Server{cfg: cfg, experimentAPI: &fakeExperimentCluster{podUID: "owned-uid", podFound: true}}
}

const statefulRequest = `{"namespace":"voice","scenario":"c2-persistence-evict","expected":"rotate","action":"fire","targetPod":"owned-0","targetUid":"owned-uid"}`

func TestStatefulExactCatalogueProducerBindsCurrentPodAndOwner(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &statefulTargetExec{}
	s := statefulSignalServer(t, fx)
	w := exactSignalRequest(s, statefulRequest)
	if w.Code != http.StatusOK {
		t.Fatalf("current StatefulSet exact target refused: %d %s", w.Code, w.Body.String())
	}
	var response struct{ AttackID string }
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.AttackID == "" {
		t.Fatalf("response=%s err=%v", w.Body.String(), err)
	}
	fx.base.mu.Lock()
	manifests := append([]string(nil), fx.base.manifests...)
	fx.base.mu.Unlock()
	if len(manifests) != 1 || !strings.Contains(manifests[0], `targets: ["voice/owned-0"]`) ||
		!strings.Contains(manifests[0], `phorvex.ai/console-target-pod-uid: "owned-uid"`) {
		t.Fatalf("wrong event creation: %v", manifests)
	}
	rec := waitCatalogueSignal(t, s, response.AttackID)
	if rec == nil || rec.TargetUID != "owned-uid" || rec.OwnerKind != "StatefulSet" || rec.OwnerUID != "set-uid" ||
		rec.UptimeBefore != 50 || rec.UptimeAfter != 50 || rec.StimulusEvidence == nil ||
		rec.StimulusEvidence.BehavioralExecuted || rec.Outcome != "" || !rec.Stateful {
		t.Fatalf("wrong source-bound record: %+v", rec)
	}
	serialized, err := json.Marshal(rec)
	if err != nil || !strings.Contains(string(serialized), `"ownerKind":"StatefulSet"`) ||
		!strings.Contains(string(serialized), `"ownerUid":"set-uid"`) ||
		!strings.Contains(string(serialized), `"uptimeBefore":50`) ||
		!strings.Contains(string(serialized), `"uptimeAfter":50`) {
		t.Fatalf("wrong serialized StatefulSet availability: %s err=%v", serialized, err)
	}
}

func TestStatefulExactAvailabilityNeverFallsBackToSameNameDeployment(t *testing.T) {
	fx := &statefulTargetExec{changeSet: func(set *appsv1.StatefulSet, _ int) { set.UID = "replacement" }}
	s := statefulSignalServer(t, fx)
	if got := s.workloadUptimeBoundKind("voice", "owned", "StatefulSet", "set-uid"); got != -1 {
		t.Fatalf("replaced StatefulSet availability=%v, want unknown even with Ready same-name Deployment", got)
	}
	if got := s.workloadUptimeBoundKind("voice", "owned", "DaemonSet", "set-uid"); got != -1 {
		t.Fatalf("unknown controller kind availability=%v, want unknown", got)
	}
	if got := s.workloadUptimeBoundKind("voice", "owned", "", "owner-uid"); got != 100 {
		t.Fatalf("persisted empty-kind Deployment compatibility=%v, want 100", got)
	}
}

func TestStatefulExactCatalogueProducerRefusesUnprovedControllerBeforeIntent(t *testing.T) {
	cases := []struct {
		name string
		pod  func(*corev1.Pod, int)
		set  func(*appsv1.StatefulSet, int)
		base func(*exactScenarioExec)
	}{
		{"pod owner missing", func(p *corev1.Pod, _ int) { p.OwnerReferences = nil }, nil, nil},
		{"extra Pod owner", func(p *corev1.Pod, _ int) {
			p.OwnerReferences = append(p.OwnerReferences, metav1.OwnerReference{Kind: "ConfigMap", Name: "other"})
		}, nil, nil},
		{"detached AMTD owner", func(p *corev1.Pod, _ int) { p.OwnerReferences[0].Kind = "AdaptiveMovingTargetDefense" }, nil, nil},
		{"wrong owner UID", func(p *corev1.Pod, _ int) { p.OwnerReferences[0].UID = "wrong" }, nil, nil},
		{"wrong Pod UID", func(p *corev1.Pod, _ int) { p.UID = "replacement" }, nil, nil},
		{"Pod deleting", func(p *corev1.Pod, _ int) { now := metav1.Now(); p.DeletionTimestamp = &now }, nil, nil},
		{"Pod unready", func(p *corev1.Pod, _ int) { p.Status.Conditions[0].Status = corev1.ConditionFalse }, nil, nil},
		{"Pod selector mismatch", func(p *corev1.Pod, _ int) { p.Labels["app"] = "other" }, nil, nil},
		{"Pod revision mismatch", func(p *corev1.Pod, _ int) { p.Labels["controller-revision-hash"] = "other" }, nil, nil},
		{"Pod index mismatch", func(p *corev1.Pod, _ int) { p.Labels["apps.kubernetes.io/pod-index"] = "1" }, nil, nil},
		{"Pod name label mismatch", func(p *corev1.Pod, _ int) { p.Labels["statefulset.kubernetes.io/pod-name"] = "other" }, nil, nil},
		{"wrong set UID", nil, func(s *appsv1.StatefulSet, _ int) { s.UID = "replacement" }, nil},
		{"set unobserved generation", nil, func(s *appsv1.StatefulSet, _ int) { s.Status.ObservedGeneration = 2 }, nil},
		{"set rolling revision", nil, func(s *appsv1.StatefulSet, _ int) { s.Status.UpdateRevision = "owned-new" }, nil},
		{"set empty revision", nil, func(s *appsv1.StatefulSet, _ int) { s.Status.CurrentRevision = "" }, nil},
		{"set selector mismatch", nil, func(s *appsv1.StatefulSet, _ int) { s.Spec.Selector.MatchLabels["app"] = "other" }, nil},
		{"set empty selector", nil, func(s *appsv1.StatefulSet, _ int) { s.Spec.Selector = &metav1.LabelSelector{} }, nil},
		{"set no replicas", nil, func(s *appsv1.StatefulSet, _ int) { zero := int32(0); s.Spec.Replicas = &zero }, nil},
		{"ordinal outside replicas", nil, func(s *appsv1.StatefulSet, _ int) { s.Spec.Ordinals = &appsv1.StatefulSetOrdinals{Start: 1} }, nil},
		{"inactive policy", nil, nil, func(f *exactScenarioExec) { f.badPolicy = true }},
		{"overlapping policy", nil, nil, func(f *exactScenarioExec) { f.overlap = true }},
		{"Pod replaced on recheck", func(p *corev1.Pod, read int) {
			if read >= 2 {
				p.UID = "replacement"
			}
		}, nil, nil},
		{"owner revision changed on recheck", nil, func(s *appsv1.StatefulSet, read int) {
			if read >= 2 {
				s.Status.CurrentRevision, s.Status.UpdateRevision = "owned-new", "owned-new"
			}
		}, nil},
		{"owner generation changed on recheck", nil, func(s *appsv1.StatefulSet, read int) {
			if read >= 2 {
				s.Generation, s.Status.ObservedGeneration = 4, 4
			}
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetSignalAttackLedger(t)
			fx := &statefulTargetExec{changePod: tc.pod, changeSet: tc.set}
			if tc.base != nil {
				tc.base(&fx.base)
			}
			s := statefulSignalServer(t, fx)
			w := exactSignalRequest(s, statefulRequest)
			if w.Code == http.StatusOK {
				t.Fatalf("unproved target accepted: %s", w.Body.String())
			}
			fx.base.mu.Lock()
			created := len(fx.base.manifests)
			fx.base.mu.Unlock()
			if created != 0 {
				t.Fatalf("rejected target created %d events", created)
			}
			if raw, err := os.ReadFile(s.cfg.statePath("effect-intents.jsonl")); err == nil && len(raw) != 0 {
				t.Fatalf("rejected target persisted intent: %s", raw)
			}
		})
	}
}

func TestStatefulExactCatalogueProducerConfiguredStartOrdinal(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &statefulTargetExec{podName: "owned-5", changePod: func(p *corev1.Pod, _ int) {
		p.Name = "owned-5"
		p.Labels["statefulset.kubernetes.io/pod-name"] = "owned-5"
		p.Labels["apps.kubernetes.io/pod-index"] = "5"
	}, changeSet: func(s *appsv1.StatefulSet, _ int) { s.Spec.Ordinals = &appsv1.StatefulSetOrdinals{Start: 5} }}
	// The resolver uses the same Kubernetes JSON producer as fire-scenario.
	s := statefulSignalServer(t, fx)
	target, err := s.resolveScenarioExactTarget("voice", "owned-5", "owned-uid")
	if err != nil || target.ownerUID != "set-uid" {
		t.Fatalf("configured start ordinal rejected: %+v err=%v", target, err)
	}
}
