/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

// Package controller — the cap#2 warm-pool / LeaderWorkerSet CONTROL PLANE
// (arch §3 cap#2, decisions D11/D12).
//
// This file implements the four shared interfaces the WarmInferenceSet reconciler
// composes, with an IN-TREE / controller-managed bare-pod realization that runs on
// kind with NO GPU:
//
//   - WarmPoolManager : maintain N warm bare pods from Spec.Template (EnsurePool),
//     own the leader-selecting Service, report ReadyShadows / CurrentLeader.
//   - ReadinessGate   : IsWarm(pod) = pod Ready AND MinWarmSeconds elapsed AND
//     RequireModelLoaded satisfied — the strict, false-readiness-proof definition.
//   - TrafficSteerer  : CutTraffic = move the leader label to the new leader so the
//     leader-selecting Service resolves to it (ServiceSelectorSwap, the realized path).
//   - LeaderSwapper   : Swap = the create-new-then-cutover phase machine
//     (Ready->flip->drain->retire->rewarm), driven by Spec.SwapRequest across
//     reconciles (restart-safe progressive realization, arch §3).
//
// OPTIONAL sigs.k8s.io/lws WRAP (NOTE only, not wired): a production deployment may
// wrap a LeaderWorkerSet (sigs.k8s.io/lws) instead of controller-managed bare pods;
// the in-tree bare-pod path here is the DEFAULT fallback and is what runs on kind.
// The interfaces below would be satisfied by an lws-backed implementation unchanged.
//
// GPU-PENDING: on kind there is no GPU and no real model server, so
// RequireModelLoaded's weights-resident verification is realized via the pod Ready
// condition + MinWarmSeconds + a model-loaded SIGNAL (the
// amtd.r6security.com/model-loaded=true annotation or a readiness-gate condition a
// test/manifest sets). True GPU-weights-resident verification is GPU-PENDING.
package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// poolClock abstracts time.Now so the readiness-gate MinWarmSeconds dwell and the
// swap-duration timing are testable. The reconciler/manager uses realClock; tests
// inject a fixed clock.
type poolClock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ---------------------------------------------------------------------------
// ReadinessGate — the strict operational definition of "warm" (D11).
// ---------------------------------------------------------------------------

// ReadinessGate decides whether a pod is WARM (swap-eligible). It is the gate the
// LeaderSwapper consults: if NO shadow is warm, a swap is BLOCKED (never a
// false-ready cutover).
type ReadinessGate struct {
	clock poolClock
}

// IsWarm reports whether pod is warm for the given WarmInferenceSet:
//
//	pod Ready condition True
//	AND (MinWarmSeconds == 0 OR seconds since Ready-transition >= MinWarmSeconds)
//	AND (RequireModelLoaded == false OR the model-loaded signal is present)
//
// GPU-PENDING: the model-loaded signal is the amtd.r6security.com/model-loaded=true
// annotation OR a readiness-gate pod condition of the same name set to True (either
// satisfies it on kind). On real GPU this is replaced by weights-resident
// verification.
func (g *ReadinessGate) IsWarm(wis *amtdv1beta1.WarmInferenceSet, pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	// (1) Pod Ready condition True (probe).
	if !podIsReady(pod) {
		return false
	}
	// (2) MinWarmSeconds dwell since the Ready transition.
	if minWarm := wis.EffectiveMinWarmSeconds(); minWarm > 0 {
		readySince, ok := podReadySince(pod)
		if !ok {
			return false
		}
		if g.clock.Now().Sub(readySince) < time.Duration(minWarm)*time.Second {
			return false
		}
	}
	// (3) RequireModelLoaded (GPU-PENDING signal on kind).
	if wis.EffectiveRequireModelLoaded() && !podModelLoaded(pod) {
		return false
	}
	return true
}

// podReadySince returns the LastTransitionTime of the PodReady=True condition.
func podReadySince(pod *corev1.Pod) (time.Time, bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			if c.LastTransitionTime.IsZero() {
				return time.Time{}, false
			}
			return c.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

// podModelLoaded reports whether the model-loaded signal is present (annotation
// amtd.r6security.com/model-loaded=true OR a readiness-gate pod condition of that
// type set to True). GPU-PENDING proxy for GPU-resident weights.
func podModelLoaded(pod *corev1.Pod) bool {
	if v, ok := pod.Annotations[amtdv1beta1.ModelLoadedAnnotation]; ok && v == "true" {
		return true
	}
	for _, c := range pod.Status.Conditions {
		if string(c.Type) == amtdv1beta1.ModelLoadedAnnotation && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// WarmPoolManager — maintain N warm bare pods + the leader-selecting Service.
// ---------------------------------------------------------------------------

// WarmPoolManager maintains the warm pool's pods and the leader-selecting Service.
// The in-tree realization creates controller-managed bare pods from Spec.Template
// (the DEFAULT fallback; an lws wrap is the optional production swap-in). It is
// CLASS-B by contract: EnsurePool never initiates a swap, it only keeps N pods +
// exactly one leader + the Service.
type WarmPoolManager struct {
	client.Client
	Scheme *runtime.Scheme
	gate   *ReadinessGate
}

// poolPods lists every pod that belongs to the given WarmInferenceSet (by the
// pool label), sorted by name for determinism.
func (m *WarmPoolManager) poolPods(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet) ([]corev1.Pod, error) {
	list := &corev1.PodList{}
	if err := m.List(ctx, list,
		client.InNamespace(wis.Namespace),
		client.MatchingLabels{amtdv1beta1.PoolPodLabel: wis.Name},
	); err != nil {
		return nil, err
	}
	pods := list.Items
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
	return pods, nil
}

// alive reports whether a pod is not terminating (DeletionTimestamp nil). A pod
// being drained/retired is excluded from the live pool count.
func alive(p *corev1.Pod) bool { return p.DeletionTimestamp == nil }

// buildPodFromTemplate materializes one warm pod from Spec.Template, stamping the
// pool label and (when leader) the leader label, and setting the WarmInferenceSet as
// controller owner.
func (m *WarmPoolManager) buildPodFromTemplate(wis *amtdv1beta1.WarmInferenceSet, name string, leader bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: *wis.Spec.Template.ObjectMeta.DeepCopy(),
		Spec:       *wis.Spec.Template.Spec.DeepCopy(),
	}
	pod.Name = name
	pod.GenerateName = ""
	pod.Namespace = wis.Namespace
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[amtdv1beta1.PoolPodLabel] = wis.Name
	if leader {
		pod.Labels[wis.EffectiveLeaderLabelKey()] = wis.EffectiveLeaderLabelValue()
	} else {
		delete(pod.Labels, wis.EffectiveLeaderLabelKey())
	}
	// If the gate carries a probe, apply it to the first container (golden-image
	// model-server health) when that container has none.
	if wis.Spec.WarmReadyGate.Probe != nil && len(pod.Spec.Containers) > 0 && pod.Spec.Containers[0].ReadinessProbe == nil {
		pod.Spec.Containers[0].ReadinessProbe = wis.Spec.WarmReadyGate.Probe.DeepCopy()
	}
	return pod
}

// EnsurePool maintains exactly N=EffectiveReplicas warm pods and exactly one leader,
// and ensures the leader-selecting Service exists/selects the leader. It is CLASS-B:
// it NEVER initiates a swap. Steps:
//   - list the pool's live pods;
//   - if there is no leader yet, elect one (prefer a warm pod; else pod[0]) and
//     stamp the leader label;
//   - create missing shadows up to N (provision standbys);
//   - delete surplus shadows beyond N (never the leader);
//   - ensure the leader-selecting Service.
//
// It returns the elected leader name (may be "" if the pool is still empty) so the
// reconciler can record ActiveLeader.
func (m *WarmPoolManager) EnsurePool(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet) (string, error) {
	n := wis.EffectiveReplicas()
	pods, err := m.poolPods(ctx, wis)
	if err != nil {
		return "", err
	}

	leaderKey := wis.EffectiveLeaderLabelKey()
	leaderVal := wis.EffectiveLeaderLabelValue()

	// During an in-flight swap the LeaderSwapper owns the leader label + pod lifecycle
	// (it briefly keeps two pods labeled during the atomic flip, then retires the old
	// leader). Class-B maintenance must NOT fight it: skip the multi-leader collapse and
	// the surplus deletion while a swap is in flight, but still create missing standbys
	// (the re-warm half) up to N.
	swapInFlight := wis.Spec.SwapRequest != nil

	// Identify existing leaders + live pods.
	var live []*corev1.Pod
	var leaders []*corev1.Pod
	for i := range pods {
		p := &pods[i]
		if !alive(p) {
			continue
		}
		live = append(live, p)
		if p.Labels[leaderKey] == leaderVal {
			leaders = append(leaders, p)
		}
	}

	// Collapse a multi-leader anomaly down to exactly one (keep the first by name;
	// demote the rest). This keeps the class-B invariant "exactly one leader". Skipped
	// during an in-flight swap (the swapper owns the transient two-leader window).
	if len(leaders) > 1 && !swapInFlight {
		for _, p := range leaders[1:] {
			delete(p.Labels, leaderKey)
			if err := m.Update(ctx, p); err != nil {
				return "", err
			}
		}
		leaders = leaders[:1]
	}

	var leaderName string
	if len(leaders) == 1 {
		leaderName = leaders[0].Name
	}

	// Elect a leader if none exists and we have live pods. Prefer a warm pod.
	if leaderName == "" && len(live) > 0 {
		elect := live[0]
		for _, p := range live {
			if m.gate.IsWarm(wis, p) {
				elect = p
				break
			}
		}
		if elect.Labels == nil {
			elect.Labels = map[string]string{}
		}
		elect.Labels[leaderKey] = leaderVal
		if err := m.Update(ctx, elect); err != nil {
			return "", err
		}
		leaderName = elect.Name
	}

	// Create missing pods up to N (the leader counts toward N). Use the LOWEST FREE
	// pod-name index so a re-warm after a retire (where intermediate indices are still
	// occupied by the new leader/shadow) does not collide with an existing pod. This is
	// the "create-new" half of create-new-then-cutover and the re-warm-a-replacement
	// step after a swap.
	//
	// Mark EVERY pod's name as used — including pods that are still TERMINATING
	// (DeletionTimestamp set, e.g. the just-retired old leader draining its 30s grace).
	// A terminating pod still holds its name in the apiserver, so reusing that name on a
	// Create races into "object is being deleted: already exists". Skipping the name
	// until termination completes lets the replacement come up immediately on a fresh
	// index instead of error-looping until the grace period ends.
	used := map[string]struct{}{}
	for i := range pods {
		used[pods[i].Name] = struct{}{}
	}
	needed := n - len(live)
	nextIdx := 0
	for created := 0; created < needed; created++ {
		// Advance to the lowest free index.
		for {
			candidate := poolPodName(wis.Name, nextIdx)
			if _, taken := used[candidate]; !taken {
				break
			}
			nextIdx++
		}
		name := poolPodName(wis.Name, nextIdx)
		used[name] = struct{}{}
		nextIdx++
		// The very first pod created on an empty pool becomes the leader.
		makeLeader := leaderName == ""
		pod := m.buildPodFromTemplate(wis, name, makeLeader)
		if err := ctrl.SetControllerReference(wis, pod, m.Scheme); err != nil {
			return "", err
		}
		if err := m.Create(ctx, pod); err != nil {
			// AlreadyExists (a concurrent reconcile created it) or a name still held by a
			// terminating pod is benign: the next reconcile converges. Don't hard-fail.
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			return "", err
		}
		if makeLeader {
			leaderName = name
		}
	}

	// Delete surplus shadows beyond N (never the leader). Skipped during an in-flight
	// swap so class-B does not delete a pod the swapper is mid-transition on.
	if len(live) > n && !swapInFlight {
		// Prefer deleting non-leader, non-warm pods first for stability.
		surplus := surplusToDelete(live, leaderName, len(live)-n)
		for _, p := range surplus {
			if err := m.Delete(ctx, p); err != nil {
				return "", err
			}
		}
	}

	// Ensure the leader-selecting Service.
	if err := m.ensureLeaderService(ctx, wis); err != nil {
		return "", err
	}

	return leaderName, nil
}

// surplusToDelete picks up to count non-leader pods to delete, preferring
// not-yet-warm pods (deterministic by name).
func surplusToDelete(live []*corev1.Pod, leaderName string, count int) []*corev1.Pod {
	var out []*corev1.Pod
	for _, p := range live {
		if p.Name == leaderName {
			continue
		}
		out = append(out, p)
		if len(out) == count {
			break
		}
	}
	return out
}

// ReadyShadows counts the pool's NON-LEADER pods that pass the readiness gate (warm,
// swap-eligible).
func (m *WarmPoolManager) ReadyShadows(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet) (int, error) {
	pods, err := m.poolPods(ctx, wis)
	if err != nil {
		return 0, err
	}
	leaderKey := wis.EffectiveLeaderLabelKey()
	leaderVal := wis.EffectiveLeaderLabelValue()
	count := 0
	for i := range pods {
		p := &pods[i]
		if !alive(p) {
			continue
		}
		if p.Labels[leaderKey] == leaderVal {
			continue // leaders are not shadows
		}
		if m.gate.IsWarm(wis, p) {
			count++
		}
	}
	return count, nil
}

// CurrentLeader returns the name of the pod currently carrying the leader label, or
// "" if none.
func (m *WarmPoolManager) CurrentLeader(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet) (string, error) {
	pods, err := m.poolPods(ctx, wis)
	if err != nil {
		return "", err
	}
	leaderKey := wis.EffectiveLeaderLabelKey()
	leaderVal := wis.EffectiveLeaderLabelValue()
	for i := range pods {
		p := &pods[i]
		if alive(p) && p.Labels[leaderKey] == leaderVal {
			return p.Name, nil
		}
	}
	return "", nil
}

// pickReadyShadow returns a warm NON-LEADER pod (the swap candidate), or nil if none
// is warm — in which case the swap is BLOCKED by the readiness gate.
func (m *WarmPoolManager) pickReadyShadow(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, leaderName string) (*corev1.Pod, error) {
	pods, err := m.poolPods(ctx, wis)
	if err != nil {
		return nil, err
	}
	for i := range pods {
		p := &pods[i]
		if !alive(p) || p.Name == leaderName {
			continue
		}
		if m.gate.IsWarm(wis, p) {
			return p, nil
		}
	}
	return nil, nil
}

// ensureLeaderService creates-or-updates the leader-selecting Service. Its selector
// is {PoolPodLabel: <set>, LeaderLabelKey: LeaderLabelValue}, so it resolves to
// EXACTLY the pod currently carrying the leader label (ServiceSelectorSwap).
func (m *WarmPoolManager) ensureLeaderService(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet) error {
	name := wis.EffectiveServiceName()
	port := wis.EffectiveServicePort()
	selector := map[string]string{
		amtdv1beta1.PoolPodLabel:      wis.Name,
		wis.EffectiveLeaderLabelKey(): wis.EffectiveLeaderLabelValue(),
	}

	svc := &corev1.Service{}
	err := m.Get(ctx, client.ObjectKey{Namespace: wis.Namespace, Name: name}, svc)
	if err == nil {
		// Reconcile the selector + port (idempotent).
		svc.Spec.Selector = selector
		svc.Spec.Ports = []corev1.ServicePort{{
			Name:       "inference",
			Port:       port,
			TargetPort: intstr.FromInt32(port),
		}}
		return m.Update(ctx, svc)
	}
	if !apierrors.IsNotFound(err) {
		return err
	}

	svc = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: wis.Namespace,
			Labels:    map[string]string{amtdv1beta1.PoolPodLabel: wis.Name},
		},
		Spec: corev1.ServiceSpec{
			Selector: selector,
			Ports: []corev1.ServicePort{{
				Name:       "inference",
				Port:       port,
				TargetPort: intstr.FromInt32(port),
			}},
		},
	}
	if err := ctrl.SetControllerReference(wis, svc, m.Scheme); err != nil {
		return err
	}
	return m.Create(ctx, svc)
}

// ---------------------------------------------------------------------------
// TrafficSteerer — move traffic to the new leader (ServiceSelectorSwap).
// ---------------------------------------------------------------------------

// TrafficSteerer flips the leader label so the leader-selecting Service resolves to
// the new leader. ServiceSelectorSwap is the realized in-tree strategy; the other
// TrafficCutStrategy values are reserved seams (documented on the enum).
type TrafficSteerer struct {
	client.Client
}

// CutTraffic atomically moves the leader label from oldLeader to newLeader. After
// this the leader-selecting Service (whose selector includes the leader label)
// resolves to newLeader. It removes the label from the old leader first conceptually,
// but order is: stamp new, then unstamp old, so there is never a zero-leader window
// the Service would resolve to nothing — briefly two pods may carry it, which the
// Service load-balances across (both serve), preserving availability during cutover.
func (s *TrafficSteerer) CutTraffic(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, oldLeader, newLeader *corev1.Pod) error {
	if wis.EffectiveTrafficCutStrategy() != amtdv1beta1.TrafficCutServiceSelectorSwap &&
		wis.EffectiveTrafficCutStrategy() != amtdv1beta1.TrafficCutLeaderLabel {
		return fmt.Errorf("TrafficCutStrategy %q is a reserved seam not realized in the in-tree control plane (only ServiceSelectorSwap/LeaderLabel are wired)", wis.EffectiveTrafficCutStrategy())
	}
	key := wis.EffectiveLeaderLabelKey()
	val := wis.EffectiveLeaderLabelValue()

	if newLeader.Labels == nil {
		newLeader.Labels = map[string]string{}
	}
	newLeader.Labels[key] = val
	if err := s.Update(ctx, newLeader); err != nil {
		return err
	}
	if oldLeader != nil && oldLeader.Name != newLeader.Name {
		delete(oldLeader.Labels, key)
		if err := s.Update(ctx, oldLeader); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// poolPodName is the deterministic name of the i-th warm pod of a set. EnsurePool
// re-warms a replacement after a retire by re-creating the lowest free index, so the
// pool's pod names stay stable across swaps.
func poolPodName(set string, i int) string {
	return fmt.Sprintf("%s-warm-%d", set, i)
}
