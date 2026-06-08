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

// Package controller implements the NIM reconciler.
//
// PHASE 0 / NIM DISSOLUTION: historically this reconciler watched pods, and when
// the applied SecurityEvents included a time-based trigger it performed the
// NIM-enhanced restart itself (annotate the pod, then delete it so the workload
// reschedules) via a hard-coded FindTimedEvent gate. Per design rule #1 every
// workload effect must be a Strategy entry routed by the matcher, so that gate is
// DEMOTED to pass-through here: a timed rotation now flows through the CRD as the
// {type:'timed', source:'TimeBasedTrigger'} -> {rotate:{}} strategy, executed
// one-shot by the SecurityEvent reconciler's Rotate branch. This reconciler no
// longer self-deletes pods on a timed event (which would double-delete with the
// Rotate branch); it remains a watch/pass-through. The reschedule mechanism
// (rescheduleByAnnotateThenDelete / processPodWithNIM) is preserved and is reused
// verbatim by the Rotate branch.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// NIMPolicy holds configurable NIM behavior (grace period, requeue interval, trigger type/source).
// Zero values are replaced by defaults in effective().
type NIMPolicy struct {
	GracePeriodSeconds int64
	RequeueAfter       time.Duration
	TriggerType        string
	TriggerSource      string
}

// DefaultNIMPolicy returns the default NIM policy (30s grace, 10s requeue, timed/TimeBasedTrigger).
func DefaultNIMPolicy() NIMPolicy {
	return NIMPolicy{
		GracePeriodSeconds: 30,
		RequeueAfter:       10 * time.Second,
		TriggerType:        TriggerTypeTimed,
		TriggerSource:      TriggerSourceTimeBasedTrigger,
	}
}

func (p NIMPolicy) effective() NIMPolicy {
	def := DefaultNIMPolicy()
	if p.GracePeriodSeconds <= 0 {
		p.GracePeriodSeconds = def.GracePeriodSeconds
	}
	if p.RequeueAfter <= 0 {
		p.RequeueAfter = def.RequeueAfter
	}
	if p.TriggerType == "" {
		p.TriggerType = def.TriggerType
	}
	if p.TriggerSource == "" {
		p.TriggerSource = def.TriggerSource
	}
	return p
}

// NIMReconciler watches pods and applies NIM enhancements when they have time-based SecurityEvent annotations.
type NIMReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Policy NIMPolicy
}

//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods/status,verbs=get
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=adaptivemovingtargetdefenses,verbs=get;list;watch

func (r *NIMReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("NIM controller processing pod", "pod", pod.Name, "namespace", pod.Namespace)

	if pod.Annotations == nil {
		logger.Info("Pod has no annotations, skipping", "pod", pod.Name)
		return ctrl.Result{}, nil
	}

	// PHASE 1 / D22 G2 cross-controller lock: if a Rotate is in progress for this
	// pod (the SecurityEvent reconciler's one-shot executor set the in-progress
	// annotation), NIM must early-return so it never races/double-acts on the
	// rotation. The recreated replacement carries no annotation, clearing the lock.
	if podHasRotationInProgress(pod) {
		logger.Info("NIM early-return: rotation in progress for this pod (D22 in-progress lock)", "pod", pod.Name)
		return ctrl.Result{}, nil
	}

	appliedEventsJSON, hasAppliedEvents := pod.Annotations[AMTD_APPLIED_SECURITY_EVENTS]
	if !hasAppliedEvents {
		logger.Info("Pod has no SecurityEvent annotations, skipping", "pod", pod.Name)
		return ctrl.Result{}, nil
	}

	logger.Info("Processing pod for NIM restart", "pod", pod.Name)
	logger.Info("Pod has SecurityEvent annotation, processing for NIM", "pod", pod.Name, "appliedEvents", appliedEventsJSON)

	var appliedEvents []amtdv1beta1.SecurityEvent
	if err := json.Unmarshal([]byte(appliedEventsJSON), &appliedEvents); err != nil {
		logger.Error(err, "Failed to parse applied SecurityEvents", "pod", pod.Name)
		return ctrl.Result{}, nil
	}

	// PHASE 0 / NIM DISSOLUTION: the hard-coded timed-event self-action is demoted to
	// pass-through. A timed rotation is now the authoritative {type:'timed',
	// source:'TimeBasedTrigger'} -> {rotate:{}} strategy, executed one-shot by the
	// SecurityEvent reconciler's Rotate branch. We do NOT annotate/delete here (that
	// would double-delete with the Rotate branch) and we do NOT self-requeue (the
	// single jittered cadence owner is time-based-trigger). FindTimedEvent is kept
	// only as the detection helper for diagnostics/future cold-fallback wiring.
	policy := r.Policy.effective()
	if timedEvent := FindTimedEvent(appliedEvents, policy.TriggerType, policy.TriggerSource); timedEvent != nil {
		logger.Info("NIM pass-through: timed rotation is now owned by the matcher Rotate path; not self-acting",
			"pod", pod.Name, "securityEvent", timedEvent.Name)
	}
	return ctrl.Result{}, nil
}

// FindTimedEvent returns the first SecurityEvent in events whose rule type and source match.
func FindTimedEvent(events []amtdv1beta1.SecurityEvent, triggerType, triggerSource string) *amtdv1beta1.SecurityEvent {
	for i := range events {
		if events[i].Spec.Rule.Type == triggerType && events[i].Spec.Rule.Source == triggerSource {
			return &events[i]
		}
	}
	return nil
}

// rescheduleByAnnotateThenDelete is the shared Phase-0 cold-rotation primitive:
// it stamps the NIM annotations (pod-startup-state, action-active, last-action
// timestamp, triggers-stopped) onto the pod via Update, then Deletes the pod
// with the given grace period so the owning controller reschedules it. It is the
// single source of truth used by BOTH the NIM reconciler's processPodWithNIM and
// the SecurityEvent reconciler's Phase-0 Rotate dispatch branch, so the dissolved
// {timed -> rotate} rule reproduces today's NIM-enhanced restart exactly.
func rescheduleByAnnotateThenDelete(ctx context.Context, c client.Client, pod *corev1.Pod, startupState string, gracePeriodSeconds int64, logger logr.Logger) error {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[NIM_POD_STARTUP_STATE] = startupState
	pod.Annotations[NIM_ACTION_ACTIVE] = "true"
	pod.Annotations[NIM_LAST_ACTION_TIMESTAMP] = strconv.FormatInt(time.Now().Unix(), 10)
	pod.Annotations[NIM_TRIGGERS_STOPPED] = "true"

	if err := c.Update(ctx, pod); err != nil {
		return fmt.Errorf("failed to update pod annotations: %w", err)
	}

	deleteOpts := &client.DeleteOptions{}
	gp := gracePeriodSeconds
	deleteOpts.GracePeriodSeconds = &gp
	logger.Info("NIM executing pod delete", "pod", pod.Name, "gracePeriod", gp)
	if err := c.Delete(ctx, pod, deleteOpts); err != nil {
		logger.Error(err, "Failed to delete pod for NIM reschedule", "pod", pod.Name)
		return fmt.Errorf("failed to delete pod for NIM reschedule: %w", err)
	}
	return nil
}

// determinePodStartupStateFor maps a pod phase to a NIM startup-state string. It
// is the package-level form of NIMReconciler.determinePodStartupState so the
// SecurityEvent reconciler can compute the same startup state for the shared
// reschedule helper without holding a NIMReconciler.
func determinePodStartupStateFor(pod corev1.Pod) string {
	switch pod.Status.Phase {
	case corev1.PodPending:
		return NIM_STARTUP_STATE_PENDING
	case corev1.PodRunning:
		return NIM_STARTUP_STATE_RUNNING
	case corev1.PodFailed:
		return NIM_STARTUP_STATE_FAILED
	default:
		return NIM_STARTUP_STATE_STARTING
	}
}

// SetupWithManager sets up the NIM controller with the Manager.
func (r *NIMReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("nim-pod").
		Complete(r)
}

func (r *NIMReconciler) determinePodStartupState(pod corev1.Pod) string {
	return determinePodStartupStateFor(pod)
}
