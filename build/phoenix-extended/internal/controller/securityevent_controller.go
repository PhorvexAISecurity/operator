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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/strings/slices"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// SecurityEventReconciler reconciles a SecurityEvent object
type SecurityEventReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIReader client.Reader
}

// defaultRotateGracePeriodSeconds is the pod-delete grace used by the Phase 0
// cold reschedule performed by the Rotate dispatch branch. It mirrors the NIM
// default grace (DefaultNIMPolicy GracePeriodSeconds) so the dissolved
// {timed -> rotate} rule reschedules with exactly today's behavior.
const defaultRotateGracePeriodSeconds int64 = 30

const securityEventAdoptionRetryInterval = 2 * time.Second

type preparedSecurityEventTarget struct {
	pod        *corev1.Pod
	management []AMTDManageInfo
}

func isControlledPhorvexQuarantine(event *amtdv1beta1.SecurityEvent) bool {
	return event != nil && event.Spec.Rule.Type == PHORVEX_QUARANTINE_RULE_TYPE && event.Spec.Rule.Source == PHORVEX_CONTROLLED_RULE_SOURCE
}

func (r *SecurityEventReconciler) identityReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// boundPhorvexQuarantineTarget validates the operator-owned identity envelope.
// External/manual Phoenix events retain their existing contract; only the exact
// Phorvex-controlled quarantine rule requires this binding.
func (r *SecurityEventReconciler) boundPhorvexQuarantineTarget(ctx context.Context, event *amtdv1beta1.SecurityEvent, namespace, name string) (*corev1.Pod, error) {
	if !isControlledPhorvexQuarantine(event) {
		return nil, nil
	}
	if len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != namespace+"/"+name {
		return nil, fmt.Errorf("controlled Phorvex quarantine must bind exactly one target")
	}
	targetUID := strings.TrimSpace(event.Annotations[PHORVEX_QUARANTINE_TARGET_UID])
	namespaceUID := strings.TrimSpace(event.Annotations[PHORVEX_QUARANTINE_NAMESPACE_UID])
	operationID := strings.TrimSpace(event.Annotations[PHORVEX_QUARANTINE_OPERATION])
	if targetUID == "" || len(targetUID) > 128 || namespaceUID == "" || len(namespaceUID) > 128 || len(operationID) != 40 {
		return nil, fmt.Errorf("controlled Phorvex quarantine identity envelope is incomplete")
	}
	ns := &corev1.Namespace{}
	if err := r.identityReader().Get(ctx, types.NamespacedName{Name: namespace}, ns); err != nil {
		return nil, fmt.Errorf("validate controlled quarantine namespace identity: %w", err)
	}
	if ns.UID == "" || string(ns.UID) != namespaceUID || ns.DeletionTimestamp != nil {
		return nil, fmt.Errorf("controlled Phorvex quarantine namespace UID changed or is terminating")
	}
	pod := &corev1.Pod{}
	if err := r.identityReader().Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, pod); err != nil {
		return nil, fmt.Errorf("validate controlled quarantine target identity: %w", err)
	}
	if pod.UID == "" || string(pod.UID) != targetUID || pod.DeletionTimestamp != nil {
		return nil, fmt.Errorf("controlled Phorvex quarantine target UID changed or is terminating")
	}
	return pod, nil
}

// prepareSecurityEventTargets validates and snapshots the complete target batch
// before the reconcile loop performs any action or records an event as applied.
// Adoption is asynchronous, so absent or empty managed-by metadata is a pending
// state rather than successful completion.

func (r *SecurityEventReconciler) prepareSecurityEventTargets(ctx context.Context, event *amtdv1beta1.SecurityEvent) ([]preparedSecurityEventTarget, bool, bool, error) {
	if event == nil {
		return nil, false, false, fmt.Errorf("SecurityEvent is required")
	}
	targets := event.Spec.Targets
	if isControlledPhorvexQuarantine(event) && len(targets) != 1 {
		return nil, false, false, fmt.Errorf("controlled Phorvex quarantine must bind exactly one target")
	}
	prepared := make([]preparedSecurityEventTarget, 0, len(targets))
	var pendingAdoption, absentPod bool
	for _, target := range targets {
		parts := strings.Split(target, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, false, false, fmt.Errorf("invalid SecurityEvent target %q: expected namespace/name", target)
		}

		pod := &corev1.Pod{}
		key := types.NamespacedName{Namespace: parts[0], Name: parts[1]}
		reader := client.Reader(r.Client)
		if isControlledPhorvexQuarantine(event) {
			reader = r.identityReader()
		}
		if err := reader.Get(ctx, key, pod); err != nil {
			if errors.IsNotFound(err) {
				// Preserve the established absent-pod no-action outcome. Because this
				// is preflight, no earlier target has been mutated yet.
				absentPod = true
				continue
			}
			return nil, false, false, fmt.Errorf("retrieve target pod %s: %w", key, err)
		}
		if isControlledPhorvexQuarantine(event) {
			bound, bindErr := r.boundPhorvexQuarantineTarget(ctx, event, parts[0], parts[1])
			if bindErr != nil {
				return nil, false, false, bindErr
			}
			pod = bound
		}

		raw, found := pod.Annotations[AMTD_MANAGED_BY]
		if !found || strings.TrimSpace(raw) == "" {
			pendingAdoption = true
			continue
		}

		var management []AMTDManageInfo
		if err := json.Unmarshal([]byte(raw), &management); err != nil {
			return nil, false, false, fmt.Errorf("decode %s annotation on pod %s: %w", AMTD_MANAGED_BY, key, err)
		}
		if len(management) == 0 {
			pendingAdoption = true
			continue
		}
		for i, info := range management {
			if info.AMTDNamespace == "" || info.AMTDName == "" {
				return nil, false, false, fmt.Errorf("invalid %s annotation entry %d on pod %s: AMTD namespace and name are required", AMTD_MANAGED_BY, i, key)
			}
		}

		prepared = append(prepared, preparedSecurityEventTarget{pod: pod, management: management})
	}
	return prepared, pendingAdoption, absentPod, nil
}

//+kubebuilder:rbac:groups=amtd.r6security.com,resources=securityevents,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=securityevents/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=securityevents/finalizers,verbs=update
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=adaptivemovingtargetdefenses,verbs=get;list;watch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=adaptivemovingtargetdefenses/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,resources=namespaces,verbs=get
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create
//+kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
//+kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch
// Phase 2 (D5, arch L228): the persisted jitter SEED lives in a dedicated
// RBAC-gated Secret the Rotate executor reads/creates per-AMTD.
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SecurityEvent object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.4/pkg/reconcile
func (r *SecurityEventReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	securityEvent := &amtdv1beta1.SecurityEvent{}

	// Retrieve SecurityEvent that triggered reconciliation from the cluster
	err := r.Client.Get(context.Background(), req.NamespacedName, securityEvent)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info(fmt.Sprintf(`SecurityEvent "%s" removed, no action is needed`, req.Name))
			return ctrl.Result{}, nil
		} else {
			log.Error(err, fmt.Sprintf(`Failed to retrieve Security Event "%s": %s`, req.Name, err.Error()))
			return ctrl.Result{}, err
		}
	}

	log.Info(fmt.Sprintf(`SecurityEvent found: "%s, targets: %s"`, securityEvent.Name, securityEvent.Spec.Targets))

	// ---------------------------------------------------
	// Process pods in the target list of the SecurityEvent
	// ---------------------------------------------------
	preparedTargets, pendingAdoption, absentPod, err := r.prepareSecurityEventTargets(ctx, securityEvent)
	if err != nil {
		return ctrl.Result{}, err
	}
	if absentPod {
		log.Info("At least one SecurityEvent target pod does not exist; no action is needed")
		return ctrl.Result{}, nil
	}
	if pendingAdoption {
		log.Info("SecurityEvent target adoption is pending; retrying", "retryAfter", securityEventAdoptionRetryInterval)
		return ctrl.Result{RequeueAfter: securityEventAdoptionRetryInterval}, nil
	}

	var AMTD *amtdv1beta1.AdaptiveMovingTargetDefense
	for _, prepared := range preparedTargets {
		pod := prepared.pod
		// Re-read and revalidate the controlled identity immediately before the
		// first annotation or action. A same-name replacement can never consume the
		// reservation or delayed event intended for the old Pod/namespace UID.
		if isControlledPhorvexQuarantine(securityEvent) {
			pod, err = r.boundPhorvexQuarantineTarget(ctx, securityEvent, prepared.pod.Namespace, prepared.pod.Name)
			if err != nil {
				return ctrl.Result{}, err
			}
		}

		// ---------------------------------------------------
		// Look for the proper action for the SecurityEvent in AMTDs that manage the pod
		// ---------------------------------------------------
		var action amtdv1beta1.AMTDAction
		var matcherModeWarning bool
		var warnAMTD *amtdv1beta1.AdaptiveMovingTargetDefense
		for _, AMTDManageInfo := range prepared.management {

			// Get AMTD resource that is in AMTDManageInfo so it belongs to the pod
			AMTD = &amtdv1beta1.AdaptiveMovingTargetDefense{}
			err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: AMTDManageInfo.AMTDNamespace, Name: AMTDManageInfo.AMTDName}, AMTD)
			if err != nil {
				if errors.IsNotFound(err) {
					log.Info(fmt.Sprintf(`AdaptiveMovingTargetDefense "%s" does not exist but found in pod annotation`, AMTDManageInfo.AMTDNamespace+"/"+AMTDManageInfo.AMTDName))
					break
				} else {
					log.Error(err, fmt.Sprintf(`Failed to retrieve AdaptiveMovingTargetDefense "%s": %s`, AMTDManageInfo.AMTDName, err.Error()))
					return ctrl.Result{}, err
				}
			}

			// Check whether there is a specific action to the security event.
			// MatchStrategyForMode is a strict superset of the previous whole-Rule
			// reflect.DeepEqual against securityEvent.Spec.Rule: in the default Exact
			// MatcherMode it evaluates the identical 3-string projection
			// {Type,ThreatLevel,Source} (byte-compatible with the old DeepEqual), and
			// in Scored mode it additionally honors Rule.Match / Rule.ScoreThreshold
			// against the whole event spec. The first-match-wins loop and the
			// zero-value sentinel below are preserved.
			for _, strategy := range AMTD.Spec.Strategy {
				if RuleHasScoredClause(strategy.Rule) && AMTD.Spec.MatcherMode != amtdv1beta1.MatcherModeScored {
					// A scored clause is inert under Exact mode; remember to warn.
					matcherModeWarning = true
					warnAMTD = AMTD
				}
				if MatchStrategyForMode(strategy.Rule, securityEvent.Spec, AMTD.Spec.MatcherMode) {
					// we found the matching strategy no need to look further
					action = strategy.Action
					break
				}
			}
			// we found the matching strategy no need to look further
			if action != (amtdv1beta1.AMTDAction{}) {
				break
			}
		}
		if isControlledPhorvexQuarantine(securityEvent) && action.Quarantine == nil {
			return ctrl.Result{}, fmt.Errorf("controlled Phorvex quarantine event did not resolve to the quarantine action")
		}

		// ---------------------------------------------------
		// If a scored strategy clause was inert because the AMTD is in (default)
		// Exact MatcherMode, surface a MatcherModeWarning condition on the AMTD so
		// the operator can see the clause had no effect (guarantees ZERO silent
		// behavior change).
		// ---------------------------------------------------
		if matcherModeWarning && warnAMTD != nil {
			if isControlledPhorvexQuarantine(securityEvent) {
				if _, err = r.boundPhorvexQuarantineTarget(ctx, securityEvent, pod.Namespace, pod.Name); err != nil {
					return ctrl.Result{}, err
				}
			}
			r.setMatcherModeWarning(ctx, warnAMTD, log)
		}

		// ---------------------------------------------------
		// Add SecurityEvent spec to the annotation of the pod
		// ---------------------------------------------------
		var appliedSecurityEvents []amtdv1beta1.SecurityEvent
		if _, found := pod.ObjectMeta.Annotations[AMTD_APPLIED_SECURITY_EVENTS]; !found {
			appliedSecurityEvents = append(appliedSecurityEvents, *securityEvent)
		} else {
			// Already AMTD member
			json.Unmarshal([]byte(pod.ObjectMeta.Annotations[AMTD_APPLIED_SECURITY_EVENTS]), &appliedSecurityEvents)

			securityEventExist := false
			for _, appliedSecurityEvent := range appliedSecurityEvents {
				if appliedSecurityEvent.Name == securityEvent.Name {
					securityEventExist = true
					break
				}
			}

			if !securityEventExist {
				appliedSecurityEvents = append(appliedSecurityEvents, *securityEvent)
			} else {
				log.Info(fmt.Sprintf(`This SecurityEvent ("%s") was already processed - ignore it`, securityEvent.Name))
				//return ctrl.Result{}, nil
			}
		}

		if appliedSecurityEvents != nil {
			appliedSecurityEventsEncoded, err := json.Marshal(appliedSecurityEvents)
			if err != nil {
				log.Error(err, fmt.Sprintf(`appliedSecurityEvents json encoding does not work: %s`, err.Error()))
			}
			if isControlledPhorvexQuarantine(securityEvent) {
				pod, err = r.boundPhorvexQuarantineTarget(ctx, securityEvent, pod.Namespace, pod.Name)
				if err != nil {
					return ctrl.Result{}, err
				}
			}
			if pod.Annotations == nil {
				pod.Annotations = map[string]string{}
			}
			pod.ObjectMeta.Annotations[AMTD_APPLIED_SECURITY_EVENTS] = string(appliedSecurityEventsEncoded)

			err = r.Client.Update(ctx, pod)
			if err != nil {
				log.Error(err, fmt.Sprintf(`Failed to update pod: "%s": %s`, pod.Name, err.Error()))
				return ctrl.Result{}, err
			}

			log.Info(fmt.Sprintf(`SecurityEvent was sucessfully applied to the pod`))
		}

		// ---------------------------------------------------
		// PHASE 3 telemetry-scoring UPDATE (cap#5, arch §2.3/§2.4, D19/D20/D22/D25/
		// D26g). Runs ONLY when the matched AMTD is in MatcherMode=Scored AND carries
		// an AdaptiveRotation block. It scores the event (Passthrough default),
		// applies the provenance + staleness gates, advances the EWMA SmoothedScore +
		// N-consecutive-high counter, computes the monotone-decreasing
		// ComputedInterval, writes ALL of it to Status (restart-safe), and yields the
		// panic-hysteresis flag the executor's G3 floor-bypass consults.
		//
		// In Exact/unset MatcherMode this block is SKIPPED ENTIRELY: no scored Status
		// field is written and the dispatch below is byte-for-byte today's behavior
		// (the EXACT-MATCH path is unchanged; panic is impossible because score.panic
		// stays false on the zero scoringResult).
		// ---------------------------------------------------
		var score scoringResult
		if AMTD != nil &&
			AMTD.Spec.MatcherMode == amtdv1beta1.MatcherModeScored &&
			AMTD.Spec.InferenceRotation != nil &&
			AMTD.Spec.InferenceRotation.AdaptiveRotation != nil {
			if isControlledPhorvexQuarantine(securityEvent) {
				if _, err = r.boundPhorvexQuarantineTarget(ctx, securityEvent, pod.Namespace, pod.Name); err != nil {
					return ctrl.Result{}, err
				}
			}
			score = r.applyScoring(ctx, AMTD, securityEvent, log)
		}

		// ---------------------------------------------------
		// Execute the proper action
		// TODO: replace with Action interface and function call
		// ---------------------------------------------------
		if action.Delete != nil {
			podErr := r.Client.Delete(ctx, pod)

			if err != nil && !errors.IsNotFound(err) {
				log.Error(podErr, fmt.Sprintf(`Failed to delete pod "%s"`, req.Name))
			}
			log.Info(fmt.Sprintf(`Pod: "%s" was sucessfully deleted with ACTION: delete`, pod.Name))
		} else if action.Debugger != nil {
			if len(pod.Spec.Containers) == 0 {
				log.Info("There is no container in the pod which can be used to attach the ephemeral container to")
				break
			}

			if action.Debugger.Name == "" {
				action.Debugger.Name = "amtd-debug-container"
			}

			ephemeralContainers := make([]string, len(pod.Spec.EphemeralContainers))
			for _, c := range pod.Spec.EphemeralContainers {
				ephemeralContainers = append(ephemeralContainers, c.Name)
			}

			if slices.Contains(ephemeralContainers, action.Debugger.Name) {
				log.Info("Cannot attach a debug container because it is already exists")
				break
			}

			ec := corev1.EphemeralContainer{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  action.Debugger.Name,
					Image: action.Debugger.Image,
					Stdin: action.Debugger.Terminal,
					TTY:   action.Debugger.Terminal,
				},
				TargetContainerName: pod.Spec.Containers[0].Name,
			}
			pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, ec)

			err = r.Client.SubResource("ephemeralcontainers").Update(ctx, pod)

			if err != nil {
				log.Error(err, fmt.Sprintf(`Failed to update pod: "%s": %s`, pod.Name, err.Error()))
				break
			}
			log.Info("Successfully attached debug container", "containerName", action.Debugger.Name)
		} else if action.CustomAction != nil {

			if len(pod.Spec.Containers) == 0 {
				log.Info("There is no container in the pod which can be used to attach the ephemeral container to")
				break
			}

			if action.CustomAction.Name == "" {
				action.CustomAction.Name = "amtd-debug-container"
			}

			if action.CustomAction.TargetContainerName == "" {
				action.CustomAction.TargetContainerName = pod.Spec.Containers[0].Name
			}

			ephemeralContainers := make([]string, len(pod.Spec.EphemeralContainers))
			for _, c := range pod.Spec.EphemeralContainers {
				ephemeralContainers = append(ephemeralContainers, c.Name)
			}

			if slices.Contains(ephemeralContainers, action.CustomAction.Name) {
				log.Info("Cannot attach a custom action container because it is already exists")
				break
			}

			ec := corev1.EphemeralContainer{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  action.CustomAction.Name,
					Image: action.CustomAction.Image,
					Stdin: action.CustomAction.Stdin,
					TTY:   action.CustomAction.TTY,
				},
				TargetContainerName: pod.Spec.Containers[0].Name,
			}
			pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, ec)

			err = r.Client.SubResource("ephemeralcontainers").Update(ctx, pod)

			if err != nil {
				log.Error(err, fmt.Sprintf(`Failed to update pod: "%s": %s`, pod.Name, err.Error()))
				break
			}
			log.Info("Successfully attached custom action container", "containerName", action.CustomAction.Name)
		} else if action.Quarantine != nil {
			networkPolicyName := fmt.Sprintf("%s-%s-%s", pod.Namespace, pod.Name, "policy")

			networkPolicy := &v1.NetworkPolicy{}
			err = r.Client.Get(ctx, types.NamespacedName{
				Namespace: pod.Namespace,
				Name:      networkPolicyName,
			}, networkPolicy)

			if err != nil {
				if !errors.IsNotFound(err) {
					return ctrl.Result{}, fmt.Errorf("get quarantine NetworkPolicy %s/%s: %w", pod.Namespace, networkPolicyName, err)
				}
				networkPolicy = &v1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      networkPolicyName,
						Namespace: pod.Namespace,
					},
					Spec: v1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{AMTD_NETWORK_POLICY: networkPolicyName},
						},
						Ingress: []v1.NetworkPolicyIngressRule{},
						Egress:  []v1.NetworkPolicyEgressRule{},
						PolicyTypes: []v1.PolicyType{
							v1.PolicyTypeIngress,
							v1.PolicyTypeEgress,
						},
					},
				}

				// Set AMTD instance as the owner and controller for the NetworkPolicy
				err := ctrl.SetControllerReference(AMTD, networkPolicy, r.Scheme)
				if err != nil {
					log.Error(err, "Failed to set AMTD as owner and controller reference on NetworkPolicy",
						"AMTD", AMTD.ObjectMeta.Name,
						"NetworkPolicy", networkPolicy.Name,
						"Namespace", networkPolicy.Namespace,
					)
				}
				if isControlledPhorvexQuarantine(securityEvent) {
					if _, err = r.boundPhorvexQuarantineTarget(ctx, securityEvent, pod.Namespace, pod.Name); err != nil {
						return ctrl.Result{}, err
					}
				}

				if err = r.Create(ctx, networkPolicy); err != nil {
					log.Error(err, "Failed to create NetworkPolicy in the cluster",
						"NetworkPolicy", networkPolicy.Name,
						"Namespace", networkPolicy.Namespace)
					return ctrl.Result{}, err
				}
			}
			if isControlledPhorvexQuarantine(securityEvent) {
				pod, err = r.boundPhorvexQuarantineTarget(ctx, securityEvent, pod.Namespace, pod.Name)
				if err != nil {
					return ctrl.Result{}, err
				}
			}

			// Relabel on every quarantine event, not only when the NetworkPolicy is first
			// created. A recreated pod can outlive the deterministic policy name and lose
			// this selector label; treating the existing policy as a completed quarantine
			// then records success while no pod is isolated.
			// i) move labels under annotations to preserve them - except those that belong to AMTD management,
			for key, value := range pod.ObjectMeta.Labels {
				if !isSetContain(AMTD.Spec.PodSelector, map[string]string{key: value}) {
					pod.ObjectMeta.Annotations[key] = value
					delete(pod.ObjectMeta.Labels, key)
				}
			}
			// ii) add the label that makes the deny-all policy select this pod
			pod.ObjectMeta.Labels[AMTD_NETWORK_POLICY] = networkPolicyName

			if err = r.Client.Update(ctx, pod); err != nil {
				log.Error(err, fmt.Sprintf(`Failed to update pod: "%s": %s`, pod.Name, err.Error()))
				return ctrl.Result{}, err
			}

			log.Info(fmt.Sprintf(`Pod %s was put in quarantine`, pod.Name))

			// Set AMTD instance as the owner and controller for the Pod - this
			// step cannot combined into a single update with relabel, because
			// until relabel another owner exists that cannot be updated
			// Actually since it's not immediate that OwnerReference is deleted
			// by ReplicaSet or sg. we need to reschedule and check it later
			if isControlledPhorvexQuarantine(securityEvent) {
				pod, err = r.boundPhorvexQuarantineTarget(ctx, securityEvent, pod.Namespace, pod.Name)
				if err != nil {
					return ctrl.Result{}, err
				}
			}
			err = ctrl.SetControllerReference(AMTD, pod, r.Scheme)
			if err != nil {
				log.Error(err, "Failed to set AMTD as owner and controller reference on Pod - Rescheduling and trying later",
					"AMTD", AMTD.ObjectMeta.Name,
					"Pod", pod.Name,
					"Namespace", networkPolicy.Namespace,
				)
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}

			err = r.Client.Update(ctx, pod)
			if err != nil {
				log.Error(err, fmt.Sprintf(`Failed to update pod: "%s": %s`, pod.Name, err.Error()))
				return ctrl.Result{}, err
			}
		} else if action.Rotate != nil {
			// PHASE 1 Rotate: the one-shot mutating-rotation executor (D2). The
			// {type:'timed', source:'TimeBasedTrigger'} -> {rotate:{}} strategy (and
			// the scored panic row) lands here. executeRotate wraps the cold
			// reschedule with the D22 storm-guard pipeline (idempotence /
			// in-progress lock / min-interval floor / readiness gate / crash-loop
			// backoff+rollback) and the D3 mutation-survival routing (resolve the
			// effective overlay from Rotate.Overrides or Rotate.PolicyRef ->
			// InferenceRotation, then either patch the top owner template durably or
			// cold-fallback), and writes the audit Status. A nil overlay degrades to
			// exactly the Phase 0 cold reschedule.
			if err := r.executeRotate(ctx, pod, AMTD, securityEvent, action.Rotate, score, log); err != nil {
				log.Error(err, fmt.Sprintf(`Failed to perform rotate on pod "%s"`, pod.Name))
				return ctrl.Result{}, err
			}
		} else if action.WarmSwap != nil {
			// PHASE 4 WarmSwap (cap#2, arch §2.1/§3, D11/D12): a matched WarmSwap action
			// triggers the leader->warm-shadow cutover for the referenced
			// WarmInferenceSet. Following the restart-safe progressive model (arch §3),
			// the action does NOT perform the swap inline — it sets the
			// WarmInferenceSet's Spec.SwapRequest; the WarmInferenceSet reconciler then
			// progresses Ready->flip->drain->retire->rewarm across reconciles and clears
			// the request. This keeps class-B maintenance provably honest (no request =>
			// no swap) and survives operator restart. The per-event outcome is recorded
			// on SecurityEventStatus.AppliedAction="warmSwap" (mirroring the Rotate
			// executor's Status write), and RotationPathFired="WarmSwap" is mirrored to
			// the AMTD WarmPool status when reachable.
			if err := r.requestWarmSwap(ctx, pod, AMTD, securityEvent, action.WarmSwap, log); err != nil {
				log.Error(err, fmt.Sprintf(`Failed to request warmSwap for pod "%s"`, pod.Name))
				return ctrl.Result{}, err
			}
		} else if action.Regenerate != nil {
			// PHASE 5 Regenerate (cap#6, arch §2.1/§3, D6/D6g): a matched Regenerate
			// action restores the pod's workload to the GOLDEN signed baseline. The
			// matcher routes a Type:'drift' SecurityEvent (emitted by the
			// BaselineDriftReconciler, which does NOT act) here. executeRegenerate
			// resolves the cluster-scoped WorkloadBaseline named by
			// action.BaselineRef, VERIFIES the pinned digests against the
			// SignaturePolicy BEFORE patching (verify-before-recreate — we never
			// self-heal onto an unverifiable target), then REUSES the D3 owner-walk
			// (classifyTopOwner/patchOwnerTemplate) to patch the top owner template
			// image back to the pinned Repository@Digest, optionally resets the
			// pod-local hardening profile, and records
			// WorkloadBaselineStatus.LastRegeneration. SecurityEventStatus.AppliedAction
			// is set to "regenerate". CAVEAT (D6/D11): signing proves PROVENANCE, not
			// BENIGNITY — the default OnDrift is Quarantine, not auto-Regenerate.
			if err := r.executeRegenerate(ctx, pod, AMTD, securityEvent, action.Regenerate, log); err != nil {
				log.Error(err, fmt.Sprintf(`Failed to perform regenerate on pod "%s"`, pod.Name))
				return ctrl.Result{}, err
			}
		} else if action.NodeRotate != nil {
			// PHASE 6 NodeRotate (cap#7, arch §2.1/§3, D25g/D26): a matched NodeRotate
			// action relocates the targeted pod onto a clean node. The action does NOT
			// cordon/drain inline — after the D26 trust gate (Source allowlist +
			// ThreatLevel floor + human-approval-for-Delete) it CREATES a cluster-scoped
			// NodeRotation request for the targeted pod's node; the NodeRotationReconciler
			// then progresses the restart-safe Cordoning->Draining->Rescheduling->Pinning->
			// Completed drain and clears nothing the matcher did not select (class-B
			// continuation). The targeted pod gets the ROTATION_IN_PROGRESS lock so NIM
			// early-returns (no double-evict). A forged/non-allowlisted/below-floor event
			// creates NO NodeRotation (recorded as a denied condition). The per-event
			// outcome is SecurityEventStatus.AppliedAction="nodeRotate" (or "-denied").
			if err := r.requestNodeRotate(ctx, pod, AMTD, securityEvent, action.NodeRotate, log); err != nil {
				log.Error(err, fmt.Sprintf(`Failed to request nodeRotate for pod "%s"`, pod.Name))
				return ctrl.Result{}, err
			}
		} else {
			log.Info(fmt.Sprintf(`ACTION: %v -> POD: %s - NOT IMPLEMENTED YET`, action, pod.Name))
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecurityEventReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&amtdv1beta1.SecurityEvent{}).
		Complete(r)
}

func isSetContain(set map[string]string, subset map[string]string) bool {
	if len(subset) == 0 {
		return false
	}
	for key, value := range subset {
		if value2, ok := set[key]; ok {
			if value != value2 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// setMatcherModeWarning records a MatcherModeWarning condition on the AMTD status
// to signal that one or more scored strategy clauses (Rule.Match /
// Rule.ScoreThreshold) were inert because the AMTD is in the default Exact
// MatcherMode. This is best-effort observability: a failure to write the status
// is logged but does not fail the reconcile (the scored clause being inert is the
// intended, fail-safe behavior either way).
func (r *SecurityEventReconciler) setMatcherModeWarning(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, log logr.Logger) {
	cond := metav1.Condition{
		Type:               "MatcherModeWarning",
		Status:             metav1.ConditionTrue,
		Reason:             "ScoredClauseInertInExactMode",
		Message:            "One or more strategy rules carry Match/ScoreThreshold clauses that are ignored because spec.matcherMode is Exact (the default). Set spec.matcherMode=Scored to enable scored matching.",
		ObservedGeneration: amtd.Generation,
	}
	if meta.SetStatusCondition(&amtd.Status.Conditions, cond) {
		if err := r.Client.Status().Update(ctx, amtd); err != nil {
			log.Error(err, "Failed to set MatcherModeWarning condition on AMTD", "AMTD", amtd.Name, "Namespace", amtd.Namespace)
		}
	}
}
