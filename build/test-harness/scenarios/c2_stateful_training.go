package scenarios

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c2StatefulTraining{}) }

const statefulMarkerObservationWindow = 20 * time.Second

var statefulMarkerObservationWait = waitStatefulMarkerObservation

// c2StatefulTraining is a legacy marker simulation. It provisions a PVC-mounted
// CPU fixture and plants the same bounded in-container marker used by the other
// legacy persistence scenarios. It does not read checkpoint bytes, measure
// application progress, or send packet probes, so those effects remain
// deliberately unobserved.
type c2StatefulTraining struct {
	app             string
	pvc             string
	targetName      string
	targetUID       types.UID
	pvcUID          types.UID
	markerPlantedAt time.Time
}

func (s *c2StatefulTraining) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-stateful-training",
		Category:           core.CategoryR6Claimed,
		Source:             "Legacy Cat2 stateful-workload narrative; corrected post25 oracle review",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1543.005", "T1486", "T1496"},
		Realism:            core.RealismMarkerSimulation,
		Mechanism:          "create one owned PVC-mounted BusyBox CPU Pod, plant a bounded synthetic marker and sleeper, wait 20 seconds, then read that marker only from the exact setup-created Pod UID",
		ClaimLimits:        "marker simulation only; exercises zero ATT&CK techniques and does not measure detection, containment, NetworkPolicy enforcement, checkpoint durability, application progress, in-memory training recovery, work preservation, destructive impact, GPU training, or a feasible alternative",
		OracleDescription:  "the marker objective succeeds only when the exact setup-created Pod UID remains Running and an error-preserving exec explicitly reads the marker; exact UID absence is reported only as identity replacement/removal",
		CleanupDescription: "delete only the Pod and PVC whose successful Create responses supplied the retained UIDs, using UID preconditions",
		R6Justification:    "The fixture can compare exact Pod-identity and ephemeral-marker persistence. Policy or event presence cannot establish containment or preserved application work, so this legacy arm makes no such claim.",
	}
}

func (s *c2StatefulTraining) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2st-train"
	s.pvc = s.app + "-work"
	s.targetName = ""
	s.targetUID = ""
	s.pvcUID = ""
	s.markerPlantedAt = time.Time{}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: s.pvc, Namespace: ns, Labels: env.OwnedLabels(nil)},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("50Mi")}},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl create pvc %s --size=50Mi -n %s  # synthetic checkpoint fixture", s.pvc, ns))
	createdPVC, err := env.Kube.CoreV1().PersistentVolumeClaims(ns).Create(ctx, pvc, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create owned stateful marker PVC %s: %w", s.pvc, err)
	}
	if createdPVC.UID == "" {
		return fmt.Errorf("create owned stateful marker PVC %s returned empty UID", s.pvc)
	}
	s.pvcUID = createdPVC.UID

	labels := mocks.LabelMap(map[string]string{defenders.RotationTargetLabel: "true", "app": s.app, "tier": "training", "data-class": "restricted"}, nil)
	pod := mocks.NewPod(env, s.app, labels).
		WithBusyboxLoop("trainer", []string{"sh", "-c", "echo START > /work/checkpoint; i=0; while true; do i=$((i+1)); echo step=$i > /work/checkpoint; sleep 2; done"}, 100, 64).
		WithVolume(
			corev1.Volume{Name: "work", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: s.pvc}}},
			corev1.VolumeMount{Name: "work", MountPath: "/work"}).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl create pod %s -n %s --mount pvc=%s  # synthetic stateful marker fixture", s.app, ns, s.pvc))
	createdPod, err := env.Kube.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create owned stateful marker Pod %s: %w", s.app, err)
	}
	if createdPod.UID == "" {
		return fmt.Errorf("create owned stateful marker Pod %s returned empty UID", s.app)
	}
	s.targetName, s.targetUID = createdPod.Name, createdPod.UID
	if err := env.WaitForPodRunning(ctx, s.targetName, 60*time.Second); err != nil {
		return err
	}
	ready, err := env.Kube.CoreV1().Pods(ns).Get(ctx, s.targetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read setup-created stateful marker Pod: %w", err)
	}
	if ready.UID != s.targetUID {
		return fmt.Errorf("setup-created stateful marker Pod UID changed: created=%s observed=%s", s.targetUID, ready.UID)
	}
	return nil
}

func (s *c2StatefulTraining) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.markerPlantedAt = time.Time{}
	if s.targetName == "" || s.targetUID == "" || s.pvcUID == "" {
		return core.AttackResult{}, errors.New("stateful marker setup identity missing")
	}
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.targetName, metav1.GetOptions{})
	if err != nil {
		return core.AttackResult{}, fmt.Errorf("read stateful marker target: %w", err)
	}
	if pod.UID != s.targetUID {
		return core.AttackResult{}, fmt.Errorf("stateful marker target UID changed before stimulus: created=%s observed=%s", s.targetUID, pod.UID)
	}
	cmds, err := plantBackdoorObserved(ctx, env, pod.Name, firstContainer(pod))
	stages := []string{"plant bounded synthetic marker and sleeper in the PVC-mounted CPU fixture"}
	if err != nil {
		return core.AttackResult{Stages: stages, Commands: cmds}, fmt.Errorf("plant stateful synthetic marker: %w", err)
	}
	s.markerPlantedAt = time.Now()
	if em, ok := emitterFromEnv(env); ok {
		if err := em.EmitSecurityEvent(ctx, env, pod.Name, amtdv1beta1.TypePanic, amtdv1beta1.ThreatLevelHigh); err == nil {
			cmds = append(cmds, "emit synthetic SecurityEvent{panic,high} for defender selection")
		}
	}
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: map[string]string{
		"classification":      string(core.RealismMarkerSimulation),
		"originalPod":         s.targetName,
		"originalPodUID":      string(s.targetUID),
		"ownedPVC":            s.pvc,
		"ownedPVCUID":         string(s.pvcUID),
		"markerPlantedAt":     s.markerPlantedAt.UTC().Format(time.RFC3339Nano),
		"exercisedTechniques": "none",
	}}, nil
}

func (s *c2StatefulTraining) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	if s.targetName == "" || s.targetUID == "" || s.markerPlantedAt.IsZero() {
		return core.OracleResult{}, errors.New("stateful marker stimulus identity or start time missing")
	}
	windowStart, windowEnd, err := statefulMarkerObservationWait(ctx, statefulMarkerObservationWindow)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("stateful marker observation window did not complete: %w", err)
	}
	if windowStart.IsZero() || windowEnd.Before(windowStart) || windowEnd.Sub(windowStart) < statefulMarkerObservationWindow {
		return core.OracleResult{}, fmt.Errorf("stateful marker observation window was shorter than %.0fs", statefulMarkerObservationWindow.Seconds())
	}

	baseEvidence := map[string]string{
		"classification":           string(core.RealismMarkerSimulation),
		"originalPod":              s.targetName,
		"originalPodUID":           string(s.targetUID),
		"observationWindowSeconds": fmt.Sprintf("%.0f", statefulMarkerObservationWindow.Seconds()),
		"containment":              "unobserved",
		"networkEffect":            "unobserved",
		"checkpointRead":           "not-performed",
		"applicationProgress":      "unobserved",
		"workPreserved":            "unobserved",
	}
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.targetName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		baseEvidence["originalUIDAbsent"] = "true"
		baseEvidence["markerPresent"] = "false"
		return core.OracleResult{Achieved: false, ObservedState: "marker simulation: exact original Pod identity is absent; containment and stateful work are unobserved", Evidence: baseEvidence}, nil
	}
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("read exact stateful marker target: %w", err)
	}
	baseEvidence["observedPodUID"] = string(pod.UID)
	if pod.UID != s.targetUID {
		baseEvidence["originalUIDAbsent"] = "true"
		baseEvidence["markerPresent"] = "false"
		return core.OracleResult{Achieved: false, ObservedState: "marker simulation: same-name Pod has a different UID; containment and stateful work are unobserved", Evidence: baseEvidence}, nil
	}
	baseEvidence["originalUIDAbsent"] = "false"
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return core.OracleResult{}, fmt.Errorf("exact stateful marker target uid=%s is not running and non-terminating", pod.UID)
	}
	markerPresent, err := observedMarker(ctx, env.Exec(ctx, pod.Name, firstContainer(pod), markerReadCommand(BackdoorMarkerPath)), BackdoorMarker)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("read exact stateful marker target uid=%s: %w", pod.UID, err)
	}
	baseEvidence["markerPresent"] = fmt.Sprintf("%v", markerPresent)
	state := fmt.Sprintf("marker simulation: exact original Pod UID retained=%v and synthetic marker present=%v; containment and stateful work are unobserved", true, markerPresent)
	return core.OracleResult{Achieved: markerPresent, ObservedState: state, Evidence: baseEvidence}, nil
}

func (s *c2StatefulTraining) Teardown(ctx context.Context, env *core.Env) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	var errs []error
	if s.targetName != "" && s.targetUID != "" {
		opts := statefulDeleteOptions(s.targetUID, true)
		env.Log.Command(fmt.Sprintf("kubectl delete pod %s -n %s --grace-period=0 --preconditions uid=%s", s.targetName, env.Config.Namespace, s.targetUID))
		if err := env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, s.targetName, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete stateful marker Pod uid=%s: %w", s.targetUID, err))
		}
	}
	if s.pvc != "" && s.pvcUID != "" {
		opts := statefulDeleteOptions(s.pvcUID, false)
		env.Log.Command(fmt.Sprintf("kubectl delete pvc %s -n %s --preconditions uid=%s", s.pvc, env.Config.Namespace, s.pvcUID))
		if err := env.Kube.CoreV1().PersistentVolumeClaims(env.Config.Namespace).Delete(ctx, s.pvc, opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete stateful marker PVC uid=%s: %w", s.pvcUID, err))
		}
	}
	return errors.Join(errs...)
}

func statefulDeleteOptions(uid types.UID, immediate bool) metav1.DeleteOptions {
	dp := metav1.DeletePropagationBackground
	opts := metav1.DeleteOptions{PropagationPolicy: &dp, Preconditions: &metav1.Preconditions{UID: &uid}}
	if immediate {
		grace := int64(0)
		opts.GracePeriodSeconds = &grace
	}
	return opts
}

func waitStatefulMarkerObservation(ctx context.Context, interval time.Duration) (time.Time, time.Time, error) {
	started := time.Now()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return started, time.Now(), ctx.Err()
	case <-timer.C:
		return started, time.Now(), nil
	}
}
