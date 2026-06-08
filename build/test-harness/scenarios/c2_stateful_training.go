package scenarios

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c2StatefulTraining{}) }

// c2StatefulTraining is the LEAD DEMO + the FEASIBILITY dimension: a long-running
// STATEFUL training job (a PVC-backed pod doing in-progress work) is compromised. The
// defense must evict the foothold WITHOUT destroying the running job.
//
//   - blind timer / full-Phoenix: their only move is DELETE (rotate) — which on a
//     stateful pod is PHYSICALLY INFEASIBLE in the sense that it DESTROYS the running
//     work (the in-memory training state dies). They "disrupt" the foothold but cause
//     HARM (stateful-destroyed).
//   - PX: its action-set generator marks rotate INFEASIBLE on a stateful pod
//     (stateful-integrity hard constraint) and finds the FEASIBLE ALTERNATIVE —
//     QUARANTINE (deny-all + detach) — which contains the foothold while the job keeps
//     running. Work preserved, harm = 0.
//
// R6 has no feasibility model and cannot score this. ORACLE (attacker wins) = the
// foothold is alive AND can still act (pod running, not quarantined). The report's
// harm / feasible-alternative / work-preserved columns are the headline.
type c2StatefulTraining struct {
	app    string
	pvc    string
	oldUID string
}

func (s *c2StatefulTraining) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-stateful-training",
		Category:           core.CategoryR6Claimed,
		Source:             "P3 LEAD DEMO; PRD §5.1A feasibility / 'critical stateful workload'; R6 pain point #3/#4",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1543.005", "T1486", "T1496"},
		R6Justification:    "A blind Delete evicts the foothold but DESTROYS the running stateful job (R6 pain point #3: can't handle critical stateful workloads; #4: prescribed action physically infeasible). PX's feasibility model excludes rotate on a stateful pod and quarantines instead — work preserved. R6 has no feasibility model; partial.",
	}
}

func (s *c2StatefulTraining) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2st-train"
	s.pvc = s.app + "-work"
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	// A PVC so the pod is STATEFUL in the defender's eyes (PX's stateful-integrity
	// constraint keys on a PVC-mounting / StatefulSet pod).
	waitPodGone(ctx, env, s.app)
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: s.pvc, Namespace: ns, Labels: env.OwnedLabels(nil)},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("50Mi")}},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl create pvc %s --size=50Mi -n %s  # training checkpoint volume", s.pvc, ns))
	if _, err := env.Kube.CoreV1().PersistentVolumeClaims(ns).Create(ctx, pvc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	labels := mocks.LabelMap(map[string]string{defenders.RotationTargetLabel: "true", "app": s.app, "tier": "training", "data-class": "restricted"}, nil)
	pod := mocks.NewPod(env, s.app, labels).
		WithBusyboxLoop("trainer", []string{"sh", "-c", "echo START > /work/checkpoint; i=0; while true; do i=$((i+1)); echo step=$i > /work/checkpoint; sleep 2; done"}, 100, 64).
		WithVolume(
			corev1.Volume{Name: "work", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: s.pvc}}},
			corev1.VolumeMount{Name: "work", MountPath: "/work"}).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s -n %s --mount pvc=%s  # stateful training job (in-progress work)", s.app, ns, s.pvc))
	if _, err := env.Kube.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	running, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return err
	}
	s.oldUID = string(running.UID)
	return nil
}

func (s *c2StatefulTraining) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.oldUID = string(pod.UID)
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	stages := []string{
		"compromise the long-running stateful training job (T1543.005)",
		"the defense must evict WITHOUT destroying the in-progress work (feasibility test)",
	}
	// If the active defender supports the reactive emitter, drive its genuine path too
	// (so full-Phoenix/reactive-only get a fair shot — they will DELETE, destroying work).
	if em, ok := emitterFromEnv(env); ok {
		if err := em.EmitSecurityEvent(ctx, env, pod.Name, amtdv1beta1.TypePanic, amtdv1beta1.ThreatLevelHigh); err == nil {
			cmds = append(cmds, "emit SecurityEvent{panic,high} -> matcher -> Delete (destroys the stateful job)")
		}
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *c2StatefulTraining) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Give the defense its window to act on the high-risk stateful pod.
	survival, stillAlive := measureSurvival(ctx, env, s.app, 20*time.Second)

	// Did the defense CHOOSE the work-preserving feasible alternative (quarantine), or
	// the destructive Delete? PX's feasibility model excludes rotate on a stateful pod
	// and emits a phorvex.quarantine; blind/full-Phoenix Delete. We key on the ACTION
	// CHOSEN (the feasibility IP) — robust to Phoenix's bare-pod quarantine nuance.
	quarantineChosen := phorvexQuarantineEmitted(ctx, env) || namespaceHasNetworkPolicy(ctx, env)
	origRunning := false
	if cur, err := runningPodByApp(ctx, env, s.app); err == nil && string(cur.UID) == s.oldUID {
		origRunning = true
	}
	workPreserved := quarantineChosen || origRunning

	// Attacker wins iff the foothold is alive AND can still act (pod intact, NOT
	// quarantined/contained). A quarantine contains it; a Delete destroys the work.
	achieved := stillAlive && !quarantineChosen && origRunning

	armAction := "none"
	harm := "none"
	infeasibleRotate := false
	if quarantineChosen {
		armAction = "quarantine" // feasible alternative found — work-preserving
	} else if !origRunning {
		armAction = "delete"
		harm = "stateful-destroyed" // the defense killed the running training job
		infeasibleRotate = true     // rotate on a stateful pod is the infeasible/harmful move
	}

	ev := map[string]string{
		"workPreserved":        fmt.Sprintf("%v", workPreserved),
		"quarantined":          fmt.Sprintf("%v", quarantineChosen),
		"armAction":            armAction,
		core.EvReactionSeconds: fmt.Sprintf("%.1f", survival),
	}
	state := fmt.Sprintf("stateful training job: foothold-alive=%v %s [work-preserved=%v] [harm=%s] [arm-action=%s] [infeasible-rotate=%v] [feasible-alt=%v] [lead-demo=true]",
		stillAlive, survivalMarker(survival, stillAlive), workPreserved, harm, armAction, infeasibleRotate, quarantineChosen)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c2StatefulTraining) Teardown(ctx context.Context, env *core.Env) error {
	_ = teardownByApp(ctx, env, s.app)
	// Best-effort PVC cleanup (idempotent).
	if env.Kube != nil && s.pvc != "" {
		_ = env.Kube.CoreV1().PersistentVolumeClaims(env.Config.Namespace).Delete(ctx, s.pvc, metav1.DeleteOptions{})
	}
	return nil
}

// phorvexQuarantineEmitted reports whether PX emitted a phorvex.quarantine
// SecurityEvent (its feasible, work-preserving alternative to a destructive Delete on
// a stateful pod). This is the direct signal that PX's feasibility model chose to
// CONTAIN rather than destroy — the IP R6 cannot produce.
func phorvexQuarantineEmitted(ctx context.Context, env *core.Env) bool {
	if env.Ctrl == nil {
		return false
	}
	var list amtdv1beta1.SecurityEventList
	if err := env.Ctrl.List(ctx, &list); err != nil {
		return false
	}
	for i := range list.Items {
		if list.Items[i].Spec.Rule.Type == "phorvex.quarantine" {
			return true
		}
	}
	return false
}

// namespaceHasNetworkPolicy reports whether any NetworkPolicy exists in the sandbox —
// the harness creates none, so its presence means a defender QUARANTINED (Phoenix's
// quarantine action applies a deny-all NetworkPolicy).
func namespaceHasNetworkPolicy(ctx context.Context, env *core.Env) bool {
	if env.Ctrl == nil {
		return false
	}
	nps, err := env.Kube.NetworkingV1().NetworkPolicies(env.Config.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false
	}
	return len(nps.Items) > 0
}
