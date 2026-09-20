package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func init() { core.RegisterScenario(&c2DwellRotation{}) }

// DwellOracleSeconds is the window the marker process tries to out-dwell. The
// marker succeeds only if it remains in the same Pod identity for this long.
const DwellOracleSeconds = 8.0

// c2DwellRotation measures only the lifetime of a bounded marker and sleeper
// process inside one Pod. It is not an exploit or malware simulation. The
// attacker oracle succeeds only while the original Pod identity and its marker
// both remain observable after the dwell window.
type c2DwellRotation struct {
	app        string
	targetName string
	targetUID  types.UID
	plantedAt  time.Time
}

func (s *c2DwellRotation) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-dwell-rotation",
		Category:           core.CategoryR6Claimed,
		Source:             "Cat2; Phoenix-K8s DWELL_TIME 0ms; AMTD-AI-infra 150d->60min; ADA Abstract",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1543.005", "T1525", "T1133", "T1078.003"},
		Realism:            core.RealismMarkerSimulation,
		Mechanism:          "deploy one BusyBox Pod, exec a bounded marker plus sleeper process, then observe the original Pod UID and marker after a fixed window",
		ClaimLimits:        "does not execute an exploit, RCE, runc overwrite, malware, external access, or natural detection; declared ATT&CK mappings are narrative context and no technique is credited as exercised",
		OracleDescription:  "the original Pod UID and its exact in-container marker both remain observable after the bounded dwell window; replacement identity and marker presence are reported separately",
		CleanupDescription: "delete Pods owned by the scenario app label",
		R6Justification:    "A rotation can bound the lifetime of this exact ephemeral marker and sleeper process. Covers only that narrow Pod-state property; it does not establish exploit prevention or malware removal.",
	}
}

func (s *c2DwellRotation) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2dr-target"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c2DwellRotation) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Scenario objects are reused across trials. Clear prior provenance before
	// this attempt so a failed lookup or plant cannot inherit an earlier UID/time.
	s.targetUID = ""
	s.targetName = ""
	s.plantedAt = time.Time{}
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.targetName, s.targetUID = pod.Name, pod.UID
	cmds, err := plantBackdoorObserved(ctx, env, pod.Name, firstContainer(pod))
	if err != nil {
		return core.AttackResult{Stages: []string{"plant bounded in-container marker and sleeper"}, Commands: cmds}, err
	}
	s.plantedAt = time.Now()
	stages := []string{"plant bounded in-container marker and sleeper", "observe ephemeral state across the dwell window"}
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: map[string]string{
		"originalPod":    s.targetName,
		"originalPodUID": string(s.targetUID),
		"plantedAt":      s.plantedAt.UTC().Format(time.RFC3339Nano),
		"realism":        string(core.RealismMarkerSimulation),
	}}, nil
}

func (s *c2DwellRotation) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	if s.targetName == "" || s.targetUID == "" || s.plantedAt.IsZero() {
		return core.OracleResult{}, fmt.Errorf("marker stimulus identity or start time missing")
	}
	observationPause(time.Duration(DwellOracleSeconds) * time.Second)
	if err := ctx.Err(); err != nil {
		return core.OracleResult{}, fmt.Errorf("dwell observation cancelled: %w", err)
	}
	pod, originalAbsent, err := c2DwellObservationTarget(ctx, env, s.app, s.targetName, s.targetUID)
	if err != nil {
		return core.OracleResult{}, err
	}
	markerPresent, err := observedMarker(ctx, env.Exec(ctx, pod.Name, firstContainer(pod), markerReadCommand(BackdoorMarkerPath)), BackdoorMarker)
	if err != nil {
		return core.OracleResult{}, err
	}
	measuredDwell := time.Since(s.plantedAt).Seconds()
	originalIdentity := pod.UID == s.targetUID
	alive := originalIdentity && markerPresent
	ev := map[string]string{
		"aliveAfterWindow":  fmt.Sprintf("%v", alive),
		"markerPresent":     fmt.Sprintf("%v", markerPresent),
		"originalIdentity":  fmt.Sprintf("%v", originalIdentity),
		"originalUIDAbsent": fmt.Sprintf("%v", originalAbsent),
		"measuredDwellSec":  fmt.Sprintf("%.3f", measuredDwell),
		"dwellWindowSec":    fmt.Sprintf("%.0f", DwellOracleSeconds),
		"observedPod":       pod.Name,
		"originalPodUID":    string(s.targetUID),
		"observedPodUID":    string(pod.UID),
		"realism":           string(core.RealismMarkerSimulation),
	}
	state := fmt.Sprintf("marker simulation: original Pod UID retained=%v and marker present=%v after %.3fs (window %.0fs)", originalIdentity, markerPresent, measuredDwell, DwellOracleSeconds)
	return core.OracleResult{Achieved: alive, ObservedState: state, Evidence: ev}, nil
}

// c2DwellObservationTarget resolves the post-window identity without allowing
// list order to turn a replacement into evidence that the original disappeared.
// If the original UID is in the complete app-labelled list, it is always the
// observation target, including while terminating. A replacement is returned
// only after a successful list proves the original UID absent. Multiple or zero
// running replacements are ambiguous and remain observation errors.
func c2DwellObservationTarget(ctx context.Context, env *core.Env, app, originalName string, originalUID types.UID) (*corev1.Pod, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("dwell target observation cancelled: %w", err)
	}
	if originalName == "" || originalUID == "" {
		return nil, false, fmt.Errorf("dwell target original identity missing for app=%s", app)
	}
	original, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, originalName, metav1.GetOptions{})
	if err == nil && original.UID == originalUID {
		return original, false, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, false, fmt.Errorf("dwell target original get failed for pod=%s: %w", originalName, err)
	}
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + app})
	if err != nil {
		return nil, false, fmt.Errorf("dwell target list failed for app=%s: %w", app, err)
	}
	var replacements []*corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.UID == originalUID {
			return pod, false, nil
		}
		if pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning {
			replacements = append(replacements, pod)
		}
	}
	if len(replacements) != 1 {
		return nil, true, fmt.Errorf("dwell target original UID %s absent for app=%s, running replacements=%d", originalUID, app, len(replacements))
	}
	if replacements[0].UID == "" {
		return nil, true, fmt.Errorf("dwell target replacement UID missing for app=%s", app)
	}
	return replacements[0], true, nil
}

func (s *c2DwellRotation) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
