package defenders

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterDefender(&reactiveOnly{}) }

// reactiveOnly is the REACTIVE-ONLY arm: genuine extended Phoenix with ONLY the
// reactive exact-match strategies ({panic|policy-violation,high,emitter} -> Delete)
// and NO scheduled/proactive timer. It acts iff a detector (the harness emitter
// stand-in) raises a matching SecurityEvent — so against a stealth dweller or a
// held-out-CVE zero-day (which emit NOTHING) it does nothing. This isolates the
// thesis test (H3): a detector-evading attack that PX's detection-INDEPENDENT
// proactive floor evicts but reactive-only cannot touch.
type reactiveOnly struct {
	mu       sync.Mutex
	proc     *exec.Cmd
	logFile  *os.File
	pin      string
	amtdName string
	actions  []float64
	skip     bool
	skipMsg  string
}

func (r *reactiveOnly) Metadata() core.DefenderMeta {
	return core.DefenderMeta{
		Name:        "d-reactive-only",
		Description: "ReactiveOnly: genuine extended Phoenix with ONLY the reactive matcher (emitter {panic|policy-violation,high} -> Delete) and NO proactive/scheduled timer. Acts solely on a detection event; does nothing when the detector is silent (the thesis baseline for H3).",
		// No proactive cadence: this arm rotates 0 times absent a detection event.
		MeanRotationIntervalSeconds: 0,
	}
}

func (r *reactiveOnly) Setup(ctx context.Context, env *core.Env) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skip, r.skipMsg, r.actions = false, "", nil

	src := env.Config.PhoenixSrcDir
	if src == "" {
		r.skip, r.skipMsg = true, "phoenixSrcDir not configured — ReactiveOnly arm skips-with-note"
		return nil
	}
	abs, err := filepath.Abs(src)
	if err != nil {
		r.skip, r.skipMsg = true, "cannot resolve phoenixSrcDir: "+err.Error()
		return nil
	}
	if _, msg := buildPhoenixOperator(ctx, env, abs); msg != "" {
		r.skip, r.skipMsg = true, msg
		return nil
	}
	if msg := installPhoenixCRDs(ctx, env, abs); msg != "" {
		r.skip, r.skipMsg = true, msg
		return nil
	}
	if err := r.applyReactiveAMTD(ctx, env); err != nil {
		r.skip, r.skipMsg = true, "apply reactive AMTD failed: "+err.Error()
		return nil
	}
	return nil
}

// applyReactiveAMTD applies an AMTD with ONLY the reactive delete strategies — no
// {timed,TimeBasedTrigger}->Rotate (that is the difference from FullPhoenix).
func (r *reactiveOnly) applyReactiveAMTD(ctx context.Context, env *core.Env) error {
	if env.Ctrl == nil {
		return fmt.Errorf("no controller-runtime client")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	r.amtdName = "harness-amtd-reactive"
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: r.amtdName, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(nil)},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{RotationTargetLabel: "true"},
			MatcherMode: amtdv1beta1.MatcherModeExact,
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule:   amtdv1beta1.Rule{Type: amtdv1beta1.TypePanic, Source: EmitterSource, ThreatLevel: amtdv1beta1.ThreatLevelHigh},
					Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
				},
				{
					Rule:   amtdv1beta1.Rule{Type: amtdv1beta1.TypePolicyViolation, Source: EmitterSource, ThreatLevel: amtdv1beta1.ThreatLevelHigh},
					Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
				},
			},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl apply AdaptiveMovingTargetDefense/%s -n %s (REACTIVE ONLY: panic->Delete, policy-violation->Delete; NO timed rotate)", r.amtdName, env.Config.Namespace))
	if err := env.Ctrl.Create(ctx, amtd); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (r *reactiveOnly) Start(ctx context.Context, env *core.Env) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.skip {
		return nil
	}
	abs, _ := filepath.Abs(env.Config.PhoenixSrcDir)
	bin := filepath.Join(abs, "bin", managerBinName())
	cmd, lf, pin, err := startPinnedProc(ctx, env, bin, abs, []string{"--leader-elect=false"}, "operator", "reactive-phoenix")
	if err != nil {
		r.skip, r.skipMsg = true, "operator start failed: "+err.Error()
		return nil
	}
	r.proc, r.logFile, r.pin = cmd, lf, pin
	time.Sleep(2 * time.Second)
	return nil
}

// EmitSecurityEvent implements the scenarios' Emitter capability: a scenario that
// models a detection event drives the reactive matcher through this. A scenario that
// emits NOTHING (stealth dweller / held-out-CVE) leaves this arm inert — by design.
func (r *reactiveOnly) EmitSecurityEvent(ctx context.Context, env *core.Env, targetPod, eventType, threatLevel string) error {
	r.mu.Lock()
	skip := r.skip
	r.mu.Unlock()
	if skip || env.Ctrl == nil {
		return fmt.Errorf("reactive-only not active")
	}
	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "harness-evt-", Labels: env.OwnedLabels(nil)},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{env.Config.Namespace + "/" + targetPod},
			Description: "harness-emitted normalized event (reactive-only arm)",
			Rule:        amtdv1beta1.Rule{Type: eventType, ThreatLevel: threatLevel, Source: EmitterSource},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl create SecurityEvent {type:%s,level:%s,source:%s} targets %s/%s", eventType, threatLevel, EmitterSource, env.Config.Namespace, targetPod))
	if err := env.Ctrl.Create(ctx, ev); err != nil {
		return err
	}
	r.mu.Lock()
	r.actions = append(r.actions, float64(time.Now().Unix()))
	r.mu.Unlock()
	return nil
}

func (r *reactiveOnly) Stop(ctx context.Context, env *core.Env) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	killProc(&r.proc)
	forceKillOperators(ctx)
	closeFile(&r.logFile)
	removeFile(&r.pin)
	return nil
}

func (r *reactiveOnly) Teardown(ctx context.Context, env *core.Env) error {
	_ = r.Stop(ctx, env)
	r.mu.Lock()
	defer r.mu.Unlock()
	if env.Ctrl != nil && r.amtdName != "" {
		amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{ObjectMeta: metav1.ObjectMeta{Name: r.amtdName, Namespace: env.Config.Namespace}}
		env.Log.Command(fmt.Sprintf("kubectl delete AdaptiveMovingTargetDefense/%s -n %s", r.amtdName, env.Config.Namespace))
		_ = env.Ctrl.Delete(ctx, amtd, &client.DeleteOptions{})
	}
	sweepOwnedSecurityEvents(ctx, env)
	sweepNamespaceNetworkPolicies(ctx, env)
	return nil
}

func (r *reactiveOnly) DefensiveActions(ctx context.Context, env *core.Env) (int, []float64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]float64, len(r.actions))
	copy(out, r.actions)
	return len(out), out, nil
}

func (r *reactiveOnly) SkipReason() (bool, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.skip, r.skipMsg
}
