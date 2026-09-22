// Package defenders contains the self-registering Defender plugins. Each defender
// is ONE file with a func init(){ core.RegisterDefender(...) }. Adding a future
// defender (e.g. Phorvex) is one new file + one register call, ZERO core changes.
package defenders

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// rotationTargetSelector is the label that marks the workload a rotation arm
// targets. Scenarios stamp their primary target pod with this so the timer
// defenders know what to rotate (mirrors an AMTD PodSelector).
const RotationTargetLabel = "r6th.io/rotation-target"

// timerEngine is the shared blind/random rotation engine used by d-r6blindtimer
// and d-randomequal. It deletes pods carrying the rotation-target label on a
// schedule, modeling a TimeBasedTrigger that caps dwell but cannot target on
// demand. It records each rotation timestamp so the runner can read defensive
// actions, compute time-to-action, and feed the adaptive learner.
type timerEngine struct {
	mu        sync.Mutex
	running   bool
	stop      chan struct{}
	rotations []float64 // unix seconds of each rotation performed
	// nextDelay returns the wait before the next rotation; this is what differs
	// between the blind (fixed) and random (memoryless) arms.
	nextDelay func() time.Duration
	wg        sync.WaitGroup
}

// startEngine launches the rotation goroutine for one trial.
func (t *timerEngine) startEngine(ctx context.Context, env *core.Env) {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.stop = make(chan struct{})
	t.rotations = nil
	t.mu.Unlock()

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			d := t.nextDelay()
			select {
			case <-t.stop:
				return
			case <-ctx.Done():
				return
			case <-time.After(d):
				t.rotateOnce(ctx, env)
			}
		}
	}()
}

// rotateOnce deletes every rotation-target pod (going through the safety guard)
// and records the timestamp.
func (t *timerEngine) rotateOnce(ctx context.Context, env *core.Env) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		env.Log.Logf("rotation refused by guard: %v", err)
		return
	}
	sel := RotationTargetLabel + "=true"
	lo := metav1.ListOptions{LabelSelector: sel}
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, lo)
	if err != nil {
		env.Log.Logf("rotation list error: %v", err)
		return
	}
	now := float64(time.Now().Unix())
	rotated := 0
	grace := int64(0)
	for i := range pods.Items {
		p := pods.Items[i]
		if p.DeletionTimestamp != nil {
			continue
		}
		env.Log.Command("kubectl delete pod " + p.Name + " -n " + env.Config.Namespace + " --grace-period=0  # rotation")
		err := env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{GracePeriodSeconds: &grace})
		if err != nil && !apierrors.IsNotFound(err) {
			env.Log.Logf("rotation delete %s error: %v", p.Name, err)
			continue
		}
		rotated++
		// If the pod was managed by a deployment it will be recreated; if it was a
		// bare pod, recreate a replacement so the workload "rotates" rather than
		// disappears (new identity = the MTD effect).
		t.recreateReplacement(ctx, env, &p)
	}
	if rotated > 0 {
		t.mu.Lock()
		t.rotations = append(t.rotations, now)
		t.mu.Unlock()
		env.Log.Logf("rotation fired: deleted %d target pod(s) at %.0f", rotated, now)
	}
}

// recreateReplacement re-creates a bare target pod with a fresh name+identity so
// the workload persists across the rotation (the genuine MTD behavior: same role,
// new identity). Deployment-managed pods are left to their controller.
func (t *timerEngine) recreateReplacement(ctx context.Context, env *core.Env, old *corev1.Pod) {
	for _, or := range old.OwnerReferences {
		if or.Controller != nil && *or.Controller {
			return // managed; controller will replace it
		}
	}
	repl := old.DeepCopy()
	repl.ObjectMeta = metav1.ObjectMeta{
		Name:      rotatedName(old.Name),
		Namespace: old.Namespace,
		Labels:    old.Labels,
	}
	repl.Status = corev1.PodStatus{}
	repl.Spec.NodeName = ""
	env.Log.Command("kubectl run " + repl.Name + " -n " + env.Config.Namespace + "  # rotation replacement (fresh identity)")
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, repl, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		env.Log.Logf("rotation replacement create error: %v", err)
	}
}

// rotatedName produces a deterministic-ish new name for the replacement pod.
func rotatedName(old string) string {
	suffix := time.Now().UnixNano() % 100000
	base := old
	if len(base) > 50 {
		base = base[:50]
	}
	return base + "-r" + itoa(suffix)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// stopEngine halts the rotation goroutine and waits for it to drain.
func (t *timerEngine) stopEngine() {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}
	t.running = false
	close(t.stop)
	t.mu.Unlock()
	t.wg.Wait()
}

// actions returns the recorded rotation timestamps (defensive actions).
func (t *timerEngine) actions() []float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]float64, len(t.rotations))
	copy(out, t.rotations)
	return out
}

func (t *timerEngine) recordAction(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rotations = append(t.rotations, float64(at.UnixNano())/float64(time.Second))
}
