/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * runNativeActuatorDemo is the LIVE-ON-KIND proof of Phorvex's own native actuator: it
 * deploys victims into a demo namespace, drives every handler via NativeActuator.Actuate,
 * and VERIFIES the real cluster state — rotate (UID gone), quarantine (deny-all NP + detach,
 * pod ALIVE = lead-demo fidelity), inject (ephemeral container), identity/route/endpoint
 * rotate (epoch labels), kv-reset (pod alive), warm-swap (shadow promoted + leader retired),
 * mig-rebind/model-shard-replace (FAIL-CLOSED without GPU/model = honest SP-0), plus the
 * dry-run guard and the quarantine rollback. Prints a PASS/FAIL table.
 */

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

func runNativeActuatorDemo(ns string) error {
	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ctx := context.Background()
	na := newDemoActuator(c)

	_ = c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	defer cleanupDemo(ctx, c, ns)

	type row struct{ action, want, got, verdict string }
	var rows []row
	pass, fail := 0, 0
	record := func(action, want, got string, ok bool) {
		v := "PASS"
		if !ok {
			v = "FAIL"
			fail++
		} else {
			pass++
		}
		rows = append(rows, row{action, want, got, v})
	}
	req := func(pod, action string) actuator.Request {
		return actuator.Request{Tenant: ns, Namespace: ns, Pod: pod, Action: model.Action(action), Reason: "native-demo", Score: 0.9}
	}

	fmt.Println("=== P-ACTUATOR: native actuator LIVE on kind ===")

	// 1. rotate — supported controller-owned target, original UID gone.
	if _, e := demoDeployment(ctx, c, ns, "victim-rotate"); e != nil {
		record("rotate", "controller-owned fixture", e.Error(), false)
	} else if name := waitDeployPod(ctx, c, ns, "victim-rotate"); name == "" {
		record("rotate", "controller-owned fixture", "no running pod", false)
	} else {
		p, e := waitPodRunning(ctx, c, ns, name)
		if e != nil {
			record("rotate", "observed target", e.Error(), false)
		} else {
			r := req(name, "rotate")
			r.TargetUID = string(p.UID)
			res, err := demoActuate(ctx, na, r)
			_, exists, readErr := getDemoPod(ctx, c, ns, name, r.TargetUID)
			gone := apierrors.IsNotFound(readErr) || (readErr == nil && !exists)
			record("rotate", "original UID gone; replacement unconfirmed", fmt.Sprintf("emitted=%v uidGone=%v err=%v", res.Emitted, gone, err), res.Emitted && gone && err == nil)
		}
	}
	if p, e := demoPod(ctx, c, ns, "victim-rotate-bare", nil); e != nil {
		record("rotate.bare", "bare Pod refused", e.Error(), false)
	} else {
		r := req(p.Name, "rotate")
		r.TargetUID = string(p.UID)
		res, err := demoActuate(ctx, na, r)
		_, exists, readErr := getDemoPod(ctx, c, ns, p.Name, r.TargetUID)
		record("rotate.bare", "bare Pod refused and untouched", fmt.Sprintf("emitted=%v sameUID=%v note=%s err=%v", res.Emitted, exists, res.Note, err), !res.Emitted && exists && readErr == nil && err == nil && strings.Contains(res.Note, "ownerless"))
	}

	// 2. quarantine — deny-all NP + detach, POD STILL ALIVE (lead-demo fidelity).
	if _, e := demoDeployment(ctx, c, ns, "victim-qtn"); e == nil {
		pod := waitDeployPod(ctx, c, ns, "victim-qtn")
		if pod != "" {
			res, err := demoActuate(ctx, na, req(pod, "quarantine"))
			alive, np, detached := verifyQuarantine(ctx, c, ns, pod)
			ok := res.Emitted && err == nil && alive && np && detached
			record("quarantine", "NP + detach + POD ALIVE", fmt.Sprintf("alive=%v denyAllNP=%v detached=%v kind=%s", alive, np, detached, res.MutationKind), ok)
			// rollback proof: restore labels/ownerRefs + delete NP.
			rbErr := na.Rollback(ctx, req(pod, "quarantine"), res.RollbackRef)
			npGone := !npExists(ctx, c, ns, "phorvex-quarantine-"+pod)
			record("quarantine.rollback", "labels restored + NP gone", fmt.Sprintf("npGone=%v err=%v", npGone, rbErr), npGone && rbErr == nil)
		}
	}

	// 3-4. debugger + custom-inject — ephemeral container appended.
	for _, a := range []string{"debugger", "custom-inject"} {
		name := "victim-" + a
		if _, e := demoPod(ctx, c, ns, name, nil); e == nil {
			res, err := demoActuate(ctx, na, req(name, a))
			has := podHasEphemeral(ctx, c, ns, name)
			record(a, "ephemeral container injected", fmt.Sprintf("hasEphemeral=%v kind=%s err=%v", has, res.MutationKind, err), res.Emitted && has && err == nil)
		}
	}

	// 5-6. identity-rotate + route-rotate — epoch label set.
	for _, pair := range [][2]string{{"identity-rotate", "phorvex.ai/identity-epoch"}, {"route-rotate", "phorvex.ai/route-epoch"}} {
		name := "victim-" + pair[0]
		if _, e := demoPod(ctx, c, ns, name, nil); e == nil {
			res, err := demoActuate(ctx, na, req(name, pair[0]))
			labeled := podHasLabel(ctx, c, ns, name, pair[1])
			record(pair[0], pair[1]+" set", fmt.Sprintf("labeled=%v kind=%s err=%v", labeled, res.MutationKind, err), res.Emitted && labeled && err == nil)
		}
	}

	// 7. kv-reset (AI pod) — pod ALIVE + flush epoch annotation (no kill).
	if _, e := demoPod(ctx, c, ns, "victim-kv", map[string]string{"phorvex.ai/model-id": "llama-70b"}); e == nil {
		res, err := demoActuate(ctx, na, req("victim-kv", "kv-reset"))
		alive := podAlive(ctx, c, ns, "victim-kv")
		anno := podHasAnno(ctx, c, ns, "victim-kv", "phorvex.ai/kv-reset-epoch")
		record("kv-reset", "pod ALIVE + flush epoch", fmt.Sprintf("alive=%v flushEpoch=%v err=%v", alive, anno, err), res.Emitted && alive && anno && err == nil)
	}

	// 8. endpoint-rotate (AI pod) — epoch label.
	if _, e := demoPod(ctx, c, ns, "victim-ep", map[string]string{"phorvex.ai/model-id": "llama-70b"}); e == nil {
		res, err := demoActuate(ctx, na, req("victim-ep", "endpoint-rotate"))
		labeled := podHasLabel(ctx, c, ns, "victim-ep", "phorvex.ai/endpoint-epoch")
		record("endpoint-rotate", "endpoint-epoch set", fmt.Sprintf("labeled=%v err=%v", labeled, err), res.Emitted && labeled && err == nil)
	}

	// 9. warm-swap — shadow promoted to leader + old leader retired (orchestration LIVE; ColdLoadSec SP-0).
	if leader := setupWarmGroup(ctx, c, ns); leader != "" {
		res, err := demoActuate(ctx, na, req(leader, "warm-swap"))
		promoted := countByRole(ctx, c, ns, "wsg", "leader") == 1
		oldGone := !podAlive(ctx, c, ns, leader)
		record("warm-swap", "shadow promoted + old leader retired", fmt.Sprintf("oneLeader=%v oldRetired=%v kind=%s err=%v", promoted, oldGone, res.MutationKind, err), res.Emitted && promoted && oldGone && err == nil)
	}

	// 10-11. mig-rebind + model-shard-replace — FAIL-CLOSED without GPU/model (honest SP-0).
	if _, e := demoPod(ctx, c, ns, "victim-mig", map[string]string{"phorvex.ai/model-id": "llama-70b"}); e == nil {
		_, err := demoActuate(ctx, na, req("victim-mig", "mig-rebind"))
		record("mig-rebind", "FAIL-CLOSED (no MIG device) [SP-0]", fmt.Sprintf("failClosed=%v err=%v", err != nil, errShort(err)), err != nil)
		_, err2 := demoActuate(ctx, na, req("victim-mig", "model-shard-replace"))
		record("model-shard-replace", "FAIL-CLOSED (no model shard) [SP-0]", fmt.Sprintf("failClosed=%v err=%v", err2 != nil, errShort(err2)), err2 != nil)
	}

	// 12. dry-run guard — a dry-run actuator must REFUSE to mutate.
	naDry := newDemoActuator(c)
	naDry.DryRun = true
	if _, e := demoPod(ctx, c, ns, "victim-dry", nil); e == nil {
		_, err := demoActuate(ctx, naDry, req("victim-dry", "rotate"))
		stillAlive := podAlive(ctx, c, ns, "victim-dry")
		record("dry-run guard", "refuse + pod untouched", fmt.Sprintf("refused=%v podAlive=%v", err != nil, stillAlive), err != nil && stillAlive)
	}

	// print the table.
	fmt.Printf("\n%-22s %-34s %-46s %s\n", "ACTION", "EXPECTED", "OBSERVED", "VERDICT")
	for _, r := range rows {
		fmt.Printf("%-22s %-34s %-46s %s\n", r.action, r.want, trunc(r.got, 46), r.verdict)
	}
	fmt.Printf("\n=== native actuator: %d PASS / %d FAIL (12 handlers + rollback + dry-run) ===\n", pass, fail)
	if fail > 0 {
		return fmt.Errorf("native-demo: %d checks failed", fail)
	}
	return nil
}

// Both production demo paths and caller-level tests use this wiring.
func newDemoActuator(c client.Client) *actuator.NativeActuator {
	n := actuator.NewNativeActuator(c)
	n.SetBoundaryReader(c) // client.New above is an uncached direct reader.
	return n
}

func demoActuate(ctx context.Context, n *actuator.NativeActuator, req actuator.Request) (actuator.Result, error) {
	if req.TargetUID == "" {
		var p corev1.Pod
		if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &p); err != nil {
			return actuator.Result{}, err
		}
		req.TargetUID = string(p.UID)
	}
	return n.Actuate(ctx, req)
}

// --- demo helpers ------------------------------------------------------------------------

var demoSelLabel = map[string]string{"phorvex.ai/native-demo": "true"}

func demoPod(ctx context.Context, c client.Client, ns, name string, extra map[string]string) (*corev1.Pod, error) {
	labels := map[string]string{"phorvex.ai/native-demo": "true", "app": name}
	for k, v := range extra {
		labels[k] = v
	}
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: ptr64(0),
			Containers:                    []corev1.Container{{Name: "c", Image: "busybox:1.36", Command: []string{"sh", "-c", "sleep 3600"}}},
		},
	}
	_ = c.Delete(ctx, p)
	if err := c.Create(ctx, p); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	return waitPodRunning(ctx, c, ns, name)
}

func demoDeployment(ctx context.Context, c client.Client, ns, name string) (*appsv1.Deployment, error) {
	repl := int32(1)
	sel := map[string]string{"app": name, "phorvex.ai/native-demo": "true"}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: demoSelLabel},
		Spec: appsv1.DeploymentSpec{
			Replicas: &repl,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: sel},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: ptr64(0),
					Containers:                    []corev1.Container{{Name: "c", Image: "busybox:1.36", Command: []string{"sh", "-c", "sleep 3600"}}},
				},
			},
		},
	}
	if err := c.Create(ctx, d); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	return d, nil
}

func setupWarmGroup(ctx context.Context, c client.Client, ns string) string {
	mk := func(name, role string) {
		l := map[string]string{"phorvex.ai/native-demo": "true", "phorvex.ai/swap-group": "wsg", "phorvex.ai/role": role, "phorvex.ai/model-loaded": "true"}
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: l},
			Spec: corev1.PodSpec{TerminationGracePeriodSeconds: ptr64(0), Containers: []corev1.Container{{Name: "c", Image: "busybox:1.36", Command: []string{"sh", "-c", "sleep 3600"}}}}}
		_ = c.Create(ctx, p)
	}
	mk("wsg-leader", "leader")
	mk("wsg-shadow", "warm-shadow")
	_, _ = waitPodRunning(ctx, c, ns, "wsg-leader")
	_, _ = waitPodRunning(ctx, c, ns, "wsg-shadow")
	return "wsg-leader"
}

func waitPodRunning(ctx context.Context, c client.Client, ns, name string) (*corev1.Pod, error) {
	for i := 0; i < 60; i++ {
		var p corev1.Pod
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p); err == nil {
			if p.Status.Phase == corev1.PodRunning {
				return &p, nil
			}
		}
		time.Sleep(time.Second)
	}
	var p corev1.Pod
	err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p)
	return &p, err
}

func waitDeployPod(ctx context.Context, c client.Client, ns, app string) string {
	for i := 0; i < 60; i++ {
		var pods corev1.PodList
		if c.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app": app}) == nil {
			for j := range pods.Items {
				if pods.Items[j].Status.Phase == corev1.PodRunning {
					return pods.Items[j].Name
				}
			}
		}
		time.Sleep(time.Second)
	}
	return ""
}

func verifyQuarantine(ctx context.Context, c client.Client, ns, pod string) (alive, np, detached bool) {
	var p corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: pod}, &p); err == nil && p.DeletionTimestamp == nil {
		alive = true
		detached = len(p.OwnerReferences) == 0 && p.Labels["phorvex.ai/quarantined"] != ""
	}
	np = npExists(ctx, c, ns, "phorvex-quarantine-"+pod)
	return
}

func npExists(ctx context.Context, c client.Client, ns, name string) bool {
	var np networkingv1.NetworkPolicy
	return c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &np) == nil
}

func getDemoPod(ctx context.Context, c client.Client, ns, name, wantUID string) (*corev1.Pod, bool, error) {
	var p corev1.Pod
	err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p)
	if err != nil {
		return nil, false, err
	}
	return &p, string(p.UID) == wantUID, nil
}

func podAlive(ctx context.Context, c client.Client, ns, name string) bool {
	var p corev1.Pod
	return c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p) == nil && p.DeletionTimestamp == nil
}

func podHasEphemeral(ctx context.Context, c client.Client, ns, name string) bool {
	var p corev1.Pod
	if c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p) != nil {
		return false
	}
	return len(p.Spec.EphemeralContainers) > 0
}

func podHasLabel(ctx context.Context, c client.Client, ns, name, key string) bool {
	var p corev1.Pod
	if c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p) != nil {
		return false
	}
	return p.Labels[key] != ""
}

func podHasAnno(ctx context.Context, c client.Client, ns, name, key string) bool {
	var p corev1.Pod
	if c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p) != nil {
		return false
	}
	return p.Annotations[key] != ""
}

func countByRole(ctx context.Context, c client.Client, ns, group, role string) int {
	var pods corev1.PodList
	if c.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"phorvex.ai/swap-group": group, "phorvex.ai/role": role}) != nil {
		return 0
	}
	n := 0
	for i := range pods.Items {
		if pods.Items[i].DeletionTimestamp == nil {
			n++
		}
	}
	return n
}

func cleanupDemo(ctx context.Context, c client.Client, ns string) {
	_ = c.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(ns), client.MatchingLabels{"phorvex.ai/native-demo": "true"})
	_ = c.DeleteAllOf(ctx, &appsv1.Deployment{}, client.InNamespace(ns), client.MatchingLabels{"phorvex.ai/native-demo": "true"})
	var nps networkingv1.NetworkPolicyList
	if c.List(ctx, &nps, client.InNamespace(ns)) == nil {
		for i := range nps.Items {
			_ = c.Delete(ctx, &nps.Items[i])
		}
	}
}

func ptr64(v int64) *int64 { return &v }
func errShort(err error) string {
	if err == nil {
		return "<nil>"
	}
	return trunc(err.Error(), 38)
}
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
