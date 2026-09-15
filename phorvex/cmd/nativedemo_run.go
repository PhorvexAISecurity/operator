package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type demoVerdict string

const (
	demoConfirmed          demoVerdict = "CONFIRMED"
	demoRefused            demoVerdict = "REFUSED"
	demoUnavailable        demoVerdict = "UNAVAILABLE"
	demoSetupFailure       demoVerdict = "SETUP-FAIL"
	demoObservationFailure demoVerdict = "OBSERVE-FAIL"
	demoCleanupFailure     demoVerdict = "CLEANUP-FAIL"
)

type demoRow struct {
	action, expected, observed string
	verdict                    demoVerdict
}

type demoReport struct{ rows []demoRow }

func (r *demoReport) add(action, expected, observed string, verdict demoVerdict) {
	r.rows = append(r.rows, demoRow{action, expected, observed, verdict})
}

func (r *demoReport) write(w io.Writer) error {
	counts := map[demoVerdict]int{}
	fmt.Fprintf(w, "\n%-24s %-16s %s\n", "ACTION", "VERDICT", "EXPECTED")
	for _, row := range r.rows {
		counts[row.verdict]++
		fmt.Fprintf(w, "%-24s %-16s %s\n    observed: %s\n", row.action, row.verdict, row.expected, row.observed)
	}
	fmt.Fprintf(w, "\n=== native actuator: %d confirmed / %d refused / %d unavailable / %d setup failures / %d observation failures / %d cleanup failures ===\n", counts[demoConfirmed], counts[demoRefused], counts[demoUnavailable], counts[demoSetupFailure], counts[demoObservationFailure], counts[demoCleanupFailure])
	if bad := counts[demoSetupFailure] + counts[demoObservationFailure] + counts[demoCleanupFailure]; bad > 0 {
		return fmt.Errorf("native-demo: %d failed checks", bad)
	}
	if counts[demoUnavailable] > 0 {
		return fmt.Errorf("native-demo: %d capabilities unavailable", counts[demoUnavailable])
	}
	return nil
}

// Acknowledged Create responses are the only authority to clean a demo object.
// A name collision is never adopted, even if it carries a previous demo label.
type demoOwned struct {
	object        client.Object
	uid           types.UID
	parent        types.UID // non-token objects are bound to an acknowledged child UID
	receiptPolicy types.UID
}
type demoRun struct {
	client    client.Client
	owned     []demoOwned
	token     string
	namespace string
}

type demoTrackingClient struct {
	client.Client
	run *demoRun
}
type demoReceiptBinding struct {
	PolicyUID       string `json:"policyUID"`
	TargetUID       string `json:"targetUID"`
	PolicyName      string `json:"policyName"`
	PolicyNamespace string `json:"policyNamespace"`
}

func (d *demoRun) ownsUID(uid string) bool {
	if uid == "" {
		return false
	}
	for _, item := range d.owned {
		if string(item.uid) == uid {
			return true
		}
	}
	return false
}

func (t *demoTrackingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := t.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	if obj.GetUID() == "" {
		return fmt.Errorf("actuator-created %s/%s acknowledged without UID", obj.GetNamespace(), obj.GetName())
	}
	owned := obj.GetLabels()["phorvex.ai/native-demo-run"] == t.run.token
	var parent types.UID
	var receiptPolicy types.UID
	if !owned {
		for _, ref := range obj.GetOwnerReferences() {
			for _, item := range t.run.owned {
				if ref.UID == item.uid {
					owned = true
					parent = ref.UID
					break
				}
			}
		}
	}
	if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Labels["phorvex.ai/operation-journal"] == "v1" {
		var binding demoReceiptBinding
		if json.Unmarshal([]byte(cm.Data["receipt"]), &binding) == nil && t.run.ownsUID(binding.PolicyUID) && t.run.ownsUID(binding.TargetUID) && binding.PolicyNamespace != "" && cm.Namespace != binding.PolicyNamespace {
			owned = true
			receiptPolicy = types.UID(binding.PolicyUID)
		}
	}
	if owned {
		t.run.owned = append(t.run.owned, demoOwned{object: obj.DeepCopyObject().(client.Object), uid: obj.GetUID(), parent: parent, receiptPolicy: receiptPolicy})
	}
	return nil
}

func (d *demoRun) trackChild(ctx context.Context, p *corev1.Pod, deploymentUID types.UID) error {
	if p.UID == "" || p.Labels["phorvex.ai/native-demo-run"] != d.token {
		return fmt.Errorf("generated Pod %s/%s lacks run ownership", p.Namespace, p.Name)
	}
	for _, ref := range p.OwnerReferences {
		if ref.Kind != "ReplicaSet" {
			continue
		}
		var rs appsv1.ReplicaSet
		if err := d.client.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: ref.Name}, &rs); err != nil {
			return err
		}
		if rs.UID != ref.UID {
			continue
		}
		for _, parent := range rs.OwnerReferences {
			if parent.UID == deploymentUID {
				d.owned = append(d.owned, demoOwned{object: p.DeepCopy(), uid: p.UID})
				return nil
			}
		}
	}
	return fmt.Errorf("generated Pod %s/%s lacks acknowledged Deployment UID %s", p.Namespace, p.Name, deploymentUID)
}

func (d *demoRun) waitOwnedDeployPod(ctx context.Context, dep *appsv1.Deployment) (*corev1.Pod, error) {
	var last error
	for attempt := 0; attempt < 60; attempt++ {
		var pods corev1.PodList
		if err := d.client.List(ctx, &pods, client.InNamespace(dep.Namespace), client.MatchingLabels{"app": dep.Name, "phorvex.ai/native-demo-run": d.token}); err != nil {
			return nil, err
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Status.Phase != corev1.PodRunning || p.UID == "" {
				continue
			}
			if err := d.trackChild(ctx, p, dep.UID); err == nil {
				return p.DeepCopy(), nil
			} else {
				last = err
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("no Running Pod with proven Deployment UID %s and run token", dep.UID)
}

func (d *demoRun) trackDescendants(ctx context.Context, dep *appsv1.Deployment) []error {
	if dep.UID == "" {
		return nil
	}
	var pods corev1.PodList
	if err := d.client.List(ctx, &pods, client.InNamespace(dep.Namespace), client.MatchingLabels{"app": dep.Name, "phorvex.ai/native-demo-run": d.token}); err != nil {
		return []error{err}
	}
	var errs []error
	for i := range pods.Items {
		p := &pods.Items[i]
		seen := false
		for _, owned := range d.owned {
			if owned.uid == p.UID {
				seen = true
				break
			}
		}
		if !seen {
			if err := d.trackChild(ctx, p, dep.UID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}

func (d *demoRun) create(ctx context.Context, obj client.Object) error {
	if obj.GetLabels() == nil {
		obj.SetLabels(map[string]string{})
	}
	labels := obj.GetLabels()
	labels["phorvex.ai/native-demo-run"] = d.token
	obj.SetLabels(labels)
	var existing client.Object = obj.DeepCopyObject().(client.Object)
	if err := d.client.Get(ctx, client.ObjectKeyFromObject(obj), existing); err == nil {
		return fmt.Errorf("demo resource collision %s/%s (uid %s)", obj.GetNamespace(), obj.GetName(), existing.GetUID())
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("demo collision check %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
	}
	if err := d.client.Create(ctx, obj); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("demo resource collision %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
		}
		return fmt.Errorf("demo create %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
	}
	if obj.GetUID() == "" {
		return fmt.Errorf("demo create %s/%s acknowledged without UID; cleanup authority unavailable", obj.GetNamespace(), obj.GetName())
	}
	d.owned = append(d.owned, demoOwned{object: obj.DeepCopyObject().(client.Object), uid: obj.GetUID()})
	return nil
}

func (d *demoRun) cleanup(ctx context.Context) []error {
	var errs []error
	for i := len(d.owned) - 1; i >= 0; i-- {
		item := d.owned[i]
		current := item.object.DeepCopyObject().(client.Object)
		key := client.ObjectKeyFromObject(item.object)
		if err := d.client.Get(ctx, key, current); err != nil {
			if !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("cleanup read %s/%s: %w", key.Namespace, key.Name, err))
			}
			continue
		}
		if item.receiptPolicy != "" {
			if current.GetUID() != item.uid {
				errs = append(errs, fmt.Errorf("administrative receipt name %s/%s was recreated: acknowledged uid %s, current uid %s", key.Namespace, key.Name, item.uid, current.GetUID()))
			} else {
				errs = append(errs, fmt.Errorf("unresolved administrative receipt %s/%s uid %s; cleanup incomplete, manual investigation required", key.Namespace, key.Name, item.uid))
			}
			continue
		}
		bound := current.GetLabels()["phorvex.ai/native-demo-run"] == d.token
		if item.parent != "" {
			bound = false
			for _, ref := range current.GetOwnerReferences() {
				if ref.UID == item.parent {
					bound = true
				}
			}
		}
		if current.GetUID() != item.uid || !bound {
			errs = append(errs, fmt.Errorf("cleanup ownership changed %s/%s: acknowledged uid %s, current uid %s", key.Namespace, key.Name, item.uid, current.GetUID()))
			continue
		}
		uid := item.uid
		if err := d.client.Delete(ctx, current, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("cleanup delete %s/%s uid %s: %w", key.Namespace, key.Name, uid, err))
			continue
		}
		gone := false
		for attempt := 0; attempt < 20; attempt++ {
			observed := item.object.DeepCopyObject().(client.Object)
			e := d.client.Get(ctx, key, observed)
			if apierrors.IsNotFound(e) || (e == nil && observed.GetUID() != uid) {
				gone = true
				break
			}
			if e != nil {
				errs = append(errs, fmt.Errorf("cleanup post-read %s/%s uid %s: %w", key.Namespace, key.Name, uid, e))
				break
			}
			select {
			case <-ctx.Done():
				errs = append(errs, ctx.Err())
				attempt = 20
			case <-time.After(250 * time.Millisecond):
			}
		}
		if !gone {
			errs = append(errs, fmt.Errorf("cleanup %s/%s uid %s not confirmed absent", key.Namespace, key.Name, uid))
		}
	}
	if d.namespace != "" {
		if err := d.waitRunResidueAbsent(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (d *demoRun) waitRunResidueAbsent(ctx context.Context) error {
	for attempt := 0; attempt < 20; attempt++ {
		var pods corev1.PodList
		var deps appsv1.DeploymentList
		var sets appsv1.ReplicaSetList
		var services corev1.ServiceList
		var policies v1alpha1.PhorvexPolicyList
		for _, entry := range []client.ObjectList{&pods, &deps, &sets, &services, &policies} {
			if err := d.client.List(ctx, entry, client.InNamespace(d.namespace), client.MatchingLabels{"phorvex.ai/native-demo-run": d.token}); err != nil {
				return fmt.Errorf("run residue inventory: %w", err)
			}
		}
		if len(pods.Items)+len(deps.Items)+len(sets.Items)+len(services.Items)+len(policies.Items) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("run token %s still has Pod/Deployment/ReplicaSet/Service/Policy residue in %s", d.token, d.namespace)
}

func demoErrors(errs []error) string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}

// The writer and client boundary permits orchestration tests without a live cluster.
func runNativeDemo(ctx context.Context, c client.Client, ns, adminNS string, w io.Writer) error {
	if w == nil {
		w = os.Stdout
	}
	report := &demoReport{}
	run := &demoRun{client: c, token: uuid.NewString(), namespace: ns}
	var namespace corev1.Namespace
	if err := c.Get(ctx, client.ObjectKey{Name: ns}, &namespace); err != nil {
		report.add("namespace", "pre-existing demo namespace required", err.Error(), demoSetupFailure)
		return report.write(w)
	}
	if namespace.DeletionTimestamp != nil {
		report.add("namespace", "active demo namespace required", "namespace terminating", demoSetupFailure)
		return report.write(w)
	}
	switch namespace.Annotations["phorvex.ai/dry-run"] {
	case "true", "True", "1", "yes":
		report.add("namespace", "active demo namespace required", "namespace dry-run annotation set", demoSetupFailure)
		return report.write(w)
	}
	n := newDemoActuator(&demoTrackingClient{Client: c, run: run})
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "native-demo-" + strings.ReplaceAll(run.token, "-", ""), Namespace: ns}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/native-demo-run": run.token}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionQuarantine, v1alpha1.ActionWarmSwap, v1alpha1.ActionModelShardReplace}}}}
	policyReady := true
	if err := run.create(ctx, policy); err != nil {
		policyReady = false
		report.add("policy", "unique current active policy", err.Error(), demoSetupFailure)
	}
	journalReady := adminNS != "" && adminNS != ns
	if !journalReady {
		report.add("journal", "protected operator namespace distinct from tenant", fmt.Sprintf("adminNS=%q tenant=%q", adminNS, ns), demoSetupFailure)
	} else {
		var admin corev1.Namespace
		if err := c.Get(ctx, client.ObjectKey{Name: adminNS}, &admin); err != nil {
			journalReady = false
			report.add("journal", "read real operator namespace", err.Error(), demoSetupFailure)
		}
	}
	if journalReady {
		n.JournalNamespace = adminNS
	}
	req := func(p *corev1.Pod, a model.Action) actuator.Request {
		return actuator.Request{Tenant: ns, Namespace: ns, Pod: p.Name, TargetUID: string(p.UID), Action: a, Reason: "native-demo", Score: 0.9, PolicyName: policy.Name, PolicyUID: string(policy.UID)}
	}
	makePod := func(action, name string, labels map[string]string) (*corev1.Pod, bool) {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"phorvex.ai/native-demo": "true", "app": name}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:1.36", Command: []string{"sh", "-c", "sleep 3600"}}}}}
		for k, v := range labels {
			p.Labels[k] = v
		}
		if err := run.create(ctx, p); err != nil {
			report.add(action, "owned fixture", err.Error(), demoSetupFailure)
			return nil, false
		}
		ready, err := waitPodRunning(ctx, c, ns, name)
		if err != nil || ready == nil || ready.Status.Phase != corev1.PodRunning || ready.UID == "" || ready.UID != p.UID || ready.Labels["phorvex.ai/native-demo-run"] != run.token {
			report.add(action, "Running fixture with UID", fmt.Sprintf("pod=%v err=%v", ready, err), demoSetupFailure)
			return nil, false
		}
		return ready, true
	}
	act := func(p *corev1.Pod, a model.Action) (actuator.Result, error) { return demoActuate(ctx, n, req(p, a)) }
	// A Deployment is required to prove controller-safe rotate and selector detach.
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "victim-rotate", Namespace: ns, Labels: map[string]string{"phorvex.ai/native-demo": "true"}}, Spec: appsv1.DeploymentSpec{Replicas: ptr32(1), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "victim-rotate"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "victim-rotate", "phorvex.ai/native-demo": "true", "phorvex.ai/native-demo-run": run.token}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:1.36", Command: []string{"sh", "-c", "sleep 3600"}}}}}}}
	if err := run.create(ctx, dep); err != nil {
		report.add("rotate", "owned Deployment fixture", err.Error(), demoSetupFailure)
	} else if p, err := run.waitOwnedDeployPod(ctx, dep); err != nil {
		report.add("rotate", "Running Pod with proven owner UID and run token", err.Error(), demoSetupFailure)
	} else {

		res, e := act(p, model.ActionRotate)
		gone, readErr := demoUIDGone(ctx, c, ns, p.Name, p.UID)
		v := demoConfirmed
		if e != nil || readErr != nil || !res.Emitted || !gone {
			v = demoObservationFailure
		}
		report.add("rotate", "selected UID gone; replacement unconfirmed", fmt.Sprintf("emitted=%v uidGone=%v act=%v read=%v", res.Emitted, gone, e, readErr), v)
	}
	if p, ok := makePod("rotate.bare", "victim-rotate-bare", nil); ok {
		res, e := act(p, model.ActionRotate)
		var after corev1.Pod
		readErr := c.Get(ctx, client.ObjectKeyFromObject(p), &after)
		v := demoRefused
		if e != nil || readErr != nil || res.Emitted || after.UID != p.UID || !strings.Contains(res.Note, "ownerless") {
			v = demoObservationFailure
		}
		report.add("rotate.bare", "ownerless Pod refused and UID untouched", fmt.Sprintf("emitted=%v note=%s act=%v read=%v", res.Emitted, res.Note, e, readErr), v)
	}
	// Canonical policy and rollback are separately observed.
	qdep := dep.DeepCopy()
	qdep.Name = "victim-qtn"
	qdep.UID = ""
	qdep.ResourceVersion = ""
	qdep.CreationTimestamp = metav1.Time{}
	qdep.Status = appsv1.DeploymentStatus{}
	qdep.Spec.Selector.MatchLabels["app"] = "victim-qtn"
	qdep.Spec.Template.Labels["app"] = "victim-qtn"
	if !policyReady || !journalReady {
		report.add("quarantine", "current policy and protected journal", "policy/journal setup unavailable", demoSetupFailure)
		report.add("quarantine.rollback", "quarantine fixture", "policy/journal setup unavailable", demoSetupFailure)
	} else if err := run.create(ctx, qdep); err != nil {
		report.add("quarantine", "owned Deployment fixture", err.Error(), demoSetupFailure)
		report.add("quarantine.rollback", "quarantine fixture", err.Error(), demoSetupFailure)
	} else if p, err := run.waitOwnedDeployPod(ctx, qdep); err != nil {
		report.add("quarantine", "Running Pod with proven owner UID and run token", err.Error(), demoSetupFailure)
		report.add("quarantine.rollback", "quarantine fixture", err.Error(), demoSetupFailure)
	} else {

		request := req(p, model.ActionQuarantine)
		res, e := demoActuate(ctx, n, request)
		ok, readErr := demoQuarantine(ctx, c, p)
		v := demoConfirmed
		if e != nil || readErr != nil || !res.Emitted || !ok {
			v = demoObservationFailure
		}
		report.add("quarantine", "canonical deny-all NP, UID alive, selector detached", fmt.Sprintf("emitted=%v observed=%v act=%v read=%v", res.Emitted, ok, e, readErr), v)
		if e != nil || !res.Emitted {
			report.add("quarantine.rollback", "quarantine emitted", "rollback unavailable after failed enactment", demoUnavailable)
		} else {
			rbErr := n.Rollback(ctx, request, res.RollbackRef)
			restored, rbRead := demoQuarantineRolledBack(ctx, c, p)
			receiptDone, receiptRead := demoReceiptFinished(ctx, c, adminNS, "quarantine", string(policy.UID), string(p.UID))
			rv := demoConfirmed
			if rbErr != nil || rbRead != nil || receiptRead != nil || !restored || !receiptDone {
				rv = demoObservationFailure
			}
			report.add("quarantine.rollback", "labels/ownerRefs restored; canonical NP and receipt gone", fmt.Sprintf("restored=%v receiptFinished=%v rollback=%v read=%v receiptRead=%v", restored, receiptDone, rbErr, rbRead, receiptRead), rv)
		}
	}
	for _, a := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		name := "victim-" + string(a)
		if p, ok := makePod(string(a), name, nil); ok {
			res, e := act(p, a)
			var after corev1.Pod
			readErr := c.Get(ctx, client.ObjectKeyFromObject(p), &after)
			v := demoConfirmed
			if e != nil || readErr != nil || !res.Emitted || len(after.Spec.EphemeralContainers) == 0 || after.UID != p.UID {
				v = demoObservationFailure
			}
			report.add(string(a), "ephemeral container on selected UID", fmt.Sprintf("emitted=%v ephemeral=%d act=%v read=%v", res.Emitted, len(after.Spec.EphemeralContainers), e, readErr), v)
		}
	}
	if p, ok := makePod("identity-rotate", "victim-identity", nil); ok {
		res, e := act(p, model.ActionIdentityRotate)
		var after corev1.Pod
		readErr := c.Get(ctx, client.ObjectKeyFromObject(p), &after)
		v := demoRefused
		declared := e != nil && strings.Contains(e.Error(), model.IdentityRotateUnsupportedReason)
		if !declared || readErr != nil || res.Emitted || after.UID != p.UID || !reflect.DeepEqual(after.Labels, p.Labels) || !reflect.DeepEqual(after.Annotations, p.Annotations) || after.Spec.ServiceAccountName != p.Spec.ServiceAccountName || after.Status.PodIP != p.Status.PodIP {
			v = demoObservationFailure
		}
		report.add("identity-rotate", "declared-only refusal; UID/IP/SA/labels unchanged", fmt.Sprintf("emitted=%v declaredRefusal=%v act=%v read=%v", res.Emitted, declared, e, readErr), v)
	}
	// Busybox has no serving stack. The refusal is the control, not a flush pass.
	if p, ok := makePod("kv-reset", "victim-kv", map[string]string{"phorvex.ai/model-id": "llama-70b"}); ok {
		res, e := act(p, model.ActionKVReset)
		var after corev1.Pod
		readErr := c.Get(ctx, client.ObjectKeyFromObject(p), &after)
		v := demoUnavailable
		if readErr != nil || res.Emitted || after.UID != p.UID || after.Annotations["phorvex.ai/kv-reset-epoch"] != "" {
			v = demoObservationFailure
		}
		report.add("kv-reset", "busybox no serving stack: no flush/epoch", fmt.Sprintf("emitted=%v note=%s act=%v read=%v", res.Emitted, res.Note, e, readErr), v)
	}
	for _, a := range []model.Action{model.ActionMIGRebind, model.ActionModelShardReplace} {
		report.add(string(a), "actual MIG device or model-shard runtime required", "busybox has no GPU/model-shard runtime; action unexecuted", demoUnavailable)
	}
	if p, ok := makePod("dry-run guard", "victim-dry", nil); ok {
		dry := newDemoActuator(c)
		dry.DryRun = true
		res, e := demoActuate(ctx, dry, req(p, model.ActionRotate))
		var after corev1.Pod
		readErr := c.Get(ctx, client.ObjectKeyFromObject(p), &after)
		v := demoRefused
		if e == nil || !strings.Contains(e.Error(), "DryRun") || readErr != nil || after.UID != p.UID || res.Emitted {
			v = demoObservationFailure
		}
		report.add("dry-run guard", "mutation refused; selected UID untouched", fmt.Sprintf("emitted=%v act=%v read=%v", res.Emitted, e, readErr), v)
	}
	report.rows = append(report.rows, runDemoRouteCase(ctx, run, n, ns, model.ActionRouteRotate))
	report.rows = append(report.rows, runDemoRouteCase(ctx, run, n, ns, model.ActionEndpointRotate))
	if !policyReady || !journalReady {
		report.add("warm-swap", "current policy and protected journal", "policy/journal setup unavailable", demoSetupFailure)
	} else {
		report.rows = append(report.rows, runDemoWarmCase(ctx, run, n, ns, policy))
	}
	var cleanupErrs []error
	for _, dep := range []*appsv1.Deployment{dep, qdep} {
		cleanupErrs = append(cleanupErrs, run.trackDescendants(ctx, dep)...)
	}
	cleanupErrs = append(cleanupErrs, run.cleanup(ctx)...)
	if len(cleanupErrs) > 0 {
		report.add("cleanup", "acknowledged owned UIDs confirmed absent", demoErrors(cleanupErrs), demoCleanupFailure)
	} else {
		report.add("cleanup", "acknowledged owned UIDs confirmed absent", "all tracked UIDs absent", demoConfirmed)
	}
	return report.write(w)
}

func ptr32(v int32) *int32 { return &v }

func runDemoRouteCase(ctx context.Context, run *demoRun, n *actuator.NativeActuator, ns string, action model.Action) demoRow {
	a := string(action)
	group := "demo-" + a
	svcName := "svc-" + a
	row := demoRow{action: a, expected: "Pod/Service selector restitched; >=2 Ready before; target Ready after", verdict: demoSetupFailure}
	createPod := func(name string, annotation bool) (*corev1.Pod, error) {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"app": group, "phorvex.ai/native-demo": "true"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:1.36", Command: []string{"sh", "-c", "sleep 3600"}}}}}
		if action == model.ActionRouteRotate {
			p.Labels[demoRouteKey] = "route-initial"
		}
		if annotation {
			p.Annotations = map[string]string{"phorvex.ai/route-service": svcName}
		}
		if err := run.create(ctx, p); err != nil {
			return nil, err
		}
		ready, err := waitPodRunning(ctx, run.client, ns, name)
		if err != nil {
			return nil, err
		}
		if ready.UID == "" || ready.UID != p.UID || ready.Labels["phorvex.ai/native-demo-run"] != run.token || ready.Status.Phase != corev1.PodRunning {
			return nil, fmt.Errorf("Pod %s not Running with UID", name)
		}
		return ready, nil
	}
	target, err := createPod(group+"-target", true)
	if err != nil {
		row.observed = err.Error()
		return row
	}
	other, err := createPod(group+"-alternative", false)
	if err != nil {
		row.observed = err.Error()
		return row
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ns}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": group}, Ports: []corev1.ServicePort{{Port: 80}}}}
	if action == model.ActionRouteRotate {
		svc.Spec.Selector[demoRouteKey] = "route-initial"
	}
	if err := run.create(ctx, svc); err != nil {
		row.observed = err.Error()
		return row
	}
	beforeReady, err := demoReadySelected(ctx, run.client, svc)
	if err != nil {
		row.verdict = demoObservationFailure
		row.observed = err.Error()
		return row
	}
	if beforeReady < 2 {
		row.verdict = demoUnavailable
		row.observed = fmt.Sprintf("only %d Ready selected backends before actuation", beforeReady)
		return row
	}
	request := actuator.Request{Tenant: ns, Namespace: ns, Pod: target.Name, TargetUID: string(target.UID), Action: action, Reason: "native-demo", Score: 0.9}
	result, actErr := demoActuate(ctx, n, request)
	mutated, readErr := demoRouteRestitched(ctx, run.client, target, svc)
	var afterSvc corev1.Service
	if e := run.client.Get(ctx, client.ObjectKeyFromObject(svc), &afterSvc); e != nil && readErr == nil {
		readErr = e
	}
	if readErr == nil && (afterSvc.UID != svc.UID || afterSvc.DeletionTimestamp != nil) {
		mutated = false
	}
	afterReady := 0
	if readErr == nil {
		afterReady, readErr = demoReadySelected(ctx, run.client, &afterSvc)
	}
	var afterOther corev1.Pod
	if e := run.client.Get(ctx, client.ObjectKeyFromObject(other), &afterOther); e != nil && readErr == nil {
		readErr = e
	}
	otherUntouched := afterOther.UID == other.UID && reflect.DeepEqual(afterOther.Labels, other.Labels) && reflect.DeepEqual(afterOther.Annotations, other.Annotations)
	row.verdict = demoConfirmed
	if actErr != nil || readErr != nil || !result.Emitted || !mutated || !otherUntouched {
		row.verdict = demoObservationFailure
	}
	row.observed = fmt.Sprintf("beforeReady=%d afterReady=%d restitched=%v alternativeUnchanged=%v emitted=%v act=%v read=%v; traffic unmeasured", beforeReady, afterReady, mutated, otherUntouched, result.Emitted, actErr, readErr)
	return row
}

func runDemoWarmCase(ctx context.Context, run *demoRun, n *actuator.NativeActuator, ns string, policy *v1alpha1.PhorvexPolicy) demoRow {
	row := demoRow{action: "warm-swap", expected: "configured RS/Service scaffold; controller membership and serving readiness required before cutover", verdict: demoSetupFailure}
	labels := map[string]string{"phorvex.ai/swap-group": "native-demo-warm", "phorvex.ai/native-demo": "true", "phorvex.ai/native-demo-run": run.token}
	replicas := int32(2)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "wsg", Namespace: ns}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"phorvex.ai/swap-group": "native-demo-warm", "phorvex.ai/native-demo": "true", "phorvex.ai/native-demo-run": run.token, "phorvex.ai/role": "warm-shadow", "phorvex.ai/model-loaded": "false"}, Annotations: map[string]string{"phorvex.ai/route-service": "wsg"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox:1.36", Command: []string{"sh", "-c", "sleep 3600"}}}}}}}
	if err := run.create(ctx, rs); err != nil {
		row.observed = err.Error()
		return row
	}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "wsg", Namespace: ns}, Spec: corev1.ServiceSpec{Selector: map[string]string{"phorvex.ai/swap-group": "native-demo-warm", "phorvex.ai/native-demo-run": run.token, "phorvex.ai/role": "leader"}, Ports: []corev1.ServicePort{{Name: "http", Port: 80}}}}
	if err := run.create(ctx, service); err != nil {
		row.observed = err.Error()
		return row
	}
	// This bounded demo does not run or impersonate the ReplicaSet controller.
	// The dedicated local-KCM test exercises the positive replenishment path.
	row.verdict = demoUnavailable
	row.observed = "configuredPool=true controllerMembers=unobserved; cutover not submitted"
	return row

}
