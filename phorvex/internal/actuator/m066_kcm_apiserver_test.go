package actuator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m066NoPodCreate struct {
	client.WithWatch
	attempts int
}

// KCM writes while the test may need a failure snapshot. Keep only a bounded
// tail and synchronize both operations to avoid races and unbounded memory.
type m066BoundedLog struct {
	mu   sync.Mutex
	tail []byte
}

const m066KCMLogLimit = 64 * 1024

func (l *m066BoundedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(p) >= m066KCMLogLimit {
		l.tail = append(l.tail[:0], p[len(p)-m066KCMLogLimit:]...)
		return len(p), nil
	}
	l.tail = append(l.tail, p...)
	if len(l.tail) > m066KCMLogLimit {
		l.tail = append([]byte(nil), l.tail[len(l.tail)-m066KCMLogLimit:]...)
	}
	return len(p), nil
}
func (l *m066BoundedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(append([]byte(nil), l.tail...))
}

func (c *m066NoPodCreate) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.Pod); ok {
		c.attempts++
		return fmt.Errorf("Phorvex Pod Create forbidden in controller warm pool")
	}
	return c.WithWatch.Create(ctx, obj, opts...)
}

func m066Kubeconfig(t *testing.T, cfg *rest.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "local-kcm-kubeconfig")
	k := clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"local": {Server: cfg.Host, CertificateAuthority: cfg.CAFile, CertificateAuthorityData: cfg.CAData, InsecureSkipTLSVerify: cfg.Insecure}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {ClientCertificate: cfg.CertFile, ClientCertificateData: cfg.CertData, ClientKey: cfg.KeyFile, ClientKeyData: cfg.KeyData, Token: cfg.BearerToken}}, Contexts: map[string]*clientcmdapi.Context{"local": {Cluster: "local", AuthInfo: "admin"}}, CurrentContext: "local"}
	if err := clientcmd.WriteToFile(k, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func m066Poll(t *testing.T, within time.Duration, check func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		ok, err := check()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal("timed out waiting for isolated ReplicaSet controller")
}

func TestM066RealReplicaSetControllerReplenishesWithoutPhorvexCreate(t *testing.T) {
	const (
		emptyLabel      = "m065.test/empty-label"
		emptyAnnotation = "m065.test/empty-annotation"
	)
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if kcm == "" {
		var lookupErr error
		kcm, lookupErr = exec.LookPath("kube-controller-manager")
		if lookupErr != nil {
			t.Skip("requires local Kubernetes v1.34.0 kube-controller-manager via KUBE_CONTROLLER_MANAGER or PATH")
		}
	}
	if _, err := os.Stat(kcm); err != nil {
		t.Skip("configured kube-controller-manager unavailable")
	}
	version, err := exec.Command(kcm, "--version").Output()
	if err != nil || !strings.Contains(string(version), "v1.34.0") {
		t.Fatalf("local kube-controller-manager must be v1.34.0: output=%q err=%v", string(version), err)
	}
	localOnly := false
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, UseExistingCluster: &localOnly}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	privateKubeconfig := m066Kubeconfig(t, cfg)
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+privateKubeconfig, "--controllers=replicaset", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = []string{"KUBECONFIG=" + privateKubeconfig}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KUBECONFIG=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	var kcmLog m066BoundedLog
	cmd.Stdout = &kcmLog
	cmd.Stderr = &kcmLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m066-local-pool"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m066-operator"}}); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "serving"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "m066", labelSwapGroup: "g", labelRole: roleLeader}, Ports: []corev1.ServicePort{{Port: 8000}}}}
	if err := c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m066"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	count := int32(2)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "pool"}, Spec: appsv1.ReplicaSetSpec{Replicas: &count, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "m066", labelSwapGroup: "g"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "m066", labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "false", emptyLabel: "", "m065.test/nonempty-label": "expected"}, Annotations: map[string]string{annoRouteService: svc.Name, annoServingPort: "8123", annoResetPath: "/custom_reset", "phorvex.ai/model-id": "declared-model", emptyAnnotation: "", "m065.test/nonempty-annotation": "expected"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}}}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	var members corev1.PodList
	m066Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &members, client.InNamespace(ns.Name)); err != nil {
			return false, err
		}
		current := &appsv1.ReplicaSet{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns.Name, Name: rs.Name}, current); err != nil {
			return false, err
		}
		return len(members.Items) == 2 && current.Status.ObservedGeneration == current.Generation && current.Status.Replicas == 2, nil
	})
	old, next := members.Items[0].DeepCopy(), members.Items[1].DeepCopy()
	old.Labels[labelRole] = roleLeader
	if err := c.Update(ctx, old); err != nil {
		t.Fatal(err)
	}
	next.Labels[labelModelLoaded] = "true"
	if err := c.Update(ctx, next); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*corev1.Pod{old, next} {
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns.Name, Name: old.Name}, old); err != nil {
		t.Fatal(err)
	}
	old.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "registry.k8s.io/pause:3.10"}}}
	if err := c.SubResource("ephemeralcontainers").Update(ctx, old); err != nil {
		t.Fatalf("inject exact incident trigger: %v", err)
	}
	oldUID := old.UID
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns.Name, Name: old.Name}, old); err != nil || old.UID != oldUID || len(old.Spec.EphemeralContainers) != 1 {
		t.Fatalf("injected old leader identity/spec not persisted: uid=%s ephemerals=%d err=%v", old.UID, len(old.Spec.EphemeralContainers), err)
	}
	guard := &m066NoPodCreate{WithWatch: c}
	req := Request{Namespace: ns.Name, Pod: old.Name, TargetUID: string(old.UID), Action: model.ActionWarmSwap, PolicyName: pol.Name, PolicyUID: string(pol.UID)}
	result, enactErr := (warmSwapHandler{}).Enact(ctx, EnactCtx{Client: guard, Reader: c, JournalNamespace: "m066-operator", VLLM: &mockVLLM{loaded: true}}, req)
	if guard.attempts != 0 {
		t.Fatalf("Phorvex attempted competing Pod Create: %d", guard.attempts)
	}
	if enactErr != nil && result.MutationKind != "swap" {
		t.Fatalf("cutover refused: result=%+v err=%v kcm=%s", result, enactErr, kcmLog.String())
	}
	var replacement *corev1.Pod
	m066Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &members, client.InNamespace(ns.Name)); err != nil {
			return false, err
		}
		current := make([]*corev1.Pod, 0, 2)
		oldUIDPresent, survivorPresent := false, false
		var newMember *corev1.Pod
		for i := range members.Items {
			p := &members.Items[i]
			if p.UID == old.UID {
				oldUIDPresent = true
			}
			o := metav1.GetControllerOf(p)
			if o == nil || o.UID != rs.UID || p.DeletionTimestamp != nil {
				continue
			}
			current = append(current, p)
			if p.UID == next.UID {
				survivorPresent = true
			}
			if p.UID != next.UID && p.UID != old.UID {
				if newMember != nil {
					return false, fmt.Errorf("multiple new RS members")
				}
				newMember = p
			}
		}
		if oldUIDPresent || !survivorPresent || newMember == nil || len(current) != int(count) {
			return false, nil
		}
		replacement = newMember.DeepCopy()
		return true, nil
	})
	if replacement == nil || replacement.Labels[labelRole] != roleShadow || len(replacement.Spec.EphemeralContainers) != 0 {
		t.Fatalf("controller replacement missing/unclean: %+v", replacement)
	}
	if o := metav1.GetControllerOf(replacement); o == nil || o.UID != rs.UID {
		t.Fatalf("replacement lacks pinned RS controller: %+v", replacement.OwnerReferences)
	}
	if value, present := replacement.Labels[emptyLabel]; !present || value != "" {
		t.Fatalf("real ReplicaSet controller lost present-empty template label: value=%q present=%t", value, present)
	}
	if value, present := replacement.Annotations[emptyAnnotation]; !present || value != "" {
		t.Fatalf("real ReplicaSet controller lost present-empty template annotation: value=%q present=%t", value, present)
	}
	for key, want := range rs.Spec.Template.Annotations {
		if got, present := replacement.Annotations[key]; !present || got != want {
			t.Fatalf("real ReplicaSet controller annotation mismatch: key=%s got=%q present=%t want=%q", key, got, present, want)
		}
	}
	t.Logf("M065 producer positive: ReplicaSet controller copied present-empty metadata to replacement UID %s", replacement.UID)
	replacement.Labels[labelModelLoaded] = "true"
	if err := c.Update(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	replacement.Status.Phase = corev1.PodRunning
	replacement.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := c.Status().Update(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	native := NewNativeActuator(guard)
	native.Reader = c
	native.JournalNamespace = "m066-operator"
	native.RecoveryVLLM = &mockVLLM{loaded: true}
	replacementUID := replacement.UID
	mutateReplacement := func(change func(*corev1.Pod)) {
		t.Helper()
		current := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns.Name, Name: replacement.Name}, current); err != nil {
			t.Fatal(err)
		}
		if current.UID != replacementUID {
			t.Fatalf("replacement identity changed: got=%s want=%s", current.UID, replacementUID)
		}
		change(current)
		if err := c.Update(ctx, current); err != nil {
			t.Fatal(err)
		}
	}
	recoverPending := func(want string) {
		t.Helper()
		events, err := native.RecoverOperations(ctx, false)
		if err != nil || len(events) != 1 || events[0].Err == nil || events[0].Outcome == "confirmed" || !strings.Contains(events[0].Err.Error(), want) {
			t.Fatalf("missing expected metadata did not retain recovery: events=%+v err=%v want=%q", events, err, want)
		}
	}
	mutateReplacement(func(p *corev1.Pod) { delete(p.Labels, emptyLabel) })
	recoverPending("template label drift")
	mutateReplacement(func(p *corev1.Pod) {
		p.Labels[emptyLabel] = ""
		delete(p.Annotations, emptyAnnotation)
	})
	recoverPending("serving annotation drift")
	mutateReplacement(func(p *corev1.Pod) { p.Annotations[emptyAnnotation] = "" })
	var events []RecoveryEvent
	m066Poll(t, 10*time.Second, func() (bool, error) {
		var e error
		events, e = native.RecoverOperations(ctx, false)
		if e != nil {
			return false, e
		}
		return len(events) == 1 && events[0].Outcome == "confirmed", nil
	})
	if guard.attempts != 0 {
		t.Fatalf("recovery attempted competing Pod Create: %d", guard.attempts)
	}
	confirmedReplacement := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns.Name, Name: replacement.Name}, confirmedReplacement); err != nil || confirmedReplacement.UID != replacementUID {
		t.Fatalf("confirmed a different replacement identity: got=%s want=%s err=%v", confirmedReplacement.UID, replacementUID, err)
	}
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	if err := c.List(ctx, &members, client.InNamespace(ns.Name)); err != nil || len(members.Items) != 2 {
		t.Fatalf("policy removal changed pool observation: count=%d err=%v", len(members.Items), err)
	}
	for i := range members.Items {
		for _, o := range members.Items[i].OwnerReferences {
			if o.UID == pol.UID {
				t.Fatalf("pool Pod has policy ownership: %s", members.Items[i].Name)
			}
		}
	}
	for _, o := range rs.OwnerReferences {
		if o.UID == pol.UID {
			t.Fatal("ReplicaSet has policy ownership")
		}
	}
	t.Log("policy owner graph absent from pool; local KCM ran ReplicaSet only, so garbage collection itself was not exercised")
	if strings.Contains(fmt.Sprint(events), "PENDING-GPU-VALIDATION") {
		t.Log("explicit local status/model-ready fixture validates controller flow only; GPU timing remains unverified")
	}
}

func TestM066RealAPICreateRejectsCopiedEphemeralContainers(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	localOnly := false
	e := &envtest.Environment{UseExistingCluster: &localOnly}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	c, err := client.New(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m066-create-validity"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	clean := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "clean-shadow", Namespace: ns.Name}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}
	if err := c.Create(ctx, clean); err != nil {
		t.Fatalf("clean Pod CREATE positive control failed: %v", err)
	}
	invalid := clean.DeepCopy()
	invalid.Name = "copied-ephemeral"
	invalid.UID = ""
	invalid.ResourceVersion = ""
	invalid.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "registry.k8s.io/pause:3.10"}}}
	if err := c.Create(ctx, invalid); err == nil {
		t.Fatal("real API accepted Pod CREATE carrying copied ephemeral containers")
	}
}
