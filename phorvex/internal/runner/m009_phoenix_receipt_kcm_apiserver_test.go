package runner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/slo"
)

// TestM009ActualNativeReceiptSnapshotRunnerAndReplicaSetController exercises
// the cross-module seam from the real native bounded-rotate producer through
// runner receipt projection and a real ReplicaSet replacement. The workload's
// explicit zero grace lets envtest, which has no kubelet, finish deletion; the
// receipt still proves the selecting policy cap and exact DELETE identities.
func TestM009ActualNativeReceiptSnapshotRunnerAndReplicaSetController(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" || os.Getenv("KUBE_CONTROLLER_MANAGER") == "" {
		t.Skip("requires pinned envtest and kube-controller-manager")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if out, err := exec.Command(kcm, "--version").Output(); err != nil || !strings.Contains(string(out), "v1.34.0") {
		t.Fatalf("kube-controller-manager must be v1.34.0: %q %v", out, err)
	}
	local := false
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases", "../../../build/phoenix-extended/config/crd/bases"}, ErrorIfCRDPathMissing: true, UseExistingCluster: &local}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: m034Scheme(t)})
	if err != nil {
		t.Fatal(err)
	}
	reader := client.Reader(c)
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	kcfg := clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"local": {Server: cfg.Host, CertificateAuthorityData: cfg.CAData}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {ClientCertificateData: cfg.CertData, ClientKeyData: cfg.KeyData}}, Contexts: map[string]*clientcmdapi.Context{"local": {Cluster: "local", AuthInfo: "admin"}}, CurrentContext: "local"}
	if err := clientcmd.WriteToFile(kcfg, kubeconfig); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+kubeconfig, "--controllers=replicaset", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })

	ns := "m009"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	replicas, zero := int32(1), int64(0)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "api"}, Spec: appsv1.ReplicaSetSpec{
		Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &zero, Containers: []corev1.Container{{Name: "api", Image: "registry.k8s.io/pause:3.10"}}}},
	}}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	var pods corev1.PodList
	m034Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &pods, client.InNamespace(ns)); err != nil {
			return false, err
		}
		return len(pods.Items) == 1, nil
	})
	original := pods.Items[0].DeepCopy()
	m034Poll(t, 10*time.Second, func() (bool, error) {
		fresh := &corev1.Pod{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(original), fresh); err != nil {
			return false, err
		}
		fresh.Status.Phase = corev1.PodRunning
		fresh.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Now()}}
		if err := c.Status().Update(ctx, fresh); err != nil {
			return false, nil
		}
		original = fresh
		return true, nil
	})

	cap := int64(3)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
		Budget:  v1alpha1.BudgetSpec{MaxGracePeriodSeconds: &cap, TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	producer := actuator.NewNativeActuator(c)
	producer.Reader = reader
	if err := producer.EnsurePolicy(ctx, actuator.TenantTarget{Namespace: ns, Tenant: "tenant", PolicyName: policy.Name, PolicyUID: string(policy.UID), Generation: policy.Generation, Selector: &policy.Spec.Selector, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}); err != nil {
		t.Fatal(err)
	}

	view := &model.WorkloadView{Pod: model.Pod{Namespace: ns, Name: original.Name, UID: string(original.UID), OwnerKind: "ReplicaSet", OwnerName: rs.Name, Ready: true, ReadyAt: original.Status.Conditions[0].LastTransitionTime.Time, ReadyReplicas: 1}}
	var auditOut bytes.Buffer
	opt := &observingOptimizer{}
	manager := &Manager{Actuator: producer, BoundaryReader: reader, Optimizer: opt, Disruption: slo.NewLedger(time.Hour), Audit: audit.New(logr.Discard(), &auditOut), Log: logr.Discard()}
	entry := &policyEntry{key: types.NamespacedName{Namespace: ns, Name: policy.Name}, uid: string(policy.UID), generation: policy.Generation, tenant: "tenant", namespace: ns,
		spec: policy.Spec}
	pol := model.Policy{Tenant: "tenant", Namespace: ns, PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, MaxGracePeriodSeconds: cap, MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	decisions := []model.Decision{{Selected: true, Feasible: true, Namespace: ns, Pod: original.Name, Action: model.ActionRotate,
		Trace: &model.DecisionTraceV2{DecisionID: "decision-m009", DispatchOutcome: model.DispatchNotAttempted}}}
	if n := manager.actuate(ctx, entry, pol, decisions, map[string]*model.WorkloadView{ns + "/" + original.Name: view}); n != 1 || !decisions[0].Actuated || decisions[0].Phoenix != nil || decisions[0].GracefulTermination == nil {
		t.Fatalf("actual runner dispatch failed: count=%d decision=%+v", n, decisions[0])
	}
	receipt := decisions[0].GracefulTermination
	if receipt.PolicyUID != string(policy.UID) || receipt.PolicyGeneration != policy.Generation || receipt.PolicyGraceCapSeconds != cap || receipt.WorkloadGraceSeconds != 0 || receipt.EffectiveGracePeriodSeconds != 0 || receipt.PodUID != string(original.UID) || receipt.PodResourceVersion == "" || receipt.TerminationStatus != "unconfirmed" {
		t.Fatalf("native graceful termination receipt=%+v", receipt)
	}
	if len(manager.pendingRotations) != 1 {
		t.Fatalf("runner did not retain actual native rotation identity: pending=%d", len(manager.pendingRotations))
	}

	var replacement *corev1.Pod
	m034Poll(t, 20*time.Second, func() (bool, error) {
		if err := reader.List(ctx, &pods, client.InNamespace(ns)); err != nil {
			return false, err
		}
		for i := range pods.Items {
			if pods.Items[i].UID != original.UID && pods.Items[i].DeletionTimestamp == nil {
				replacement = pods.Items[i].DeepCopy()
				return true, nil
			}
		}
		return false, nil
	})
	m034Poll(t, 10*time.Second, func() (bool, error) {
		fresh := &corev1.Pod{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(replacement), fresh); err != nil {
			return false, err
		}
		fresh.Status.Phase = corev1.PodRunning
		fresh.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Now()}}
		if err := c.Status().Update(ctx, fresh); err != nil {
			return false, nil
		}
		replacement = fresh
		return true, nil
	})
	var snapshot *ingest.Snapshot
	m034Poll(t, 10*time.Second, func() (bool, error) {
		current, collectErr := ingest.CollectSnapshot(ctx, c, time.Now().UTC(), func(*model.Pod) float64 { return 1 }, reader)
		if collectErr != nil {
			return false, collectErr
		}
		recovered, originalPresent := false, false
		for i := range current.Pods {
			if current.Pods[i].UID == string(original.UID) {
				originalPresent = true
			}
			if current.Pods[i].UID == string(replacement.UID) && current.Pods[i].Ready {
				recovered = true
			}
		}
		if originalPresent || !recovered {
			return false, nil
		}
		snapshot = current
		return true, nil
	})
	manager.observeReadyRotations(observationOf(snapshot))
	if len(opt.observations) != 1 || len(manager.pendingRotations) != 0 {
		t.Fatalf("exact native request/replacement did not resolve runner: observations=%v pending=%d", opt.observations, len(manager.pendingRotations))
	}
	if strings.Contains(auditOut.String(), `"outcome":"confirmed-execution-recovery"`) {
		t.Fatalf("native request must not inherit Phoenix execution-receipt claims: %s", auditOut.String())
	}
}
