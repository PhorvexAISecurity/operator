package console

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/cataloguev1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kfake "k8s.io/client-go/kubernetes/fake"
)

func podBoundAdmissionDestination() runDestination {
	return runDestination{Targets: []string{hostTargetID, defaultTargetID}, Tenants: []string{"voice"},
		ScopeTarget: defaultTargetID, ScopeTenant: "voice", SuiteSHA256: strings.Repeat("a", 64)}
}

func TestPodBoundTokenPriorAdmissionRetainsExactVoiceFence(t *testing.T) {
	setup := func(t *testing.T) (*RunManager, *RunStatus) {
		t.Helper()
		cfg := disjointFixtureConfig(t)
		prior, _ := writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
		return NewRunManager(cfg), prior
	}
	t.Run("reviewed-terminal", func(t *testing.T) {
		rm, prior := setup(t)
		rm.mu.Lock()
		err := rm.podBoundTokenPriorAdmissionLocked(podBoundAdmissionDestination())
		rm.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if !prior.UnsafeToRetry || !rm.runs[prior.ID].UnsafeToRetry {
			t.Fatal("old Voice debt was cleared")
		}
	})
	t.Run("second-unsafe", func(t *testing.T) {
		rm, _ := setup(t)
		rm.mu.Lock()
		rm.runs["other"] = &RunStatus{ID: "other", UnsafeToRetry: true}
		err := rm.podBoundTokenPriorAdmissionLocked(podBoundAdmissionDestination())
		rm.mu.Unlock()
		if err == nil {
			t.Fatal("second unsafe run admitted")
		}
	})
	t.Run("active-old-process", func(t *testing.T) {
		rm, _ := setup(t)
		rm.mu.Lock()
		rm.procs[podBoundPriorVoiceID] = &exec.Cmd{}
		err := rm.podBoundTokenPriorAdmissionLocked(podBoundAdmissionDestination())
		rm.mu.Unlock()
		if err == nil {
			t.Fatal("active old Voice process admitted")
		}
	})
	for _, tc := range []struct{ name, file, old, new string }{
		{"unknown-effect", "journal.jsonl", `"step":"voice.transcript-delete"`, `"step":"voice.secret-delete"`},
		{"eviction-target", "journal.jsonl", `"podUID":"11111111-1111-4111-8111-111111111111"`, `"podUID":"33333333-3333-4333-8333-333333333333"`},
		{"broad-transcript-selector", "runtime.json", `"transcriptPodSelector": "app=voice-bot"`, `"transcriptPodSelector": "app=pod-token"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rm, prior := setup(t)
			path := filepath.Join(rm.cfg.runOutputPath(prior.ID), tc.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), tc.old) {
				t.Fatal("mutation fixture not found")
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(raw), tc.old, tc.new, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			rm.mu.Lock()
			err = rm.podBoundTokenPriorAdmissionLocked(podBoundAdmissionDestination())
			rm.mu.Unlock()
			if err == nil {
				t.Fatal("altered Voice original admitted")
			}
		})
	}
}

// Set PHORVEX_PRIOR_VOICE_ORIGINALS to the private PR327 capture directory to
// exercise the unchanged validator on the actual retained R18 bytes. The
// originals stay outside the repository and are never rewritten by this test.
func TestPodBoundTokenActualR18Originals(t *testing.T) {
	storage := os.Getenv("PHORVEX_PRIOR_VOICE_ORIGINALS")
	if storage == "" {
		t.Skip("private R18 originals directory not supplied")
	}
	statusRaw, err := os.ReadFile(filepath.Join(storage, "status.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var status persistedRunStatus
	if err := json.Unmarshal(statusRaw, &status); err != nil || status.Run.ID != podBoundPriorVoiceID {
		t.Fatalf("original status unavailable: %v", err)
	}
	const stateDir = "/var/lib/phorvex-console"
	const expectedDir = stateDir + "/runs/v1run-5"
	proof, err := podBoundTokenPriorProofAt(&status.Run, storage, expectedDir, stateDir)
	if err != nil {
		t.Fatalf("unchanged originals rejected: %v", err)
	}
	if !proof.Present || proof.NamespaceUID != "b52897be-d967-4cbf-be1c-f211eba5a95a" || proof.DeploymentUID != "9212e1a8-c21d-49cd-9854-85a1b306a8f4" || proof.TargetPodUID != "1c1ef9fa-a57f-4137-8963-22ff3049ae1e" || proof.ReplacementPodUID != "b5a68706-cca4-46d9-b47b-f2e414ea68ae" {
		t.Fatalf("actual Voice authority extraction differs: %+v", proof)
	}
	for _, tc := range []struct{ name, file, old, new string }{
		{"unknown-effect", "journal.jsonl", `"step":"voice.transcript-delete"`, `"step":"voice.secret-delete"`},
		{"eviction-uid", "journal.jsonl", `"podUID":"1c1ef9fa-a57f-4137-8963-22ff3049ae1e"`, `"podUID":"2c1ef9fa-a57f-4137-8963-22ff3049ae1e"`},
		{"selector-change", "runtime.json", `"transcriptPodSelector": "app=voice-bot"`, `"transcriptPodSelector": "app=pod-token"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"job.json", "runtime.json", "result.json", "metrics.jsonl", "journal.jsonl"} {
				raw, err := os.ReadFile(filepath.Join(storage, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, tc.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), tc.old) {
				t.Fatal("actual original mutation target absent")
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(raw), tc.old, tc.new, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := podBoundTokenPriorProofAt(&status.Run, dir, expectedDir, stateDir); err == nil {
				t.Fatal("mutated R18 original accepted")
			}
		})
	}
}

type podBoundLivePeerFixture struct {
	s      *Server
	kc     *kfake.Clientset
	r      podBoundTokenRequest
	p      podBoundTokenProfile
	policy *v1alpha1.PhorvexPolicyList
}

func podBoundLivePeer(t *testing.T) podBoundLivePeerFixture {
	t.Helper()
	cfg := disjointFixtureConfig(t)
	_, _ = writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
	rm := NewRunManager(cfg)
	nonce := "abcdef123456abcdef123456"
	name := "pod-token-" + nonce
	oldDepUID := types.UID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	oldRSUID := types.UID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	oldSvcUID := types.UID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	oldPDBUID := types.UID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	newDepUID := types.UID("44444444-4444-4444-8444-444444444444")
	newRSUID := types.UID("55555555-5555-4555-8555-555555555555")
	newSvcUID := types.UID("66666666-6666-4666-8666-666666666666")
	sourceUID := types.UID("77777777-7777-4777-8777-777777777777")
	peerUID := types.UID("88888888-8888-4888-8888-888888888888")
	oldPodUID := types.UID("99999999-9999-4999-8999-999999999999")
	controller := true
	owner := func(kind, name string, uid types.UID) []metav1.OwnerReference {
		apiVersion := "apps/v1"
		if kind == "Service" {
			apiVersion = "v1"
		}
		return []metav1.OwnerReference{{APIVersion: apiVersion, Kind: kind, Name: name, UID: uid, Controller: &controller}}
	}
	oldLabels := map[string]string{"app": "voice-bot"}
	newLabels := map[string]string{podBoundOwnerLabel: nonce, "r6th.io/owned": "true", "r6th.io/scenario": "c2-pod-bound-api-auth-response", "r6th.io/trial": "0"}
	ready := true
	readyStatus := corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1", ContainerStatuses: []corev1.ContainerStatus{{Name: "responder", Ready: true}}, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
	sourceLabels := map[string]string{}
	for k, v := range newLabels {
		sourceLabels[k] = v
	}
	sourceLabels[podBoundRoleLabel] = "source"
	replicas := int32(2)
	objects := []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice", UID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: oldDepUID}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: oldLabels}}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-rs", Namespace: "voice", UID: oldRSUID, Labels: oldLabels, OwnerReferences: owner("Deployment", "voice-bot", oldDepUID)}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: oldSvcUID}, Spec: corev1.ServiceSpec{Selector: oldLabels}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: oldPDBUID}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: oldLabels}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-old", Namespace: "voice", UID: oldPodUID, Labels: oldLabels, OwnerReferences: owner("ReplicaSet", "voice-bot-rs", oldRSUID)}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "voice", UID: newDepUID}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{podBoundOwnerLabel: nonce}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: newLabels}}}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: name + "-rs", Namespace: "voice", UID: newRSUID, Labels: newLabels, OwnerReferences: owner("Deployment", name, newDepUID)}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "voice", UID: newSvcUID}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{podBoundOwnerLabel: nonce}}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "voice", UID: "aaaa1111-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, Spec: policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{podBoundOwnerLabel: nonce}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-rs-a", Namespace: "voice", UID: sourceUID, Labels: sourceLabels, OwnerReferences: owner("ReplicaSet", name+"-rs", newRSUID)}, Spec: corev1.PodSpec{NodeName: "node"}, Status: readyStatus},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-rs-b", Namespace: "voice", UID: peerUID, Labels: newLabels, OwnerReferences: owner("ReplicaSet", name+"-rs", newRSUID)}, Spec: corev1.PodSpec{NodeName: "node"}, Status: readyStatus},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "manager", Namespace: "phorvex-system", UID: "manager-dep", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: func() *int32 { v := int32(1); return &v }(), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "manager"}}}, Status: appsv1.DeploymentStatus{ReadyReplicas: 1, ObservedGeneration: 1}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "manager-pod", Namespace: "phorvex-system", UID: "manager-pod-uid", Labels: map[string]string{"app": "manager"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.2", ContainerStatuses: []corev1.ContainerStatus{{Name: "manager", Ready: true, ContainerID: "containerd://manager", ImageID: "manager@sha256:abc", RestartCount: 0}}, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}},
	}
	slice := func(service string, uids ...types.UID) *discoveryv1.EndpointSlice {
		serviceUID := newSvcUID
		if service == "voice-bot" {
			serviceUID = oldSvcUID
		}
		out := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: service + "-slice", Namespace: "voice", Labels: map[string]string{discoveryv1.LabelServiceName: service}, OwnerReferences: owner("Service", service, serviceUID)}}
		for _, uid := range uids {
			out.Endpoints = append(out.Endpoints, discoveryv1.Endpoint{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "voice", UID: uid}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
		}
		return out
	}
	objects = append(objects, slice("voice-bot", oldPodUID), slice(name, sourceUID, peerUID))
	kc := kfake.NewSimpleClientset(objects...)
	policies := &v1alpha1.PhorvexPolicyList{Items: []v1alpha1.PhorvexPolicy{
		{TypeMeta: metav1.TypeMeta{APIVersion: "phorvex.ai/v1alpha1", Kind: "PhorvexPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: "voice-defense", Namespace: "voice", UID: "old-policy", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: oldLabels}, Mode: "active"}},
		{TypeMeta: metav1.TypeMeta{APIVersion: "phorvex.ai/v1alpha1", Kind: "PhorvexPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "voice", UID: "new-policy", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: nonce, Selector: metav1.LabelSelector{MatchLabels: map[string]string{podBoundOwnerLabel: nonce, podBoundRoleLabel: "source"}}, Mode: "active"}},
	}}
	cfg.Exec = func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || len(args) < 6 || args[2] != "get" || args[3] != "phorvexpolicy" {
			return "", os.ErrInvalid
		}
		if len(args) == 7 {
			for i := range policies.Items {
				if policies.Items[i].Name == args[4] {
					raw, err := json.Marshal(policies.Items[i])
					return string(raw), err
				}
			}
			return "", os.ErrNotExist
		}
		raw, err := json.Marshal(policies)
		return string(raw), err
	}
	policyRaw, _ := json.Marshal(policies.Items[1])
	var policyJSON map[string]any
	if err := json.Unmarshal(policyRaw, &policyJSON); err != nil {
		t.Fatal(err)
	}
	specRaw, _ := json.Marshal(policyJSON["spec"])
	r := podBoundTokenRequest{RunID: "run-6", Nonce: nonce, ClusterUID: "cluster-uid", Namespace: "voice", NamespaceUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", SourcePodName: name + "-rs-a", SourcePodUID: string(sourceUID), PeerPodName: name + "-rs-b", PeerPodUID: string(peerUID), ServiceName: name, ServiceUID: string(newSvcUID), DeploymentUID: string(newDepUID), ReplicaSetUID: string(newRSUID), PolicyName: name, PolicyUID: "new-policy", PolicyGeneration: 1, PolicySpecSHA256: podBoundHash(specRaw), ProfileSHA256: strings.Repeat("a", 64), ManagerPodUID: "manager-pod-uid", ManagerContainerID: "containerd://manager", ManagerImageID: "manager@sha256:abc"}
	p := podBoundTokenProfile{Context: defaultTargetID, Namespace: "voice"}
	p.Fixture.RunID = r.RunID
	p.Fixture.Nonce = nonce
	p.Fixture.ClusterUID = r.ClusterUID
	p.Fixture.ManagerNamespace = "phorvex-system"
	p.Fixture.ManagerDeployment = "manager"
	p.Fixture.ManagerImageID = r.ManagerImageID
	p.Fixture.AllowedNodeName = "node"
	return podBoundLivePeerFixture{s: &Server{cfg: cfg, runs: rm}, kc: kc, r: r, p: p, policy: policies}
}

func TestPodBoundTokenDisjointLiveGraph(t *testing.T) {
	t.Run("actual-graph", func(t *testing.T) {
		f := podBoundLivePeer(t)
		if err := f.s.podBoundTokenDisjointLive(context.Background(), f.kc, f.r, f.p); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, f *podBoundLivePeerFixture)
	}{
		{"old-selector-overlap", func(t *testing.T, f *podBoundLivePeerFixture) {
			d, e := f.kc.AppsV1().Deployments("voice").Get(context.Background(), "voice-bot", metav1.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			d.Spec.Selector.MatchLabels = map[string]string{podBoundOwnerLabel: f.r.Nonce}
			if _, e = f.kc.AppsV1().Deployments("voice").Update(context.Background(), d, metav1.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
		}},
		{"source-label-overlap", func(t *testing.T, f *podBoundLivePeerFixture) {
			p, e := f.kc.CoreV1().Pods("voice").Get(context.Background(), f.r.SourcePodName, metav1.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			p.Labels["app"] = "voice-bot"
			if _, e = f.kc.CoreV1().Pods("voice").Update(context.Background(), p, metav1.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
		}},
		{"old-target-uid-reuse", func(t *testing.T, f *podBoundLivePeerFixture) {
			p, e := f.kc.CoreV1().Pods("voice").Get(context.Background(), f.r.SourcePodName, metav1.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			p.UID = "11111111-1111-4111-8111-111111111111"
			f.r.SourcePodUID = string(p.UID)
			if _, e = f.kc.CoreV1().Pods("voice").Update(context.Background(), p, metav1.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
		}},
		{"source-owner-drift", func(t *testing.T, f *podBoundLivePeerFixture) {
			p, e := f.kc.CoreV1().Pods("voice").Get(context.Background(), f.r.SourcePodName, metav1.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			p.OwnerReferences[0].UID = "wrong"
			if _, e = f.kc.CoreV1().Pods("voice").Update(context.Background(), p, metav1.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
		}},
		{"old-service-routes-new", func(t *testing.T, f *podBoundLivePeerFixture) {
			s, e := f.kc.DiscoveryV1().EndpointSlices("voice").Get(context.Background(), "voice-bot-slice", metav1.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			ready := true
			s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "voice", UID: types.UID(f.r.SourcePodUID)}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
			if _, e = f.kc.DiscoveryV1().EndpointSlices("voice").Update(context.Background(), s, metav1.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
		}},
		{"new-service-routes-old", func(t *testing.T, f *podBoundLivePeerFixture) {
			s, e := f.kc.DiscoveryV1().EndpointSlices("voice").Get(context.Background(), f.r.ServiceName+"-slice", metav1.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			ready := true
			s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "voice", UID: "99999999-9999-4999-8999-999999999999"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
			if _, e = f.kc.DiscoveryV1().EndpointSlices("voice").Update(context.Background(), s, metav1.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
		}},
		{"policy-overlap", func(_ *testing.T, f *podBoundLivePeerFixture) {
			f.policy.Items = append(f.policy.Items, v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "voice", UID: "other", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{podBoundOwnerLabel: f.r.Nonce}}, Mode: "active"}})
		}},
		{"actual-label-policy-overlap", func(t *testing.T, f *podBoundLivePeerFixture) {
			pod, err := f.kc.CoreV1().Pods("voice").Get(context.Background(), f.r.SourcePodName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pod.Labels["extra"] = "matched"
			if _, err := f.kc.CoreV1().Pods("voice").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			f.policy.Items = append(f.policy.Items, v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "voice", UID: "other", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"extra": "matched"}}, Mode: "active"}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := podBoundLivePeer(t)
			tc.mutate(t, &f)
			if err := f.s.podBoundTokenDisjointLive(context.Background(), f.kc, f.r, f.p); err == nil {
				t.Fatal("overlapping or changed graph accepted")
			}
		})
	}
}

func TestPodBoundTokenDisjointAfterExactRotateReceipt(t *testing.T) {
	f := podBoundLivePeer(t)
	barrier := podBoundTokenBarrier{RunID: f.r.RunID, Nonce: f.r.Nonce, Event: PodBoundTokenEvent{SourcePodUID: f.r.SourcePodUID}, Decision: PodBoundTokenDecision{SelectedAction: "rotate"}, Operation: PodBoundTokenOperation{TerminationStatus: "REQUEST_CONFIRMED", ReceiptSHA256: strings.Repeat("b", 64)}}
	if err := f.kc.CoreV1().Pods("voice").Delete(context.Background(), f.r.SourcePodName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	peer, err := f.kc.CoreV1().Pods("voice").Get(context.Background(), f.r.PeerPodName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	replacement := peer.DeepCopy()
	replacement.Name = "pod-token-" + f.r.Nonce + "-rs-c"
	replacement.UID = "aaaaaaaa-1111-4111-8111-111111111111"
	if _, err := f.kc.CoreV1().Pods("voice").Create(context.Background(), replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	slice, err := f.kc.DiscoveryV1().EndpointSlices("voice").Get(context.Background(), f.r.ServiceName+"-slice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range slice.Endpoints {
		if slice.Endpoints[i].TargetRef.UID == types.UID(f.r.SourcePodUID) {
			slice.Endpoints[i].TargetRef.UID = replacement.UID
		}
	}
	if _, err := f.kc.DiscoveryV1().EndpointSlices("voice").Update(context.Background(), slice, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.podBoundTokenDisjointAfterReceipt(context.Background(), f.kc, f.r, f.p, barrier); err != nil {
		t.Fatal(err)
	}
	barrier.Operation.ReceiptSHA256 = ""
	if err := f.s.podBoundTokenDisjointAfterReceipt(context.Background(), f.kc, f.r, f.p, barrier); err == nil {
		t.Fatal("missing receipt admitted after source absence")
	}
	barrier.Operation.ReceiptSHA256 = strings.Repeat("b", 64)
	peer.UID = "changed"
	if _, err := f.kc.CoreV1().Pods("voice").Update(context.Background(), peer, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.podBoundTokenDisjointAfterReceipt(context.Background(), f.kc, f.r, f.p, barrier); err == nil {
		t.Fatal("peer drift admitted after source absence")
	}
}
