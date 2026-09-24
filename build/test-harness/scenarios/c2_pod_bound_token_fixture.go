package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const podTokenOwnerLabel = "fixture.phorvex.ai/token-response"
const podTokenRoleLabel = "fixture.phorvex.ai/role"
const podTokenPhaseFile = "pod-bound-token-phases.jsonl"
const podTokenPort = 8080

// The counter is changed only by actual /ready requests. The Kubernetes Pod
// UID and nonce in the reply let a routed Service response identify its member.
const podTokenServerSource = `import http.server,json,os,threading
uid=os.environ["POD_UID"]; nonce=os.environ["NONCE"]; count=0; lock=threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  global count
  if self.path=="/ready":
   with lock: count+=1
   body=json.dumps({"podUID":uid,"nonce":nonce},separators=(",",":")).encode()
   self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
  elif self.path=="/metrics":
   with lock: current=count
   body=("# TYPE http_requests_total counter\nhttp_requests_total{namespace=\"voice\",pod=\""+os.environ["POD_NAME"]+"\",nonce=\""+nonce+"\"} "+str(current)+"\n").encode()
   self.send_response(200);self.send_header("Content-Type","text/plain; version=0.0.4");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
  else: self.send_error(404)
http.server.ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
`

type podTokenFixture struct {
	name             string
	namespaceUID     types.UID
	created          map[string]types.UID
	deploymentUID    types.UID
	replicaSetUID    types.UID
	source           corev1.Pod
	peer             corev1.Pod
	serviceUID       types.UID
	policyUID        types.UID
	policyGeneration int64
	policySpecSHA    string
	monitorUID       types.UID
	sourceOriginalRV string
}

func podTokenName(nonce string) string { return "pod-token-" + nonce }
func podTokenLabels(nonce string) map[string]string {
	return map[string]string{podTokenOwnerLabel: nonce, core.OwnedLabelKey: core.OwnedLabelValue, core.ScenarioLabelKey: "c2-pod-bound-api-auth-response", core.TrialLabelKey: "0"}
}
func podTokenCreatePhase(env *core.Env, operation, resource, name string, uid types.UID) error {
	if env == nil || env.Config.PodBoundTokenFixture == nil || len(operation) > 32 || len(resource) > 64 || len(name) > 128 {
		return errors.New("Pod token phase identity invalid")
	}
	row := map[string]string{"schema": "pod-bound-token-phase-v1", "runID": env.Config.PodBoundTokenFixture.RunID, "nonce": env.Config.PodBoundTokenFixture.Nonce, "operation": operation, "resource": resource, "name": name, "uid": string(uid), "at": podTokenUTC()}
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if len(raw) > 2048 {
		return errors.New("Pod token phase oversized")
	}
	path := filepath.Join(env.Config.OutDir, podTokenPhaseFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if n, e := f.Write(append(raw, '\n')); e != nil || n != len(raw)+1 {
		return errors.New("Pod token phase write incomplete")
	}
	return f.Sync()
}
func podTokenAck(env *core.Env, f *podTokenFixture, resource, name string, uid types.UID) error {
	if uid == "" {
		return errors.New("Pod token create returned no UID")
	}
	if err := env.RecordCreatedUID(resource, name, uid); err != nil {
		return err
	}
	if err := podTokenCreatePhase(env, "CREATE_ACK", resource, name, uid); err != nil {
		return err
	}
	if f.created == nil {
		f.created = map[string]types.UID{}
	}
	f.created[resource+"/"+name] = uid
	return nil
}
func podTokenIntent(env *core.Env, resource, name string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	return podTokenCreatePhase(env, "CREATE_INTENT", resource, name, "")
}

func podTokenPolicyObject(env *core.Env, name string) *unstructured.Unstructured {
	nonce := env.Config.PodBoundTokenFixture.Nonce
	p := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy",
		"metadata": map[string]any{"name": name, "namespace": env.Config.Namespace, "labels": map[string]any{podTokenOwnerLabel: nonce, core.OwnedLabelKey: core.OwnedLabelValue}},
		"spec": map[string]any{"tenant": nonce, "selector": map[string]any{"matchLabels": map[string]any{podTokenOwnerLabel: nonce, podTokenRoleLabel: "source"}},
			"mode": "active", "actions": map[string]any{"enabled": []any{"rotate", "quarantine"}},
			"triggers":   map[string]any{"eventDriven": true, "reactiveOnly": true, "eventAgeHorizon": "1h"},
			"budget":     map[string]any{"tickInterval": "5s", "antiOverRotationWindow": "90s", "proactiveFloor": "15m", "maxMovesPerTick": int64(1), "maxGracePeriodSeconds": int64(30)},
			"slo":        map[string]any{"minAvailableReplicas": int64(1), "costCeiling": "1.2"},
			"objective":  map[string]any{"costWeights": map[string]any{"normSparsity": "0.4", "flowDisruption": "0.6"}, "lambda": "0.4"},
			"assetValue": map[string]any{"weightSecrets": "0.8", "blastRadiusFromGraph": false}}}}
	p.SetGroupVersionKind(natsResponsePolicyGVK)
	return p
}
func podTokenMonitor(env *core.Env, name string) *unstructured.Unstructured {
	nonce := env.Config.PodBoundTokenFixture.Nonce
	m := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "monitoring.coreos.com/v1", "kind": "PodMonitor",
		"metadata": map[string]any{"name": name, "namespace": env.Config.Namespace, "labels": map[string]any{podTokenOwnerLabel: nonce, core.OwnedLabelKey: core.OwnedLabelValue}},
		"spec": map[string]any{"selector": map[string]any{"matchLabels": map[string]any{podTokenOwnerLabel: nonce}},
			"namespaceSelector":   map[string]any{"matchNames": []any{env.Config.Namespace}},
			"podMetricsEndpoints": []any{map[string]any{"port": "metrics", "path": "/metrics", "interval": "30s"}}}}}
	m.SetGroupVersionKind(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "PodMonitor"})
	return m
}
func podTokenDeployment(env *core.Env, name string) *appsv1.Deployment {
	nonce := env.Config.PodBoundTokenFixture.Nonce
	labels := podTokenLabels(nonce)
	no, yes := false, true
	replicas := int32(2)
	user := int64(65532)
	expiry := int64(600)
	template := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
		NodeName: env.Config.PodBoundTokenFixture.AllowedNodeName, ServiceAccountName: name, AutomountServiceAccountToken: &no,
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &user, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers: []corev1.Container{{Name: "responder", Image: env.Config.PodBoundTokenFixture.FixtureImageID, ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"python3", "-B", "-c", podTokenServerSource},
			Env:             []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}, {Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}, {Name: "NONCE", Value: nonce}},
			Ports:           []corev1.ContainerPort{{Name: "metrics", ContainerPort: podTokenPort}},
			ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromString("metrics")}}, PeriodSeconds: 3, TimeoutSeconds: 1},
			Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("20m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "pod-bound-token", MountPath: "/var/run/pod-token", ReadOnly: true}}}},
		Volumes: []corev1.Volume{{Name: "pod-bound-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &expiry}}}}}}}}}
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace, Labels: labels}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{podTokenOwnerLabel: nonce}}, Template: template}}
}
func podTokenReady(p corev1.Pod) bool {
	if p.UID == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || len(p.Status.ContainerStatuses) != 1 || !p.Status.ContainerStatuses[0].Ready {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func podTokenAwaitPods(ctx context.Context, env *core.Env, f *podTokenFixture) error {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		list, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: podTokenOwnerLabel + "=" + env.Config.PodBoundTokenFixture.Nonce, Limit: 10})
		if err == nil && list.Continue == "" && len(list.Items) == 2 && podTokenReady(list.Items[0]) && podTokenReady(list.Items[1]) {
			sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
			a, b := list.Items[0], list.Items[1]
			if a.UID == b.UID || a.Spec.NodeName != env.Config.PodBoundTokenFixture.AllowedNodeName || b.Spec.NodeName != a.Spec.NodeName {
				return errors.New("Pod token serving Pod identity differs")
			}
			if len(a.OwnerReferences) != 1 || len(b.OwnerReferences) != 1 || a.OwnerReferences[0].UID == "" || a.OwnerReferences[0].UID != b.OwnerReferences[0].UID {
				return errors.New("Pod token ReplicaSet ownership differs")
			}
			rs, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, a.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil || rs.UID != a.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].UID != f.deploymentUID {
				return errors.New("Pod token Deployment ownership differs")
			}
			f.replicaSetUID = rs.UID
			f.source = a
			f.peer = b
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func podTokenEndpointMember(ctx context.Context, env *core.Env, f podTokenFixture, uid types.UID) error {
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + f.name, Limit: 20})
	if err != nil || slices.Continue != "" || len(slices.Items) == 0 {
		return errors.New("Pod token Service EndpointSlice unavailable")
	}
	for _, s := range slices.Items {
		for _, e := range s.Endpoints {
			if e.TargetRef != nil && e.TargetRef.Kind == "Pod" && e.TargetRef.UID == uid && e.Conditions.Ready != nil && *e.Conditions.Ready {
				return nil
			}
		}
	}
	return errors.New("Pod token routed member absent from Ready EndpointSlice")
}
func podTokenPolicyDigest(p *unstructured.Unstructured) string {
	raw, _ := json.Marshal(p.Object["spec"])
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func podTokenFixtureCreate(ctx context.Context, env *core.Env) (podTokenFixture, error) {
	var f podTokenFixture
	cfg := env.Config.PodBoundTokenFixture
	if cfg == nil || env.Config.Namespace != "voice" || env.NamespaceUID() == "" || env.Ctrl == nil || env.Kube == nil || env.Rest == nil {
		return f, errors.New("Pod token fixture authority unavailable")
	}
	f.name = podTokenName(cfg.Nonce)
	f.namespaceUID = env.NamespaceUID()
	ns := env.Config.Namespace
	labels := podTokenLabels(cfg.Nonce)
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: f.name, Namespace: ns, Labels: labels}, AutomountServiceAccountToken: func() *bool { v := false; return &v }()}
	if err := podTokenIntent(env, "serviceaccounts", f.name); err != nil {
		return f, err
	}
	madeSA, err := env.Kube.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return f, err
	}
	if err = podTokenAck(env, &f, "serviceaccounts", f.name, madeSA.UID); err != nil {
		return f, err
	}
	dep := podTokenDeployment(env, f.name)
	if err = podTokenIntent(env, "deployments", f.name); err != nil {
		return f, err
	}
	madeDep, err := env.Kube.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{})
	if err != nil {
		return f, err
	}
	f.deploymentUID = madeDep.UID
	if err = podTokenAck(env, &f, "deployments", f.name, madeDep.UID); err != nil {
		return f, err
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: f.name, Namespace: ns, Labels: labels}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{podTokenOwnerLabel: cfg.Nonce}, Ports: []corev1.ServicePort{{Name: "http", Port: podTokenPort, TargetPort: intstr.FromString("metrics")}}}}
	if err = podTokenIntent(env, "services", f.name); err != nil {
		return f, err
	}
	madeSvc, err := env.Kube.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil {
		return f, err
	}
	f.serviceUID = madeSvc.UID
	if err = podTokenAck(env, &f, "services", f.name, madeSvc.UID); err != nil {
		return f, err
	}
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: f.name, Namespace: ns, Labels: labels}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: ptrIntstr(intstr.FromInt(1)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{podTokenOwnerLabel: cfg.Nonce}}}}
	if err = podTokenIntent(env, "poddisruptionbudgets", f.name); err != nil {
		return f, err
	}
	madePDB, err := env.Kube.PolicyV1().PodDisruptionBudgets(ns).Create(ctx, pdb, metav1.CreateOptions{})
	if err != nil {
		return f, err
	}
	if err = podTokenAck(env, &f, "poddisruptionbudgets", f.name, madePDB.UID); err != nil {
		return f, err
	}
	if err = podTokenAwaitPods(ctx, env, &f); err != nil {
		return f, err
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: f.name, Namespace: ns, Labels: labels}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{f.peer.Name}, Verbs: []string{"get"}}}}
	if err = podTokenIntent(env, "roles", f.name); err != nil {
		return f, err
	}
	madeRole, err := env.Kube.RbacV1().Roles(ns).Create(ctx, role, metav1.CreateOptions{})
	if err != nil {
		return f, err
	}
	if err = podTokenAck(env, &f, "roles", f.name, madeRole.UID); err != nil {
		return f, err
	}
	binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: f.name, Namespace: ns, Labels: labels}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: f.name, Namespace: ns}}, RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: f.name}}
	if err = podTokenIntent(env, "rolebindings", f.name); err != nil {
		return f, err
	}
	madeBinding, err := env.Kube.RbacV1().RoleBindings(ns).Create(ctx, binding, metav1.CreateOptions{})
	if err != nil {
		return f, err
	}
	if err = podTokenAck(env, &f, "rolebindings", f.name, madeBinding.UID); err != nil {
		return f, err
	}
	source := f.source.DeepCopy()
	f.sourceOriginalRV = source.ResourceVersion
	if source.Labels == nil {
		source.Labels = map[string]string{}
	}
	source.Labels[podTokenRoleLabel] = "source"
	if err = podTokenCreatePhase(env, "PATCH_INTENT", "pods", source.Name, source.UID); err != nil {
		return f, err
	}
	updated, err := env.Kube.CoreV1().Pods(ns).Update(ctx, source, metav1.UpdateOptions{})
	if err != nil || updated.UID != source.UID {
		return f, errors.New("Pod token source role patch ambiguous")
	}
	f.source = *updated
	if err = podTokenCreatePhase(env, "PATCH_ACK", "pods", source.Name, source.UID); err != nil {
		return f, err
	}
	policy := podTokenPolicyObject(env, f.name)
	if err = podTokenIntent(env, "phorvexpolicies", f.name); err != nil {
		return f, err
	}
	if err = env.Ctrl.Create(ctx, policy); err != nil {
		return f, err
	}
	f.policyUID = policy.GetUID()
	f.policyGeneration = policy.GetGeneration()
	f.policySpecSHA = podTokenPolicyDigest(policy)
	if err = podTokenAck(env, &f, "phorvexpolicies", f.name, policy.GetUID()); err != nil {
		return f, err
	}
	monitor := podTokenMonitor(env, f.name)
	if err = podTokenIntent(env, "podmonitors", f.name); err != nil {
		return f, err
	}
	if err = env.Ctrl.Create(ctx, monitor); err != nil {
		return f, err
	}
	f.monitorUID = monitor.GetUID()
	if err = podTokenAck(env, &f, "podmonitors", f.name, monitor.GetUID()); err != nil {
		return f, err
	}
	for _, p := range []corev1.Pod{f.source, f.peer} {
		if err = podTokenEndpointMember(ctx, env, f, p.UID); err != nil {
			return f, err
		}
	}
	return f, nil
}

func podTokenCurrentPod(ctx context.Context, env *core.Env, p corev1.Pod) error {
	got, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	if err != nil || got.UID != p.UID || !podTokenReady(*got) || got.Status.ContainerStatuses[0].ImageID != env.Config.PodBoundTokenFixture.FixtureImageID {
		return errors.New("Pod token serving Pod changed")
	}
	return nil
}
func podTokenCurrentPolicy(ctx context.Context, env *core.Env, f podTokenFixture) error {
	p := &unstructured.Unstructured{}
	p.SetGroupVersionKind(natsResponsePolicyGVK)
	if err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: env.Config.Namespace, Name: f.name}, p); err != nil || p.GetUID() != f.policyUID || p.GetGeneration() != f.policyGeneration || podTokenPolicyDigest(p) != f.policySpecSHA {
		return errors.New("Pod token policy changed")
	}
	return nil
}
func podTokenNoCollision(ctx context.Context, env *core.Env) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicyList"})
	if err := env.Ctrl.List(ctx, list, ctrlclient.InNamespace(env.Config.Namespace)); err != nil || list.GetContinue() != "" {
		return errors.New("Pod token policy inventory incomplete")
	}
	nonce := env.Config.PodBoundTokenFixture.Nonce
	baseLabels := labels.Set(podTokenLabels(nonce))
	sourceLabels := labels.Set(podTokenLabels(nonce))
	sourceLabels[podTokenRoleLabel] = "source"
	for i := range list.Items {
		tenant, found, err := unstructured.NestedString(list.Items[i].Object, "spec", "tenant")
		if err != nil || !found || tenant == nonce {
			return errors.New("Pod token policy tenant collision or ambiguity")
		}
		selectorMap, found, err := unstructured.NestedMap(list.Items[i].Object, "spec", "selector")
		if err != nil || !found {
			return errors.New("existing Voice policy selector unavailable")
		}
		raw, err := json.Marshal(selectorMap)
		if err != nil || len(raw) > 16<<10 {
			return errors.New("existing Voice policy selector oversized")
		}
		var selector metav1.LabelSelector
		if json.Unmarshal(raw, &selector) != nil {
			return errors.New("existing Voice policy selector malformed")
		}
		compiled, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil || compiled.Empty() || compiled.Matches(baseLabels) || compiled.Matches(sourceLabels) {
			return errors.New("existing Voice policy selector overlaps nonce fixture")
		}
	}
	return nil
}

// The old Voice bot owns app=voice-bot. Refuse any selector overlap before
// creating a nonce fixture and recheck before emitting the one event request.
func podTokenDisjointPrecreate(ctx context.Context, env *core.Env) error {
	ns := env.Config.Namespace
	baseLabels := labels.Set(podTokenLabels(env.Config.PodBoundTokenFixture.Nonce))
	sourceLabels := labels.Set(podTokenLabels(env.Config.PodBoundTokenFixture.Nonce))
	sourceLabels[podTokenRoleLabel] = "source"
	overlaps := func(selector labels.Selector) bool {
		return selector.Matches(baseLabels) || selector.Matches(sourceLabels)
	}
	dep, err := env.Kube.AppsV1().Deployments(ns).Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.DeletionTimestamp != nil || dep.Spec.Selector == nil {
		return errors.New("old Voice Deployment authority unavailable")
	}
	depSelector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || depSelector.Empty() || overlaps(depSelector) {
		return errors.New("old Voice Deployment selector overlaps fixture")
	}
	svc, err := env.Kube.CoreV1().Services(ns).Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || svc.UID == "" || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) == 0 || overlaps(labels.SelectorFromSet(svc.Spec.Selector)) {
		return errors.New("old Voice Service selector overlaps fixture")
	}
	pdb, err := env.Kube.PolicyV1().PodDisruptionBudgets(ns).Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || pdb.UID == "" || pdb.DeletionTimestamp != nil || pdb.Spec.Selector == nil {
		return errors.New("old Voice PDB authority unavailable")
	}
	pdbSelector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil || pdbSelector.Empty() || overlaps(pdbSelector) {
		return errors.New("old Voice PDB selector overlaps fixture")
	}
	oldPods, err := env.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: "app=voice-bot", Limit: 10})
	if err != nil || oldPods.Continue != "" || len(oldPods.Items) == 0 {
		return errors.New("old Voice Pod graph unavailable")
	}
	for _, p := range oldPods.Items {
		if p.UID == "" || p.Labels[podTokenOwnerLabel] == env.Config.PodBoundTokenFixture.Nonce ||
			p.Labels["app"] != "voice-bot" {
			return errors.New("old Voice Pod overlaps nonce fixture")
		}
	}
	return nil
}
func podTokenIsNotFound(err error) bool  { return apierrors.IsNotFound(err) }
func podTokenUID(v types.UID) *types.UID { return &v }
func podTokenUIDDelete(v types.UID) metav1.DeleteOptions {
	return metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &v}}
}
func podTokenSortedUIDs(m map[string]types.UID) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"/"+string(v))
	}
	sort.Strings(out)
	return out
}
func podTokenFixtureSummary(f podTokenFixture) string {
	return strings.Join(podTokenSortedUIDs(f.created), ";")
}
