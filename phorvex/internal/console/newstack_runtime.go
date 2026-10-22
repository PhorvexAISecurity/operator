package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	phorvexv1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type newstackRuntime struct {
	server *Server
	kube   client.Client
	http   *http.Client
	run    *newstackRun
}

func newstackID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func crmFixtureSHA() string {
	sum := sha256.Sum256([]byte(newstackFixtureSource))
	return hex.EncodeToString(sum[:])
}

func newstackScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = discoveryv1.AddToScheme(scheme)
	_ = policyv1.AddToScheme(scheme)
	_ = phorvexv1.AddToScheme(scheme)
	_ = admissionv1.AddToScheme(scheme)
	_ = authenticationv1.AddToScheme(scheme)
	_ = authorizationv1.AddToScheme(scheme)
	return scheme
}

func (s *Server) newstackRuntime(run *newstackRun) (*newstackRuntime, error) {
	kube := s.cfg.newstackClient
	if kube == nil {
		config, err := s.podBoundRESTConfig()
		if err != nil {
			return nil, errors.New("in-cluster staging credentials unavailable")
		}
		config.Timeout = 5 * time.Second
		kube, err = client.New(config, client.Options{Scheme: newstackScheme()})
		if err != nil {
			return nil, errors.New("staging cluster client unavailable")
		}
	}
	h := s.cfg.newstackHTTP
	if h == nil {
		h = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fixture redirects are refused") }}
	}
	return &newstackRuntime{server: s, kube: kube, http: h, run: run}, nil
}

func (w *newstackRuntime) preflight(ctx context.Context, item newstackCase) error {
	namespace := &corev1.Namespace{}
	if err := w.kube.Get(ctx, client.ObjectKey{Name: newstackNamespace}, namespace); err != nil || namespace.UID == "" || namespace.DeletionTimestamp != nil {
		return errors.New("staging namespace identity unavailable")
	}
	lock := &corev1.ConfigMap{}
	if err := w.kube.Get(ctx, client.ObjectKey{Namespace: newstackNamespace, Name: newstackLaneName}, lock); err == nil {
		return errors.New("shared newstack lane is occupied; inspect retained run then use cleanup for its case")
	} else if !apierrors.IsNotFound(err) {
		return errors.New("shared newstack lane cannot be read")
	}
	if item.Fixture == "crm-refund" {
		for _, object := range []client.Object{&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "crm"}}, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: crmrefund.GuardConfigMapName}}, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "crm"}}, &phorvexv1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "crm-defense"}}} {
			if err := w.kube.Get(ctx, client.ObjectKey{Namespace: newstackNamespace, Name: object.GetName()}, object); err == nil {
				return newstackConflict(fmt.Sprintf("%T", object), object.GetName())
			} else if !apierrors.IsNotFound(err) {
				return errors.New("CRM collision inventory unavailable")
			}
		}
		var pods corev1.PodList
		if err := w.kube.List(ctx, &pods, client.InNamespace(newstackNamespace), client.MatchingLabels{"app": "crm"}); err != nil {
			return errors.New("CRM pod collision inventory unavailable")
		}
		if len(pods.Items) != 0 {
			return newstackConflict("Pod", "app=crm")
		}
	}
	if eventtrust.Injector() == "" || !strings.HasPrefix(eventtrust.Injector(), "system:serviceaccount:"+newstackNamespace+":") {
		return errors.New("trusted event injector must be the staging attacks ServiceAccount")
	}
	if item.Fixture == "crm-refund" && !crmrefund.NamespaceAllowed(newstackNamespace) {
		return errors.New("PHORVEX_CRM_REFUND_NAMESPACE=phorvex-staging is required for the CRM fixture")
	}
	if err := eventtrust.CheckIdentityPolicy(ctx, w.kube, w.server.cfg.NewstackIdentityPolicy); err != nil {
		return errors.New("installed SecurityEvent creator identity guard is unavailable or invalid")
	}
	if err := w.permissions(ctx); err != nil {
		return err
	}
	if w.server.cfg.AuditSource != nil {
		if _, err := w.server.cfg.AuditSource.Manifest(ctx); err != nil {
			return errors.New("authenticated brain audit source unavailable")
		}
	}
	return nil
}

// These authorization reviews are nonpersistent API queries. They establish
// the running ServiceAccount and its effective fixed-namespace permissions
// without creating a fixture or an attack signal.
func (w *newstackRuntime) permissions(ctx context.Context) error {
	identity := &authenticationv1.SelfSubjectReview{}
	if err := w.kube.Create(ctx, identity); err != nil || identity.Status.UserInfo.Username != eventtrust.Injector() {
		return errors.New("running ServiceAccount differs from the configured staging event injector")
	}
	for _, resource := range []struct {
		group, name string
		namespaced  bool
		verbs       []string
	}{
		{"", "configmaps", true, []string{"get", "list", "create", "delete"}},
		{"", "services", true, []string{"get", "list", "create", "delete"}},
		{"apps", "deployments", true, []string{"get", "list", "create", "delete"}},
		{"apps", "replicasets", true, []string{"get", "list"}},
		{"", "pods", true, []string{"get", "list"}},
		{"policy", "poddisruptionbudgets", true, []string{"get", "list", "create", "delete"}},
		{"discovery.k8s.io", "endpointslices", true, []string{"get", "list"}},
		{"phorvex.ai", "phorvexpolicies", true, []string{"get", "list", "create", "delete"}},
		{"amtd.r6security.com", "securityevents", false, []string{"get", "list", "create", "delete"}},
	} {
		for _, verb := range resource.verbs {
			attributes := &authorizationv1.ResourceAttributes{Group: resource.group, Resource: resource.name, Verb: verb}
			if resource.namespaced {
				attributes.Namespace = newstackNamespace
			}
			review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: attributes}}
			if err := w.kube.Create(ctx, review); err != nil || !review.Status.Allowed || review.Status.Denied || review.Status.EvaluationError != "" {
				return fmt.Errorf("staging attacks permission unavailable: %s %s", verb, resource.name)
			}
		}
	}
	return nil
}

func (w *newstackRuntime) metadata(name string, item newstackCase) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: newstackNamespace, Name: name, Labels: map[string]string{newstackRunLabel: w.run.RunID, newstackFixtureLabel: item.Fixture, "data-class": "restricted"}, Annotations: map[string]string{newstackIntentAnnotation: w.run.RunID}}
}

func (w *newstackRuntime) create(ctx context.Context, object client.Object) error {
	if object.GetObjectKind().GroupVersionKind().Kind == "" {
		gvk, err := w.kube.GroupVersionKindFor(object)
		if err != nil {
			return err
		}
		object.GetObjectKind().SetGroupVersionKind(gvk)
	}
	// The exact object name and ownership nonce are durable before its CREATE.
	w.run.Objects = append(w.run.Objects, newstackObjectRef(object))
	if err := w.evidence(fmt.Sprintf("object-%02d-intent.json", len(w.run.Objects)), object); err != nil {
		return errors.New("object source intent persistence failed")
	}
	if err := w.server.newstackSave(w.run); err != nil {
		return errors.New("object intent persistence failed")
	}
	if err := w.kube.Create(ctx, object); err != nil {
		return fmt.Errorf("create %s %s unavailable or colliding", object.GetObjectKind().GroupVersionKind().Kind, object.GetName())
	}
	w.run.Objects[len(w.run.Objects)-1] = newstackObjectRef(object)
	if err := w.evidence(fmt.Sprintf("object-%02d-created.json", len(w.run.Objects)), object); err != nil {
		return errors.New("created object evidence persistence failed")
	}
	if object.GetUID() == "" {
		return errors.New("created object UID missing")
	}
	return w.server.newstackSave(w.run)
}

func (w *newstackRuntime) acquire(ctx context.Context, item newstackCase) error {
	lock := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: w.metadata(newstackLaneName, item), Data: map[string]string{"runId": w.run.RunID, "caseId": item.ID}}
	if err := w.kube.Create(ctx, lock); err != nil {
		current := &corev1.ConfigMap{}
		if getErr := w.kube.Get(ctx, client.ObjectKey{Namespace: newstackNamespace, Name: newstackLaneName}, current); getErr == nil && newstackOwned(current, w.run) && current.Data["caseId"] == item.ID {
			w.run.LockUID = string(current.UID)
			_ = w.server.newstackSave(w.run)
		}
		return errors.New("shared newstack lane acquisition refused or acknowledgement ambiguous")
	}
	w.run.LockUID = string(lock.UID)
	if lock.UID == "" {
		return errors.New("shared lane UID missing")
	}
	return w.savePhase("lane-acquired")
}

func (w *newstackRuntime) provision(ctx context.Context, item newstackCase) error {
	name := newstackResourceName(item, w.run)
	source := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: w.metadata(name+"-fixture", item), Data: map[string]string{"fixture.py": newstackFixtureSource}}
	immutable := true
	source.Immutable = &immutable
	if err := w.create(ctx, source); err != nil {
		return err
	}
	if item.Fixture == "crm-refund" {
		guard := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: w.metadata(crmrefund.GuardConfigMapName, item), Data: map[string]string{crmrefund.GuardKey: `{"denied_order_ids":[]}`}}
		if err := w.create(ctx, guard); err != nil {
			return err
		}
		w.run.GuardUID = string(guard.UID)
	}
	selector := map[string]string{newstackRunLabel: w.run.RunID}
	if item.Fixture == "crm-refund" {
		selector = map[string]string{"app": "crm"}
	}
	service := &corev1.Service{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: w.metadata(name, item), Spec: corev1.ServiceSpec{Selector: selector, Ports: []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP}}}}
	if err := w.create(ctx, service); err != nil {
		return err
	}
	w.run.ServiceUID = string(service.UID)
	one := intstr.FromInt32(1)
	pdb := &policyv1.PodDisruptionBudget{TypeMeta: metav1.TypeMeta{APIVersion: "policy/v1", Kind: "PodDisruptionBudget"}, ObjectMeta: w.metadata(name, item), Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{newstackRunLabel: w.run.RunID}}}}
	if err := w.create(ctx, pdb); err != nil {
		return err
	}
	two := int32(2)
	grace := int64(5)
	off := false
	nonroot := true
	uid := int64(65532)
	mode := int32(0444)
	podmeta := w.metadata("", item)
	podmeta.Namespace = ""
	if item.Fixture == "crm-refund" {
		podmeta.Labels["app"] = "crm"
		podmeta.Annotations[crmrefund.GuardUIDAnnotation] = w.run.GuardUID
		podmeta.Annotations[crmrefund.ServiceUIDAnnotation] = w.run.ServiceUID
	}
	podspec := corev1.PodSpec{AutomountServiceAccountToken: &off, TerminationGracePeriodSeconds: &grace, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid, RunAsGroup: &uid, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}, Volumes: []corev1.Volume{{Name: "fixture", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: source.Name}, DefaultMode: &mode}}}}, Containers: []corev1.Container{{Name: "fixture", Image: newstackFixtureImage, ImagePullPolicy: corev1.PullIfNotPresent, Command: []string{"python3", "-u", "-B", "/fixture/fixture.py"}, Env: []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}}, Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}, VolumeMounts: []corev1.VolumeMount{{Name: "fixture", MountPath: "/fixture", ReadOnly: true}}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health", Port: intstr.FromInt32(8080)}}, PeriodSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 2}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("20m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &off, ReadOnlyRootFilesystem: &nonroot, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}}
	if item.Fixture == "crm-refund" {
		podspec.Volumes = append(podspec.Volumes, corev1.Volume{Name: "refund-guard", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: crmrefund.GuardConfigMapName}, DefaultMode: &mode}}})
		podspec.Containers[0].VolumeMounts = append(podspec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "refund-guard", MountPath: crmrefund.GuardMountPath, ReadOnly: true})
	}
	deploy := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: w.metadata(name, item), Spec: appsv1.DeploymentSpec{Replicas: &two, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{newstackRunLabel: w.run.RunID}}, Template: corev1.PodTemplateSpec{ObjectMeta: podmeta, Spec: podspec}}}
	if err := w.create(ctx, deploy); err != nil {
		return err
	}
	return w.savePhase("provisioned")
}

func (w *newstackRuntime) policy(ctx context.Context, item newstackCase) error {
	name := newstackResourceName(item, w.run) + "-defense"
	moves := 1
	grace := int64(5)
	policy := &phorvexv1.PhorvexPolicy{TypeMeta: metav1.TypeMeta{APIVersion: phorvexv1.GroupVersion.String(), Kind: "PhorvexPolicy"}, ObjectMeta: w.metadata(name, item), Spec: phorvexv1.PhorvexPolicySpec{Tenant: newstackNamespace, Mode: "active", Selector: metav1.LabelSelector{MatchLabels: map[string]string{newstackRunLabel: w.run.RunID}}, Objective: phorvexv1.ObjectiveSpec{DisruptionAversion: "0.1"}, Budget: phorvexv1.BudgetSpec{MaxMovesPerTick: &moves, MaxGracePeriodSeconds: &grace, TickInterval: metav1.Duration{Duration: 2 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: 24 * time.Hour}}, SLO: phorvexv1.SLOSpec{MinAvailableReplicas: 1, CostCeiling: "1000"}, AssetValue: phorvexv1.AssetValueSpec{FromLabels: map[string]phorvexv1.LabelValueWeights{"data-class": {"restricted": "1.0"}}}, Triggers: phorvexv1.TriggersSpec{EventDriven: true, ReactiveOnly: true, KillChainSource: []string{"redteam"}}, Actions: phorvexv1.ActionsSpec{Enabled: []phorvexv1.ActionType{phorvexv1.ActionType(item.Action)}}}}
	if err := w.create(ctx, policy); err != nil {
		return err
	}
	w.run.PolicyUID = string(policy.UID)
	w.run.PolicyGeneration = policy.Generation
	if policy.Generation < 1 {
		return errors.New("policy generation missing")
	}
	return w.savePhase("policy-ready")
}

func (w *newstackRuntime) roster(ctx context.Context, item newstackCase) ([]corev1.Pod, newstackSample, error) {
	var list corev1.PodList
	selector := map[string]string{newstackRunLabel: w.run.RunID}
	if item.Fixture == "crm-refund" {
		selector = map[string]string{"app": "crm"}
	}
	if err := w.kube.List(ctx, &list, client.InNamespace(newstackNamespace), client.MatchingLabels(selector)); err != nil {
		return nil, newstackSample{}, errors.New("fixture Pod inventory unavailable")
	}
	var pods []corev1.Pod
	byUID := map[string]corev1.Pod{}
	sample := newstackSample{At: time.Now().UTC().Format(time.RFC3339Nano), PodUIDs: []string{}}
	for i := range list.Items {
		pod := list.Items[i]
		if !newstackOwned(&pod, w.run) || pod.Labels[newstackFixtureLabel] != item.Fixture || pod.UID == "" {
			return nil, sample, errors.New("fixture Pod ownership differs")
		}
		if pod.DeletionTimestamp != nil {
			continue
		}
		pods = append(pods, pod)
		byUID[string(pod.UID)] = pod
		sample.PodUIDs = append(sample.PodUIDs, string(pod.UID))
		if podReady(&pod) {
			sample.Ready++
		}
	}
	var slices discoveryv1.EndpointSliceList
	if err := w.kube.List(ctx, &slices, client.InNamespace(newstackNamespace), client.MatchingLabels{discoveryv1.LabelServiceName: newstackResourceName(item, w.run)}); err != nil {
		return nil, sample, errors.New("fixture EndpointSlice inventory unavailable")
	}
	ready := map[string]bool{}
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || (endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
				continue
			}
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" {
				return nil, sample, errors.New("fixture ready endpoint is not Pod-bound")
			}
			pod, ok := byUID[string(endpoint.TargetRef.UID)]
			if !ok {
				continue
			} // propagation lag never earns serving credit
			if endpoint.TargetRef.Name != pod.Name || len(endpoint.Addresses) != 1 || endpoint.Addresses[0] != pod.Status.PodIP {
				return nil, sample, errors.New("fixture ready endpoint identity differs")
			}
			if podReady(&pod) {
				ready[string(pod.UID)] = true
			}
		}
	}
	sample.ReadyEndpoints = len(ready)
	sort.Strings(sample.PodUIDs)
	sort.Slice(pods, func(i, j int) bool {
		a, b := pods[i].CreationTimestamp.Time, pods[j].CreationTimestamp.Time
		if a.Equal(b) {
			return pods[i].Name < pods[j].Name
		}
		return a.Before(b)
	})
	return pods, sample, nil
}

func (w *newstackRuntime) stable(ctx context.Context, item newstackCase) error {
	for _, ref := range w.run.Objects {
		if ref.Kind != "Service" && ref.Kind != "PhorvexPolicy" && !(ref.Kind == "ConfigMap" && ref.Name == crmrefund.GuardConfigMapName) {
			continue
		}
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
		if err := w.kube.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, object); err != nil || !newstackOwned(object, w.run) || string(object.GetUID()) != ref.UID || object.GetDeletionTimestamp() != nil {
			return errors.New("fixture Service, policy or guard identity drift")
		}
		if ref.Kind == "PhorvexPolicy" && object.GetGeneration() != w.run.PolicyGeneration {
			return errors.New("fixture policy generation drift")
		}
	}
	var policies phorvexv1.PhorvexPolicyList
	if err := w.kube.List(ctx, &policies, client.InNamespace(newstackNamespace)); err != nil {
		return errors.New("policy selector inventory unavailable")
	}
	fixtureLabels := labels.Set{newstackRunLabel: w.run.RunID, newstackFixtureLabel: item.Fixture, "data-class": "restricted"}
	if item.Fixture == "crm-refund" {
		fixtureLabels["app"] = "crm"
	}
	for _, policy := range policies.Items {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
		if err != nil {
			return errors.New("another policy selector is invalid")
		}
		if selector.Matches(fixtureLabels) && string(policy.UID) != w.run.PolicyUID {
			return errors.New("another policy selects the disposable fixture")
		}
	}
	return nil
}

func (w *newstackRuntime) request(ctx context.Context, base, path string, body any, reply any) (int, error) {
	var reader io.Reader
	method := http.MethodGet
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(raw)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := w.http.Do(req)
	if err != nil {
		return 0, errors.New("fixture HTTP request unavailable")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return response.StatusCode, errors.New("fixture HTTP response unavailable")
	}
	if reply != nil && response.StatusCode == 200 {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(reply) != nil || d.Decode(new(any)) != io.EOF {
			return response.StatusCode, errors.New("fixture HTTP response contract differs")
		}
	}
	return response.StatusCode, nil
}

func newstackPodURL(pod corev1.Pod) string {
	return "http://" + net.JoinHostPort(pod.Status.PodIP, "8080")
}
func (w *newstackRuntime) serviceURL(item newstackCase) string {
	return "http://" + newstackResourceName(item, w.run) + "." + newstackNamespace + ".svc.cluster.local:8080"
}

func (w *newstackRuntime) baseline(ctx context.Context, item newstackCase, pods []corev1.Pod) error {
	for _, pod := range pods {
		var health struct {
			OK  bool   `json:"ok"`
			UID string `json:"pod_uid"`
		}
		code, err := w.request(ctx, newstackPodURL(pod), "/health", nil, &health)
		if err != nil || code != 200 || !health.OK || health.UID != string(pod.UID) {
			return errors.New("fixture exact-Pod health baseline unavailable")
		}
	}
	w.run.TargetPod = pods[0].Name
	w.run.TargetUID = string(pods[0].UID)
	w.run.PeerUID = string(pods[1].UID)
	if item.Fixture == "crm-refund" {
		for _, pair := range []struct{ phone, account, order string }{{crmLiveOrderPhone, crmLiveOrderAccountID, crmLiveOrderID}, {"+15551230001", crmLiveCallerAccountID, "OR-5001"}} {
			var orders struct {
				Account string `json:"account_id"`
				Orders  []struct {
					Order   string `json:"order_id"`
					Account string `json:"account_id"`
				} `json:"orders"`
			}
			code, err := w.request(ctx, w.serviceURL(item), "/orders/by-phone?phone="+url.QueryEscape(pair.phone), nil, &orders)
			if err != nil || code != 200 || orders.Account != pair.account || len(orders.Orders) != 1 || orders.Orders[0].Order != pair.order || orders.Orders[0].Account != pair.account {
				return errors.New("synthetic cross-account order ownership baseline differs")
			}
		}
		for _, pod := range pods {
			var guard crmGuardStateReply
			code, err := w.request(ctx, newstackPodURL(pod), "/phorvex-guard/state", nil, &guard)
			if err != nil || code != 200 || guard.DeniedOrderIDs == nil || len(guard.DeniedOrderIDs) != 0 {
				return errors.New("fresh CRM guard baseline is not empty on every replica")
			}
		}
		if ok, err := w.refund(ctx, w.serviceURL(item), crmLiveOrderID, 200); err != nil || !ok {
			return errors.New("real cross-record refund did not land")
		}
	} else {
		var installed struct {
			UID       string `json:"pod_uid"`
			Installed bool   `json:"installed"`
		}
		code, err := w.request(ctx, newstackPodURL(pods[0]), "/foothold", map[string]string{"marker": w.run.RunID}, &installed)
		if err != nil || code != 200 || !installed.Installed || installed.UID != w.run.TargetUID {
			return errors.New("synthetic pod-resident marker installation failed")
		}
		var state struct {
			UID     string   `json:"pod_uid"`
			Markers []string `json:"markers"`
		}
		code, err = w.request(ctx, newstackPodURL(pods[0]), "/foothold", nil, &state)
		if err != nil || code != 200 || state.UID != w.run.TargetUID || len(state.Markers) != 1 || state.Markers[0] != w.run.RunID {
			return errors.New("synthetic pod-resident foothold baseline did not land")
		}
	}
	w.run.BaselineLanded = true
	w.run.BaselineAt = time.Now().UTC().Format(time.RFC3339Nano)
	return w.savePhase("baseline-landed")
}

func (w *newstackRuntime) refund(ctx context.Context, base, order string, want int) (bool, error) {
	var reply struct {
		Refund string  `json:"refund_id"`
		Status string  `json:"status"`
		Order  string  `json:"order_id"`
		Amount float64 `json:"amount"`
	}
	code, err := w.request(ctx, base, "/refunds", map[string]any{"order_id": order, "amount": 0.01, "reason": "owned staging fixture cross-record trial"}, &reply)
	if err != nil || code != want {
		return false, err
	}
	if want == 403 {
		return true, nil
	}
	return reply.Refund != "" && reply.Status == "issued" && reply.Order == order && reply.Amount == 0.01, nil
}

func (w *newstackRuntime) event(ctx context.Context, item newstackCase) error {
	annotations := map[string]string{model.ConsoleTargetPodUIDAnnotation: w.run.TargetUID, newstackIntentAnnotation: w.run.RunID}
	rule := "Panic"
	if item.Fixture == "crm-refund" {
		observed, err := time.Parse(time.RFC3339Nano, w.run.BaselineAt)
		if err != nil {
			return err
		}
		observation := crmrefund.Observation{Version: 1, OrderID: crmLiveOrderID, OrderAccountID: crmLiveOrderAccountID, CallerAccountID: crmLiveCallerAccountID, GuardConfigMapUID: w.run.GuardUID, ServiceUID: w.run.ServiceUID, TargetPodUID: w.run.TargetUID, PeerPodUID: w.run.PeerUID, Objective: crmLiveScenario, ObservedAt: observed, PolicyName: newstackResourceName(item, w.run) + "-defense", PolicyUID: w.run.PolicyUID, PolicyGeneration: w.run.PolicyGeneration}
		raw, _ := json.Marshal(observation)
		annotations[crmrefund.ObservationAnnotation] = string(raw)
		rule = crmrefund.RuleType
	}
	name := "newstack-event-" + strings.TrimPrefix(w.run.RunID, "ns-")
	event := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent", "metadata": map[string]any{"name": name}, "spec": map[string]any{"description": "explicitly test-injected after measured disposable staging fixture stimulus", "targets": []any{newstackNamespace + "/" + w.run.TargetPod}, "rule": map[string]any{"type": rule, "threatLevel": "critical", "source": "redteam"}, "anomalyScore": "1.0000"}}}
	event.SetLabels(map[string]string{newstackRunLabel: w.run.RunID, newstackFixtureLabel: item.Fixture, "phorvex.ai/redteam": "true"})
	event.SetAnnotations(annotations)
	w.run.Stimulus = &attackStimulusEvidence{Kind: "test-injected-after-real-staging-fixture-stimulus", TargetUID: w.run.TargetUID, EventName: name, EventRule: rule, Correlation: w.run.RunID, BehavioralExecuted: true, Limitation: item.Limitation}
	if err := w.create(ctx, event); err != nil {
		return err
	}
	targets, _, _ := unstructured.NestedStringSlice(event.Object, "spec", "targets")
	actualRule, _, _ := unstructured.NestedString(event.Object, "spec", "rule", "type")
	source, _, _ := unstructured.NestedString(event.Object, "spec", "rule", "source")
	if event.GetNamespace() != "" || event.GetAnnotations()[eventtrust.CreatorIdentityAnnotation] != eventtrust.Injector() || event.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != w.run.TargetUID || len(targets) != 1 || targets[0] != newstackNamespace+"/"+w.run.TargetPod || actualRule != rule || source != "redteam" || event.GetCreationTimestamp().Time.IsZero() {
		return errors.New("created SecurityEvent admission identity differs")
	}
	if item.Fixture == "crm-refund" && event.GetAnnotations()[crmrefund.ObservationAnnotation] != annotations[crmrefund.ObservationAnnotation] {
		return errors.New("admitted CRM observation differs")
	}
	w.run.Stimulus.EventUID = string(event.GetUID())
	w.run.Stimulus.EventCreatedAt = event.GetCreationTimestamp().UTC().Format(time.RFC3339Nano)
	w.run.Stimulus.Observed = true
	return w.savePhase("trusted-event-created")
}

func newstackMatchDecision(row audit.Record, run *newstackRun, item newstackCase, collected time.Time) (decisionEvidence, bool) {
	if run.Stimulus == nil {
		return decisionEvidence{}, false
	}
	baseline, err := time.Parse(time.RFC3339Nano, run.BaselineAt)
	if err != nil || row.Time.Before(baseline) || row.Time.After(collected) {
		return decisionEvidence{}, false
	}
	trace := row.DecisionTrace
	if row.Kind != "phorvex.decision" || trace == nil || trace.Validate() != nil || trace.AssetNamespace != newstackNamespace || trace.AssetName != run.TargetPod || trace.AssetUID != run.TargetUID || trace.PolicyNamespace != newstackNamespace || trace.PolicyName != newstackResourceName(item, run)+"-defense" || trace.PolicyUID != run.PolicyUID || trace.DecisionID == "" || trace.TickID == "" || trace.SelectedAction != row.Action || trace.DispatchOutcome != row.DispatchOutcome {
		return decisionEvidence{}, false
	}
	record := &attackRecord{Namespace: newstackNamespace, Pod: run.TargetPod, TargetUID: run.TargetUID, ObservationStart: run.BaselineAt, ObservationEnd: collected.Add(time.Second).UTC().Format(time.RFC3339Nano), StimulusEvidence: run.Stimulus}
	evidence, ok := exactDecisionEvidence(record, &row, collected)
	if !ok || evidence.TrustVerdict != eventtrust.TrustTrusted || evidence.CreatorIdentity != eventtrust.Injector() || evidence.DeclaredSource != "redteam" {
		return decisionEvidence{}, false
	}
	trusted := 0
	for _, event := range row.Events {
		if event.TrustVerdict == eventtrust.TrustTrusted && event.Weight > 0 {
			trusted++
			if event.EventUID != run.Stimulus.EventUID || event.TargetPodUID != run.TargetUID {
				return decisionEvidence{}, false
			}
		}
	}
	if trusted != 1 {
		return decisionEvidence{}, false
	}
	return evidence, true
}

type newstackSampler struct {
	mu      sync.Mutex
	samples []newstackSample
	err     error
	cancel  context.CancelFunc
	done    chan struct{}
}

func (w *newstackRuntime) startSampler(ctx context.Context, item newstackCase, baseline newstackSample) *newstackSampler {
	ctx, cancel := context.WithCancel(ctx)
	monitor := &newstackSampler{samples: []newstackSample{baseline}, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(monitor.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			_, sample, err := w.roster(ctx, item)
			monitor.mu.Lock()
			if err != nil && ctx.Err() == nil {
				monitor.err = err
			}
			if err == nil {
				monitor.samples = append(monitor.samples, sample)
				if sample.Ready < 1 || sample.ReadyEndpoints < 1 {
					monitor.err = errors.New("fixture sampled availability fell below one Ready Pod or ready endpoint")
				}
			}
			failed := monitor.err != nil
			monitor.mu.Unlock()
			if failed {
				return
			}
		}
	}()
	return monitor
}
func (monitor *newstackSampler) failure() error {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	return monitor.err
}
func (monitor *newstackSampler) stop(run *newstackRun) error {
	monitor.cancel()
	<-monitor.done
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	run.AvailabilitySamples = append([]newstackSample(nil), monitor.samples...)
	run.MinimumReady = 2
	run.MinimumReadyEndpoints = 2
	for _, sample := range monitor.samples {
		run.MinimumReady = min(run.MinimumReady, sample.Ready)
		run.MinimumReadyEndpoints = min(run.MinimumReadyEndpoints, sample.ReadyEndpoints)
	}
	return monitor.err
}

func (w *newstackRuntime) execute(ctx context.Context, item newstackCase) (resultErr error) {
	if err := w.preflight(ctx, item); err != nil {
		return err
	}
	if err := w.acquire(ctx, item); err != nil {
		return err
	}
	if err := w.provision(ctx, item); err != nil {
		return err
	}
	startup, stopStartup := context.WithTimeout(ctx, 70*time.Second)
	var pods []corev1.Pod
	var baseline newstackSample
	err := newstackWait(startup, time.Second, func() (bool, error) {
		roster, sample, err := w.roster(startup, item)
		if err != nil {
			return false, err
		}
		if len(roster) == 2 && sample.Ready == 2 && sample.ReadyEndpoints == 2 {
			pods, baseline = roster, sample
			return true, nil
		}
		return false, nil
	})
	stopStartup()
	if err != nil {
		return errors.New("two-replica fixture baseline did not become fully Ready")
	}
	if err = w.policy(ctx, item); err != nil {
		return err
	}
	if err = w.stable(ctx, item); err != nil {
		return err
	}
	monitor := w.startSampler(ctx, item, baseline)
	defer func() {
		if err := monitor.stop(w.run); err != nil {
			resultErr = err
			w.run.Verdict = "UNKNOWN"
		}
		if err := w.server.newstackSave(w.run); err != nil {
			resultErr = errors.New("measured oracle persistence failed")
			w.run.Verdict = "UNKNOWN"
		}
	}()
	if err = w.baseline(ctx, item, pods); err != nil {
		return err
	}
	if err = w.stable(ctx, item); err != nil {
		return err
	}
	if err = w.event(ctx, item); err != nil {
		return err
	}
	// The event, target and baseline are fixed before the ordinary decision path is observed.
	// Neither this runner nor the fixture invokes the actuator or removes a Pod.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	nextAudit := time.Time{}
	for {
		if err = monitor.failure(); err != nil {
			return err
		}
		if err = w.stable(ctx, item); err != nil {
			return err
		}
		current, sample, rosterErr := w.roster(ctx, item)
		if rosterErr != nil {
			return rosterErr
		}
		if sample.Ready < 1 || sample.ReadyEndpoints < 1 {
			return errors.New("fixture availability floor failed")
		}
		if time.Now().After(nextAudit) {
			readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
			rows, readErr := w.server.readDecisionWindow(readCtx, "")
			readCancel()
			nextAudit = time.Now().Add(2 * time.Second)
			if readErr == nil {
				for i := range rows {
					if evidence, matched := newstackMatchDecision(rows[i], w.run, item, time.Now()); matched {
						// Keep the first selected action as an immutable causal identity. A later
						// actuation row may enrich only that same decision/tick/action.
						prior := w.run.Decision
						if prior == nil || (!prior.Selected && evidence.Selected) || (prior.DecisionID == evidence.DecisionID && prior.TickID == evidence.TickID && prior.Action == evidence.Action && evidence.Actuated) {
							w.run.Decision = &evidence
							if err = w.evidence("decision-original.json", rows[i]); err != nil {
								return errors.New("exact decision evidence persistence failed")
							}
						}
					}
				}
			}
		}
		decision := w.run.Decision
		if decision != nil && decision.Selected && decision.Action != item.Action {
			return errors.New("normal brain selected a different action")
		}
		if decision != nil && decision.Selected && decision.Actuated && decision.DispatchOutcome == model.DispatchEmitted && !decision.DryRun && !decision.KillSwitch && decision.Action == item.Action {
			if item.Fixture == "crm-refund" {
				if complete, oracleErr := w.crmOracle(ctx, item, current); oracleErr != nil {
					return oracleErr
				} else if complete {
					w.run.Verdict = "DEFENDED"
					return w.savePhase("oracle-complete")
				}
			} else if complete, oracleErr := w.rotateOracle(ctx, current, sample); oracleErr != nil {
				return oracleErr
			} else if complete {
				w.run.Verdict = "DEFENDED"
				return w.savePhase("oracle-complete")
			}
		}
		if err = w.server.newstackSave(w.run); err != nil {
			return errors.New("run evidence persistence failed")
		}
		select {
		case <-ctx.Done():
			return errors.New("bounded run deadline reached before exact brain actuation and oracle completed")
		case <-ticker.C:
		}
	}
}

func newstackWait(ctx context.Context, poll time.Duration, fn func() (bool, error)) error {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if ok, err := fn(); err != nil {
			return err
		} else if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *newstackRuntime) rotateOracle(ctx context.Context, pods []corev1.Pod, sample newstackSample) (bool, error) {
	// Explicit GET proves disappearance of the exact old incarnation, independently
	// of readiness and label-selector filtering. Same-name replacement is allowed.
	old := &corev1.Pod{}
	err := w.kube.Get(ctx, client.ObjectKey{Namespace: newstackNamespace, Name: w.run.TargetPod}, old)
	if err == nil && string(old.UID) == w.run.TargetUID {
		return false, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return false, errors.New("exact old Pod absence could not be confirmed")
	}
	if len(pods) != 2 || sample.Ready != 2 || sample.ReadyEndpoints != 2 {
		return false, nil
	}
	var replacement *corev1.Pod
	peerFound := false
	for i := range pods {
		if string(pods[i].UID) == w.run.TargetUID {
			return false, nil
		}
		if string(pods[i].UID) == w.run.PeerUID {
			peerFound = true
		} else {
			replacement = &pods[i]
		}
	}
	if !peerFound || replacement == nil || !podReady(replacement) {
		return false, nil
	}
	var state struct {
		UID     string   `json:"pod_uid"`
		Markers []string `json:"markers"`
	}
	code, err := w.request(ctx, newstackPodURL(*replacement), "/foothold", nil, &state)
	if err != nil || code != 200 || state.UID != string(replacement.UID) || state.Markers == nil || len(state.Markers) != 0 {
		return false, errors.New("fresh replacement did not prove cleared process marker")
	}
	w.run.OldUIDAbsent = true
	w.run.MarkerCleared = true
	w.run.ReplacementUID = string(replacement.UID)
	w.run.Recovered = true
	w.run.LegitimateSucceeded = true
	return true, nil
}

func (w *newstackRuntime) crmOracle(ctx context.Context, item newstackCase, pods []corev1.Pod) (bool, error) {
	if len(pods) != 2 {
		return false, errors.New("CRM serving roster changed")
	}
	foundTarget, foundPeer := false, false
	for _, pod := range pods {
		foundTarget = foundTarget || string(pod.UID) == w.run.TargetUID
		foundPeer = foundPeer || string(pod.UID) == w.run.PeerUID
	}
	if !foundTarget || !foundPeer {
		return false, errors.New("CRM exact target or peer UID changed")
	}
	for _, pod := range pods {
		var guard crmGuardStateReply
		code, err := w.request(ctx, newstackPodURL(pod), "/phorvex-guard/state", nil, &guard)
		if err != nil || code != 200 {
			return false, errors.New("CRM replica guard readback unavailable")
		}
		if len(guard.DeniedOrderIDs) != 1 || guard.DeniedOrderIDs[0] != crmLiveOrderID {
			return false, nil
		}
	}
	// Test each serving path directly and the installed Service, then verify an
	// unrelated legitimate order still succeeds on each path.
	bases := []string{w.serviceURL(item)}
	for _, pod := range pods {
		bases = append(bases, newstackPodURL(pod))
	}
	for _, base := range bases {
		denied, err := w.refund(ctx, base, crmLiveOrderID, 403)
		if err != nil || !denied {
			return false, errors.New("forbidden refund replay was not denied on every serving path")
		}
		kept, err := w.refund(ctx, base, "OR-5001", 200)
		if err != nil || !kept {
			return false, errors.New("legitimate refund did not continue on every serving path")
		}
	}
	w.run.EveryReplicaDenied = true
	w.run.ReplayDenied = true
	w.run.LegitimateSucceeded = true
	w.run.Recovered = true
	return true, nil
}

func (w *newstackRuntime) runWithCleanup(item newstackCase) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Second)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = errors.New("unexpected runner failure; exact run retained for cleanup")
			w.run.Verdict = "UNKNOWN"
		}
		if w.run.LockUID != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
			cleanupErr := w.cleanup(cleanupCtx)
			cleanupCancel()
			if cleanupErr != nil {
				err = errors.Join(err, errors.New("cleanup: "+cleanupErr.Error()))
				w.run.CleanupComplete = false
				w.run.Verdict = "UNKNOWN"
			}
		}
	}()
	return w.execute(ctx, item)
}
