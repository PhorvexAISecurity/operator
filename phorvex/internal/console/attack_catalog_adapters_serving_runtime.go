package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const servingCatalogueRunLabel = "phorvex.ai/attack-catalogue-serving-run"

type kubernetesServingCatalogueRuntime struct{ server *Server }

func newKubernetesServingCatalogueRuntime(server *Server) servingCatalogueRuntime {
	if server == nil {
		return unavailableServingCatalogueRuntime{reason: "serving catalogue attacks server is unavailable"}
	}
	return &kubernetesServingCatalogueRuntime{server: server}
}

type servingPolicyPin struct {
	UID        string
	Generation int64
}

type servingPodPin struct {
	Name, UID, ResourceVersion, IP, NodeName string
	RestartCount                             int32
}

type servingObjectPin struct {
	Name, UID, ResourceVersion string
}

type servingCatalogueKubePreparation struct {
	profileDigest string
	kube          kubernetes.Interface
	dynamic       dynamic.Interface
	policy        servingPolicyPin
	target        servingPodPin
	bystander     servingPodPin
	signal        servingCatalogueSignal
	decision      servingCatalogueDecision
	runID         string
	startedAt     time.Time
	jobs          []servingObjectPin
	rate          *servingRatePreparation
	sensitive     *sensitiveOutputPreparation
	kv            *servingKVPreparation
}

type servingRatePreparation struct {
	statusBaseline          servingRateStatusSnapshot
	budget, status, journal servingObjectPin
	journalOperationID      string
	loadImage, nodeName     string
}

type sensitiveOutputPreparation struct {
	configMap          servingObjectPin
	baselineActivation string
	restoredActivation string
	markerSHA256       string
	benignSHA256       string
	operationID        string
}

type servingKVPreparation struct {
	baselineResetCount uint64
	marker             string
	seededTarget       bool
	seededBystander    bool
}

func (r *kubernetesServingCatalogueRuntime) clients() (kubernetes.Interface, dynamic.Interface, error) {
	if r == nil || r.server == nil {
		return nil, nil, errors.New("serving catalogue server runtime is unavailable")
	}
	var cfg *rest.Config
	if r.server.cfg.ExperimentRESTConfig != nil {
		cfg = rest.CopyConfig(r.server.cfg.ExperimentRESTConfig)
	} else {
		var err error
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, nil, errors.New("in-cluster serving catalogue authority is unavailable")
		}
	}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, errors.New("serving catalogue Kubernetes client is unavailable")
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, errors.New("serving catalogue event client is unavailable")
	}
	return kube, dyn, nil
}

func (r *kubernetesServingCatalogueRuntime) Preflight(ctx context.Context, profile servingCatalogueProfile) (any, error) {
	if err := profile.validate(); err != nil {
		return nil, err
	}
	kube, dyn, err := r.clients()
	if err != nil {
		return nil, err
	}
	policy, err := servingCataloguePolicy(ctx, dyn, profile)
	if err != nil {
		return nil, err
	}
	p := &servingCatalogueKubePreparation{profileDigest: profile.digest(), kube: kube, dynamic: dyn, policy: policy}
	switch profile.Family {
	case servingRateFamily:
		err = preflightServingRate(ctx, profile, p)
	case sensitiveOutputFamily:
		err = preflightSensitiveOutput(ctx, profile, p)
	case servingKVFamily:
		err = preflightServingKV(ctx, profile, p)
	default:
		err = errors.New("unknown serving catalogue family")
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func servingCataloguePolicy(ctx context.Context, dyn dynamic.Interface, profile servingCatalogueProfile) (servingPolicyPin, error) {
	policy, err := dyn.Resource(phorvexPolicyGVR).Namespace(profile.Namespace).Get(ctx, profile.PolicyName, metav1.GetOptions{})
	if err != nil || policy.GetUID() == "" || policy.GetGeneration() < 1 || policy.GetDeletionTimestamp() != nil {
		return servingPolicyPin{}, errors.New("reviewed serving catalogue policy is unavailable")
	}
	mode, _, _ := unstructured.NestedString(policy.Object, "spec", "mode")
	eventDriven, _, _ := unstructured.NestedBool(policy.Object, "spec", "triggers", "eventDriven")
	reactive, _, _ := unstructured.NestedBool(policy.Object, "spec", "triggers", "reactiveOnly")
	matchLabels, _, _ := unstructured.NestedStringMap(policy.Object, "spec", "selector", "matchLabels")
	enabled, _, _ := unstructured.NestedStringSlice(policy.Object, "spec", "actions", "enabled")
	wantLabels := labels.Set{}
	parts := strings.SplitN(profile.Selector, "=", 2)
	if len(parts) == 2 {
		wantLabels[parts[0]] = parts[1]
	}
	wantActions := []string{profile.ExpectedAction}
	if profile.Family == servingKVFamily {
		wantActions = []string{"rotate", "kv-reset"}
	}
	if mode != "active" || !eventDriven || !reactive || len(wantLabels) != 1 ||
		len(matchLabels) != 1 || !labels.Equals(labels.Set(matchLabels), wantLabels) ||
		!slicesEqualStrings(enabled, wantActions) {
		return servingPolicyPin{}, errors.New("serving catalogue policy differs from the fixed active reactive profile")
	}
	return servingPolicyPin{UID: string(policy.GetUID()), Generation: policy.GetGeneration()}, nil
}

func slicesEqualStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func servingReadyPods(ctx context.Context, kube kubernetes.Interface, namespace, selector string, limit int64) ([]servingPodPin, error) {
	pods, err := kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: limit})
	if err != nil || pods.Continue != "" {
		return nil, errors.New("serving catalogue Pod inventory is unavailable or exceeded its bound")
	}
	result := make([]servingPodPin, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !podReady(pod) ||
			pod.UID == "" || pod.ResourceVersion == "" || pod.Status.PodIP == "" {
			continue
		}
		result = append(result, servingPodPin{Name: pod.Name, UID: string(pod.UID),
			ResourceVersion: pod.ResourceVersion, IP: pod.Status.PodIP, NodeName: pod.Spec.NodeName,
			RestartCount: servingPodRestartCount(pod)})
	}
	return result, nil
}

func servingPodRestartCount(pod *corev1.Pod) int32 {
	var restarts int32
	if pod != nil {
		for _, status := range pod.Status.ContainerStatuses {
			restarts += status.RestartCount
		}
	}
	return restarts
}

func (r *kubernetesServingCatalogueRuntime) Execute(ctx context.Context, run AttackCatalogRunContext, profile servingCatalogueProfile, state any) (servingCatalogueRuntimeObservation, error) {
	p, ok := state.(*servingCatalogueKubePreparation)
	if !ok || p == nil || p.kube == nil || p.dynamic == nil || p.profileDigest != profile.digest() {
		return servingCatalogueRuntimeObservation{}, errors.New("serving catalogue Kubernetes preparation changed")
	}
	if p.runID != "" && p.runID != run.RunID {
		return servingCatalogueRuntimeObservation{}, errors.New("serving catalogue Kubernetes preparation belongs to another run")
	}
	p.runID = run.RunID
	p.startedAt = time.Now().UTC()
	switch profile.Family {
	case servingRateFamily:
		return r.executeServingRate(ctx, run, profile, p)
	case sensitiveOutputFamily:
		return r.executeSensitiveOutput(ctx, run, profile, p)
	case servingKVFamily:
		return r.executeServingKV(ctx, run, profile, p)
	default:
		return servingCatalogueRuntimeObservation{}, errors.New("unknown serving catalogue family")
	}
}

func (r *kubernetesServingCatalogueRuntime) Cleanup(ctx context.Context, run AttackCatalogRunContext, profile servingCatalogueProfile, state any) servingCatalogueRuntimeCleanup {
	p, ok := state.(*servingCatalogueKubePreparation)
	if !ok || p == nil || p.kube == nil || p.dynamic == nil || p.profileDigest != profile.digest() {
		return servingCatalogueRuntimeCleanup{Attempted: true, Reason: "serving catalogue Kubernetes preparation changed"}
	}
	switch profile.Family {
	case servingRateFamily:
		return cleanupServingRate(ctx, run, profile, p)
	case sensitiveOutputFamily:
		return cleanupSensitiveOutput(ctx, run, profile, p)
	case servingKVFamily:
		return cleanupServingKV(ctx, run, profile, p)
	default:
		return servingCatalogueRuntimeCleanup{Attempted: true, Reason: "unknown serving catalogue family"}
	}
}

func servingRandomSuffix() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func createServingSignal(ctx context.Context, p *servingCatalogueKubePreparation, run AttackCatalogRunContext,
	profile servingCatalogueProfile, annotations map[string]string) (servingCatalogueSignal, error) {
	suffix, err := servingRandomSuffix()
	if err != nil {
		return servingCatalogueSignal{}, errors.New("serving catalogue signal identity generation failed")
	}
	name := "catalog-serving-" + suffix
	allAnnotations := map[string]any{model.ConsoleTargetPodUIDAnnotation: p.target.UID, attackCatalogCorrelationAnnotation: run.RunID}
	for key, value := range annotations {
		allAnnotations[key] = value
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{
			"name":        name,
			"labels":      map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": profile.CatalogueID},
			"annotations": allAnnotations,
		},
		"spec": map[string]any{
			"description": "bounded server-owned catalogue validation " + profile.CatalogueID,
			"targets":     []any{profile.Namespace + "/" + p.target.Name},
			"rule":        map[string]any{"type": profile.EventType, "threatLevel": "critical", "source": "console-catalogue"},
		},
	}}
	created, err := p.dynamic.Resource(securityEventGVR).Create(ctx, object, metav1.CreateOptions{})
	if err != nil {
		p.signal = servingCatalogueSignal{Name: name}
		return p.signal, errors.New("serving catalogue signal admission failed")
	}
	creator := created.GetAnnotations()["phorvex.ai/creator-identity"]
	targets, _, _ := unstructured.NestedStringSlice(created.Object, "spec", "targets")
	eventType, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "type")
	signal := servingCatalogueSignal{Created: true, Name: name, UID: string(created.GetUID()), Creator: creator,
		TargetUID: p.target.UID, CreatedAt: created.GetCreationTimestamp().Time}
	p.signal = signal
	if created.GetName() != name || signal.UID == "" || creator != eventtrust.Injector() ||
		created.GetCreationTimestamp().Time.IsZero() || created.GetCreationTimestamp().Time.Before(p.startedAt) ||
		created.GetDeletionTimestamp() != nil ||
		created.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != p.target.UID ||
		created.GetAnnotations()[attackCatalogCorrelationAnnotation] != run.RunID ||
		len(targets) != 1 || targets[0] != profile.Namespace+"/"+p.target.Name || eventType != profile.EventType {
		return signal, errors.New("serving catalogue admitted signal identity or target differs")
	}
	return signal, nil
}

func deleteServingSignal(ctx context.Context, p *servingCatalogueKubePreparation) (bool, error) {
	if p.signal.Name == "" {
		return true, nil
	}
	if p.signal.UID == "" {
		object, err := p.dynamic.Resource(securityEventGVR).Get(ctx, p.signal.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if p.runID == "" || object.GetAnnotations()[attackCatalogCorrelationAnnotation] != p.runID ||
			object.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != p.target.UID {
			return false, errors.New("ambiguous serving catalogue signal is not owned by a run")
		}
		p.signal.UID = string(object.GetUID())
	}
	uid := types.UID(p.signal.UID)
	err := p.dynamic.Resource(securityEventGVR).Delete(ctx, p.signal.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	_, err = p.dynamic.Resource(securityEventGVR).Get(ctx, p.signal.Name, metav1.GetOptions{})
	return apierrors.IsNotFound(err), nil
}

func (r *kubernetesServingCatalogueRuntime) pollInterval() time.Duration {
	interval := r.server.cfg.AttackCatalogPollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return interval
}

func (r *kubernetesServingCatalogueRuntime) matchingDecision(ctx context.Context, profile servingCatalogueProfile,
	p *servingCatalogueKubePreparation, signal servingCatalogueSignal) (servingCatalogueSignal, servingCatalogueDecision, bool) {
	rows, err := r.server.readAttackCatalogAudit(ctx)
	if err != nil {
		return signal, servingCatalogueDecision{}, false
	}
	for _, row := range rows {
		matchedSignal, decision, ok := matchServingDecision(row, profile, p, signal)
		if ok {
			if profile.Family == servingRateFamily {
				event, getErr := p.dynamic.Resource(securityEventGVR).Get(ctx, matchedSignal.Name, metav1.GetOptions{})
				if getErr != nil || string(event.GetUID()) != matchedSignal.UID || event.GetCreationTimestamp().Time.IsZero() {
					continue
				}
				matchedSignal.CreatedAt = event.GetCreationTimestamp().Time
			}
			return matchedSignal, decision, true
		}
	}
	return signal, servingCatalogueDecision{}, false
}

func matchServingDecision(row audit.Record, profile servingCatalogueProfile, p *servingCatalogueKubePreparation,
	signal servingCatalogueSignal) (servingCatalogueSignal, servingCatalogueDecision, bool) {
	trace := row.DecisionTrace
	if row.Kind != "phorvex.decision" || row.Time.Before(p.startedAt) || row.Time.After(time.Now().Add(2*time.Second)) || row.Namespace != profile.Namespace ||
		(!signal.CreatedAt.IsZero() && !validAttackCatalogReceiptTime(row.Time, signal.CreatedAt)) ||
		row.Pod != p.target.Name || trace == nil || trace.DecisionID == "" || trace.PolicyNamespace != profile.Namespace ||
		trace.PolicyName != profile.PolicyName || trace.PolicyUID != p.policy.UID || trace.AssetUID != p.target.UID ||
		trace.SelectedAction != row.Action || trace.DryRun != row.DryRun || row.DryRun ||
		trace.DispatchOutcome != row.DispatchOutcome || row.DispatchOutcome != model.DispatchEmitted ||
		row.Action != profile.ExpectedAction {
		return signal, servingCatalogueDecision{}, false
	}
	matches := 0
	creator := eventtrust.Injector()
	if profile.Family == servingRateFamily {
		creator = "system:serviceaccount:" + profile.Namespace + ":rate-detector"
	}
	maxEventAge := row.Time.Sub(p.startedAt).Seconds() + 1
	for _, event := range row.Events {
		if event.Type != profile.EventType || event.TargetPodUID != p.target.UID || !event.TargetsPod ||
			event.TrustVerdict != "trusted" || !event.TimestampPresent || event.Name == "" || event.EventUID == "" ||
			event.CreatorIdentity != creator || event.AgeSec < 0 || event.AgeSec > maxEventAge {
			continue
		}
		if signal.UID != "" && (event.EventUID != signal.UID || event.Name != signal.Name || event.CreatorIdentity != signal.Creator) {
			continue
		}
		signal.Name, signal.UID, signal.Creator, signal.TargetUID = event.Name, event.EventUID, event.CreatorIdentity, event.TargetPodUID
		if signal.CreatedAt.IsZero() {
			signal.CreatedAt = row.Time.Add(-time.Duration(event.AgeSec * float64(time.Second)))
		}
		signal.ObservedAt = row.Time
		signal.Created, signal.Observed = true, true
		matches++
	}
	if matches != 1 {
		return signal, servingCatalogueDecision{}, false
	}
	decision := servingCatalogueDecision{Observed: true, ID: trace.DecisionID, Selected: row.Selected,
		Feasible: row.Feasible, Actuated: row.Actuated, Action: row.Action,
		DispatchOutcome: row.DispatchOutcome, Handler: row.Handler,
		ObjectsTouched: append([]string(nil), row.ObjectsTouched...), ObservedAt: row.Time}
	return signal, decision, true
}

func servingObjectPinFromMeta(meta metav1.Object) servingObjectPin {
	return servingObjectPin{Name: meta.GetName(), UID: string(meta.GetUID()), ResourceVersion: meta.GetResourceVersion()}
}

func exactDeleteJob(ctx context.Context, kube kubernetes.Interface, namespace string, pin servingObjectPin) error {
	if pin.Name == "" || pin.UID == "" {
		return errors.New("catalogue load Job identity is incomplete")
	}
	uid := types.UID(pin.UID)
	propagation := metav1.DeletePropagationBackground
	err := kube.BatchV1().Jobs(namespace).Delete(ctx, pin.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}, PropagationPolicy: &propagation})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func podProxyJSON(ctx context.Context, kube kubernetes.Interface, namespace, pod string, port int32,
	method, path string, body any, out any) error {
	if kube == nil || namespace == "" || pod == "" || port <= 0 || !strings.HasPrefix(path, "/") {
		return errors.New("serving Pod proxy request is incomplete")
	}
	var request *rest.Request
	name := pod + ":" + strconv.Itoa(int(port))
	switch method {
	case http.MethodGet:
		request = kube.CoreV1().RESTClient().Get()
	case http.MethodPost:
		request = kube.CoreV1().RESTClient().Post()
	default:
		return errors.New("serving Pod proxy method is unsupported")
	}
	request = request.Namespace(namespace).Resource("pods").Name(name).SubResource("proxy").Suffix(strings.TrimPrefix(path, "/"))
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		request = request.SetHeader("Content-Type", "application/json").Body(raw)
	}
	raw, err := request.DoRaw(ctx)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("serving Pod proxy response is empty or exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("serving Pod proxy response is malformed")
	}
	return nil
}

func deploymentPin(ctx context.Context, kube kubernetes.Interface, namespace, name string) (*appsv1.Deployment, error) {
	deployment, err := kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || deployment.UID == "" || deployment.ResourceVersion == "" || deployment.DeletionTimestamp != nil {
		return nil, errors.New("serving catalogue Deployment is unavailable")
	}
	return deployment, nil
}

func noExistingServingJobs(ctx context.Context, kube kubernetes.Interface, namespace string) error {
	jobs, err := kube.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{LabelSelector: servingCatalogueRunLabel, Limit: 2})
	if err != nil || jobs.Continue != "" || len(jobs.Items) != 0 {
		return errors.New("a prior serving catalogue load Job exists; reconcile before launch")
	}
	return nil
}

var _ = batchv1.Job{}
