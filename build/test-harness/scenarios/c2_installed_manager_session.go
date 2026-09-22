package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func init() { core.RegisterScenario(&c2InstalledManagerSession{}) }

const (
	installedSessionScenario        = "c2-installed-manager-session"
	installedSessionApp             = "c2-installed-session"
	installedSessionDeployment      = "c2-installed-session"
	installedSessionTargetService   = "c2-installed-session-target"
	installedSessionSharedService   = "c2-installed-session-shared"
	installedSessionPDB             = "c2-installed-session"
	installedSessionTargetRoute     = "fixture.phorvex.ai/session-target"
	installedSessionWindow          = 90 * time.Second
	installedSessionSegment         = 18 * time.Second
	installedSessionCoordination    = 80 * time.Second
	installedSessionSamplePeriod    = 500 * time.Millisecond
	installedSessionExecTimeout     = 23 * time.Second
	installedSessionSampleLimit     = 200
	installedSessionReceiptMaxBytes = 96 * 1024
	installedSessionGraceSeconds    = int64(30)
	installedSessionMinimumPodAge   = 90 * time.Second
	installedSessionAgeWaitBound    = 105 * time.Second
)

// installedSessionAvailabilitySource makes read-only application requests for
// the entire declared observation window. It emits one typed item per attempt,
// including failures, and never exports exception text or response bodies.
const installedSessionAvailabilitySource = `import datetime, json, signal, sys, time, urllib.error, urllib.parse, urllib.request
base, session_id, duration_text, cadence_text = sys.argv[1:]
duration, cadence = float(duration_text), float(cadence_text)
if not 0 < duration <= 20 or not 0.1 <= cadence <= 2: raise ValueError("invalid availability bounds")
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
def strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise ValueError("duplicate response field")
        out[key] = value
    return out
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url): return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
url = base + "/session?" + urllib.parse.urlencode({"id": session_id})
started = now(); deadline = time.monotonic() + duration; observations = []
while True:
    attempt = {"atUTC": now(), "known": False, "category": "transport-unavailable", "httpStatus": 0, "podUID": ""}
    response = None
    try:
        try: response = opener.open(urllib.request.Request(url, method="GET"), timeout=min(2.0, max(0.1, deadline-time.monotonic())))
        except urllib.error.HTTPError as error: response = error
        raw = response.read(1025)
        attempt["httpStatus"] = response.status
        if len(raw) > 1024:
            attempt["category"] = "response-too-large"
        else:
            try:
                parsed = json.loads(raw, object_pairs_hook=strict_object)
                valid = type(parsed) is dict and set(parsed) == {"podUID", "id", "present"} and type(parsed["podUID"]) is str and parsed["podUID"] and parsed["id"] == session_id and type(parsed["present"]) is bool and response.status in (200, 404) and (response.status == 200) == parsed["present"]
                if valid: attempt.update({"known": True, "category": "application-response", "podUID": parsed["podUID"]})
                else: attempt["category"] = "invalid-response"
            except Exception: attempt["category"] = "invalid-response"
    except Exception:
        pass
    observations.append(attempt)
    remaining = deadline-time.monotonic()
    if remaining <= 0: break
    time.sleep(min(cadence, remaining))
sys.stdout.write(json.dumps({"version":1,"serviceURL":base,"sessionID":session_id,"durationMillis":round(duration*1000),"cadenceMillis":round(cadence*1000),"startedAtUTC":started,"endedAtUTC":now(),"observations":observations}, sort_keys=True, separators=(",", ":")))
`

type installedSessionAvailabilityObservation struct {
	AtUTC      string `json:"atUTC"`
	Known      bool   `json:"known"`
	Category   string `json:"category"`
	HTTPStatus int    `json:"httpStatus"`
	PodUID     string `json:"podUID"`
}

type installedSessionAvailability struct {
	Version        int                                       `json:"version"`
	ServiceURL     string                                    `json:"serviceURL"`
	SessionID      string                                    `json:"sessionID"`
	DurationMillis int                                       `json:"durationMillis"`
	CadenceMillis  int                                       `json:"cadenceMillis"`
	SegmentCount   int                                       `json:"segmentCount,omitempty"`
	StartedAtUTC   string                                    `json:"startedAtUTC"`
	EndedAtUTC     string                                    `json:"endedAtUTC"`
	Observations   []installedSessionAvailabilityObservation `json:"observations"`
}

type c2InstalledManagerSession struct {
	deploymentUID      types.UID
	pdbUID             types.UID
	pdbRV              string
	targetServiceUID   types.UID
	sharedServiceUID   types.UID
	producerUID        types.UID
	replicaSetName     string
	replicaSetUID      types.UID
	targetRouteValue   string
	originalName       string
	originalUID        types.UID
	originalRV         string
	originalCreatedAt  string
	originalAgeReadyAt string
	peerUID            types.UID
	sessionID          string
	availability       installedSessionAvailability
	availabilityRaw    string
	coordination       core.TargetedActionResult
	coordinationUsed   bool
	benchmarkEvidence  map[string]string
	originalAbsent     bool
	replacementUID     types.UID
	oldSessionPresent  bool
	freshStateProven   bool
	effectStatus       string
	absenceObservedAt  string
}

func (*c2InstalledManagerSession) UsesTargetedActionCoordination() bool { return true }

func (s *c2InstalledManagerSession) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:          installedSessionScenario,
		Category:      core.CategoryR6Claimed,
		Source:        "Post25 installed-manager catalogue: owned two-replica process-state and availability control",
		R6ResponseTag: core.R6Partial,
		BenignControl: true,
		Realism:       core.RealismExecutable,
		Mechanism: fmt.Sprintf("two controller-owned CPU replicas run the source-hashed process-memory fixture under an owned PodDisruptionBudget; one exact live Pod receives a route label that is absent from the template, a session is established before a target coordinator may act, and read-only shared-Service requests run every %s in five bounded foreground segments across a predeclared %s window; image=%s serverSourceSHA256=%s availabilitySourceSHA256=%s",
			installedSessionSamplePeriod, installedSessionWindow, sessionPythonImage, sessionServerSourceSHA256(), installedSessionAvailabilitySourceSHA256()),
		ClaimLimits:        "benign functional comparison only; zero ATT&CK/security efficacy and excluded from security and ROI denominators; a decision or dispatch receipt does not prove process-state loss, replacement, or continuous availability",
		OracleDescription:  "retain every shared-Service attempt as success or typed unknown; independently bind exact original Pod presence or absence, owner-stable replacement, old process-state survival or loss, and fresh-state recovery; keep complete attributed non-selection as a valid no-op",
		CleanupDescription: "UID-preconditioned deletion of the PodDisruptionBudget, two Services, Deployment, producer Pod, and defender-owned policy/target label; runner-owned cleanup separately verifies absence",
		R6Justification:    "Pod replacement can clear process-local state while peers preserve request availability. This scenario measures those separate application effects without an attack, exploit, or security-efficacy claim.",
	}
}

func (s *c2InstalledManagerSession) Setup(ctx context.Context, env *core.Env) error {
	s.deploymentUID, s.pdbUID, s.pdbRV, s.targetServiceUID, s.sharedServiceUID, s.producerUID = "", "", "", "", "", ""
	s.replicaSetName, s.replicaSetUID, s.originalName, s.originalUID, s.originalRV, s.originalCreatedAt, s.originalAgeReadyAt, s.peerUID, s.sessionID = "", "", "", "", "", "", "", "", ""
	s.availability, s.availabilityRaw, s.coordination, s.coordinationUsed = installedSessionAvailability{}, "", core.TargetedActionResult{}, false
	s.originalAbsent, s.replacementUID, s.oldSessionPresent, s.freshStateProven, s.effectStatus, s.absenceObservedAt = false, "", false, false, "not-observed", ""
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	two := int32(2)
	noToken, runAsNonRoot, readOnly, noEscalation := false, true, true, false
	runAsUser := int64(65532)
	baseLabels := env.OwnedLabels(map[string]string{"app": installedSessionApp})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: installedSessionDeployment, Namespace: env.Config.Namespace, Labels: cloneStringMap(baseLabels)},
		Spec: appsv1.DeploymentSpec{
			Replicas: &two,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": installedSessionApp}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: cloneStringMap(baseLabels), Annotations: map[string]string{"r6th.io/session-source-sha256": sessionServerSourceSHA256()}},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &noToken,
					NodeSelector:                 cloneStringMap(env.Config.BenignSessionNodeSelector),
					SecurityContext:              &corev1.PodSecurityContext{RunAsNonRoot: &runAsNonRoot, RunAsUser: &runAsUser, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{
						Name: "session", Image: sessionPythonImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"python3", "-B", "-c", sessionServerSource},
						Env:             []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}},
						Ports:           []corev1.ContainerPort{{Name: "http", ContainerPort: sessionPort}},
						ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("http")}}, InitialDelaySeconds: 1, PeriodSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 5},
						Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("20m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEscalation, ReadOnlyRootFilesystem: &readOnly, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					}},
				},
			},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl create deployment %s -n %s  # two-replica installed-manager session fixture", installedSessionDeployment, env.Config.Namespace))
	createdDeployment, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Create(ctx, dep, metav1.CreateOptions{})
	if err != nil || createdDeployment == nil || createdDeployment.UID == "" {
		return errors.Join(err, errors.New("create installed session Deployment returned no owned UID"))
	}
	s.deploymentUID = createdDeployment.UID
	initialMinAvailable := intstr.FromInt(2)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: installedSessionPDB, Namespace: env.Config.Namespace, Labels: cloneStringMap(baseLabels)},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &initialMinAvailable,
			Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": installedSessionApp}},
		},
	}
	env.Log.Command(fmt.Sprintf("kubectl create poddisruptionbudget %s -n %s --selector=app=%s --min-available=2", installedSessionPDB, env.Config.Namespace, installedSessionApp))
	createdPDB, err := env.Kube.PolicyV1().PodDisruptionBudgets(env.Config.Namespace).Create(ctx, pdb, metav1.CreateOptions{})
	if err != nil || createdPDB == nil || createdPDB.UID == "" || createdPDB.ResourceVersion == "" {
		return errors.Join(err, errors.New("create installed session PodDisruptionBudget returned no exact identity"))
	}
	s.pdbUID, s.pdbRV = createdPDB.UID, createdPDB.ResourceVersion
	for _, item := range []struct {
		name     string
		selector map[string]string
		setUID   func(types.UID)
	}{
		{name: installedSessionSharedService, selector: map[string]string{"app": installedSessionApp}, setUID: func(uid types.UID) { s.sharedServiceUID = uid }},
		{name: installedSessionTargetService, selector: map[string]string{"app": installedSessionApp, installedSessionTargetRoute: s.routeValue(env)}, setUID: func(uid types.UID) { s.targetServiceUID = uid }},
	} {
		svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: item.name, Namespace: env.Config.Namespace, Labels: cloneStringMap(baseLabels)}, Spec: corev1.ServiceSpec{Selector: item.selector, Ports: []corev1.ServicePort{{Name: "http", Port: sessionPort, TargetPort: intstr.FromString("http")}}}}
		env.Log.Command(fmt.Sprintf("kubectl create service clusterip %s -n %s --tcp=%d:%d", item.name, env.Config.Namespace, sessionPort, sessionPort))
		created, createErr := env.Kube.CoreV1().Services(env.Config.Namespace).Create(ctx, svc, metav1.CreateOptions{})
		if createErr != nil || created == nil || created.UID == "" {
			return errors.Join(createErr, fmt.Errorf("create installed session Service %s returned no owned UID", item.name))
		}
		item.setUID(created.UID)
	}
	producer := installedSessionProducerPod(env)
	env.Log.Command(fmt.Sprintf("kubectl run %s -n %s --image=%s  # installed-manager HTTP producer", sessionProducer, env.Config.Namespace, sessionPythonImage))
	createdProducer, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, producer, metav1.CreateOptions{})
	if err != nil || createdProducer == nil || createdProducer.UID == "" {
		return errors.Join(err, errors.New("create installed session producer returned no owned UID"))
	}
	s.producerUID = createdProducer.UID
	if err := env.WaitForPodRunning(ctx, sessionProducer, 60*time.Second); err != nil {
		return fmt.Errorf("wait installed session producer: %w", err)
	}
	pods, rsName, rsUID, err := waitInstalledSessionPods(ctx, env, s.deploymentUID, 60*time.Second)
	if err != nil {
		return err
	}
	s.replicaSetName, s.replicaSetUID = rsName, rsUID
	original := pods[0].DeepCopy()
	if original.ResourceVersion == "" {
		return errors.New("installed session target has no resourceVersion")
	}
	original.Labels[installedSessionTargetRoute] = s.targetRouteValue
	env.Log.Command(fmt.Sprintf("kubectl label pod %s -n %s %s=%s --resource-version=%s", original.Name, env.Config.Namespace, installedSessionTargetRoute, s.targetRouteValue, original.ResourceVersion))
	updated, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Update(ctx, original, metav1.UpdateOptions{})
	if err != nil || updated == nil || updated.UID != original.UID || updated.ResourceVersion == "" {
		return errors.Join(err, errors.New("bind exact installed session target route returned a different identity"))
	}
	s.originalName, s.originalUID, s.originalRV = updated.Name, updated.UID, updated.ResourceVersion
	s.originalCreatedAt = updated.CreationTimestamp.UTC().Format(time.RFC3339Nano)
	s.peerUID = pods[1].UID
	if err := waitInstalledSessionTargetEndpoint(ctx, env, s.targetServiceUID, s.originalName, s.originalUID, 30*time.Second); err != nil {
		return err
	}
	ageReadyPod, ageReadyAt, err := waitInstalledSessionTargetAge(ctx, env, s.originalName, s.originalUID, installedSessionMinimumPodAge, installedSessionAgeWaitBound)
	if err != nil {
		return err
	}
	s.originalRV = ageReadyPod.ResourceVersion
	s.originalAgeReadyAt = ageReadyAt.UTC().Format(time.RFC3339Nano)
	if err := s.waitInstalledSessionPDBInitial(ctx, env, 30*time.Second); err != nil {
		return err
	}
	return nil
}

func (s *c2InstalledManagerSession) routeValue(env *core.Env) string {
	if s.targetRouteValue == "" {
		s.targetRouteValue = fmt.Sprintf("trial-%d", env.Trial)
	}
	return s.targetRouteValue
}

func (s *c2InstalledManagerSession) waitInstalledSessionPDBInitial(ctx context.Context, env *core.Env, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pdb, err := env.Kube.PolicyV1().PodDisruptionBudgets(env.Config.Namespace).Get(ctx, installedSessionPDB, metav1.GetOptions{})
		if err == nil && pdb != nil && pdb.UID == s.pdbUID && pdb.ResourceVersion != "" && pdb.DeletionTimestamp == nil && pdb.Spec.MinAvailable != nil && pdb.Spec.MinAvailable.Type == intstr.Int && pdb.Spec.MinAvailable.IntVal == 2 && pdb.Spec.Selector != nil && len(pdb.Spec.Selector.MatchLabels) == 1 && pdb.Spec.Selector.MatchLabels["app"] == installedSessionApp && len(pdb.Spec.Selector.MatchExpressions) == 0 && pdb.Status.ObservedGeneration == pdb.Generation && pdb.Status.ExpectedPods == 2 && pdb.Status.CurrentHealthy == 2 && pdb.Status.DesiredHealthy == 2 && pdb.Status.DisruptionsAllowed == 0 {
			s.pdbRV = pdb.ResourceVersion
			return nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("read installed session PodDisruptionBudget: %w", err)
		}
		if time.Now().After(deadline) {
			return errors.New("installed session PodDisruptionBudget did not converge to exact 2/2 availability floor")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func installedSessionProducerPod(env *core.Env) *corev1.Pod {
	noToken, runAsNonRoot, readOnly, noEscalation := false, true, true, false
	runAsUser := int64(65532)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: sessionProducer, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(map[string]string{"app": sessionProducer})},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &noToken,
			NodeSelector:                 cloneStringMap(env.Config.BenignSessionNodeSelector),
			SecurityContext:              &corev1.PodSecurityContext{RunAsNonRoot: &runAsNonRoot, RunAsUser: &runAsUser, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Containers: []corev1.Container{{
				Name:            "producer",
				Image:           sessionPythonImage,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"python3", "-c", "import time; time.sleep(3600)"},
				Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("32Mi")}},
				SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &noEscalation, ReadOnlyRootFilesystem: &readOnly, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			}},
		},
	}
}

func installedSessionAvailabilitySourceSHA256() string {
	sum := sha256.Sum256([]byte(installedSessionAvailabilitySource))
	return fmt.Sprintf("%x", sum)
}

func waitInstalledSessionPods(ctx context.Context, env *core.Env, deploymentUID types.UID, timeout time.Duration) ([]*corev1.Pod, string, types.UID, error) {
	deadline := time.Now().Add(timeout)
	for {
		pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + installedSessionApp})
		if err == nil {
			ready := make([]*corev1.Pod, 0, 2)
			var rsName string
			var rsUID types.UID
			valid := true
			for i := range pods.Items {
				pod := &pods.Items[i]
				if !podReady(pod) || pod.DeletionTimestamp != nil {
					continue
				}
				name, uid, validateErr := validateInstalledSessionPod(ctx, env, pod, deploymentUID)
				if validateErr != nil || rsUID != "" && (name != rsName || uid != rsUID) {
					valid = false
					break
				}
				rsName, rsUID = name, uid
				ready = append(ready, pod.DeepCopy())
			}
			if valid && len(ready) == 2 {
				sort.Slice(ready, func(i, j int) bool { return string(ready[i].UID) < string(ready[j].UID) })
				return ready, rsName, rsUID, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, "", "", errors.New("installed session Deployment did not produce exactly two validated Ready Pods")
		}
		select {
		case <-ctx.Done():
			return nil, "", "", fmt.Errorf("installed session readiness cancelled: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func validateInstalledSessionPod(ctx context.Context, env *core.Env, pod *corev1.Pod, deploymentUID types.UID) (string, types.UID, error) {
	if pod == nil || pod.UID == "" || pod.ResourceVersion == "" || !podReady(pod) || pod.DeletionTimestamp != nil {
		return "", "", errors.New("installed session Pod identity/readiness invalid")
	}
	for key, value := range env.OwnedLabels(map[string]string{"app": installedSessionApp}) {
		if pod.Labels[key] != value {
			return "", "", fmt.Errorf("installed session Pod label %q differs", key)
		}
	}
	if pod.Labels[defenders.RotationTargetLabel] != "" || pod.Labels[installedSessionTargetRoute] != "" {
		return "", "", errors.New("installed session template unexpectedly selected a target")
	}
	if pod.Annotations["r6th.io/session-source-sha256"] != sessionServerSourceSHA256() || len(pod.Spec.Containers) != 1 {
		return "", "", errors.New("installed session Pod source/container differs")
	}
	container := pod.Spec.Containers[0]
	if container.Name != "session" || container.Image != sessionPythonImage || !slices.Equal(container.Command, []string{"python3", "-B", "-c", sessionServerSource}) {
		return "", "", errors.New("installed session Pod image/command differs")
	}
	var rsName string
	var rsUID types.UID
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "ReplicaSet" && owner.Controller != nil && *owner.Controller {
			if rsUID != "" {
				return "", "", errors.New("installed session Pod has multiple controller owners")
			}
			rsName, rsUID = owner.Name, owner.UID
		}
	}
	if rsName == "" || rsUID == "" {
		return "", "", errors.New("installed session Pod ReplicaSet owner missing")
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, rsName, metav1.GetOptions{})
	if err != nil || rs.UID != rsUID {
		return "", "", errors.New("installed session ReplicaSet identity differs")
	}
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" && owner.Name == installedSessionDeployment && owner.UID == deploymentUID && owner.Controller != nil && *owner.Controller {
			return rsName, rsUID, nil
		}
	}
	return "", "", errors.New("installed session ReplicaSet is not owned by exact Deployment")
}

func waitInstalledSessionTargetEndpoint(ctx context.Context, env *core.Env, serviceUID types.UID, podName string, podUID types.UID, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		list, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + installedSessionTargetService})
		if err == nil {
			matches, foreign := 0, false
			for i := range list.Items {
				slice := &list.Items[i]
				owned := false
				for _, owner := range slice.OwnerReferences {
					if owner.Kind == "Service" && owner.Name == installedSessionTargetService && owner.UID == serviceUID && owner.Controller != nil && *owner.Controller {
						owned = true
					}
				}
				if !owned {
					foreign = true
					continue
				}
				for _, endpoint := range slice.Endpoints {
					if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
						continue
					}
					if endpoint.TargetRef != nil && endpoint.TargetRef.Kind == "Pod" && endpoint.TargetRef.Namespace == env.Config.Namespace && endpoint.TargetRef.Name == podName && endpoint.TargetRef.UID == podUID {
						matches++
					} else {
						foreign = true
					}
				}
			}
			if matches == 1 && !foreign {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.New("installed session target Service did not converge to exact Pod UID")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("installed session target endpoint wait cancelled: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func waitInstalledSessionTargetAge(ctx context.Context, env *core.Env, podName string, podUID types.UID, minimumAge, bound time.Duration) (*corev1.Pod, time.Time, error) {
	deadline := time.Now().Add(bound)
	for {
		pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil || pod.UID != podUID || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || !podReady(pod) || pod.Labels[installedSessionTargetRoute] == "" || pod.Labels[defenders.RotationTargetLabel] != "" {
			return nil, time.Time{}, errors.Join(err, errors.New("installed session target changed during anti-over-rotation warmup"))
		}
		if !pod.CreationTimestamp.IsZero() && time.Since(pod.CreationTimestamp.Time) >= minimumAge {
			return pod, time.Now().UTC(), nil
		}
		if time.Now().After(deadline) {
			return nil, time.Time{}, errors.New("installed session target did not reach the predeclared anti-over-rotation age")
		}
		select {
		case <-ctx.Done():
			return nil, time.Time{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func runInstalledSessionAvailability(ctx context.Context, env *core.Env, expectedProducerUID types.UID, sessionID string) (installedSessionAvailability, string, error) {
	serviceURL := fmt.Sprintf("http://%s:%d", installedSessionSharedService, sessionPort)
	aggregate := installedSessionAvailability{Version: 1, ServiceURL: serviceURL, SessionID: sessionID, DurationMillis: int(installedSessionWindow.Milliseconds()), CadenceMillis: int(installedSessionSamplePeriod.Milliseconds()), SegmentCount: int(installedSessionWindow / installedSessionSegment)}
	var segmentReceipts []json.RawMessage
	for segment := 0; segment < aggregate.SegmentCount; segment++ {
		part, raw, err := runInstalledSessionAvailabilitySegment(ctx, env, expectedProducerUID, sessionID, installedSessionSegment)
		if len(raw) > 0 {
			segmentReceipts = append(segmentReceipts, json.RawMessage(raw))
		}
		if err != nil {
			return aggregate, marshalInstalledSessionSegmentReceipts(segmentReceipts), fmt.Errorf("installed availability segment %d: %w", segment, err)
		}
		if segment == 0 {
			aggregate.StartedAtUTC = part.StartedAtUTC
		}
		aggregate.EndedAtUTC = part.EndedAtUTC
		aggregate.Observations = append(aggregate.Observations, part.Observations...)
		if len(aggregate.Observations) > installedSessionSampleLimit {
			return aggregate, marshalInstalledSessionSegmentReceipts(segmentReceipts), errors.New("installed availability aggregate exceeded observation bound")
		}
	}
	raw := marshalInstalledSessionSegmentReceipts(segmentReceipts)
	if len(raw) > installedSessionReceiptMaxBytes {
		return aggregate, raw, errors.New("installed availability aggregate receipt exceeded byte bound")
	}
	return aggregate, raw, nil
}

func runInstalledSessionAvailabilitySegment(ctx context.Context, env *core.Env, expectedProducerUID types.UID, sessionID string, duration time.Duration) (installedSessionAvailability, string, error) {
	var out installedSessionAvailability
	producer, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, sessionProducer, metav1.GetOptions{})
	if err != nil || validateSessionProducer(env, producer, expectedProducerUID) != nil {
		return out, "", errors.New("installed availability producer identity invalid before exec")
	}
	serviceURL := fmt.Sprintf("http://%s:%d", installedSessionSharedService, sessionPort)
	command := []string{"python3", "-B", "-c", installedSessionAvailabilitySource, serviceURL, sessionID, strconv.FormatFloat(duration.Seconds(), 'f', 3, 64), strconv.FormatFloat(installedSessionSamplePeriod.Seconds(), 'f', 3, 64)}
	result := env.ExecWithTimeout(ctx, sessionProducer, "producer", installedSessionExecTimeout, command)
	raw := result.Stdout
	if len(raw) > installedSessionReceiptMaxBytes {
		return out, "", fmt.Errorf("installed availability receipt exceeded %d bytes", installedSessionReceiptMaxBytes)
	}
	sum := sha256.Sum256([]byte(raw))
	env.Log.Logf("installed-manager availability-receipt bytes=%d sha256=%x exit=%d", len(raw), sum, result.ExitCode)
	producerAfter, afterErr := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, sessionProducer, metav1.GetOptions{})
	if afterErr != nil || validateSessionProducer(env, producerAfter, expectedProducerUID) != nil {
		return out, raw, errors.New("installed availability producer identity invalid after exec")
	}
	if result.Err != nil || result.ExitCode != 0 {
		return out, raw, fmt.Errorf("installed availability producer failed: exit=%d", result.ExitCode)
	}
	out, err = parseInstalledSessionAvailability([]byte(raw), serviceURL, sessionID, duration)
	return out, raw, err
}

func marshalInstalledSessionSegmentReceipts(receipts []json.RawMessage) string {
	raw, _ := json.Marshal(struct {
		SchemaVersion string            `json:"schemaVersion"`
		Segments      []json.RawMessage `json:"segments"`
	}{SchemaVersion: "phorvex.installed-session-availability.v1", Segments: receipts})
	return string(raw)
}

func parseInstalledSessionAvailability(raw []byte, serviceURL, sessionID string, duration time.Duration) (installedSessionAvailability, error) {
	var out installedSessionAvailability
	if len(raw) == 0 || len(raw) > installedSessionReceiptMaxBytes {
		return out, errors.New("installed availability receipt size invalid")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return out, fmt.Errorf("installed availability receipt duplicates: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("decode installed availability receipt: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return out, err
	}
	if out.Version != 1 || out.ServiceURL != serviceURL || out.SessionID != sessionID || out.DurationMillis != int(duration.Milliseconds()) || out.CadenceMillis != int(installedSessionSamplePeriod.Milliseconds()) || out.SegmentCount != 0 || len(out.Observations) < 1 || len(out.Observations) > installedSessionSampleLimit {
		return out, errors.New("installed availability receipt identity/bounds differ")
	}
	started, err := time.Parse(time.RFC3339Nano, out.StartedAtUTC)
	if err != nil {
		return out, errors.New("installed availability start timestamp invalid")
	}
	ended, err := time.Parse(time.RFC3339Nano, out.EndedAtUTC)
	if err != nil || ended.Before(started) || ended.Sub(started) < duration || ended.Sub(started) > duration+5*time.Second {
		return out, errors.New("installed availability receipt window invalid")
	}
	previous := started
	for i, observation := range out.Observations {
		at, parseErr := time.Parse(time.RFC3339Nano, observation.AtUTC)
		if parseErr != nil || at.Before(previous) || at.Before(started) || at.After(ended) {
			return out, fmt.Errorf("installed availability observation %d timestamp invalid", i)
		}
		previous = at
		if observation.Known {
			if observation.Category != "application-response" || observation.PodUID == "" || !installedOneOf(strconv.Itoa(observation.HTTPStatus), "200", "404") {
				return out, fmt.Errorf("installed availability observation %d known shape invalid", i)
			}
		} else if observation.PodUID != "" || !installedOneOf(observation.Category, "transport-unavailable", "invalid-response", "response-too-large") || observation.HTTPStatus < 0 || observation.HTTPStatus > 599 {
			return out, fmt.Errorf("installed availability observation %d unknown shape invalid", i)
		}
	}
	return out, nil
}

func (s *c2InstalledManagerSession) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if s.originalName == "" || s.originalUID == "" || s.originalRV == "" || s.peerUID == "" || s.replicaSetUID == "" || s.producerUID == "" || s.pdbUID == "" || s.pdbRV == "" {
		return core.AttackResult{}, errors.New("installed session fixture identities missing")
	}
	if env.Rand == nil {
		return core.AttackResult{}, errors.New("installed session has no deterministic trial RNG")
	}
	s.sessionID = fmt.Sprintf("installed-%d-%016x", env.Trial, env.Rand.Uint64())
	established, err := performSessionBatchToService(ctx, env, installedSessionTargetService, []sessionBatchOperation{{Method: "POST", ID: s.sessionID, When: "always"}, {Method: "GET", ID: s.sessionID, When: "always"}}, s.producerUID)
	stages := []string{"establish and retrieve one synthetic process-memory session through the exact target Service"}
	if err != nil || len(established.Responses) != 2 || established.ServedUID != s.originalUID {
		return s.installedSessionAttackResult(stages, "establishment-invalid"), errors.Join(err, errors.New("installed session establishment failed or changed target"))
	}
	created, retained := established.Responses[0].Reply, established.Responses[1].Reply
	if created.HTTPStatus != 201 || !created.Body.Created || !created.Body.Present || created.Body.PodUID != string(s.originalUID) || retained.HTTPStatus != 200 || !retained.Body.Present || retained.Body.PodUID != string(s.originalUID) {
		return s.installedSessionAttackResult(stages, "establishment-invalid"), errors.New("installed session establishment receipt differs")
	}

	availabilityDone := make(chan struct {
		observation installedSessionAvailability
		raw         string
		err         error
	}, 1)
	go func() {
		observation, raw, sampleErr := runInstalledSessionAvailability(ctx, env, s.producerUID, s.sessionID)
		availabilityDone <- struct {
			observation installedSessionAvailability
			raw         string
			err         error
		}{observation, raw, sampleErr}
	}()
	stages = append(stages, fmt.Sprintf("issue typed read-only shared-Service requests every %s for the fixed %s window", installedSessionSamplePeriod, installedSessionWindow))

	var coordinateErr error
	if defender, ok := core.LookupDefender(env.DefenderName); ok {
		if coordinator, ok := defender.(core.TargetedActionCoordinator); ok {
			s.coordinationUsed = true
			coordinateStarted := time.Now().UTC()
			deadline := coordinateStarted.Add(installedSessionCoordination)
			request := core.TargetedActionRequest{
				Objective: installedSessionScenario, Namespace: env.Config.Namespace, TargetKind: "Pod", TargetName: s.originalName, TargetUID: string(s.originalUID), TargetResourceVersion: s.originalRV,
				OwnerKind: "ReplicaSet", OwnerName: s.replicaSetName, OwnerUID: string(s.replicaSetUID), TargetLabelKey: defenders.RotationTargetLabel, TargetLabelValue: "true", RequestedGraceSeconds: installedSessionGraceSeconds,
				AvailabilityPolicyName: installedSessionPDB, AvailabilityPolicyUID: string(s.pdbUID), AvailabilityPolicyResourceVersion: s.pdbRV, AvailabilitySelectorKey: "app", AvailabilitySelectorValue: installedSessionApp, InitialMinAvailable: 2, EligibleMinAvailable: 1,
				SessionEstablishedUTC: established.Ended.UTC().Format(time.RFC3339Nano), DeadlineUTC: deadline.Format(time.RFC3339Nano),
			}
			coordCtx, cancel := context.WithDeadline(ctx, deadline)
			s.coordination, coordinateErr = coordinator.CoordinateTargetedAction(coordCtx, env, request)
			cancel()
			if validateErr := validateInstalledSessionCoordination(env, request, s.coordination); validateErr != nil {
				coordinateErr = errors.Join(coordinateErr, validateErr)
			}
			stages = append(stages, "coordinate one exact UID/RV/grace target only after session establishment")
		}
	}
	availability := <-availabilityDone
	s.availability, s.availabilityRaw = availability.observation, availability.raw
	if availability.err != nil {
		return s.installedSessionAttackResult(stages, "availability-invalid"), errors.Join(coordinateErr, availability.err)
	}
	if coordinateErr != nil {
		return s.installedSessionAttackResult(stages, "coordination-invalid"), coordinateErr
	}
	return s.installedSessionAttackResult(stages, "execute-complete"), nil
}

func validateInstalledSessionCoordination(env *core.Env, request core.TargetedActionRequest, result core.TargetedActionResult) error {
	if result.SchemaVersion != "phorvex.targeted-action-result.v1" || result.Coordinator != env.DefenderName || !result.AttributionComplete || result.TargetName != request.TargetName || result.TargetUID != request.TargetUID || result.TargetResourceVersion == "" || result.RequestedGraceSeconds != request.RequestedGraceSeconds || result.AvailabilityPolicyResourceVersion == "" || result.AvailabilityPolicyResourceVersion == request.AvailabilityPolicyResourceVersion {
		return errors.New("installed session targeted-action result identity/attribution incomplete")
	}
	if !installedOneOf(result.Disposition, "no-action", "refused", "dispatched-unconfirmed", "failed", "unknown") {
		return errors.New("installed session targeted-action disposition invalid")
	}
	started, err := time.Parse(time.RFC3339Nano, result.StartedAtUTC)
	if err != nil {
		return errors.New("installed session targeted-action start invalid")
	}
	ended, err := time.Parse(time.RFC3339Nano, result.EndedAtUTC)
	if err != nil || ended.Before(started) {
		return errors.New("installed session targeted-action interval invalid")
	}
	established, err := time.Parse(time.RFC3339Nano, request.SessionEstablishedUTC)
	if err != nil || started.Before(established) {
		return errors.New("installed session targeted action preceded establishment")
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineUTC)
	if err != nil || ended.After(deadline.Add(time.Second)) {
		return errors.New("installed session targeted action exceeded deadline")
	}
	if result.Disposition == "dispatched-unconfirmed" {
		actionAt, parseErr := time.Parse(time.RFC3339Nano, result.ActionAtUTC)
		if parseErr != nil || actionAt.Before(started) || actionAt.After(ended) {
			return errors.New("installed session dispatched action timestamp invalid")
		}
	} else if result.ActionAtUTC != "" {
		return errors.New("installed session non-dispatch result carries action timestamp")
	}
	for _, receipt := range []string{result.ControlReceiptJSON, result.EligibleReceiptJSON, result.AuthorizationReceiptJSON} {
		if len(receipt) > 32*1024 {
			return errors.New("installed session coordinator receipt exceeds bound")
		}
		if receipt != "" && (!json.Valid([]byte(receipt)) || rejectDuplicateJSONFields([]byte(receipt)) != nil) {
			return errors.New("installed session coordinator receipt JSON invalid")
		}
	}
	if result.Coordinator == "d-phorvex-installed" && (result.ControlReceiptJSON == "" || result.EligibleReceiptJSON == "" || result.AuthorizationReceiptJSON == "") {
		return errors.New("installed manager result omitted control, eligible, or fixture authorization receipt")
	}
	if result.Coordinator == "d-phorvex-installed" {
		var receipt struct {
			SchemaVersion, Namespace, RoleName, RoleUID, RoleBindingName, RoleBindingUID string
			ManagerServiceAccount, ManagerNamespace, TargetName, TargetUID, FixtureNonce string
			AuthorizationDenyNamespace, GateScope                                        string
			ManagerGroups                                                                []string
			NamelessFixtureAllowed, NamedTargetAllowed, UnrelatedNamespaceDenied         bool
		}
		decoder := json.NewDecoder(bytes.NewReader([]byte(result.AuthorizationReceiptJSON)))
		decoder.DisallowUnknownFields()
		wantGroups := []string{"system:serviceaccounts", "system:serviceaccounts:" + env.Config.InstalledManagerFixture.ManagerNamespace, "system:authenticated"}
		if err := decoder.Decode(&receipt); err != nil || ensureJSONEOF(decoder) != nil || receipt.SchemaVersion != "phorvex.installed-fixture-authorization.v1" || receipt.Namespace != env.Config.Namespace || receipt.RoleName != "harness-installed-manager-eviction" || receipt.RoleBindingName != receipt.RoleName || receipt.RoleUID == "" || receipt.RoleBindingUID == "" || receipt.ManagerServiceAccount != env.Config.InstalledManagerFixture.ManagerServiceAccount || receipt.ManagerNamespace != env.Config.InstalledManagerFixture.ManagerNamespace || receipt.TargetName != request.TargetName || receipt.TargetUID != request.TargetUID || receipt.FixtureNonce != env.Config.InstalledManagerFixture.FixtureNonce || receipt.AuthorizationDenyNamespace != env.Config.InstalledManagerFixture.AuthorizationDenyNamespace || !slices.Equal(receipt.ManagerGroups, wantGroups) || !receipt.NamelessFixtureAllowed || !receipt.NamedTargetAllowed || !receipt.UnrelatedNamespaceDenied || receipt.GateScope == "" {
			return errors.Join(err, errors.New("installed manager fixture authorization receipt differs"))
		}
	}
	if result.Coordinator != "d-phorvex-installed" && (result.ControlReceiptJSON != "" || result.EligibleReceiptJSON != "" || result.AuthorizationReceiptJSON != "") {
		return errors.New("non-installed coordinator supplied installed audit receipts")
	}
	return nil
}

func (s *c2InstalledManagerSession) installedSessionAttackResult(stages []string, phase string) core.AttackResult {
	s.updateInstalledSessionBenchmarkEvidence(phase, "not-observed", false, "", "", "")
	return core.AttackResult{Stages: stages, BenchmarkEvidence: s.benchmarkEvidence}
}

func (s *c2InstalledManagerSession) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	known, unknown := installedAvailabilityCounts(s.availability)
	baseEvidence := map[string]string{
		"originalPodUID": string(s.originalUID), "peerPodUID": string(s.peerUID), "availabilityAttempts": strconv.Itoa(len(s.availability.Observations)), "availabilityKnown": strconv.Itoa(known), "availabilityUnknown": strconv.Itoa(unknown),
		"originalCreatedAtUTC": s.originalCreatedAt, "originalAgeReadyAtUTC": s.originalAgeReadyAt,
		"coordinationUsed": strconv.FormatBool(s.coordinationUsed), "coordinationDisposition": s.coordination.Disposition,
	}
	if len(s.availability.Observations) == 0 || known+unknown != len(s.availability.Observations) {
		s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", "availability-unavailable", false, "", "", "")
		return core.OracleResult{Evidence: baseEvidence}, errors.New("installed session availability observation incomplete")
	}
	original, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.originalName, metav1.GetOptions{})
	switch {
	case err == nil && original.UID != s.originalUID:
		s.effectStatus = "identity-ambiguous"
		s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", "", "")
		return core.OracleResult{Evidence: baseEvidence}, errors.New("installed session original Pod name was reused with a different UID")
	case err == nil && original.DeletionTimestamp != nil:
		s.effectStatus = "censored-terminating"
		s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", "", "")
		baseEvidence["originalDeleting"] = "true"
		return core.OracleResult{Evidence: baseEvidence}, errors.New("installed session effect censored while original Pod remained terminating")
	case err == nil:
		if validateErr := validateInstalledSessionObservedPod(ctx, env, original, s.deploymentUID, s.replicaSetName, s.replicaSetUID); validateErr != nil {
			s.effectStatus = "identity-invalid"
			s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", "", "")
			return core.OracleResult{Evidence: baseEvidence}, validateErr
		}
		batch, batchErr := performSessionBatchToService(ctx, env, installedSessionTargetService, []sessionBatchOperation{{Method: "GET", ID: s.sessionID, When: "always"}}, s.producerUID)
		if batchErr != nil || len(batch.Responses) != 1 || batch.ServedUID != s.originalUID {
			s.effectStatus = "original-state-unknown"
			s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", "", "")
			return core.OracleResult{Evidence: baseEvidence}, errors.Join(batchErr, errors.New("installed session retained-original measurement failed"))
		}
		reply := batch.Responses[0].Reply
		if reply.HTTPStatus != 200 || !reply.Body.Present || reply.Body.PodUID != string(s.originalUID) {
			s.effectStatus = "original-state-contradictory"
			s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", "", "")
			return core.OracleResult{Evidence: baseEvidence}, errors.New("installed session exact original did not retain established process state")
		}
		s.oldSessionPresent, s.effectStatus = true, "original-state-retained"
		s.updateInstalledSessionBenchmarkEvidence("oracle-complete", s.effectStatus, true, string(s.originalUID), "", "")
		baseEvidence["oldSessionPresent"], baseEvidence["effectStatus"] = "true", s.effectStatus
		return core.OracleResult{Achieved: true, ObservedState: "benign installed-manager control: exact original Pod UID retained the established process-local session; shared-Service request successes and typed unknowns are reported separately", Evidence: baseEvidence}, nil
	case apierrors.IsNotFound(err):
		s.originalAbsent, s.absenceObservedAt = true, time.Now().UTC().Format(time.RFC3339Nano)
	default:
		s.effectStatus = "identity-read-unavailable"
		s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", "", "")
		return core.OracleResult{Evidence: baseEvidence}, fmt.Errorf("read installed session original Pod: %w", err)
	}

	pods, _, _, err := waitInstalledSessionPods(ctx, env, s.deploymentUID, 20*time.Second)
	if err != nil {
		s.effectStatus = "replacement-unavailable"
		s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", "", "")
		return core.OracleResult{Evidence: baseEvidence}, err
	}
	var replacement *corev1.Pod
	for _, pod := range pods {
		if pod.UID != s.originalUID && pod.UID != s.peerUID {
			if replacement != nil {
				return core.OracleResult{Evidence: baseEvidence}, errors.New("installed session replacement identity ambiguous")
			}
			replacement = pod.DeepCopy()
		}
	}
	if replacement == nil {
		return core.OracleResult{Evidence: baseEvidence}, errors.New("installed session owner-stable replacement missing")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return core.OracleResult{Evidence: baseEvidence}, err
	}
	replacement.Labels[installedSessionTargetRoute] = s.targetRouteValue
	env.Log.Command(fmt.Sprintf("kubectl label pod %s -n %s %s=%s --resource-version=%s", replacement.Name, env.Config.Namespace, installedSessionTargetRoute, s.targetRouteValue, replacement.ResourceVersion))
	replacement, err = env.Kube.CoreV1().Pods(env.Config.Namespace).Update(ctx, replacement, metav1.UpdateOptions{})
	if err != nil || replacement == nil || replacement.UID == "" {
		return core.OracleResult{Evidence: baseEvidence}, errors.Join(err, errors.New("bind installed session replacement route returned no identity"))
	}
	s.replacementUID = replacement.UID
	if err := waitInstalledSessionTargetEndpoint(ctx, env, s.targetServiceUID, replacement.Name, replacement.UID, 20*time.Second); err != nil {
		return core.OracleResult{Evidence: baseEvidence}, err
	}
	freshID := s.sessionID + "-fresh"
	batch, err := performSessionBatchToService(ctx, env, installedSessionTargetService, []sessionBatchOperation{{Method: "GET", ID: s.sessionID, When: "always"}, {Method: "POST", ID: freshID, When: "old-absent"}, {Method: "GET", ID: freshID, When: "old-absent"}}, s.producerUID)
	if err != nil || len(batch.Responses) != 3 || batch.ServedUID != replacement.UID {
		s.effectStatus = "replacement-state-unknown"
		s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", string(replacement.UID), "")
		return core.OracleResult{Evidence: baseEvidence}, errors.Join(err, errors.New("installed session replacement measurement failed"))
	}
	old, created, verified := batch.Responses[0].Reply, batch.Responses[1].Reply, batch.Responses[2].Reply
	if old.HTTPStatus != 404 || old.Body.Present || old.Body.PodUID != string(replacement.UID) || created.HTTPStatus != 201 || !created.Body.Created || !created.Body.Present || created.Body.PodUID != string(replacement.UID) || verified.HTTPStatus != 200 || !verified.Body.Present || verified.Body.PodUID != string(replacement.UID) {
		s.effectStatus = "replacement-state-contradictory"
		s.updateInstalledSessionBenchmarkEvidence("oracle-invalid", s.effectStatus, false, "", string(replacement.UID), "")
		return core.OracleResult{Evidence: baseEvidence}, errors.New("installed session replacement process-state proof differs")
	}
	s.freshStateProven, s.effectStatus = true, "original-state-lost-fresh-state-recovered"
	attribution := "unattributed"
	if s.coordinationUsed && s.coordination.Disposition == "dispatched-unconfirmed" {
		attribution = "target-matched-dispatch-and-independent-effect"
	}
	s.updateInstalledSessionBenchmarkEvidence("oracle-complete", s.effectStatus, false, attribution, string(replacement.UID), s.absenceObservedAt)
	baseEvidence["originalUIDAbsent"], baseEvidence["replacementPodUID"], baseEvidence["oldSessionPresent"], baseEvidence["freshStateProven"], baseEvidence["effectStatus"], baseEvidence["effectAttribution"] = "true", string(replacement.UID), "false", "true", s.effectStatus, attribution
	return core.OracleResult{Achieved: false, ObservedState: "benign installed-manager control: exact original UID was absent; an owner-stable replacement lacked the old process-local session and retained fresh state; shared-Service request successes and typed unknowns are reported separately", Evidence: baseEvidence}, nil
}

func validateInstalledSessionObservedPod(ctx context.Context, env *core.Env, pod *corev1.Pod, deploymentUID types.UID, rsName string, rsUID types.UID) error {
	if pod == nil || pod.UID == "" || !podReady(pod) || pod.DeletionTimestamp != nil || pod.Annotations["r6th.io/session-source-sha256"] != sessionServerSourceSHA256() || len(pod.Spec.Containers) != 1 {
		return errors.New("installed session observed Pod provenance differs")
	}
	for key, value := range env.OwnedLabels(map[string]string{"app": installedSessionApp}) {
		if pod.Labels[key] != value {
			return fmt.Errorf("installed session observed Pod label %q differs", key)
		}
	}
	container := pod.Spec.Containers[0]
	if container.Name != "session" || container.Image != sessionPythonImage || !slices.Equal(container.Command, []string{"python3", "-B", "-c", sessionServerSource}) || !exactSessionControllerOwner(pod.OwnerReferences, "ReplicaSet", rsName, rsUID) {
		return errors.New("installed session observed Pod container/controller differs")
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, rsName, metav1.GetOptions{})
	if err != nil || rs.UID != rsUID || !exactSessionControllerOwner(rs.OwnerReferences, "Deployment", installedSessionDeployment, deploymentUID) {
		return errors.New("installed session observed ReplicaSet/Deployment differs")
	}
	return nil
}

func exactSessionControllerOwner(owners []metav1.OwnerReference, kind, name string, uid types.UID) bool {
	matches := 0
	for _, owner := range owners {
		if owner.Controller != nil && *owner.Controller {
			if owner.Kind != kind || owner.Name != name || owner.UID != uid {
				return false
			}
			matches++
		}
	}
	return matches == 1
}

func installedAvailabilityCounts(availability installedSessionAvailability) (known, unknown int) {
	for _, observation := range availability.Observations {
		if observation.Known {
			known++
		} else {
			unknown++
		}
	}
	return known, unknown
}

func (s *c2InstalledManagerSession) updateInstalledSessionBenchmarkEvidence(phase, oracleStatus string, achieved bool, attribution, observedUID, absenceAt string) error {
	known, unknown := installedAvailabilityCounts(s.availability)
	rawHash := ""
	if s.availabilityRaw != "" {
		sum := sha256.Sum256([]byte(s.availabilityRaw))
		rawHash = fmt.Sprintf("%x", sum)
	}
	evidence := map[string]string{
		"schema":                             "phorvex.installed-session-benchmark-evidence.v1",
		"suite":                              "post25-installed-manager-session.v1",
		"phase":                              phase,
		"oracle.status":                      oracleStatus,
		"oracle.achieved":                    strconv.FormatBool(achieved),
		"claimScope":                         "benign-process-state-and-availability-only",
		"fixture.image":                      sessionPythonImage,
		"source.serverSHA256":                sessionServerSourceSHA256(),
		"source.availabilitySHA256":          installedSessionAvailabilitySourceSHA256(),
		"deployment.uid":                     string(s.deploymentUID),
		"availabilityPolicy.name":            installedSessionPDB,
		"availabilityPolicy.uid":             string(s.pdbUID),
		"availabilityPolicy.initialRV":       s.pdbRV,
		"availabilityPolicy.eligibleRV":      s.coordination.AvailabilityPolicyResourceVersion,
		"availabilityPolicy.initialMinimum":  "2",
		"availabilityPolicy.eligibleMinimum": "1",
		"replicaSet.uid":                     string(s.replicaSetUID),
		"original.podUID":                    string(s.originalUID),
		"original.createdAtUTC":              s.originalCreatedAt,
		"original.ageReadyAtUTC":             s.originalAgeReadyAt,
		"original.minimumAgeSeconds":         strconv.FormatInt(int64(installedSessionMinimumPodAge/time.Second), 10),
		"peer.podUID":                        string(s.peerUID),
		"replacement.podUID":                 string(s.replacementUID),
		"original.absent":                    strconv.FormatBool(s.originalAbsent),
		"original.absenceObservedAt":         absenceAt,
		"oldSession.present":                 strconv.FormatBool(s.oldSessionPresent),
		"freshState.proven":                  strconv.FormatBool(s.freshStateProven),
		"effect.status":                      s.effectStatus,
		"effect.attribution":                 attribution,
		"effect.observedPodUID":              observedUID,
		"availability.windowMillis":          strconv.FormatInt(installedSessionWindow.Milliseconds(), 10),
		"availability.cadenceMillis":         strconv.FormatInt(installedSessionSamplePeriod.Milliseconds(), 10),
		"availability.segmentCount":          strconv.Itoa(s.availability.SegmentCount),
		"availability.startedAtUTC":          s.availability.StartedAtUTC,
		"availability.endedAtUTC":            s.availability.EndedAtUTC,
		"availability.attempts":              strconv.Itoa(len(s.availability.Observations)),
		"availability.known":                 strconv.Itoa(known),
		"availability.unknown":               strconv.Itoa(unknown),
		"availability.segmentReceiptsSHA256": rawHash,
		"coordination.used":                  strconv.FormatBool(s.coordinationUsed),
		"coordination.schema":                s.coordination.SchemaVersion,
		"coordination.coordinator":           s.coordination.Coordinator,
		"coordination.startedAtUTC":          s.coordination.StartedAtUTC,
		"coordination.endedAtUTC":            s.coordination.EndedAtUTC,
		"coordination.disposition":           s.coordination.Disposition,
		"coordination.attributionComplete":   strconv.FormatBool(s.coordination.AttributionComplete),
		"coordination.targetUID":             s.coordination.TargetUID,
		"coordination.targetResourceVersion": s.coordination.TargetResourceVersion,
		"coordination.requestedGraceSeconds": strconv.FormatInt(s.coordination.RequestedGraceSeconds, 10),
		"coordination.actionAtUTC":           s.coordination.ActionAtUTC,
		"coordination.controlReceipt":        s.coordination.ControlReceiptJSON,
		"coordination.eligibleReceipt":       s.coordination.EligibleReceiptJSON,
		"coordination.authorizationReceipt":  s.coordination.AuthorizationReceiptJSON,
		"availability.observationCount":      strconv.Itoa(len(s.availability.Observations)),
	}
	for i, observation := range s.availability.Observations {
		raw, err := json.Marshal(observation)
		if err != nil {
			return err
		}
		evidence[fmt.Sprintf("availability.observation.%03d", i)] = string(raw)
	}
	if s.benchmarkEvidence == nil {
		s.benchmarkEvidence = map[string]string{}
	}
	clear(s.benchmarkEvidence)
	for key, value := range evidence {
		s.benchmarkEvidence[key] = value
	}
	return validateInstalledSessionBenchmarkEvidence(s.benchmarkEvidence)
}

func validateInstalledSessionBenchmarkEvidence(evidence map[string]string) error {
	if len(evidence) > 256 {
		return fmt.Errorf("installed session benchmark evidence has %d fields", len(evidence))
	}
	total := 0
	for key, value := range evidence {
		if len(key) > 64 || len(value) > 32*1024 {
			return fmt.Errorf("installed session benchmark evidence field exceeds bound: %s", key)
		}
		total += len(key) + len(value)
	}
	if total > 128*1024 {
		return fmt.Errorf("installed session benchmark evidence exceeds byte bound: %d", total)
	}
	required := []string{"schema", "suite", "phase", "oracle.status", "oracle.achieved", "claimScope", "fixture.image", "source.serverSHA256", "source.availabilitySHA256", "deployment.uid", "availabilityPolicy.name", "availabilityPolicy.uid", "availabilityPolicy.initialRV", "availabilityPolicy.eligibleRV", "availabilityPolicy.initialMinimum", "availabilityPolicy.eligibleMinimum", "replicaSet.uid", "original.podUID", "original.createdAtUTC", "original.ageReadyAtUTC", "original.minimumAgeSeconds", "peer.podUID", "replacement.podUID", "original.absent", "original.absenceObservedAt", "oldSession.present", "freshState.proven", "effect.status", "effect.attribution", "effect.observedPodUID", "availability.windowMillis", "availability.cadenceMillis", "availability.segmentCount", "availability.startedAtUTC", "availability.endedAtUTC", "availability.attempts", "availability.known", "availability.unknown", "availability.segmentReceiptsSHA256", "availability.observationCount", "coordination.used", "coordination.schema", "coordination.coordinator", "coordination.startedAtUTC", "coordination.endedAtUTC", "coordination.disposition", "coordination.attributionComplete", "coordination.targetUID", "coordination.targetResourceVersion", "coordination.requestedGraceSeconds", "coordination.actionAtUTC", "coordination.controlReceipt", "coordination.eligibleReceipt", "coordination.authorizationReceipt"}
	allowed := make(map[string]bool, len(required)+installedSessionSampleLimit)
	for _, key := range required {
		allowed[key] = true
		if _, ok := evidence[key]; !ok {
			return fmt.Errorf("installed session benchmark evidence missing %s", key)
		}
	}
	if evidence["schema"] != "phorvex.installed-session-benchmark-evidence.v1" || evidence["suite"] != "post25-installed-manager-session.v1" || evidence["claimScope"] != "benign-process-state-and-availability-only" || evidence["fixture.image"] != sessionPythonImage || evidence["source.serverSHA256"] != sessionServerSourceSHA256() || evidence["source.availabilitySHA256"] != installedSessionAvailabilitySourceSHA256() || evidence["availabilityPolicy.name"] != installedSessionPDB || evidence["availabilityPolicy.uid"] == "" || evidence["availabilityPolicy.initialRV"] == "" || evidence["availabilityPolicy.initialMinimum"] != "2" || evidence["availabilityPolicy.eligibleMinimum"] != "1" {
		return errors.New("installed session benchmark evidence source/schema differs")
	}
	createdAt, createdErr := time.Parse(time.RFC3339Nano, evidence["original.createdAtUTC"])
	ageReadyAt, ageReadyErr := time.Parse(time.RFC3339Nano, evidence["original.ageReadyAtUTC"])
	if createdErr != nil || ageReadyErr != nil || ageReadyAt.Sub(createdAt) < installedSessionMinimumPodAge || evidence["original.minimumAgeSeconds"] != "90" {
		return errors.New("installed session target age evidence invalid")
	}
	if !installedOneOf(evidence["phase"], "establishment-invalid", "availability-invalid", "coordination-invalid", "execute-complete", "oracle-complete", "oracle-invalid") {
		return errors.New("installed session benchmark evidence phase invalid")
	}
	for _, key := range []string{"oracle.achieved", "original.absent", "oldSession.present", "freshState.proven", "coordination.used", "coordination.attributionComplete"} {
		if _, err := strconv.ParseBool(evidence[key]); err != nil {
			return fmt.Errorf("installed session benchmark evidence %s invalid", key)
		}
	}
	attempts, err := strconv.Atoi(evidence["availability.attempts"])
	if err != nil || attempts < 0 || attempts > installedSessionSampleLimit || evidence["availability.observationCount"] != strconv.Itoa(attempts) {
		return errors.New("installed session benchmark evidence attempt count invalid")
	}
	known, errKnown := strconv.Atoi(evidence["availability.known"])
	unknown, errUnknown := strconv.Atoi(evidence["availability.unknown"])
	if errKnown != nil || errUnknown != nil || known < 0 || unknown < 0 || known+unknown != attempts {
		return errors.New("installed session benchmark evidence known/unknown counts differ")
	}
	retainedKnown := 0
	for i := 0; i < attempts; i++ {
		key := fmt.Sprintf("availability.observation.%03d", i)
		allowed[key] = true
		raw := []byte(evidence[key])
		if err := rejectDuplicateJSONFields(raw); err != nil {
			return err
		}
		var observation installedSessionAvailabilityObservation
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&observation); err != nil || ensureJSONEOF(dec) != nil {
			return fmt.Errorf("installed session benchmark evidence %s invalid", key)
		}
		if _, err := time.Parse(time.RFC3339Nano, observation.AtUTC); err != nil {
			return fmt.Errorf("installed session benchmark evidence %s timestamp invalid", key)
		}
		if observation.Known {
			retainedKnown++
			if observation.Category != "application-response" || observation.PodUID == "" || !installedOneOf(strconv.Itoa(observation.HTTPStatus), "200", "404") {
				return fmt.Errorf("installed session benchmark evidence %s known shape invalid", key)
			}
		} else if observation.PodUID != "" || !installedOneOf(observation.Category, "transport-unavailable", "invalid-response", "response-too-large") {
			return fmt.Errorf("installed session benchmark evidence %s unknown shape invalid", key)
		}
	}
	if retainedKnown != known {
		return errors.New("installed session benchmark evidence retained known count differs")
	}
	for key := range evidence {
		if !allowed[key] {
			return fmt.Errorf("installed session benchmark evidence key %s not allowed", key)
		}
	}
	coordinationUsed, _ := strconv.ParseBool(evidence["coordination.used"])
	if !coordinationUsed {
		for _, key := range []string{"coordination.schema", "coordination.coordinator", "coordination.startedAtUTC", "coordination.endedAtUTC", "coordination.disposition", "coordination.targetUID", "coordination.targetResourceVersion", "coordination.actionAtUTC", "coordination.controlReceipt", "coordination.eligibleReceipt", "coordination.authorizationReceipt"} {
			if evidence[key] != "" {
				return errors.New("installed session benchmark evidence has coordination data without coordinator")
			}
		}
		if evidence["coordination.requestedGraceSeconds"] != "0" || evidence["coordination.attributionComplete"] != "false" {
			return errors.New("installed session benchmark evidence no-coordinator counters differ")
		}
	} else {
		if evidence["availabilityPolicy.eligibleRV"] == "" || evidence["availabilityPolicy.eligibleRV"] == evidence["availabilityPolicy.initialRV"] {
			return errors.New("installed session benchmark evidence availability policy transition missing")
		}
		for _, key := range []string{"coordination.schema", "coordination.coordinator", "coordination.startedAtUTC", "coordination.endedAtUTC", "coordination.disposition", "coordination.targetUID", "coordination.targetResourceVersion"} {
			if evidence[key] == "" {
				return fmt.Errorf("installed session benchmark evidence missing %s", key)
			}
		}
	}
	return nil
}

func (s *c2InstalledManagerSession) Teardown(ctx context.Context, env *core.Env) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	var problems []error
	foreground := metav1.DeletePropagationForeground
	deleteOptions := func(uid types.UID) metav1.DeleteOptions {
		return metav1.DeleteOptions{PropagationPolicy: &foreground, Preconditions: &metav1.Preconditions{UID: &uid}}
	}
	if s.pdbUID != "" {
		env.Log.Command(fmt.Sprintf("kubectl delete poddisruptionbudget %s -n %s --precondition-uid=%s", installedSessionPDB, env.Config.Namespace, s.pdbUID))
		if err := env.Kube.PolicyV1().PodDisruptionBudgets(env.Config.Namespace).Delete(ctx, installedSessionPDB, deleteOptions(s.pdbUID)); err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, err)
		}
	}
	for _, service := range []struct {
		name string
		uid  types.UID
	}{{installedSessionTargetService, s.targetServiceUID}, {installedSessionSharedService, s.sharedServiceUID}} {
		if service.uid == "" {
			continue
		}
		env.Log.Command(fmt.Sprintf("kubectl delete service %s -n %s --precondition-uid=%s", service.name, env.Config.Namespace, service.uid))
		if err := env.Kube.CoreV1().Services(env.Config.Namespace).Delete(ctx, service.name, deleteOptions(service.uid)); err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, err)
		}
	}
	if s.deploymentUID != "" {
		env.Log.Command(fmt.Sprintf("kubectl delete deployment %s -n %s --precondition-uid=%s", installedSessionDeployment, env.Config.Namespace, s.deploymentUID))
		if err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Delete(ctx, installedSessionDeployment, deleteOptions(s.deploymentUID)); err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, err)
		}
	}
	if s.producerUID != "" {
		env.Log.Command(fmt.Sprintf("kubectl delete pod %s -n %s --precondition-uid=%s", sessionProducer, env.Config.Namespace, s.producerUID))
		if err := env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, sessionProducer, deleteOptions(s.producerUID)); err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func installedOneOf(value string, allowed ...string) bool {
	return slices.Contains(allowed, value)
}
