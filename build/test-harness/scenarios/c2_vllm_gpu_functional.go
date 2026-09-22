package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/portforward"
	transportspdy "k8s.io/client-go/transport/spdy"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/gpufunctional"
)

const (
	vllmPrefixScenario = "c2-vllm-prefix-cache-reset"
	vllmDrainScenario  = "c2-vllm-request-drain"
	vllmSuiteVersion   = "post25-vllm-functional-v1"
	vllmRunLabelKey    = "fixture.phorvex.ai/run"
	vllmModelLabelKey  = "fixture.phorvex.ai/model-digest"
)

func init() {
	core.RegisterScenario(&c2VLLMFunctional{operation: "prefix-cache-reset"})
	core.RegisterScenario(&c2VLLMFunctional{operation: "request-drain"})
}

type c2VLLMFunctional struct {
	operation   string
	unavailable string
	probe       *gpufunctional.Client
	capability  gpufunctional.Capability
	receipt     any
	evidence    map[string]string
	portStop    chan struct{}
	portDone    chan error
}

func (s *c2VLLMFunctional) Metadata() core.ScenarioMeta {
	name, mechanism, oracle := vllmPrefixScenario,
		"real vLLM 0.7.3 OPT-125m prefix-cache protocol through an exact owned ordinary-GPU Pod port-forward",
		"establishes real prefix reuse; direct mode requires idle reset acknowledgement, first post-reset miss, later repopulation, and correlated busy refusal"
	if s.operation == "request-drain" {
		name = vllmDrainScenario
		mechanism = "real streaming vLLM 0.7.3 OPT-125m request plus operation-bound drain, exact dispositions, admission closure and explicit reopen"
		oracle = "binds a live admitted stream to one operation generation; requires closed late admission, complete dispositions, two zero-queue observations, unchanged engine epoch, reopen, and successful recovery inference"
	}
	return core.ScenarioMeta{
		Name: name, Category: core.CategoryR6Claimed,
		Source:                 "Post25 accepted ordinary-GPU vLLM 0.7.3 functional producers",
		R6ResponseTag:          core.R6Partial,
		BenignControl:          true,
		Realism:                core.RealismExecutable,
		Mechanism:              mechanism,
		ClaimLimits:            "functional direct/no-action control only; the arms use different request counts and horizons and are ineligible for availability, cost, latency or brain-performance comparison; no cross-session leak, physical erasure, CVE, installed-manager dispatch, detection, containment, voice equivalence, ROI, or security-efficacy claim",
		OracleDescription:      oracle,
		CleanupDescription:     "close the exact Pod port-forward, restore drain admission when a direct operation began, and revalidate the externally owned Pod, owner, Service, EndpointSlice, node, engine epoch and source without deleting them",
		R6Justification:        "Promotes already exercised real GPU protocol producers into a repeatable benign benchmark while keeping direct functional effects separate from installed decision attribution.",
		CapabilityRequirements: []core.Capability{core.CapGPU},
	}
}

func (s *c2VLLMFunctional) Setup(ctx context.Context, env *core.Env) error {
	operation := s.operation
	*s = c2VLLMFunctional{operation: operation}
	fixture := env.Config.GPUFunctionalFixture
	if fixture == nil {
		s.unavailable = "GPU functional fixture authority is not configured"
		return nil
	}
	if fixture.Operation != s.operation {
		return fmt.Errorf("GPU fixture operation %q does not match scenario %q", fixture.Operation, s.operation)
	}
	if err := s.validateFixture(ctx, env, fixture); err != nil {
		return err
	}
	token, err := readGPUFixtureToken(fixture.BearerTokenFile)
	if err != nil {
		return err
	}
	if err := s.openProbe(ctx, env, token); err != nil {
		return errors.Join(err, s.closePortForward())
	}
	capability, _, err := s.probe.Capability(ctx)
	if err != nil {
		return fmt.Errorf("GPU fixture capability unavailable: %w", err)
	}
	if err := validateGPUCapability(capability, fixture); err != nil {
		return err
	}
	s.capability = capability
	return nil
}

func readGPUFixtureToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read GPU fixture bearer metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > 4096 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("GPU fixture bearer file must be a private regular file of 32..4096 bytes")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read GPU fixture bearer: %w", err)
	}
	if bytes.ContainsAny(raw, "\r\n\x00") {
		return "", errors.New("GPU fixture bearer content is malformed")
	}
	token := string(raw)
	if len(token) < 32 || strings.TrimSpace(token) != token {
		return "", errors.New("GPU fixture bearer content is malformed")
	}
	return token, nil
}

func (s *c2VLLMFunctional) validateFixture(ctx context.Context, env *core.Env, fixture *config.GPUFunctionalFixtureConfig) error {
	current, err := env.NamespaceCurrent(ctx)
	if err != nil {
		return fmt.Errorf("read GPU fixture namespace authority: %w", err)
	}
	if !current {
		return errors.New("GPU fixture namespace authority differs")
	}
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read GPU fixture namespace: %w", err)
	}
	if string(ns.UID) != fixture.NamespaceUID || ns.DeletionTimestamp != nil {
		return errors.New("GPU fixture namespace identity differs")
	}
	node, err := env.Kube.CoreV1().Nodes().Get(ctx, fixture.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read GPU fixture node: %w", err)
	}
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, fixture.PodName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(pod.UID) != fixture.PodUID || pod.DeletionTimestamp != nil || pod.Spec.NodeName != fixture.NodeName || !podReady(pod) || pod.Labels[vllmRunLabelKey] != fixture.RunLabel || pod.Annotations[vllmModelLabelKey] != fixture.ModelDigest || pod.Labels[core.OwnedLabelKey] == core.OwnedLabelValue {
		return errors.New("GPU fixture Pod identity, readiness, node, run/model binding or external ownership differs")
	}
	if err := validateGPUNode(node, pod, fixture); err != nil {
		return err
	}
	if !exactControllerOwner(pod.OwnerReferences, fixture.OwnerKind, fixture.OwnerName, types.UID(fixture.OwnerUID)) {
		return errors.New("GPU fixture Pod controller owner differs")
	}
	if err := validateGPUOwner(ctx, env, fixture); err != nil {
		return err
	}
	container, status, err := exactGPUContainer(pod, fixture.ContainerName)
	if err != nil {
		return err
	}
	gpu := container.Resources.Limits[corev1.ResourceName("nvidia.com/gpu")]
	if gpu.Cmp(resource.MustParse("1")) != 0 || container.Image != fixture.Image || status.ImageID != fixture.ImageID || status.RestartCount != fixture.RestartCount || status.State.Running == nil || status.State.Running.StartedAt.UTC().Format(time.RFC3339Nano) != fixture.StartedAt {
		return errors.New("GPU fixture container image, runtime incarnation or exact one-GPU limit differs")
	}
	svc, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, fixture.ServiceName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(svc.UID) != fixture.ServiceUID || svc.DeletionTimestamp != nil || svc.Labels[vllmRunLabelKey] != fixture.RunLabel || svc.Labels[core.OwnedLabelKey] == core.OwnedLabelValue || len(svc.Spec.Selector) == 0 || svc.Spec.Selector[vllmRunLabelKey] != fixture.RunLabel || len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != fixture.Port || svc.Spec.Ports[0].TargetPort.IntValue() != int(fixture.Port) {
		return errors.New("GPU fixture Service identity, selector, ownership or port differs")
	}
	for key, value := range svc.Spec.Selector {
		if pod.Labels[key] != value {
			return errors.New("GPU fixture Service selector does not select the exact Pod")
		}
	}
	selected, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector})})
	if err != nil {
		return fmt.Errorf("list GPU fixture selected Pods: %w", err)
	}
	if len(selected.Items) != 1 || selected.Items[0].UID != pod.UID {
		return errors.New("GPU fixture Service selector is not single-Pod exact")
	}
	return validateGPUEndpoint(ctx, env, fixture, pod.UID)
}

func validateGPUNode(node *corev1.Node, pod *corev1.Pod, fixture *config.GPUFunctionalFixtureConfig) error {
	if node == nil || pod == nil || node.Name != fixture.NodeName || string(node.UID) != fixture.NodeUID || node.DeletionTimestamp != nil || node.Spec.Unschedulable {
		return errors.New("GPU fixture node identity/readiness differs")
	}
	ready := false
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			ready = condition.Status == corev1.ConditionTrue
			break
		}
	}
	allocatable := node.Status.Allocatable[corev1.ResourceName("nvidia.com/gpu")]
	if !ready || allocatable.Cmp(resource.MustParse("1")) < 0 {
		return errors.New("GPU fixture node is not Ready or lacks one allocatable GPU")
	}
	if len(node.Spec.Taints) == 0 {
		return nil
	}
	if len(node.Spec.Taints) != 1 {
		return errors.New("GPU fixture node has foreign or additional taints")
	}
	taint := node.Spec.Taints[0]
	if taint.Key != "nvidia.com/gpu" || taint.Value != "true" || taint.Effect != corev1.TaintEffectNoSchedule {
		return errors.New("GPU fixture node taint differs from the exact dedicated-GPU taint")
	}
	matched := 0
	for _, toleration := range pod.Spec.Tolerations {
		if toleration.Key == taint.Key && toleration.Value == taint.Value && toleration.Effect == taint.Effect && (toleration.Operator == "" || toleration.Operator == corev1.TolerationOpEqual) && toleration.TolerationSeconds == nil {
			matched++
		}
	}
	if matched != 1 {
		return errors.New("GPU fixture Pod lacks one exact dedicated-GPU taint toleration")
	}
	return nil
}

func exactControllerOwner(refs []metav1.OwnerReference, kind, name string, uid types.UID) bool {
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller && ref.Kind == kind && ref.Name == name && ref.UID == uid {
			return true
		}
	}
	return false
}

func validateGPUOwner(ctx context.Context, env *core.Env, fixture *config.GPUFunctionalFixtureConfig) error {
	var uid types.UID
	var labels map[string]string
	var deleting bool
	switch fixture.OwnerKind {
	case "Deployment":
		obj, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Get(ctx, fixture.OwnerName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		uid, labels, deleting = obj.UID, obj.Labels, obj.DeletionTimestamp != nil
	case "ReplicaSet":
		obj, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, fixture.OwnerName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		uid, labels, deleting = obj.UID, obj.Labels, obj.DeletionTimestamp != nil
	case "StatefulSet":
		obj, err := env.Kube.AppsV1().StatefulSets(env.Config.Namespace).Get(ctx, fixture.OwnerName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		uid, labels, deleting = obj.UID, obj.Labels, obj.DeletionTimestamp != nil
	}
	if string(uid) != fixture.OwnerUID || deleting || labels[vllmRunLabelKey] != fixture.RunLabel || labels[core.OwnedLabelKey] == core.OwnedLabelValue {
		return errors.New("GPU fixture controller identity, run binding or external ownership differs")
	}
	return nil
}

func exactGPUContainer(pod *corev1.Pod, name string) (corev1.Container, corev1.ContainerStatus, error) {
	var containers []corev1.Container
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			containers = append(containers, c)
		}
	}
	var statuses []corev1.ContainerStatus
	for _, st := range pod.Status.ContainerStatuses {
		if st.Name == name {
			statuses = append(statuses, st)
		}
	}
	if len(containers) != 1 || len(statuses) != 1 {
		return corev1.Container{}, corev1.ContainerStatus{}, errors.New("GPU fixture exact container/status is absent or ambiguous")
	}
	return containers[0], statuses[0], nil
}

func validateGPUEndpoint(ctx context.Context, env *core.Env, fixture *config.GPUFunctionalFixtureConfig, podUID types.UID) error {
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + fixture.ServiceName})
	if err != nil {
		return err
	}
	matches := 0
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Name != fixture.PodName || endpoint.TargetRef.UID != podUID {
				continue
			}
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				return errors.New("GPU fixture exact endpoint is not ready")
			}
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("GPU fixture requires one exact ready endpoint, got %d", matches)
	}
	return nil
}

func validateGPUCapability(cap gpufunctional.Capability, fixture *config.GPUFunctionalFixtureConfig) error {
	if cap.PodUID != fixture.PodUID || cap.EngineSource != fixture.EngineSourceSHA256 || (fixture.ProxySourceGitSHA != "" && cap.ProxySource != fixture.ProxySourceGitSHA) || cap.Admission != "OPEN" {
		return errors.New("GPU engine capability Pod/source/admission identity differs")
	}
	return nil
}

func (s *c2VLLMFunctional) openProbe(ctx context.Context, env *core.Env, token string) error {
	if env.Rest == nil {
		return errors.New("GPU fixture requires live REST config for exact Pod port-forward")
	}
	transport, upgrader, err := transportspdy.RoundTripperFor(env.Rest)
	if err != nil {
		return err
	}
	u, err := url.Parse(env.Rest.Host)
	if err != nil {
		return err
	}
	u.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", env.Config.Namespace, env.Config.GPUFunctionalFixture.PodName)
	u.RawQuery, u.Fragment = "", ""
	dialer := transportspdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, u)
	s.portStop = make(chan struct{})
	ready := make(chan struct{})
	s.portDone = make(chan error, 1)
	var out, errOut bytes.Buffer
	pf, err := portforward.New(dialer, []string{"0:" + strconv.Itoa(int(env.Config.GPUFunctionalFixture.Port))}, s.portStop, ready, &out, &errOut)
	if err != nil {
		return err
	}
	go func() { s.portDone <- pf.ForwardPorts() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-s.portDone:
		close(s.portStop)
		s.portStop, s.portDone = nil, nil
		return fmt.Errorf("GPU port-forward stopped before ready: %v %s", err, errOut.String())
	case <-ready:
	}
	ports, err := pf.GetPorts()
	if err != nil || len(ports) != 1 || ports[0].Remote != uint16(env.Config.GPUFunctionalFixture.Port) {
		return fmt.Errorf("GPU forwarded port identity differs: %v", err)
	}
	s.probe, err = gpufunctional.New(fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local), token, nil)
	return err
}

func (s *c2VLLMFunctional) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if s.unavailable != "" {
		return core.AttackResult{Skipped: true, SkipReason: s.unavailable}, nil
	}
	fixture := env.Config.GPUFunctionalFixture
	direct := fixture.Mode == "direct"
	var err error
	if s.operation == "prefix-cache-reset" {
		receipt, runErr := s.probe.RunPrefix(ctx, direct)
		s.receipt, err = receipt, runErr
	} else {
		owner := gpufunctional.DrainOwner{Tenant: "catalogue-functional", NamespaceUID: fixture.NamespaceUID, PolicyUID: fixture.RunLabel, PodUID: fixture.PodUID, ServiceUID: fixture.ServiceUID}
		receipt, runErr := s.probe.RunDrain(ctx, direct, owner)
		s.receipt, err = receipt, runErr
	}
	raw, marshalErr := json.Marshal(s.receipt)
	status := "complete"
	if err != nil {
		status = "incomplete"
	}
	attempts, acknowledgements, restorationAttempts, restorationAcknowledgements := vllmProtocolCounts(s.receipt)
	s.evidence = map[string]string{
		"suiteVersion": vllmSuiteVersion, "scenario": s.Metadata().Name, "operation": s.operation, "fixtureMode": fixture.Mode,
		"functionalArm": map[bool]string{true: "direct-producer", false: "no-action"}[direct], "oracleStatus": status,
		"receiptJSON": string(raw), "receiptSHA256": fmt.Sprintf("%x", sha256.Sum256(raw)),
		"protocolOperationAttempts": strconv.Itoa(attempts), "protocolOperationAcknowledgements": strconv.Itoa(acknowledgements),
		"restorationAttempts": strconv.Itoa(restorationAttempts), "restorationAcknowledgements": strconv.Itoa(restorationAcknowledgements),
		"installedManagerDispatchProven": "false", "nativeHandlerDispatchProven": "false",
		"securityOutcome": "not-measured", "cveOutcome": "not-measured", "costOutcome": "not-measured", "namespaceUID": fixture.NamespaceUID,
		"workloadComparison": "unmatched-functional-protocol-check", "availabilityComparisonEligible": "false",
		"costComparisonEligible": "false", "brainPerformanceComparisonEligible": "false",
		"podUID": fixture.PodUID, "serviceUID": fixture.ServiceUID, "ownerUID": fixture.OwnerUID, "nodeUID": fixture.NodeUID,
		"engineBootID": s.capability.EngineBootID, "engineSourceSHA256": fixture.EngineSourceSHA256, "modelDigest": fixture.ModelDigest,
	}
	if evidenceErr := validateVLLMEvidence(s.evidence); evidenceErr != nil {
		err = errors.Join(err, evidenceErr)
	}
	return core.AttackResult{Stages: vllmStages(s.operation, direct, s.receipt), BenchmarkEvidence: s.evidence}, errors.Join(err, marshalErr)
}

func vllmProtocolCounts(receipt any) (attempts, acknowledgements, restorationAttempts, restorationAcknowledgements int) {
	observed := func(observation gpufunctional.Observation) bool { return observation.StartedAt != "" }
	acknowledged := func(observation gpufunctional.Observation) bool {
		return observation.Status >= 200 && observation.Status < 300 && len(observation.Body) != 0
	}
	switch value := receipt.(type) {
	case gpufunctional.PrefixReceipt:
		if reset := value.Reset; reset != nil {
			if observed(reset.Observation) {
				attempts++
			}
			if acknowledged(reset.Observation) {
				acknowledgements++
			}
		}
		if value.Busy != nil {
			if observed(value.Busy.Reset.Observation) {
				attempts++
			}
			if acknowledged(value.Busy.Reset.Observation) {
				acknowledgements++
			}
		}
	case gpufunctional.DrainReceipt:
		if value.CreateObservation != nil && observed(*value.CreateObservation) {
			attempts++
		}
		if value.CreateObservation != nil && acknowledged(*value.CreateObservation) && value.Create != nil && value.Create.OperationID != "" {
			acknowledgements++
		}
		if value.ReopenObservation != nil && observed(*value.ReopenObservation) {
			restorationAttempts++
		}
		if value.ReopenObservation != nil && acknowledged(*value.ReopenObservation) && value.Reopen != nil && value.Reopen.State == "OPENED" {
			restorationAcknowledgements++
		}
		for _, observation := range value.CleanupObservations {
			if !strings.HasSuffix(observation.Path, "/reopen") {
				continue
			}
			if observed(observation) {
				restorationAttempts++
			}
			if acknowledged(observation) && value.Reopen != nil && value.Reopen.State == "OPENED" {
				restorationAcknowledgements++
			}
		}
	}
	return
}

func vllmStages(operation string, direct bool, receipt any) []string {
	stages := []string{"bind exact external GPU fixture and establish real inference"}
	if !direct {
		return append(stages, "observe bounded no-action functional state")
	}
	if operation == "prefix-cache-reset" {
		return append(stages, "establish real prefix reuse", "send one direct idle prefix reset", "observe first miss then cache repopulation", "correlate busy reset refusal with live inference")
	}
	return append(stages, "admit one real streaming request", "send one operation-bound direct drain", "observe admission closure and complete request dispositions", "observe two zero-queue snapshots", "reopen admission and prove recovery inference")
}

func validateVLLMEvidence(evidence map[string]string) error {
	if len(evidence) > 40 {
		return errors.New("GPU functional evidence item count exceeds bound")
	}
	total := 0
	for key, value := range evidence {
		if len(key) > 96 || len(value) > 512<<10 {
			return fmt.Errorf("GPU evidence field %q exceeds bound", key)
		}
		total += len(key) + len(value)
	}
	if total > 768<<10 {
		return errors.New("GPU functional evidence total exceeds bound")
	}
	return nil
}

func (s *c2VLLMFunctional) SuccessOracle(context.Context, *core.Env) (core.OracleResult, error) {
	if s.receipt == nil || s.evidence["oracleStatus"] != "complete" {
		return core.OracleResult{}, errors.New("GPU functional receipt is incomplete")
	}
	state := fmt.Sprintf("%s %s functional oracle complete; security and installed dispatch not measured", s.operation, s.evidence["functionalArm"])
	return core.OracleResult{Achieved: true, ObservedState: state, Evidence: s.evidence}, nil
}

func (s *c2VLLMFunctional) Teardown(ctx context.Context, env *core.Env) error {
	if env.Config.GPUFunctionalFixture == nil || s.unavailable != "" {
		return s.closePortForward()
	}
	var capabilityErr error
	if s.probe != nil {
		capability, _, err := s.probe.Capability(ctx)
		if err == nil {
			err = validateGPUCapability(capability, env.Config.GPUFunctionalFixture)
		}
		if err == nil && s.capability.EngineBootID != "" && capability.EngineBootID != s.capability.EngineBootID {
			err = errors.New("GPU fixture engine boot changed during trial")
		}
		capabilityErr = err
	}
	forwardErr := s.closePortForward()
	return errors.Join(capabilityErr, forwardErr, s.validateFixture(ctx, env, env.Config.GPUFunctionalFixture))
}

func (s *c2VLLMFunctional) closePortForward() error {
	return s.closePortForwardWithin(3 * time.Second)
}

func (s *c2VLLMFunctional) closePortForwardWithin(bound time.Duration) error {
	if s.portStop != nil {
		close(s.portStop)
		s.portStop = nil
		select {
		case err := <-s.portDone:
			s.portDone = nil
			return err
		case <-time.After(bound):
			return errors.New("GPU fixture port-forward did not stop within cleanup bound")
		}
	}
	return nil
}
