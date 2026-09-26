package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

var podBoundCapacity = regexp.MustCompile("used=([0-9]+) limit=([0-9]+)")

func (s *Server) currentPodBoundTokenGrant(id string) error {
	s.runs.mu.Lock()
	launched, ok := s.runs.podBoundTokenPrincipals[id]
	status := s.runs.runs[id]
	s.runs.mu.Unlock()
	if !ok || status == nil || !podBoundNamedCase(status.Config) || status.State != "running" ||
		principalKey(&launched) != status.Owner || s.auth == nil {
		return errors.New("Pod-bound token run owner unavailable")
	}
	grants := s.auth.grants
	if s.auth.grantsPath != "" {
		var err error
		grants, err = LoadGrantFile(s.auth.grantsPath)
		if err != nil {
			return errors.New("current Pod-bound token grant unavailable")
		}
	}
	p, found := grants.Lookup(launched.Issuer, launched.Subject)
	if !found || !p.HasRole(RoleOperator) || !p.AllowsTenant(podBoundNamespace(status.Config)) ||
		!p.AllowsTarget(hostTargetID) || !p.AllowsTarget(status.ScopeTarget) ||
		status.ScopeTenant != podBoundNamespace(status.Config) {
		return errors.New("Pod-bound token target or tenant grant changed")
	}
	return nil
}

func (s *Server) podBoundRESTConfig() (*rest.Config, error) {
	if s.cfg.ExperimentRESTConfig != nil {
		return rest.CopyConfig(s.cfg.ExperimentRESTConfig), nil
	}
	return rest.InClusterConfig()
}

func (s *Server) podBoundTokenCurrentSource(ctx context.Context, kc kubernetes.Interface, r podBoundTokenRequest, p podBoundTokenProfile, allowSourceLifecycle bool) error {
	ns, err := kc.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.DeletionTimestamp != nil {
		return errors.New("Pod-bound token namespace identity changed")
	}
	if r.Namespace == podBoundTokenCPUNamespace && ns.Labels["phorvex.ai/cpu-token-fixture"] != "true" {
		return errors.New("CPU token namespace ownership label absent")
	}
	sys, err := kc.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || string(sys.UID) != p.Fixture.ClusterUID || r.ClusterUID != p.Fixture.ClusterUID {
		return errors.New("Pod-bound token cluster identity changed")
	}
	source, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.SourcePodName, metav1.GetOptions{})
	if err != nil && (!allowSourceLifecycle || !apierrors.IsNotFound(err)) {
		return errors.New("Pod-bound token source Pod read changed")
	}
	if err == nil && ((!allowSourceLifecycle && (!podReady(source) || source.DeletionTimestamp != nil)) ||
		(string(source.UID) == r.SourcePodUID && source.Spec.NodeName != p.Fixture.AllowedNodeName)) {
		return errors.New("Pod-bound token source Pod changed")
	}
	if err == nil && !allowSourceLifecycle && string(source.UID) != r.SourcePodUID {
		return errors.New("Pod-bound token source Pod incarnation changed")
	}
	peer, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.PeerPodName, metav1.GetOptions{})
	if err != nil || string(peer.UID) != r.PeerPodUID || !podReady(peer) || peer.DeletionTimestamp != nil ||
		peer.Spec.NodeName != p.Fixture.AllowedNodeName || peer.Name == r.SourcePodName ||
		string(peer.UID) == r.SourcePodUID {
		return errors.New("Pod-bound token peer Pod changed")
	}
	service, err := kc.CoreV1().Services(r.Namespace).Get(ctx, r.ServiceName, metav1.GetOptions{})
	if err != nil || string(service.UID) != r.ServiceUID || service.DeletionTimestamp != nil ||
		service.Spec.Type != corev1.ServiceTypeClusterIP ||
		service.Spec.Selector["fixture.phorvex.ai/token-response"] != r.Nonce {
		return errors.New("Pod-bound token Service changed")
	}
	if !allowSourceLifecycle {
		target, targetErr := s.resolveScenarioExactTargetForTenant(r.Namespace, r.SourcePodName, r.SourcePodUID, r.Nonce)
		if targetErr != nil || target.policyName != r.PolicyName || target.policyUID != r.PolicyUID ||
			target.policyGen != r.PolicyGeneration || target.ownerKind != "Deployment" ||
			target.ownerUID != r.DeploymentUID || target.ownerRevision != r.ReplicaSetUID {
			return errors.New("Pod-bound token exact policy authority changed")
		}
	}
	fixtureDep, err := kc.AppsV1().Deployments(r.Namespace).Get(ctx, r.PolicyName, metav1.GetOptions{})
	if err != nil || string(fixtureDep.UID) != r.DeploymentUID || fixtureDep.DeletionTimestamp != nil ||
		fixtureDep.Spec.Selector == nil || fixtureDep.Spec.Replicas == nil || *fixtureDep.Spec.Replicas < 1 {
		return errors.New("Pod-bound token fixture Deployment changed")
	}
	if len(peer.OwnerReferences) != 1 || peer.OwnerReferences[0].Kind != "ReplicaSet" ||
		string(peer.OwnerReferences[0].UID) != r.ReplicaSetUID {
		return errors.New("Pod-bound token peer owner changed")
	}
	fixtureRS, err := kc.AppsV1().ReplicaSets(r.Namespace).Get(ctx, peer.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil || string(fixtureRS.UID) != r.ReplicaSetUID || fixtureRS.DeletionTimestamp != nil ||
		len(fixtureRS.OwnerReferences) != 1 || string(fixtureRS.OwnerReferences[0].UID) != r.DeploymentUID {
		return errors.New("Pod-bound token fixture ReplicaSet changed")
	}
	var policy unstructured.Unstructured
	if err := s.scenarioObject(r.Namespace, "phorvexpolicy", r.PolicyName, &policy); err != nil ||
		string(policy.GetUID()) != r.PolicyUID || policy.GetGeneration() != r.PolicyGeneration ||
		policy.GetDeletionTimestamp() != nil {
		return errors.New("Pod-bound token policy incarnation changed")
	}
	specRaw, err := json.Marshal(policy.Object["spec"])
	if err != nil || policy.Object["spec"] == nil || podBoundHash(specRaw) != r.PolicySpecSHA256 {
		return errors.New("Pod-bound token policy spec changed")
	}
	dep, err := kc.AppsV1().Deployments(p.Fixture.ManagerNamespace).Get(ctx, p.Fixture.ManagerDeployment, metav1.GetOptions{})
	if err != nil || dep.DeletionTimestamp != nil || dep.Spec.Selector == nil ||
		dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || dep.Status.ReadyReplicas != 1 ||
		dep.Status.ObservedGeneration < dep.Generation {
		return errors.New("Pod-bound token manager Deployment unavailable")
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return errors.New("Pod-bound token manager selector unavailable")
	}
	pods, err := kc.CoreV1().Pods(p.Fixture.ManagerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 3})
	if err != nil || pods.Continue != "" || len(pods.Items) != 1 || string(pods.Items[0].UID) != r.ManagerPodUID ||
		!podReady(&pods.Items[0]) || len(pods.Items[0].Status.ContainerStatuses) != 1 ||
		pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 ||
		pods.Items[0].Status.ContainerStatuses[0].ContainerID != r.ManagerContainerID ||
		pods.Items[0].Status.ContainerStatuses[0].ImageID != r.ManagerImageID ||
		r.ManagerImageID != p.Fixture.ManagerImageID {
		return errors.New("Pod-bound token installed manager incarnation changed")
	}
	return nil
}

func (s *Server) podBoundCreateTypedEvent(ctx context.Context, kc kubernetes.Interface, base *rest.Config, r podBoundTokenRequest) (*unstructured.Unstructured, dynamic.Interface, error) {
	creatorIdentity := podBoundCreator(podBoundProfileForNamespace(r.Namespace))
	if creatorIdentity == "" {
		return nil, nil, errors.New("Pod-bound token creator scope absent")
	}
	creatorName := strings.TrimPrefix(creatorIdentity, "system:serviceaccount:phorvex-system:")
	sa, err := kc.CoreV1().ServiceAccounts("phorvex-system").Get(ctx, creatorName, metav1.GetOptions{})
	if err != nil || sa.UID == "" || sa.DeletionTimestamp != nil || sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		return nil, nil, podBoundEventError("CREATOR_SERVICEACCOUNT_FAILED", err)
	}
	vap, err := kc.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, creatorName, metav1.GetOptions{})
	if err != nil || vap.DeletionTimestamp != nil || vap.Spec.FailurePolicy == nil ||
		*vap.Spec.FailurePolicy != "Fail" || len(vap.Spec.Validations) < 3 ||
		len(vap.Spec.MatchConditions) == 0 {
		return nil, nil, podBoundEventError("CREATOR_POLICY_FAILED", err)
	}
	if vap.Spec.MatchConditions[0].Expression !=
		"request.userInfo.username == '"+creatorIdentity+"'" ||
		vap.Spec.Validations[0].Expression != "variables.event.metadata.name.startsWith('phorvex-e2e-')" ||
		vap.Spec.Validations[1].Expression != "size(variables.event.spec.targets) == 1 && variables.event.spec.targets[0].startsWith('"+r.Namespace+"/')" ||
		vap.Spec.Validations[2].Expression != "variables.event.spec.rule.source == 'PhorvexE2EDetector'" {
		return nil, nil, podBoundEventError("CREATOR_SCOPE_FAILED", nil)
	}
	binding, err := kc.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, creatorName, metav1.GetOptions{})
	if err != nil || binding.DeletionTimestamp != nil || binding.Spec.PolicyName != creatorName ||
		len(binding.Spec.ValidationActions) != 1 || binding.Spec.ValidationActions[0] != "Deny" {
		return nil, nil, podBoundEventError("CREATOR_BINDING_FAILED", err)
	}
	ttl := int64(600)
	token, err := kc.CoreV1().ServiceAccounts("phorvex-system").CreateToken(ctx, creatorName,
		&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &ttl}}, metav1.CreateOptions{})
	if err != nil || token.Status.Token == "" || token.Status.ExpirationTimestamp.Time.Before(time.Now().Add(5*time.Minute)) {
		return nil, nil, podBoundEventError("TOKEN_REQUEST_FAILED", err)
	}
	cfg := rest.CopyConfig(base)
	cfg.BearerToken, cfg.BearerTokenFile = token.Status.Token, ""
	cfg.Username, cfg.Password = "", ""
	cfg.Impersonate = rest.ImpersonationConfig{}
	creator, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, podBoundEventError("CREATOR_CLIENT_FAILED", err)
	}
	event := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": "phorvex-e2e-" + r.Nonce,
			"annotations": map[string]any{model.ConsoleTargetPodUIDAnnotation: r.SourcePodUID}},
		"spec": map[string]any{"description": "Synthetic owned Pod-bound API bearer observation",
			"targets": []any{r.Namespace + "/" + r.SourcePodName},
			"rule":    map[string]any{"type": model.AttackVectorPodBoundAPIAuth, "threatLevel": "critical", "source": "PhorvexE2EDetector"}},
	}}
	gvr := schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents"}
	created, err := creator.Resource(gvr).Create(ctx, event, metav1.CreateOptions{})
	if err != nil {
		return nil, creator, podBoundEventError("EVENT_CREATE_FAILED", fmt.Errorf("typed event CREATE outcome unknown; one-use fence: %w", err))
	}
	readback, err := creator.Resource(gvr).Get(ctx, created.GetName(), metav1.GetOptions{})
	if err != nil || readback == nil {
		return nil, creator, podBoundEventError("EVENT_READBACK_FAILED", err)
	}
	targets, targetOK, targetErr := unstructured.NestedStringSlice(readback.Object, "spec", "targets")
	ruleType, typeOK, typeErr := unstructured.NestedString(readback.Object, "spec", "rule", "type")
	ruleSource, sourceOK, sourceErr := unstructured.NestedString(readback.Object, "spec", "rule", "source")
	threat, threatOK, threatErr := unstructured.NestedString(readback.Object, "spec", "rule", "threatLevel")
	if readback.GetUID() == "" || readback.GetUID() != created.GetUID() ||
		readback.GetName() != "phorvex-e2e-"+r.Nonce ||
		readback.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != r.SourcePodUID ||
		readback.GetAnnotations()["phorvex.ai/creator-identity"] != creatorIdentity ||
		targetErr != nil || !targetOK || len(targets) != 1 || targets[0] != r.Namespace+"/"+r.SourcePodName ||
		typeErr != nil || !typeOK || ruleType != model.AttackVectorPodBoundAPIAuth ||
		sourceErr != nil || !sourceOK || ruleSource != "PhorvexE2EDetector" ||
		threatErr != nil || !threatOK || threat != "critical" {
		return nil, creator, podBoundEventError("EVENT_STAMP_FAILED", nil)
	}
	return readback, creator, nil
}

func podBoundTypedDecision(raw []byte, r podBoundTokenRequest, eventUID string) (PodBoundTokenDecision, PodBoundTokenOperation, error) {
	var rec audit.Record
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Kind != "phorvex.decision" ||
		rec.Namespace != r.Namespace || rec.Pod != r.SourcePodName || rec.DecisionTrace == nil {
		return PodBoundTokenDecision{}, PodBoundTokenOperation{}, errors.New("exact target decision row malformed")
	}
	trace := rec.DecisionTrace
	if trace.PolicyUID != r.PolicyUID || trace.AssetUID != r.SourcePodUID ||
		trace.DecisionID == "" || trace.SelectedAction != rec.Action ||
		(rec.DispatchOutcome != "" && trace.DispatchOutcome != rec.DispatchOutcome) ||
		trace.Validate() != nil {
		return PodBoundTokenDecision{}, PodBoundTokenOperation{}, errors.New("exact policy, source or decision trace differs")
	}
	if rec.DispatchOutcome == "" && (rec.Action != "noop" || trace.DispatchOutcome != model.DispatchNotAttempted) {
		return PodBoundTokenDecision{}, PodBoundTokenOperation{}, errors.New("mutating decision lacks recorded dispatch outcome")
	}
	nEvent := 0
	for _, ev := range rec.Events {
		if ev.EventUID != eventUID {
			continue
		}
		if ev.Type != model.AttackVectorPodBoundAPIAuth || ev.Name != "phorvex-e2e-"+r.Nonce ||
			ev.CreatorIdentity != podBoundCreator(podBoundProfileForNamespace(r.Namespace)) ||
			ev.TargetPodUID != r.SourcePodUID || ev.TrustVerdict != "trusted" || !ev.TargetsPod || !ev.TimestampPresent {
			return PodBoundTokenDecision{}, PodBoundTokenOperation{}, errors.New("typed event was not admitted by source")
		}
		nEvent++
	}
	if nEvent != 1 {
		return PodBoundTokenDecision{}, PodBoundTokenOperation{}, errors.New("typed event attribution absent or ambiguous")
	}
	nFact := 0
	for _, fact := range trace.Facts {
		if fact.FactType != "podBoundKubeAPIAuthPotential" {
			continue
		}
		if fact.SteeredBy == nil || fact.SteeredBy.RuleType != model.AttackVectorPodBoundAPIAuth ||
			fact.SteeredBy.AppliedMultiplier != 3 || len(fact.SteeredBy.Events) != 1 ||
			fact.SteeredBy.Events[0].EventUID != eventUID ||
			fact.SteeredBy.Events[0].TargetPodUID != r.SourcePodUID ||
			len(fact.CoveringActions) != 1 || fact.CoveringActions[0] != "rotate" {
			return PodBoundTokenDecision{}, PodBoundTokenOperation{}, errors.New("typed fact steering differs")
		}
		nFact++
	}
	if nFact != 1 {
		return PodBoundTokenDecision{}, PodBoundTokenOperation{}, errors.New("typed fact absent or ambiguous")
	}
	d := PodBoundTokenDecision{ID: trace.DecisionID, SelectedAction: rec.Action,
		DispatchOutcome: trace.DispatchOutcome, CostCeiling: trace.CostCeiling, AuditCoverage: "COMPLETE",
		RequestRateStatus: "MISSING_REQUEST_RATE"}
	if podBoundFreshRequestRate(r, rec) {
		d.RequestRateStatus = "MEASURED_FRESH"
	}
	for _, row := range trace.ActionStatus {
		switch row.Action {
		case "rotate":
			d.RotateStatus, d.RotateReason = row.Status, safeNATSWhy(row.Reason)
		case "quarantine":
			d.QuarantineStatus, d.QuarantineReason = row.Status, safeNATSWhy(row.Reason)
			if match := podBoundCapacity.FindStringSubmatch(row.Reason); len(match) == 3 {
				d.QuarantineUsed, _ = strconv.Atoi(match[1])
				d.QuarantineLimit, _ = strconv.Atoi(match[2])
			}
		}
	}
	for _, candidate := range trace.Candidates {
		if candidate.Action == "rotate" {
			if candidate.ExpectedCost.Present {
				d.RotateExpectedCost = candidate.ExpectedCost.Value
			}
			if candidate.CostHigh.Present {
				d.RotateHighCost = candidate.CostHigh.Value
			}
			d.FlowRegime = candidate.FlowRegime
			break
		}
	}
	op := PodBoundTokenOperation{TerminationStatus: "NOT_DISPATCHED"}
	if rec.Action == "rotate" && rec.Selected && rec.Actuated && trace.DispatchOutcome == model.DispatchEmitted {
		receipt := rec.GracefulTermination
		// The actuator reports accepted Eviction with termination still unconfirmed.
		// Original-Pod absence is a later, independent producer observation.
		if receipt == nil || receipt.PolicyNamespace != r.Namespace || receipt.PolicyName != r.PolicyName ||
			receipt.PolicyUID != r.PolicyUID || receipt.PolicyGeneration != r.PolicyGeneration ||
			receipt.PodUID != r.SourcePodUID || receipt.PodResourceVersion == "" ||
			receipt.TerminationStatus != "unconfirmed" {
			return d, op, errors.New("emitted rotate lacks exact graceful termination request")
		}
		b, _ := json.Marshal(receipt)
		op.TerminationStatus, op.ReceiptSHA256 = "REQUEST_CONFIRMED", podBoundHash(b)
	} else if rec.Action != "noop" || rec.Selected || rec.Actuated || trace.DispatchOutcome != model.DispatchNotAttempted {
		op.TerminationStatus = "UNCONFIRMED"
	}
	return d, op, nil
}

// The manager trace only carries presence and signal source, not the scrape
// sample timestamps. Join it to the fixture's two fresh, source-Pod samples
// before calling this decision's request rate measured.
func podBoundFreshRequestRate(r podBoundTokenRequest, rec audit.Record) bool {
	if rec.DecisionTrace == nil || !rec.DecisionTrace.Inputs.RequestRate.Present ||
		r.MetricStatus != "MEASURED_FRESH" || r.MetricSourcePodName != r.SourcePodName ||
		r.PodMonitorUID == "" || !mongoSHA.MatchString(r.MetricQuerySHA256) ||
		r.MetricFirstValue < 0 || r.MetricSecondValue <= r.MetricFirstValue {
		return false
	}
	first, e1 := time.Parse(time.RFC3339Nano, r.MetricFirstAt)
	second, e2 := time.Parse(time.RFC3339Nano, r.MetricSecondAt)
	requested, e3 := time.Parse(time.RFC3339Nano, r.RequestedAt)
	decision, e4 := time.Parse(time.RFC3339Nano, rec.DecisionTrace.Timestamp)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil ||
		second.Sub(first) < 15*time.Second || second.After(requested) ||
		requested.Sub(second) > 90*time.Second || decision.Before(requested) ||
		decision.Sub(second) > 150*time.Second {
		return false
	}
	seen := false
	for _, signal := range rec.DecisionTrace.Inputs.TelemetryStates {
		if signal.Signal != "reqRate" {
			continue
		}
		if seen || signal.State != "present" || signal.Src != "prometheus-http" {
			return false
		}
		seen = true
	}
	return seen
}

func podBoundCompetingUnattributedOperation(raw []byte) bool {
	var rec audit.Record
	if json.Unmarshal(raw, &rec) != nil {
		return true
	}
	if rec.Action != "noop" || rec.Selected || rec.Actuated || rec.GracefulTermination != nil {
		return true
	}
	if rec.DecisionTrace != nil && rec.DecisionTrace.DispatchOutcome != model.DispatchNotAttempted {
		return true
	}
	return rec.DispatchOutcome != "" && rec.DispatchOutcome != model.DispatchNotAttempted
}

func (s *Server) coordinatePodBoundTokenResponse(parent context.Context, id, out string) (runErr error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()
	s.runs.mu.Lock()
	status := s.runs.runs[id]
	profile := ""
	if status != nil {
		profile = status.Config
	}
	s.runs.mu.Unlock()
	if !podBoundNamedCase(profile) {
		return errors.New("Pod-bound token named profile unavailable")
	}
	var r podBoundTokenRequest
	rawReq, err := podBoundTokenWaitFile(ctx, out, podBoundRequestFile, &r)
	if err != nil {
		return err
	}
	// Bind diagnostics only after the request identity is established. A failure
	// before this point cannot be safely attributed to a harness request.
	if r.Schema != "pod-bound-token-request-v1" || r.RunID != id || !podBoundTokenNonce.MatchString(r.Nonce) {
		return errors.New("Pod-bound token request identity differs")
	}
	stage := "request-validation"
	requestSHA := podBoundHash(rawReq)
	defer func() {
		if runErr != nil {
			if receiptErr := recordPodBoundCoordinatorFailure(out, r, requestSHA, stage, runErr); receiptErr != nil {
				runErr = errors.Join(runErr, fmt.Errorf("Pod-bound token coordinator diagnostic receipt unavailable: %w", receiptErr))
			}
		}
	}()
	if r.Schema != "pod-bound-token-request-v1" || r.RunID != id ||
		!podBoundTokenNonce.MatchString(r.Nonce) || r.Namespace != podBoundNamespace(profile) ||
		r.SourcePodUID == "" || r.PeerPodUID == "" || r.SourcePodUID == r.PeerPodUID ||
		r.SourceBeforeHTTP != 200 || r.PeerBeforeHTTP != 200 || r.ServiceBeforeHTTP != 200 ||
		r.PolicyGeneration < 1 || !mongoSHA.MatchString(r.PolicySpecSHA256) ||
		!mongoSHA.MatchString(r.ProfileSHA256) {
		return errors.New("Pod-bound token baseline request incomplete")
	}
	if profile == podBoundTokenCPUConfig {
		if r.CaseID != podBoundTokenCPUCaseID || r.PDBUID == "" || r.PeerExpiry == "" ||
			r.MetricStatus != "MEASURED_FRESH" || !podBoundCPURequestTimeValid(r, time.Now().UTC()) {
			return errors.New("CPU token case, measured source rate or before-expiry budget unavailable")
		}
	} else if r.CaseID != "" && r.CaseID != podBoundTokenVoiceCaseID {
		return errors.New("Voice token case differs")
	}
	stage = "authorization"
	if err := s.currentPodBoundTokenGrant(id); err != nil {
		return err
	}
	cfgRaw, err := readBoundedFile(filepath.Join(s.cfg.runsDir(), "configs", id+".yaml"), 64<<10)
	if err != nil || podBoundHash(cfgRaw) != r.ProfileSHA256 {
		return errors.New("Pod-bound token authorized profile changed")
	}
	pinned := s.cfg.PodBoundTokenProfileSHA256
	if profile == podBoundTokenCPUConfig {
		pinned = s.cfg.PodBoundTokenCPUProfileSHA256
	}
	templateRaw, err := readBoundedFile(filepath.Join(s.cfg.HarnessDir, allowedConfigs[profile].File), 64<<10)
	if err != nil || podBoundHash(templateRaw) != pinned ||
		!podBoundTokenRuntimeMatchesTemplate(templateRaw, cfgRaw, id, r.Nonce, out) {
		return errors.New("Pod-bound token reviewed template or prepared runtime profile changed")
	}
	var p podBoundTokenProfile
	if err := yaml.Unmarshal(cfgRaw, &p); err != nil || p.Fixture.Nonce != r.Nonce ||
		p.Fixture.RunID != id || p.Context == "" {
		return errors.New("Pod-bound token runtime profile differs")
	}
	stage = "source-validation"
	restCfg, err := s.podBoundRESTConfig()
	if err != nil {
		return err
	}
	kc, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	if err := s.podBoundTokenCurrentSource(ctx, kc, r, p, false); err != nil {
		return err
	}
	stage = "audit-start"
	manifest, err := s.cfg.AuditSource.Manifest(ctx)
	if err != nil || len(manifest.Segments) == 0 || manifest.Segments[0].ID != "live" {
		return errors.New("Pod-bound token authenticated audit start unavailable")
	}
	seg := manifest.Segments[0]
	if seg.Size > 0 {
		last, err := s.cfg.AuditSource.Chunk(ctx, seg, seg.Size-1)
		if err != nil || len(last) != 1 || last[0] != '\n' {
			return errors.New("Pod-bound token audit start is not a complete line")
		}
	}
	start := podBoundTokenAuditStart{Schema: "pod-bound-token-audit-start-v1", RunID: id, Nonce: r.Nonce,
		SourceIdentity: s.cfg.AuditSourceIdentity, Segment: seg, Offset: seg.Size, RequestSHA256: podBoundHash(rawReq)}
	if _, err := writePodBoundOwnedFile(out, "pod-bound-token-audit-start.json", start); err != nil {
		return err
	}
	stage = "post-audit-authorization"
	if err := s.currentPodBoundTokenGrant(id); err != nil {
		return err
	}
	stage = "post-audit-source"
	if err := s.podBoundTokenCurrentSource(ctx, kc, r, p, false); err != nil {
		return err
	}
	stage = "post-audit-source-manifest"
	if _, err := verifyPodBoundTokenSourceManifest(p); err != nil {
		return err
	}
	stage = "post-audit-disjointness"
	if err := s.podBoundTokenDisjointLive(ctx, kc, r, p); err != nil {
		return err
	}
	stage = "signal-intent"
	if err := s.persistCatalogueSignalIntent("/api/runs/start", "pod-bound-token", r.Namespace,
		profile, r.SourcePodUID, &attackStimulusEvidence{Kind: "synthetic-catalogue-signal",
			TargetUID: r.SourcePodUID, EventName: "phorvex-e2e-" + r.Nonce,
			EventRule: model.AttackVectorPodBoundAPIAuth, Correlation: r.Nonce}); err != nil {
		return err
	}
	stage = "typed-event-create"
	created, creator, err := s.podBoundCreateTypedEvent(ctx, kc, restCfg, r)
	if err != nil {
		return err
	}
	gvr := schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents"}
	defer func() {
		cleanupCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer done()
		_ = creator.Resource(gvr).Delete(cleanupCtx, created.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: ptrUID(created.GetUID())}})
	}()
	stage = "decision-observation"
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var barrierSHA string
	var selectedBarrier podBoundTokenBarrier
decisionLoop:
	for {
		if err := s.currentPodBoundTokenGrant(id); err != nil {
			return err
		}
		m, err := s.cfg.AuditSource.Manifest(ctx)
		if err != nil || len(m.Segments) == 0 || m.Segments[0].Generation != seg.Generation ||
			m.Segments[0].Anchor != seg.Anchor || m.Segments[0].Size < seg.Size {
			return errors.New("Pod-bound token audit generation changed before decision")
		}
		nowSeg := m.Segments[0]
		if nowSeg.Size > seg.Size {
			query := audittransport.ExactWindowRequest{
				Segment: nowSeg, StartOffset: seg.Size, EndOffset: nowSeg.Size, Namespace: r.Namespace,
				PodName: r.SourcePodName, PodUID: r.SourcePodUID, PolicyUID: r.PolicyUID}
			commitment, err := s.cfg.AuditSource.CaptureExactWindow(ctx, query)
			if err != nil {
				return fmt.Errorf("Pod-bound token exact audit capture gap: %w", err)
			}
			query.Commitment = &commitment
			seal, err := s.cfg.AuditSource.SelectExact(ctx, query)
			if err != nil {
				return fmt.Errorf("Pod-bound token exact audit gap: %w", err)
			}
			for _, row := range seal.Rows {
				d, op, err := podBoundTypedDecision(row.Raw, r, string(created.GetUID()))
				if err != nil {
					if strings.Contains(err.Error(), "typed event attribution absent") {
						continue
					}
					return err
				}
				allowSourceLifecycle := d.SelectedAction == "rotate" && op.TerminationStatus == "REQUEST_CONFIRMED"
				if err := s.podBoundTokenCurrentSource(ctx, kc, r, p, allowSourceLifecycle); err != nil {
					return err
				}
				barrier := podBoundTokenBarrier{Schema: "pod-bound-token-barrier-v1", RunID: id, Nonce: r.Nonce,
					RequestSHA256: podBoundHash(rawReq), Event: PodBoundTokenEvent{UID: string(created.GetUID()),
						Kind: model.AttackVectorPodBoundAPIAuth, Creator: p.Fixture.EventCreator, SourcePodUID: r.SourcePodUID, TrustVerified: true},
					Decision: d, Operation: op, DecisionRowSHA: podBoundHash(row.Raw),
					ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				barrierSHA, err = writePodBoundOwnedFile(out, podBoundBarrierFile, barrier)
				if err != nil {
					return err
				}
				selectedBarrier = barrier
				break decisionLoop
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("Pod-bound token decision observation interrupted")
		case <-deadline.C:
			return errors.New("Pod-bound token exact typed decision absent")
		case <-tick.C:
		}
	}
	stage = "observation-commit"
	var observation podBoundTokenObservationEnd
	endRaw, err := podBoundTokenWaitFile(ctx, out, podBoundObservationEndFile, &observation)
	if err != nil {
		return err
	}
	if observation.Schema != "pod-bound-token-observation-end-v1" ||
		observation.RunID != id || observation.Nonce != r.Nonce ||
		observation.RequestSHA256 != podBoundHash(rawReq) ||
		observation.BarrierSHA256 != barrierSHA {
		return errors.New("Pod-bound token observation end identity differs")
	}
	observedEnd, err := time.Parse(time.RFC3339Nano, observation.ObservationEndedAt)
	if err != nil || observedEnd.After(time.Now().Add(2*time.Second)) {
		return errors.New("Pod-bound token declared observation end is invalid")
	}
	if err := s.currentPodBoundTokenGrant(id); err != nil {
		return err
	}
	if err := s.podBoundTokenCurrentSource(ctx, kc, r, p,
		selectedBarrier.Decision.SelectedAction == "rotate" && selectedBarrier.Operation.TerminationStatus == "REQUEST_CONFIRMED"); err != nil {
		return err
	}
	if err := s.podBoundTokenDisjointAfterReceipt(ctx, kc, r, p, selectedBarrier); err != nil {
		return err
	}
	if _, err := verifyPodBoundTokenSourceManifest(p); err != nil {
		return err
	}
	endManifest, err := s.cfg.AuditSource.Manifest(ctx)
	if err != nil || len(endManifest.Segments) == 0 ||
		endManifest.Segments[0].ID != seg.ID ||
		endManifest.Segments[0].Generation != seg.Generation ||
		endManifest.Segments[0].Anchor != seg.Anchor ||
		endManifest.Segments[0].Size <= seg.Size {
		return errors.New("Pod-bound token observation-end audit generation changed")
	}
	endSeg := endManifest.Segments[0]
	q := audittransport.ExactWindowRequest{Segment: endSeg, StartOffset: seg.Size,
		EndOffset: endSeg.Size, Namespace: r.Namespace, PodName: r.SourcePodName,
		PodUID: r.SourcePodUID, PolicyUID: r.PolicyUID}
	committed, err := s.cfg.AuditSource.CaptureExactWindow(ctx, q)
	if err != nil {
		return fmt.Errorf("Pod-bound token observation-end audit commitment gap: %w", err)
	}
	ack := podBoundTokenObservationCommitted{Schema: "pod-bound-token-observation-committed-v1",
		RunID: id, Nonce: r.Nonce, ObservationEndSHA256: podBoundHash(endRaw),
		RequestSHA256: podBoundHash(rawReq), BarrierSHA256: barrierSHA,
		SourceIdentity: s.cfg.AuditSourceIdentity, Commitment: committed}
	if _, err := writePodBoundOwnedFile(out, podBoundObservationCommittedFile, ack); err != nil {
		return err
	}
	// The event belongs to this run and is removed only with its exact API UID.
	stage = "event-cleanup"
	if err := creator.Resource(gvr).Delete(ctx, created.GetName(), metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: ptrUID(created.GetUID())}}); err != nil {
		return fmt.Errorf("Pod-bound token exact event cleanup unconfirmed: %w", err)
	}
	for {
		_, err := creator.Resource(gvr).Get(ctx, created.GetName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			break
		}
		if err != nil {
			return fmt.Errorf("Pod-bound token event absence unavailable: %w", err)
		}
		select {
		case <-ctx.Done():
			return errors.New("Pod-bound token event deletion not confirmed")
		case <-time.After(500 * time.Millisecond):
		}
	}
	_, err = writePodBoundOwnedFile(out, podBoundEventCleanupFile, podBoundTokenEventCleanup{
		Schema: "pod-bound-token-event-cleanup-v1", RunID: id, Nonce: r.Nonce,
		EventUID: string(created.GetUID()), Status: "CONFIRMED_ABSENT",
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	return err
}

// prepareSuite stamps only these run-private fields into the reviewed template.
// The harness request hashes its resulting YAML, while the opt-in installation
// pins the original template. Both authorities must remain joined.
func podBoundTokenRuntimeMatchesTemplate(templateRaw, runtimeRaw []byte, id, nonce, out string) bool {
	var doc map[string]any
	if yaml.Unmarshal([]byte(strings.TrimPrefix(string(templateRaw), "\xef\xbb\xbf")), &doc) != nil {
		return false
	}
	fixture, ok := doc["podBoundTokenFixture"].(map[string]any)
	if !ok {
		return false
	}
	fixture["runID"], fixture["nonce"] = id, nonce
	doc["outDir"] = out
	prepared, err := yaml.Marshal(doc)
	return err == nil && string(prepared) == string(runtimeRaw)
}

func ptrUID(v types.UID) *types.UID { return &v }
