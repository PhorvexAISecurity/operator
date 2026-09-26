package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
)

type outputEvidence struct {
	files    map[string][]byte
	terminal availabilityTerminal
	profile  guardrailOutputProfile
	marker   string
}

func (e outputEvidence) original(name string) ([]byte, error) {
	raw := e.files[name]
	if len(raw) == 0 {
		return nil, errors.New("original receipt missing: " + name)
	}
	return raw, nil
}
func (e outputEvidence) decode(name string, out any) error {
	raw, err := e.original(name)
	if err != nil {
		return err
	}
	return availabilityDecode(raw, out)
}
func (e outputEvidence) kube(label string, out any) error {
	var found []byte
	for name, raw := range e.files {
		if strings.HasPrefix(name, "kube-") && strings.HasSuffix(name, "-"+label+".json") {
			if found != nil {
				return errors.New("ambiguous original Kubernetes read: " + label)
			}
			found = raw
		}
	}
	if found == nil {
		return errors.New("original Kubernetes read absent: " + label)
	}
	return availabilityDecode(found, out)
}
func (e outputEvidence) http(label string) (int, []byte, error) {
	var envelope availabilityHTTP
	if err := e.decode(label+"-stdout.bin", &envelope); err != nil {
		return 0, nil, err
	}
	body, err := base64.StdEncoding.Strict().DecodeString(envelope.BodyBase64)
	if err != nil || len(body) > 65536 || !bytes.Equal(body, e.files[label+"-body.bin"]) {
		return 0, nil, errors.New("original HTTP envelope and body differ: " + label)
	}
	return envelope.Status, body, nil
}
func (e outputEvidence) snapshot(label string) (outputSnapshot, error) {
	var snapshot outputSnapshot
	if err := e.decode(label+"-snapshot.json", &snapshot); err != nil {
		return snapshot, err
	}
	f := e.profile.Fixture
	if snapshot.ClusterUID != f.ClusterUID || snapshot.TargetPodUID != f.PodUID || snapshot.TargetProxyImageID != f.PodImageID ||
		snapshot.TargetSupportImageID != f.SupportImageID || snapshot.ServiceUID != f.ServiceUID ||
		snapshot.SourceUID != f.SourceUID || snapshot.ModelPodUID != f.ModelTargetPodUID ||
		snapshot.ModelImageID != f.ModelTargetImageID || snapshot.ModelServiceUID != f.ModelServiceUID ||
		snapshot.ManagerPodUID != f.ManagerPodUID || snapshot.ManagerImageID != f.ManagerImageID ||
		snapshot.ConsoleImageID != f.ConsoleImageID || snapshot.ConsoleDeploymentUID != f.ConsoleDeploymentUID ||
		snapshot.PolicyUID != f.PolicyUID || snapshot.PolicyGeneration != f.PolicyGeneration ||
		snapshot.ConfigMapUID != f.OutputPolicyConfigMapUID || snapshot.RuleSHA256 != f.OutputPolicyRuleSHA256 || !snapshot.ProxyReady {
		return snapshot, errors.New("original output source or policy identity differs")
	}
	var source map[string]any
	if err := e.kube(label+"-source", &source); err != nil {
		return snapshot, err
	}
	sourceData := availabilityMap(source["data"])
	proxyText, policyText, supportText := availabilityString(sourceData, "guardrail_proxy.py"),
		availabilityString(sourceData, "output_policy.py"), availabilityString(sourceData, "support_fixture.py")
	if availabilityUID(source) != snapshot.SourceUID || source["immutable"] != true || len(sourceData) != 3 ||
		proxyText == "" || policyText == "" || supportText == "" ||
		availabilityHash(append(append([]byte(proxyText), 0), []byte(policyText)...)) != f.SourceSHA256 ||
		availabilityHash([]byte(supportText)) != f.SupportSourceSHA256 {
		return snapshot, errors.New("original immutable fixture source differs")
	}
	var cluster, pod, service, fixtureEndpoints, modelPod, modelService, modelEndpoints, policy, manager, console, consoleRS, consoleDeployment map[string]any
	for _, row := range []struct {
		name   string
		target *map[string]any
	}{
		{label + "-cluster", &cluster}, {label + "-fixture-pod", &pod}, {label + "-fixture-service", &service},
		{label + "-fixture-endpoints", &fixtureEndpoints}, {label + "-model-pod", &modelPod},
		{label + "-model-service", &modelService}, {label + "-model-endpoints", &modelEndpoints},
		{label + "-policy", &policy}, {label + "-manager", &manager}, {label + "-console", &console},
		{label + "-console-rs", &consoleRS}, {label + "-console-deployment", &consoleDeployment},
	} {
		if err := e.kube(row.name, row.target); err != nil {
			return snapshot, err
		}
	}
	_, proxyImage, proxyErr := availabilityStatus(pod, "guardrail-proxy")
	_, supportImage, supportErr := availabilityStatus(pod, "support-app")
	_, modelImage, modelErr := availabilityStatus(modelPod, "vllm")
	_, managerImage, managerErr := availabilityStatus(manager, "manager")
	_, consoleImage, consoleErr := availabilityStatus(console, "console")
	if proxyErr != nil || supportErr != nil || modelErr != nil || managerErr != nil || consoleErr != nil ||
		availabilityUID(cluster) != snapshot.ClusterUID || availabilityUID(pod) != snapshot.TargetPodUID ||
		availabilityUID(service) != snapshot.ServiceUID || availabilityUID(modelPod) != snapshot.ModelPodUID ||
		availabilityUID(modelService) != snapshot.ModelServiceUID || availabilityUID(policy) != snapshot.PolicyUID ||
		availabilityUID(manager) != snapshot.ManagerPodUID || availabilityUID(console) != snapshot.ConsolePodUID ||
		proxyImage != snapshot.TargetProxyImageID || supportImage != snapshot.TargetSupportImageID ||
		modelImage != snapshot.ModelImageID || managerImage != snapshot.ManagerImageID || consoleImage != snapshot.ConsoleImageID ||
		!outputReadyRoute(fixtureEndpoints, service, pod, f.PodUID) ||
		!outputReadyRoute(modelEndpoints, modelService, modelPod, f.ModelTargetPodUID) ||
		!outputPolicyMount(pod, f.OutputPolicyConfigMapName) {
		return snapshot, errors.New("original fixture/model route or container source differs")
	}
	var self map[string]string
	if e.decode("self-identity.json", &self) != nil ||
		availabilityString(availabilityMeta(console), "name") != self["name"] || availabilityUID(console) != self["uid"] ||
		snapshot.ConsolePodUID != self["uid"] ||
		availabilityUID(consoleDeployment) != f.ConsoleDeploymentUID {
		return snapshot, errors.New("original console identity or deployment differs")
	}
	rsName, rsUID, rsErr := availabilityController(console, "ReplicaSet")
	depName, depUID, depErr := availabilityController(consoleRS, "Deployment")
	if rsErr != nil || depErr != nil || rsName != availabilityString(availabilityMeta(consoleRS), "name") ||
		rsUID != availabilityUID(consoleRS) || depName != f.ConsoleDeploymentName || depUID != f.ConsoleDeploymentUID ||
		depName != availabilityString(availabilityMeta(consoleDeployment), "name") {
		return snapshot, errors.New("original console owner chain differs")
	}
	annotations := availabilityMap(availabilityMeta(pod)["annotations"])
	if annotations["phorvex.ai/output-policy-configmap"] != f.OutputPolicyConfigMapName ||
		annotations["phorvex.ai/output-policy-rule-sha256"] != f.OutputPolicyRuleSHA256 ||
		annotations["phorvex.ai/output-proxy-source-sha256"] != f.SourceSHA256 ||
		annotations["phorvex.ai/output-support-source-sha256"] != f.SupportSourceSHA256 ||
		annotations["phorvex.ai/output-event-creator"] != f.EventCreator ||
		"system:serviceaccount:phorvex-system:"+availabilityString(availabilityMap(console["spec"]), "serviceAccountName") != f.EventCreator {
		return snapshot, errors.New("original fixture source annotations or creator differ")
	}
	specRaw, _ := json.Marshal(policy["spec"])
	if availabilityHash(specRaw) != snapshot.PolicySpecSHA256 ||
		availabilityMap(policy["status"])["observedGeneration"] != float64(snapshot.PolicyGeneration) {
		return snapshot, errors.New("original dedicated policy spec or generation differs")
	}
	var policyCM map[string]any
	if err := e.kube(label+"-output-policy", &policyCM); err != nil {
		return snapshot, err
	}
	data := availabilityMap(policyCM["data"])
	if availabilityUID(policyCM) != snapshot.ConfigMapUID || !outputControllerOwned(policyCM, f.PodName, f.PodUID) ||
		len(data) != 2 || availabilityString(data, "rule.json") != string(outputRuleBytes(f.PodUID)) ||
		availabilityHash([]byte(availabilityString(data, "rule.json"))) != f.OutputPolicyRuleSHA256 {
		return snapshot, errors.New("original immutable rule or owned ConfigMap differs")
	}
	var activation map[string]any
	if availabilityDecode([]byte(availabilityString(data, "activation.json")), &activation) != nil ||
		activation["active"] != snapshot.Active || activation["revision"] != float64(snapshot.Revision) ||
		activation["operationId"] != snapshot.OperationID || activation["configMapUID"] != snapshot.ConfigMapUID {
		return snapshot, errors.New("original activation differs from snapshot")
	}
	status, raw, err := e.http(label + "-proxy-state")
	var proxy map[string]any
	if err != nil || status != 200 || availabilityDecode(raw, &proxy) != nil || proxy["ready"] != true ||
		proxy["active"] != snapshot.Active || proxy["revision"] != float64(snapshot.Revision) ||
		proxy["operationId"] != snapshot.OperationID || proxy["configMapUID"] != snapshot.ConfigMapUID ||
		proxy["ruleSHA256"] != f.OutputPolicyRuleSHA256 || proxy["podUID"] != f.PodUID ||
		proxy["proxySourceSHA256"] != f.SourceSHA256 || proxy["supportSourceSHA256"] != f.SupportSourceSHA256 {
		return snapshot, errors.New("original effective proxy state differs")
	}
	status, raw, err = e.http(label + "-support-state")
	var support map[string]any
	if err != nil || status != 200 || availabilityDecode(raw, &support) != nil ||
		support["completedModelCalls"] != float64(snapshot.CompletedModelCalls) ||
		support["supportSourceSHA256"] != f.SupportSourceSHA256 || support["model"] != f.ModelID {
		return snapshot, errors.New("original support model-call state differs")
	}
	return snapshot, nil
}

func (e outputEvidence) control(label, which string) (string, error) {
	request := availabilityRequest(e.profile.Fixture.ModelID, "CNR_00000000", which)
	var intent map[string]any
	if e.decode(label+"-intent.json", &intent) != nil || intent["requestSHA256"] != availabilityHash(request) ||
		intent["method"] != "POST" || intent["path"] != "/v1/chat/completions" ||
		intent["host"] != e.profile.Fixture.ModelServiceName+".vllm.svc" || intent["port"] != float64(8000) {
		return "UNKNOWN", errors.New("original legitimate-control request differs")
	}
	status, body, err := e.http(label)
	if err != nil {
		return "UNKNOWN", err
	}
	return availabilityClass(which, status, body, "CNR_00000000"), nil
}

func (e outputEvidence) supportIntent(label string, request []byte) error {
	var intent map[string]any
	if e.decode(label+"-intent.json", &intent) != nil || intent["method"] != "POST" ||
		intent["path"] != guardrailOutputPath || intent["port"] != float64(8000) ||
		intent["requestSHA256"] != availabilityHash(request) || intent["oneDispatchNoRetry"] != true {
		return errors.New("original fixed support request differs: " + label)
	}
	return nil
}

func readGuardrailOutputProbeResult(out, id, admittedSHA string) (*guardrailOutputProbeResult, error) {
	raw, err := readNATSResponseSizedFile(out, "guardrail-output-terminal.json", 96<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var terminal availabilityTerminal
	if availabilityDecode(raw, &terminal) != nil || terminal.Schema != "guardrail-output-terminal-v2" ||
		terminal.RunID != id || terminal.ProfileSHA256 != admittedSHA || !staticSHA256.MatchString(admittedSHA) ||
		len(terminal.Receipts) < 5 || len(terminal.Receipts) > 250 || terminal.ConsolePOSTsAttempted != 1 ||
		terminal.SecurityEventsAttempted > 1 || terminal.GuardedChatsAttempted > 7 ||
		terminal.KubeReadsAttempted > 120 || terminal.ExactEventDeletesAttempted > 1 {
		return nil, errors.New("output terminal identity or budget differs")
	}
	e := outputEvidence{files: map[string][]byte{}, terminal: terminal}
	for _, receipt := range terminal.Receipts {
		if receipt.File == "" || strings.ContainsAny(receipt.File, "/\\") || strings.HasPrefix(receipt.File, ".") ||
			receipt.Bytes < 1 || receipt.Bytes > 1<<20 || !staticSHA256.MatchString(receipt.SHA256) || e.files[receipt.File] != nil {
			return nil, errors.New("output original receipt inventory malformed")
		}
		b, readErr := readNATSResponseSizedFile(out, receipt.File, int64(receipt.Bytes))
		if readErr != nil || len(b) != receipt.Bytes || availabilityHash(b) != receipt.SHA256 {
			return nil, errors.New("output original receipt changed")
		}
		e.files[receipt.File] = b
	}
	profileRaw, err := e.original("profile-original.yaml")
	if err != nil || availabilityHash(profileRaw) != admittedSHA {
		return nil, errors.New("original output profile differs")
	}
	e.profile, err = parseGuardrailOutputProfile(profileRaw)
	if err != nil {
		return nil, err
	}
	markerRaw, err := e.original("private-marker.bin")
	if err != nil || !outputMarkerPattern.Match(markerRaw) || !bytes.Equal(markerRaw, bytes.TrimSpace(markerRaw)) {
		return nil, errors.New("original private marker invalid")
	}
	e.marker = string(markerRaw)
	if !bytes.Equal(e.files["owned-marker-stdout.bin"], markerRaw) || !bytes.Equal(e.files["fixed-support-request.bin"], []byte(guardrailOutputBody)) {
		return nil, errors.New("owned marker or fixed request receipt differs")
	}
	var privateIntent map[string]any
	var selfIdentity map[string]string
	if e.decode("private-intent.json", &privateIntent) != nil ||
		privateIntent["objective"] != "synthetic-support-internal-field-egress-v1" ||
		privateIntent["requestSHA256"] != availabilityHash([]byte(guardrailOutputBody)) ||
		privateIntent["maximumSupportCalls"] != float64(3) || privateIntent["maximumInjectedEvents"] != float64(1) ||
		privateIntent["firstDisclosureRemainsLanded"] != true ||
		e.decode("self-identity.json", &selfIdentity) != nil || !staticUID.MatchString(selfIdentity["uid"]) || selfIdentity["name"] == "" {
		return nil, errors.New("original private intent or console identity differs")
	}
	result := newGuardrailOutputProbeResult(admittedSHA)
	result.ModelControlRoute = e.profile.Fixture.ModelServiceName + ".vllm.svc:8000/v1/chat/completions"
	before, err := e.snapshot("before")
	if err != nil || before.Active || before.Revision != 0 || before.OperationID != "" || before.ConsolePodUID != selfIdentity["uid"] {
		return result, errors.New("original inactive output baseline differs")
	}
	if err := e.supportIntent("before-case", []byte(guardrailOutputBody)); err != nil {
		return result, err
	}
	preStatus, preBody, err := e.http("before-case")
	if err != nil {
		return result, err
	}
	var baselineObservation map[string]any
	if e.decode("baseline-observation.json", &baselineObservation) != nil ||
		baselineObservation["responseSHA256"] != availabilityHash(preBody) ||
		baselineObservation["requestSHA256"] != availabilityHash([]byte(guardrailOutputBody)) {
		return result, errors.New("original measured support disclosure not bound to fixed request and response")
	}
	if _, parseErr := time.Parse(time.RFC3339Nano, availabilityString(baselineObservation, "observedAt")); parseErr != nil {
		return result, errors.New("original disclosure observation time malformed")
	}
	result.BeforeSupport, err = classifyGuardrailOutputSupport(preStatus, preBody, e.marker, e.profile.Fixture.ModelID, true)
	if err != nil {
		return result, err
	}
	result.BeforeSayOK, err = e.control("before-say_ok", "say_ok")
	if err != nil {
		return result, err
	}
	result.BeforeArithmetic, err = e.control("before-arithmetic", "arithmetic")
	if err != nil {
		return result, err
	}
	postBaseline, err := e.snapshot("post-baseline")
	if err != nil || !outputSameSource(before, postBaseline) || postBaseline.ConfigMapResourceVersion != before.ConfigMapResourceVersion ||
		postBaseline.Active || postBaseline.Revision != 0 || postBaseline.CompletedModelCalls != before.CompletedModelCalls+1 {
		return result, errors.New("original measured model baseline changed")
	}
	gate := guardrailOutputOutcome(result.BeforeSupport, "", result.BeforeSayOK, result.BeforeArithmetic, "", "", "", false)
	if result.BeforeSupport != "DISCLOSED" || result.BeforeSayOK != "OK" || result.BeforeArithmetic != "FOUR" {
		if terminal.SecurityEventsAttempted != 0 || !terminal.CleanupVerified || terminal.Status != gate ||
			e.files["event-create-manifest.yaml"] != nil || e.files["audit-terminal.json"] != nil {
			return result, errors.New("non-disclosing baseline followed by mutation or inconsistent terminal")
		}
		result.Status, result.Accepted, result.CleanupVerified = gate, gate != "UNKNOWN", true
		return result, nil
	}
	result.InitialDisclosureLanded = true
	return e.readAfterOutput(result, before, preBody)
}

func (e outputEvidence) readAfterOutput(result *guardrailOutputProbeResult, before outputSnapshot, preBody []byte) (*guardrailOutputProbeResult, error) {
	preEvent, err := e.snapshot("pre-event")
	if err != nil || !outputSameSource(before, preEvent) || preEvent.ConfigMapResourceVersion != before.ConfigMapResourceVersion || preEvent.Active {
		return result, errors.New("original immediate pre-event source drift")
	}
	if e.terminal.SecurityEventsAttempted != 1 || !e.terminal.CleanupVerified || e.terminal.ExactEventDeletesAttempted != 1 {
		return result, errors.New("exact injected event and cleanup absent")
	}
	result.EventMode = "INJECTED_AFTER_MEASURED_DISCLOSURE"
	var producer attackStimulusEvidence
	var event availabilityEvent
	var created map[string]any
	if e.decode("event-producer.json", &producer) != nil || !producer.Observed || producer.EventRule != guardrailOutputEventType ||
		e.decode("event-identity.json", &event) != nil || event.UID != producer.EventUID || event.Name != producer.EventName ||
		event.CreatorIdentity != e.profile.Fixture.EventCreator || event.TargetPodUID != before.TargetPodUID ||
		e.kube("created-event", &created) != nil || availabilityUID(created) != event.UID {
		return result, errors.New("original injected output event provenance differs")
	}
	var baselineObservation, eventIntent map[string]any
	if e.decode("baseline-observation.json", &baselineObservation) != nil || e.decode("event-intent.json", &eventIntent) != nil ||
		eventIntent["targetPodUID"] != before.TargetPodUID || eventIntent["ruleSHA256"] != before.RuleSHA256 ||
		eventIntent["configMapUID"] != before.ConfigMapUID || eventIntent["baselineGate"] != "THREAT_LANDED_BEFORE_INJECTED_RESPONSE" ||
		eventIntent["maximumSecurityEvents"] != float64(1) {
		return result, errors.New("original one-use output event intent differs")
	}
	var auditStart availabilityAuditStart
	if e.decode("audit-start.json", &auditStart) != nil || eventIntent["auditStartSHA256"] != availabilityHash(mustAvailabilityJSON(auditStart)) {
		return result, errors.New("original output event and audit checkpoint differ")
	}
	var observation map[string]any
	annotations := availabilityMap(availabilityMeta(created)["annotations"])
	if availabilityDecode([]byte(availabilityString(annotations, "phorvex.ai/sensitive-output-observation-v1")), &observation) != nil ||
		!outputObservationValid(observation, before, e.profile.Fixture.PolicyName, availabilityString(baselineObservation, "observedAt")) ||
		availabilityString(annotations, "phorvex.ai/creator-identity") != event.CreatorIdentity {
		return result, errors.New("original event observation or authenticated creator differs")
	}
	observedAt, timeErr := time.Parse(time.RFC3339Nano, availabilityString(observation, "observedAt"))
	createdAt, createdErr := time.Parse(time.RFC3339Nano, availabilityString(availabilityMeta(created), "creationTimestamp"))
	if timeErr != nil || createdErr != nil || createdAt.Add(time.Second).Before(observedAt) || createdAt.Sub(observedAt) >= 45*time.Second {
		return result, errors.New("injected output event not fresh after measured disclosure")
	}
	var inventory map[string]any
	if e.kube("pre-event-inventory", &inventory) != nil ||
		availabilityString(availabilityMeta(inventory), "continue") != "" {
		return result, errors.New("original pre-event inventory incomplete")
	}
	items, ok := inventory["items"].([]any)
	if !ok || len(items) > 512 {
		return result, errors.New("original pre-event inventory malformed")
	}
	for _, raw := range items {
		item := availabilityMap(raw)
		if availabilityUID(item) == event.UID || availabilityString(availabilityMeta(item), "name") == event.Name {
			return result, errors.New("injected output event existed before one-shot creation")
		}
	}
	var eventManifest, eventReply map[string]any
	if e.decode("event-create-manifest.yaml", &eventManifest) != nil || e.decode("event-create-reply.json", &eventReply) != nil ||
		availabilityString(availabilityMeta(eventManifest), "name") != event.Name ||
		availabilityString(availabilityMeta(eventReply), "uid") != event.UID ||
		availabilityString(availabilityMap(availabilityMeta(eventManifest)["annotations"]), "phorvex.ai/sensitive-output-observation-v1") !=
			availabilityString(annotations, "phorvex.ai/sensitive-output-observation-v1") ||
		bytes.Contains(e.files["event-create-manifest.yaml"], []byte(e.marker)) ||
		bytes.Contains(e.files["event-create-reply.json"], []byte(e.marker)) {
		return result, errors.New("original injected event manifest, reply or marker isolation differs")
	}
	result.EventUID = event.UID
	if err := e.verifyOutputCleanup(before, event); err != nil {
		return result, err
	}
	if err := e.verifyOutputAudit(before, event, result); err != nil {
		return result, err
	}
	postAction, err := e.snapshot("post-action")
	if err != nil || !outputSameSource(before, postAction) {
		return result, errors.New("original post-action source drift")
	}
	if err := e.supportIntent("after-case", []byte(guardrailOutputBody)); err != nil {
		return result, err
	}
	if err := e.supportIntent("after-unrelated", []byte(guardrailOutputUnrelatedBody)); err != nil {
		return result, err
	}
	postStatus, postBody, err := e.http("after-case")
	if err != nil {
		return result, err
	}
	result.AfterSupport, err = classifyGuardrailOutputSupport(postStatus, postBody, e.marker, e.profile.Fixture.ModelID, false)
	if err != nil {
		return result, err
	}
	if result.AfterSupport == "PROTECTED_PUBLIC_ANSWER" &&
		(outputCompletionID(preBody) == "" || outputCompletionID(postBody) == "" || outputCompletionID(preBody) == outputCompletionID(postBody)) {
		return result, errors.New("repeated support response lacks a distinct real model completion")
	}
	result.AfterSayOK, err = e.control("after-say_ok", "say_ok")
	if err != nil {
		return result, err
	}
	result.AfterArithmetic, err = e.control("after-arithmetic", "arithmetic")
	if err != nil {
		return result, err
	}
	unrelatedStatus, unrelatedBody, err := e.http("after-unrelated")
	if err != nil {
		return result, err
	}
	result.UnrelatedSupport = outputUnrelatedClass(unrelatedStatus, unrelatedBody, e.marker, e.profile.Fixture.ModelID)
	final, err := e.snapshot("final")
	if err != nil || !outputSameSource(before, final) || final.CompletedModelCalls < postAction.CompletedModelCalls+1 {
		return result, errors.New("original final source or real model call differs")
	}
	joined := outputActivationJoined(before, postAction, final, result)
	result.Status = guardrailOutputOutcome(result.BeforeSupport, result.AfterSupport, result.BeforeSayOK, result.BeforeArithmetic,
		result.AfterSayOK, result.AfterArithmetic, result.UnrelatedSupport, joined)
	result.PolicyRevision = final.Revision
	result.CleanupVerified = true
	result.Accepted = result.Status != "UNKNOWN"
	return result, nil
}

func outputObservationValid(observation map[string]any, before outputSnapshot, policyName, observedAt string) bool {
	return len(observation) == 10 && observation["version"] == float64(1) &&
		observation["ruleId"] == guardrailOutputRuleID && observation["ruleSHA256"] == before.RuleSHA256 &&
		observation["configMapUID"] == before.ConfigMapUID && observation["podUID"] == before.TargetPodUID &&
		observation["requestPath"] == guardrailOutputPath && observation["policyUID"] == before.PolicyUID &&
		observation["policyName"] == policyName && observation["policyGeneration"] == float64(before.PolicyGeneration) &&
		observation["observedAt"] == observedAt
}

func outputActivationJoined(before, postAction, final outputSnapshot, result *guardrailOutputProbeResult) bool {
	return result != nil && result.DecisionID != "" && result.OperationID != "" && result.ActivationPath != "" &&
		postAction.Active && final.Active && postAction.Revision == before.Revision+1 && final.Revision == postAction.Revision &&
		postAction.ConfigMapResourceVersion != before.ConfigMapResourceVersion &&
		final.ConfigMapResourceVersion == postAction.ConfigMapResourceVersion &&
		postAction.OperationID == result.OperationID && final.OperationID == result.OperationID
}

func (e outputEvidence) verifyOutputCleanup(before outputSnapshot, event availabilityEvent) error {
	var cluster, predelete, ack, absence map[string]any
	var intent availabilityEvent
	if e.decode("cleanup-cluster.json", &cluster) != nil || availabilityUID(cluster) != before.ClusterUID ||
		e.decode("event-predelete.json", &predelete) != nil || e.decode("delete-intent.json", &intent) != nil ||
		e.decode("delete-ack.json", &ack) != nil || e.decode("event-absence.json", &absence) != nil {
		return errors.New("original exact output event cleanup receipts absent")
	}
	meta, spec := availabilityMeta(predelete), availabilityMap(predelete["spec"])
	notes, labels := availabilityMap(meta["annotations"]), availabilityMap(meta["labels"])
	targets, _ := spec["targets"].([]any)
	if intent != event || event.TargetPodUID != before.TargetPodUID ||
		availabilityString(meta, "uid") != event.UID || availabilityString(meta, "name") != event.Name ||
		availabilityString(meta, "resourceVersion") != event.ResourceVersion ||
		availabilityString(notes, "phorvex.ai/creator-identity") != event.CreatorIdentity ||
		availabilityString(labels, "phorvex.ai/attack-correlation") != event.Correlation ||
		availabilityString(labels, "phorvex.ai/console-vllm") != "true" || len(targets) != 1 ||
		targets[0] != "vllm/"+e.profile.Fixture.PodName ||
		availabilityMap(spec["rule"])["type"] != event.RuleType || availabilityMap(spec["rule"])["source"] != event.Source ||
		ack["acknowledged"] != true || ack["uid"] != event.UID || ack["resourceVersion"] != event.ResourceVersion ||
		absence["notFound"] != true || absence["uid"] != event.UID || absence["name"] != event.Name {
		return errors.New("original exact output event cleanup differs")
	}
	return nil
}

func (e outputEvidence) verifyOutputAudit(before outputSnapshot, event availabilityEvent, result *guardrailOutputProbeResult) error {
	var audit availabilityAuditTerminal
	var start availabilityAuditStart
	if e.decode("audit-terminal.json", &audit) != nil || e.decode("audit-start.json", &start) != nil ||
		audit.Schema != "guardrail-availability-audit-terminal-v1" || audit.Status != "COMPLETE" || !audit.CoverageComplete ||
		audit.SourceIdentity != e.profile.Fixture.AuditURL+"|"+e.profile.Fixture.AuditServerName ||
		audit.StartSHA256 != availabilityHash(mustAvailabilityJSON(start)) || audit.UnboundTargetRows == nil || *audit.UnboundTargetRows != 0 ||
		len(audit.TargetRows) == 0 || audit.RawAuditRetained || audit.BytesRead != audit.FrozenBytes || audit.DataGETs != len(audit.ChunkReceipts) {
		return errors.New("authenticated output audit coverage incomplete")
	}
	startRaw, se := e.original("audit-start-manifest.json")
	endRaw, ee := e.original("audit-end-manifest.json")
	finalRaw, fe := e.original("audit-terminal-manifest.json")
	var sm, em, fm audittransport.Manifest
	if se != nil || ee != nil || fe != nil || availabilityDecode(startRaw, &sm) != nil || availabilityDecode(endRaw, &em) != nil ||
		availabilityDecode(finalRaw, &fm) != nil || !availabilityValidManifest(sm) || !availabilityValidManifest(em) ||
		!availabilityValidManifest(fm) || availabilityHash(startRaw) != start.ManifestSHA256 ||
		availabilityHash(endRaw) != audit.EndManifestSHA256 || availabilityHash(finalRaw) != audit.TerminalManifestSHA256 ||
		start.Schema != "guardrail-availability-audit-start-v1" || start.SourceIdentity != audit.SourceIdentity ||
		sm.Segments[0] != start.Segment || start.CheckpointSize != start.Segment.Size || start.AlignedOffset > start.CheckpointSize ||
		sm.FetchedAt > em.FetchedAt || em.FetchedAt > fm.FetchedAt {
		return errors.New("authenticated output audit manifests differ")
	}
	spans, spanErr := availabilitySpans(start, em)
	finalSpans, finalErr := availabilitySpans(start, fm)
	if spanErr != nil || finalErr != nil || len(finalSpans) < len(spans) {
		return errors.New("authenticated output audit spans differ")
	}
	for i, span := range spans {
		a, b := span[0].(audittransport.Segment), finalSpans[i][0].(audittransport.Segment)
		if a.Generation != b.Generation || a.Anchor != b.Anchor || b.Size < span[2].(int64) {
			return errors.New("authenticated output audit generation changed")
		}
	}
	var sum int64
	index := 0
	for _, span := range spans {
		seg, off, end := span[0].(audittransport.Segment), span[1].(int64), span[2].(int64)
		for off < end {
			if index >= len(audit.ChunkReceipts) {
				return errors.New("authenticated output audit chunk missing")
			}
			c := audit.ChunkReceipts[index]
			want := int(min(int64(audittransport.ChunkBytes), end-off))
			if c.SegmentID != seg.ID || c.Generation != seg.Generation || c.Offset != off || c.Bytes != want || !staticSHA256.MatchString(c.SHA256) {
				return errors.New("authenticated output audit chunk differs")
			}
			off += int64(want)
			sum += int64(want)
			index++
		}
	}
	if index != len(audit.ChunkReceipts) || sum != audit.FrozenBytes {
		return errors.New("authenticated output audit bytes incomplete")
	}
	var selected *availabilityDecision
	observed := false
	for i := range audit.TargetRows {
		d := &audit.TargetRows[i]
		if d.PolicyUID != before.PolicyUID || d.AssetUID != before.TargetPodUID || d.DecisionID == "" || d.TickID == "" || d.OtherTrustedEventCount != 0 {
			return errors.New("output audit target, decision or competing event differs")
		}
		if d.EventCoverage == "EXACT_TRUSTED_EVENT_OBSERVED" {
			if d.ExactEventUID != event.UID || d.ExactEventName != event.Name || d.ExactEventCreator != event.CreatorIdentity ||
				d.ExactEventTargetPodUID != before.TargetPodUID || d.EventWeight <= 0 {
				return errors.New("output audit event identity differs")
			}
			observed = true
		}
		if d.Selected || d.Actuated || d.Action != "noop" {
			if selected != nil {
				return errors.New("multiple mutating output decisions")
			}
			selected = d
		}
	}
	if !observed {
		return errors.New("injected output event absent from authenticated decisions")
	}
	if selected == nil || selected.Action != "sensitive-output-policy-activate" || !selected.Selected ||
		selected.EventCoverage != "EXACT_TRUSTED_EVENT_OBSERVED" || selected.EventEvidence <= 0 ||
		outputDispatchPath(selected) == "" {
		return nil // observed NOOP or unrelated action: truthful non-defense
	}
	var journal map[string]any
	if e.decode("journal-observed.json", &journal) != nil ||
		availabilityString(availabilityMeta(journal), "name") != outputJournalName(before.TargetPodUID) {
		return errors.New("selected output action lacks protected journal")
	}
	var receipt map[string]any
	if availabilityUID(journal) == "" || availabilityString(availabilityMeta(journal), "namespace") != "phorvex-system" ||
		availabilityMap(availabilityMeta(journal)["labels"])["phorvex.ai/output-policy-journal"] != "v1" ||
		availabilityDecode([]byte(availabilityString(availabilityMap(journal["data"]), "receipt")), &receipt) != nil ||
		receipt["version"] != float64(1) || receipt["kind"] != "sensitive-output-policy-activate" || receipt["phase"] != "terminal-full" ||
		receipt["policyNamespace"] != "vllm" || receipt["policyName"] != e.profile.Fixture.PolicyName ||
		receipt["policyGeneration"] != float64(before.PolicyGeneration) || receipt["targetName"] != e.profile.Fixture.PodName ||
		receipt["creatorIdentity"] != event.CreatorIdentity || receipt["configMapName"] != e.profile.Fixture.OutputPolicyConfigMapName ||
		receipt["targetUID"] != before.TargetPodUID || receipt["policyUID"] != before.PolicyUID ||
		receipt["configMapUID"] != before.ConfigMapUID || receipt["ruleSHA256"] != before.RuleSHA256 ||
		receipt["selectedConfigMapResourceVersion"] != before.ConfigMapResourceVersion || receipt["selectedRevision"] != float64(before.Revision) ||
		receipt["proxySourceSHA256"] != e.profile.Fixture.SourceSHA256 || receipt["supportSourceSHA256"] != e.profile.Fixture.SupportSourceSHA256 ||
		receipt["proxyImageID"] != e.profile.Fixture.PodImageID || receipt["supportImageID"] != e.profile.Fixture.SupportImageID ||
		receipt["eventUID"] != event.UID || receipt["eventName"] != event.Name ||
		receipt["tickId"] != selected.TickID || receipt["selectionDecisionId"] != selected.DecisionID ||
		availabilityMap(receipt["prior"])["active"] != false || availabilityMap(receipt["desired"])["active"] != true ||
		availabilityMap(receipt["prior"])["revision"] != float64(before.Revision) ||
		availabilityMap(receipt["desired"])["revision"] != float64(before.Revision+1) ||
		availabilityMap(receipt["prior"])["configMapUID"] != before.ConfigMapUID ||
		availabilityMap(receipt["desired"])["configMapUID"] != before.ConfigMapUID ||
		availabilityMap(receipt["prior"])["ruleId"] != guardrailOutputRuleID ||
		availabilityMap(receipt["desired"])["ruleId"] != guardrailOutputRuleID {
		return errors.New("selected output action lacks exact terminal protected operation")
	}
	op, ok := receipt["operationId"].(string)
	wantOp := sha256.Sum256([]byte("phorvex-output-policy-v1\x00" + before.PolicyUID + "\x00" + before.TargetPodUID + "\x00" + event.UID + "\x00" + selected.TickID + "\x00" + selected.DecisionID))
	if !ok || op != hex.EncodeToString(wantOp[:]) || availabilityMap(receipt["desired"])["operationId"] != op ||
		availabilityMap(receipt["prior"])["operationId"] != before.OperationID {
		return errors.New("protected output operation token absent")
	}
	result.DecisionID, result.OperationID = selected.DecisionID, op
	result.ActivationPath = outputDispatchPath(selected)
	if result.ActivationPath == "TERMINAL_CONFIRMED_AFTER_DISPATCH_ERROR" && e.hasPreparedOutputJournal(before, event, selected, op) {
		result.ActivationPath = "RECOVERED_AFTER_PENDING"
	}
	return nil
}

func outputDispatchPath(selected *availabilityDecision) string {
	if selected == nil || !selected.Selected || selected.Action != "sensitive-output-policy-activate" {
		return ""
	}
	if selected.Actuated && selected.DispatchOutcome == "emitted" && selected.TopLevelDispatchOutcome == "emitted" {
		return "DIRECT_EMITTED"
	}
	if !selected.Actuated && selected.DispatchOutcome == "dispatch-error" && selected.TopLevelDispatchOutcome == "dispatch-error" {
		return "TERMINAL_CONFIRMED_AFTER_DISPATCH_ERROR"
	}
	return ""
}

func (e outputEvidence) hasPreparedOutputJournal(before outputSnapshot, event availabilityEvent, selected *availabilityDecision, op string) bool {
	for name, raw := range e.files {
		if !strings.HasPrefix(name, "kube-") || !strings.Contains(name, "-journal-poll-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		var cm map[string]any
		if availabilityDecode(raw, &cm) != nil || availabilityString(availabilityMeta(cm), "name") != outputJournalName(before.TargetPodUID) {
			continue
		}
		var receipt map[string]any
		if availabilityDecode([]byte(availabilityString(availabilityMap(cm["data"]), "receipt")), &receipt) == nil &&
			receipt["phase"] == "prepared" && receipt["policyUID"] == before.PolicyUID &&
			receipt["targetUID"] == before.TargetPodUID && receipt["eventUID"] == event.UID &&
			receipt["eventName"] == event.Name && receipt["tickId"] == selected.TickID &&
			receipt["selectionDecisionId"] == selected.DecisionID && receipt["operationId"] == op &&
			receipt["configMapUID"] == before.ConfigMapUID && receipt["ruleSHA256"] == before.RuleSHA256 {
			return true
		}
	}
	return false
}
