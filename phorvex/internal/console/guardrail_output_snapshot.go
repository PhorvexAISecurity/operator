package console

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/phorvex/phorvex/internal/outputpolicy"
)

func outputRuleBytes(podUID string) []byte {
	return outputpolicy.RuleBytes(podUID)
}

func outputReadyRoute(list, service, pod map[string]any, podUID string) bool {
	if availabilityString(availabilityMeta(list), "continue") != "" {
		return false
	}
	podIP := availabilityString(availabilityMap(pod["status"]), "podIP")
	if podIP == "" || availabilityUID(pod) != podUID {
		return false
	}
	selector := availabilityMap(availabilityMap(service["spec"])["selector"])
	labels := availabilityMap(availabilityMeta(pod)["labels"])
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	servicePorts, _ := availabilityMap(service["spec"])["ports"].([]any)
	matchedPort := 0
	for _, raw := range servicePorts {
		port := availabilityMap(raw)
		if port["port"] != float64(8000) || (port["protocol"] != nil && port["protocol"] != "TCP") {
			continue
		}
		target := port["targetPort"]
		if target == nil || target == float64(8000) {
			matchedPort++
			continue
		}
		name, ok := target.(string)
		if !ok || name == "" {
			return false
		}
		containers, _ := availabilityMap(pod["spec"])["containers"].([]any)
		resolved := false
		for _, rawContainer := range containers {
			ports, _ := availabilityMap(rawContainer)["ports"].([]any)
			for _, rawPort := range ports {
				entry := availabilityMap(rawPort)
				if entry["name"] == name && entry["containerPort"] == float64(8000) &&
					(entry["protocol"] == nil || entry["protocol"] == "TCP") {
					resolved = true
				}
			}
		}
		if resolved {
			matchedPort++
		}
	}
	if matchedPort != 1 {
		return false
	}
	items, _ := list["items"].([]any)
	readyCount, pinnedCount := 0, 0
	for _, item := range items {
		row := availabilityMap(item)
		if availabilityString(availabilityMap(availabilityMeta(row)["labels"]), "kubernetes.io/service-name") !=
			availabilityString(availabilityMeta(service), "name") {
			return false
		}
		endpoints, _ := row["endpoints"].([]any)
		for _, endpoint := range endpoints {
			e := availabilityMap(endpoint)
			if availabilityMap(e["conditions"])["ready"] == false {
				continue
			}
			readyCount++
			addresses, _ := e["addresses"].([]any)
			ports, _ := row["ports"].([]any)
			routePort := false
			for _, rawPort := range ports {
				port := availabilityMap(rawPort)
				if port["port"] == float64(8000) && (port["protocol"] == nil || port["protocol"] == "TCP") {
					routePort = true
				}
			}
			if availabilityString(availabilityMap(e["targetRef"]), "uid") == podUID &&
				len(addresses) == 1 && addresses[0] == podIP && routePort {
				pinnedCount++
			}
		}
	}
	return readyCount == 1 && pinnedCount == 1
}

func outputControllerOwned(cm map[string]any, podName, podUID string) bool {
	owners, _ := availabilityMeta(cm)["ownerReferences"].([]any)
	if len(owners) != 1 {
		return false
	}
	o := availabilityMap(owners[0])
	return o["kind"] == "Pod" && o["name"] == podName && o["uid"] == podUID && o["controller"] == true
}

func outputPolicyMount(pod map[string]any, configMapName string) bool {
	volumes, _ := availabilityMap(pod["spec"])["volumes"].([]any)
	var volume string
	for _, raw := range volumes {
		v := availabilityMap(raw)
		if availabilityString(availabilityMap(v["configMap"]), "name") == configMapName {
			if volume != "" || availabilityMap(v["configMap"])["optional"] != true {
				return false
			}
			volume = availabilityString(v, "name")
		}
	}
	if volume == "" {
		return false
	}
	containers, _ := availabilityMap(pod["spec"])["containers"].([]any)
	for _, raw := range containers {
		c := availabilityMap(raw)
		if c["name"] != "guardrail-proxy" {
			continue
		}
		mounts, _ := c["volumeMounts"].([]any)
		for _, rawMount := range mounts {
			m := availabilityMap(rawMount)
			if m["name"] == volume && m["mountPath"] == "/etc/phorvex/output-policy" && m["readOnly"] == true && m["subPath"] == nil && m["subPathExpr"] == nil {
				return true
			}
		}
	}
	return false
}

func (w *outputWorker) snapshot(label string) (outputSnapshot, error) {
	f := w.profile.Fixture
	read := func(s string, args ...string) (map[string]any, error) { return w.kube(label+"-"+s, args...) }
	var out outputSnapshot
	cluster, err := read("cluster", "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return out, err
	}
	pod, err := read("fixture-pod", "-n", "vllm", "get", "pod", f.PodName, "-o", "json")
	if err != nil {
		return out, err
	}
	service, err := read("fixture-service", "-n", "vllm", "get", "service", f.ServiceName, "-o", "json")
	if err != nil {
		return out, err
	}
	fixtureEndpoints, err := read("fixture-endpoints", "-n", "vllm", "get", "endpointslices.discovery.k8s.io", "-l", "kubernetes.io/service-name="+f.ServiceName, "-o", "json")
	if err != nil {
		return out, err
	}
	modelPod, err := read("model-pod", "-n", "vllm", "get", "pod", f.ModelTargetPodName, "-o", "json")
	if err != nil {
		return out, err
	}
	modelService, err := read("model-service", "-n", "vllm", "get", "service", f.ModelServiceName, "-o", "json")
	if err != nil {
		return out, err
	}
	modelEndpoints, err := read("model-endpoints", "-n", "vllm", "get", "endpointslices.discovery.k8s.io", "-l", "kubernetes.io/service-name="+f.ModelServiceName, "-o", "json")
	if err != nil {
		return out, err
	}
	source, err := read("source", "-n", "vllm", "get", "configmap", f.SourceConfigMapName, "-o", "json")
	if err != nil {
		return out, err
	}
	sourceData := availabilityMap(source["data"])
	proxyText, policyText, supportText := availabilityString(sourceData, "guardrail_proxy.py"),
		availabilityString(sourceData, "output_policy.py"), availabilityString(sourceData, "support_fixture.py")
	if source["immutable"] != true || len(sourceData) != 3 || proxyText == "" || policyText == "" || supportText == "" ||
		availabilityHash(append(append([]byte(proxyText), 0), []byte(policyText)...)) != f.SourceSHA256 ||
		availabilityHash([]byte(supportText)) != f.SupportSourceSHA256 {
		return out, errors.New("immutable fixture source package differs")
	}
	policyCM, err := read("output-policy", "-n", "vllm", "get", "configmap", f.OutputPolicyConfigMapName, "-o", "json")
	if err != nil {
		return out, err
	}
	policy, err := read("policy", "-n", "vllm", "get", "phorvexpolicies.phorvex.ai", f.PolicyName, "-o", "json")
	if err != nil {
		return out, err
	}
	manager, err := read("manager", "-n", "phorvex-system", "get", "pod", f.ManagerPodName, "-o", "json")
	if err != nil {
		return out, err
	}
	console, err := read("console", "-n", "phorvex-system", "get", "pod", w.selfName, "-o", "json")
	if err != nil {
		return out, err
	}
	rsName, rsUID, err := availabilityController(console, "ReplicaSet")
	if err != nil {
		return out, err
	}
	rs, err := read("console-rs", "-n", "phorvex-system", "get", "replicaset", rsName, "-o", "json")
	if err != nil || availabilityUID(rs) != rsUID {
		return out, errors.New("console ReplicaSet identity changed")
	}
	depName, depUID, err := availabilityController(rs, "Deployment")
	if err != nil || depName != f.ConsoleDeploymentName || depUID != f.ConsoleDeploymentUID {
		return out, errors.New("console Deployment identity changed")
	}
	dep, err := read("console-deployment", "-n", "phorvex-system", "get", "deployment", depName, "-o", "json")
	if err != nil || availabilityUID(dep) != depUID {
		return out, errors.New("console Deployment UID changed")
	}
	proxyID, proxyImage, err := availabilityStatus(pod, "guardrail-proxy")
	if err != nil || proxyID == "" {
		return out, errors.New("fixture proxy container unavailable")
	}
	supportID, supportImage, err := availabilityStatus(pod, "support-app")
	if err != nil || supportID == "" {
		return out, errors.New("fixture support container unavailable")
	}
	_, modelImage, err := availabilityStatus(modelPod, "vllm")
	if err != nil {
		return out, errors.New("real model container unavailable")
	}
	_, managerImage, err := availabilityStatus(manager, "manager")
	if err != nil {
		return out, errors.New("manager container unavailable")
	}
	_, consoleImage, err := availabilityStatus(console, "console")
	if err != nil {
		return out, errors.New("console container unavailable")
	}
	annotations := availabilityMap(availabilityMeta(pod)["annotations"])
	if annotations["phorvex.ai/output-policy-configmap"] != f.OutputPolicyConfigMapName ||
		annotations["phorvex.ai/output-policy-rule-sha256"] != f.OutputPolicyRuleSHA256 ||
		annotations["phorvex.ai/output-proxy-source-sha256"] != f.SourceSHA256 ||
		annotations["phorvex.ai/output-support-source-sha256"] != f.SupportSourceSHA256 ||
		annotations["phorvex.ai/output-event-creator"] != f.EventCreator ||
		!outputPolicyMount(pod, f.OutputPolicyConfigMapName) {
		return out, errors.New("fixture output policy source or mount differs")
	}
	if "system:serviceaccount:phorvex-system:"+availabilityString(availabilityMap(console["spec"]), "serviceAccountName") != f.EventCreator {
		return out, errors.New("reviewed event creator is not the actual console identity")
	}
	if !outputControllerOwned(policyCM, f.PodName, f.PodUID) || !outputReadyRoute(fixtureEndpoints, service, pod, f.PodUID) ||
		!outputReadyRoute(modelEndpoints, modelService, modelPod, f.ModelTargetPodUID) {
		return out, errors.New("owned ConfigMap or exact Service routing differs")
	}
	data := availabilityMap(policyCM["data"])
	if len(data) != 2 || data["rule.json"] != string(outputRuleBytes(f.PodUID)) || availabilityHash([]byte(availabilityString(data, "rule.json"))) != f.OutputPolicyRuleSHA256 {
		return out, errors.New("preinstalled immutable output rule differs")
	}
	var activation map[string]any
	if err = availabilityDecode([]byte(availabilityString(data, "activation.json")), &activation); err != nil || len(activation) != 6 ||
		activation["version"] != float64(1) || activation["ruleId"] != guardrailOutputRuleID || activation["configMapUID"] != f.OutputPolicyConfigMapUID {
		return out, errors.New("output activation pair malformed")
	}
	active, ok := activation["active"].(bool)
	if !ok {
		return out, errors.New("output activation state malformed")
	}
	revision, ok := activation["revision"].(float64)
	if !ok || revision < 0 || revision != float64(int64(revision)) {
		return out, errors.New("output activation revision malformed")
	}
	operationID, ok := activation["operationId"].(string)
	if !ok || len(operationID) > 128 {
		return out, errors.New("output activation operation malformed")
	}
	stateStatus, stateBody, err := w.httpCall(label+"-proxy-state", "guardrail-proxy", 8000, "GET", "/v1/output-policy/state", nil)
	if err != nil || stateStatus != 200 {
		return out, errors.New("effective proxy policy state unavailable")
	}
	var state map[string]any
	if availabilityDecode(stateBody, &state) != nil || state["ready"] != true || state["version"] != float64(1) ||
		state["podUID"] != f.PodUID || state["configMapUID"] != f.OutputPolicyConfigMapUID ||
		state["ruleId"] != guardrailOutputRuleID || state["ruleSHA256"] != f.OutputPolicyRuleSHA256 ||
		state["proxySourceSHA256"] != f.SourceSHA256 || state["supportSourceSHA256"] != f.SupportSourceSHA256 ||
		state["active"] != active || state["revision"] != revision || state["operationId"] != operationID {
		return out, errors.New("effective proxy readback differs from ConfigMap and pinned source")
	}
	supportStatus, supportBody, err := w.httpCall(label+"-support-state", "support-app", 8002, "GET", "/v1/support/state", nil)
	if err != nil || supportStatus != 200 {
		return out, errors.New("support app state unavailable")
	}
	var support map[string]any
	if availabilityDecode(supportBody, &support) != nil || support["version"] != float64(1) ||
		support["supportSourceSHA256"] != f.SupportSourceSHA256 || support["model"] != f.ModelID {
		return out, errors.New("support source or configured real model differs")
	}
	completed, ok := support["completedModelCalls"].(float64)
	if !ok || completed < 0 || completed != float64(int64(completed)) {
		return out, errors.New("support completed model count malformed")
	}
	out = outputSnapshot{ClusterUID: availabilityUID(cluster), TargetPodUID: availabilityUID(pod),
		TargetProxyImageID: proxyImage, TargetSupportImageID: supportImage, ServiceUID: availabilityUID(service),
		SourceUID: availabilityUID(source), ModelPodUID: availabilityUID(modelPod), ModelImageID: modelImage,
		ModelServiceUID: availabilityUID(modelService), ManagerPodUID: availabilityUID(manager), ManagerImageID: managerImage,
		ConsolePodUID: availabilityUID(console), ConsoleImageID: consoleImage, ConsoleDeploymentUID: availabilityUID(dep),
		PolicyUID: availabilityUID(policy), ConfigMapUID: availabilityUID(policyCM),
		ConfigMapResourceVersion: availabilityString(availabilityMeta(policyCM), "resourceVersion"),
		RuleSHA256:               f.OutputPolicyRuleSHA256, Active: active, Revision: int64(revision), OperationID: operationID,
		ProxyReady: true, CompletedModelCalls: int64(completed)}
	if n, ok := availabilityMeta(policy)["generation"].(float64); ok {
		out.PolicyGeneration = int64(n)
	}
	spec, _ := json.Marshal(policy["spec"])
	out.PolicySpecSHA256 = availabilityHash(spec)
	if out.ClusterUID != f.ClusterUID || out.TargetPodUID != f.PodUID || out.TargetProxyImageID != f.PodImageID ||
		out.TargetSupportImageID != f.SupportImageID || out.ServiceUID != f.ServiceUID || out.SourceUID != f.SourceUID ||
		out.ModelPodUID != f.ModelTargetPodUID || out.ModelImageID != f.ModelTargetImageID || out.ModelServiceUID != f.ModelServiceUID ||
		out.ManagerPodUID != f.ManagerPodUID || out.ManagerImageID != f.ManagerImageID || out.ConsolePodUID != w.selfUID ||
		out.ConsoleImageID != f.ConsoleImageID || out.ConsoleDeploymentUID != f.ConsoleDeploymentUID ||
		out.PolicyUID != f.PolicyUID || out.PolicyGeneration != f.PolicyGeneration || out.ConfigMapUID != f.OutputPolicyConfigMapUID ||
		availabilityMap(policy["status"])["observedGeneration"] != float64(f.PolicyGeneration) ||
		strings.TrimSpace(out.ConfigMapResourceVersion) == "" {
		return out, errors.New("reviewed fixture, model, manager or policy identity changed")
	}
	if err = w.saveJSON(label+"-snapshot.json", out); err != nil {
		return out, err
	}
	return out, nil
}

func outputSameSource(before, after outputSnapshot) bool {
	return before.ClusterUID == after.ClusterUID && before.TargetPodUID == after.TargetPodUID &&
		before.TargetProxyImageID == after.TargetProxyImageID && before.TargetSupportImageID == after.TargetSupportImageID &&
		before.ServiceUID == after.ServiceUID && before.SourceUID == after.SourceUID &&
		before.ModelPodUID == after.ModelPodUID && before.ModelImageID == after.ModelImageID && before.ModelServiceUID == after.ModelServiceUID &&
		before.ManagerPodUID == after.ManagerPodUID && before.ManagerImageID == after.ManagerImageID &&
		before.ConsolePodUID == after.ConsolePodUID && before.ConsoleImageID == after.ConsoleImageID &&
		before.ConsoleDeploymentUID == after.ConsoleDeploymentUID && before.PolicyUID == after.PolicyUID &&
		before.PolicyGeneration == after.PolicyGeneration && before.PolicySpecSHA256 == after.PolicySpecSHA256 &&
		before.ConfigMapUID == after.ConfigMapUID && before.RuleSHA256 == after.RuleSHA256 && after.ProxyReady
}
