package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const (
	liteLiveRule       = "phorvex.attack.litellm-client-abuse"
	liteLiveAnnotation = "phorvex.ai/litellm-client-observation-v1"
	liteLiveServiceURL = "http://litellm.litellm.svc:4000/v1/chat/completions"
)

var liteLiveSequence atomic.Uint64

type liteLivePod struct {
	Name           string `json:"name"`
	UID            string `json:"uid"`
	BackendImageID string `json:"backendImageID"`
	GatewayImageID string `json:"gatewayImageID"`
}

type liteLLMLiveProfile struct {
	Version             int           `json:"version"`
	ClusterUID          string        `json:"clusterUID"`
	NamespaceUID        string        `json:"namespaceUID"`
	DeploymentUID       string        `json:"deploymentUID"`
	ServiceUID          string        `json:"serviceUID"`
	SourceConfigMapUID  string        `json:"sourceConfigMapUID"`
	SourceSHA256        string        `json:"sourceSHA256"`
	GatewayImage        string        `json:"gatewayImage"`
	ClientsConfigMapUID string        `json:"clientsConfigMapUID"`
	ClientsSHA256       string        `json:"clientsSHA256"`
	PolicyConfigMapUID  string        `json:"policyConfigMapUID"`
	PolicyName          string        `json:"policyName"`
	PolicyUID           string        `json:"policyUID"`
	PolicyGeneration    int64         `json:"policyGeneration"`
	ModelAlias          string        `json:"modelAlias"`
	AttackerSHA256      string        `json:"attackerSHA256"`
	ControlSHA256       string        `json:"controlSHA256"`
	Pods                []liteLivePod `json:"pods"`
	EventCreator        string        `json:"eventCreator"`
	AuditSourceIdentity string        `json:"auditSourceIdentity"`
	MaxRunSeconds       int           `json:"maxRunSeconds"`
}

type liteLiveCounters struct {
	ForwardedRequests   int64 `json:"forwardedRequests"`
	UpstreamCompletions int64 `json:"upstreamCompletions"`
	DeniedRequests      int64 `json:"deniedRequests"`
	UsageTokens         int64 `json:"usageTokens"`
}

type liteLiveStatus struct {
	Version      int    `json:"version"`
	PodUID       string `json:"podUID"`
	SourceSHA256 string `json:"sourceSHA256"`
	ConfigMapUID string `json:"configMapUID"`
	ClientSHA256 string `json:"clientSHA256"`
	Active       bool   `json:"active"`
	Revision     int64  `json:"revision"`
	OperationID  string `json:"operationId"`
	Ready        bool   `json:"ready"`
	Counters     struct {
		Attacker liteLiveCounters `json:"attacker"`
		Control  liteLiveCounters `json:"control"`
	} `json:"counters"`
}

type liteLiveSnapshot struct {
	ClusterUID          string            `json:"clusterUID"`
	NamespaceUID        string            `json:"namespaceUID"`
	DeploymentUID       string            `json:"deploymentUID"`
	ServiceUID          string            `json:"serviceUID"`
	SourceConfigMapUID  string            `json:"sourceConfigMapUID"`
	ClientsConfigMapUID string            `json:"clientsConfigMapUID"`
	PolicyConfigMapUID  string            `json:"policyConfigMapUID"`
	PolicyConfigMapRV   string            `json:"policyConfigMapRV"`
	PolicyUID           string            `json:"policyUID"`
	PolicyGeneration    int64             `json:"policyGeneration"`
	Active              bool              `json:"active"`
	Revision            int64             `json:"revision"`
	OperationID         string            `json:"operationId"`
	Pods                []liteLivePod     `json:"pods"`
	PodIPs              map[string]string `json:"podIPs"`
}

type liteLiveCall struct {
	Class         string `json:"class"`
	Status        int    `json:"status"`
	GatewayPodUID string `json:"gatewayPodUID"`
	BodySHA256    string `json:"bodySHA256"`
	CompletionID  string `json:"completionID,omitempty"`
	Model         string `json:"model,omitempty"`
	UsageTokens   int64  `json:"usageTokens,omitempty"`
}

type liteLLMLiveProbeResult struct {
	Status                      string   `json:"status"`
	Accepted                    bool     `json:"accepted"`
	Scenario                    string   `json:"scenario"`
	InitialAcceptedWork         bool     `json:"initialAcceptedWork"`
	InitialUsageTokens          int64    `json:"initialUsageTokens"`
	SignalMode                  string   `json:"signalMode"`
	EventUID                    string   `json:"eventUID,omitempty"`
	SelectedAction              string   `json:"selectedAction,omitempty"`
	SelectionDecisionID         string   `json:"selectionDecisionID,omitempty"`
	DispatchPath                string   `json:"dispatchPath,omitempty"`
	TerminalJournal             bool     `json:"terminalJournal"`
	BothGatewaysActive          bool     `json:"bothGatewaysActive"`
	ReplayBlockedBeforeUpstream bool     `json:"replayBlockedBeforeUpstream"`
	BenignContinuity            bool     `json:"benignContinuity"`
	Issues                      []string `json:"issues"`
}

type liteLiveWorker struct {
	s             *Server
	p             liteLLMLiveProfile
	profileSHA    string
	ctx           context.Context
	stop          context.CancelFunc
	out           string
	reads         int
	attackerToken string
	controlToken  string
	statusToken   string
	audit         *availabilityWorker
}

func liteSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func parseLiteLiveProfile(raw []byte) (liteLLMLiveProfile, error) {
	var p liteLLMLiveProfile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 16<<10 || dec.Decode(&p) != nil || dec.Decode(new(any)) != io.EOF ||
		p.Version != 1 || p.ClusterUID == "" || p.NamespaceUID == "" || p.DeploymentUID == "" || p.ServiceUID == "" ||
		p.SourceConfigMapUID == "" || !staticSHA256.MatchString(p.SourceSHA256) || !mongoPinnedImage.MatchString(p.GatewayImage) || p.ClientsConfigMapUID == "" ||
		!staticSHA256.MatchString(p.ClientsSHA256) || p.PolicyConfigMapUID == "" || p.PolicyName == "" || p.PolicyUID == "" ||
		p.PolicyGeneration < 1 || (p.ModelAlias != "gpt-4o-mini" && p.ModelAlias != "gpt-3.5-turbo") ||
		!staticSHA256.MatchString(p.AttackerSHA256) || !staticSHA256.MatchString(p.ControlSHA256) || p.AttackerSHA256 == p.ControlSHA256 ||
		len(p.Pods) != 2 || p.Pods[0].Name == p.Pods[1].Name || p.Pods[0].UID == p.Pods[1].UID ||
		p.EventCreator != "system:serviceaccount:phorvex-system:phorvex-phorvex-console" ||
		p.AuditSourceIdentity == "" || p.MaxRunSeconds != 900 {
		return p, errors.New("reviewed LiteLLM Live profile invalid")
	}
	for _, pod := range p.Pods {
		if pod.Name == "" || pod.UID == "" || !mongoPinnedImage.MatchString(pod.BackendImageID) || !mongoPinnedImage.MatchString(pod.GatewayImageID) {
			return p, errors.New("LiteLLM Live Pod pin invalid")
		}
	}
	sort.Slice(p.Pods, func(i, j int) bool { return p.Pods[i].Name < p.Pods[j].Name })
	return p, nil
}

func loadLiteLiveProfile(cfg Config) (liteLLMLiveProfile, []byte, error) {
	var p liteLLMLiveProfile
	if !cfg.LiteLLMLiveEnabled || !staticSHA256.MatchString(cfg.LiteLLMLiveProfileSHA256) ||
		cfg.LiteLLMLiveProfilePath != "/etc/phorvex-litellm-live/profile.json" || cfg.AuditSource == nil {
		return p, nil, errors.New("LiteLLM Live installation disabled or audit source unavailable")
	}
	raw, err := readPinnedNamedProfile(cfg.LiteLLMLiveProfilePath, cfg.LiteLLMLiveProfileSHA256)
	if err != nil {
		return p, nil, errors.New("LiteLLM Live profile bytes unavailable")
	}
	p, err = parseLiteLiveProfile(raw)
	if err != nil || cfg.AuditSourceIdentity != p.AuditSourceIdentity {
		return p, nil, errors.New("LiteLLM Live profile or audit identity differs")
	}
	return p, raw, nil
}

func (s *Server) liteLLMLiveFire(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Scenario string `json:"scenario"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF ||
		(input.Scenario != "ai2-unbounded-consumption" && input.Scenario != "ai2-query-extraction") {
		writeJSON(w, 400, map[string]string{"error": "reviewed LiteLLM Live scenario required"})
		return
	}
	p, raw, err := loadLiteLiveProfile(s.cfg)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "reviewed LiteLLM Live profile unavailable"})
		return
	}
	if err = s.persistEffectIntent("/api/litellm/live/fire", actorOf(r), "litellm", input.Scenario); err != nil {
		writeJSON(w, 503, map[string]string{"error": "LiteLLM Live intent persistence unavailable"})
		return
	}
	started := s.cfg.now().UTC()
	id := "atk-" + strconv.FormatInt(started.UnixNano(), 36) + strconv.FormatUint(liteLiveSequence.Add(1), 36)
	probe := &liteLLMLiveProbeResult{Status: "UNKNOWN", Scenario: input.Scenario, SignalMode: "NONE", Issues: []string{}}
	record := &attackRecord{ID: id, FiredAt: started.Format(time.RFC3339Nano), Service: "litellm", Namespace: "litellm", Pod: p.Pods[0].Name,
		TargetUID: p.Pods[0].UID, Attack: input.Scenario, AttackID: input.Scenario, MITRE: "query-channel", Expected: "litellm-client-revoke",
		EvidenceKind: "litellm-live-client-policy", OutcomeClass: "litellm-live-UNKNOWN", Status: "running", LiteLLMLiveProbe: probe,
		ProducerRoute: liteLiveServiceURL, ResultSchema: "litellm-live-v1",
		ObservationStart: started.Format(time.RFC3339Nano), ObservationEnd: started.Add(900 * time.Second).Format(time.RFC3339Nano), started: started, accepted: started}
	publishAttack(record)
	go s.runLiteLive(record, p, raw)
	writeJSON(w, 200, map[string]any{"ok": true, "attackId": id, "scenario": input.Scenario, "status": "running",
		"message": "Real LiteLLM Service calls are measuring. A test signal is injected only after independently accepted original work and benign control. Final defense requires selected native policy activation, both gateway readbacks, stopped replay, and benign continuity."})
}

func (s *Server) runLiteLive(r *attackRecord, p liteLLMLiveProfile, raw []byte) {
	out := s.cfg.statePath(filepath.Join("litellm-live", r.ID))
	probe := r.LiteLLMLiveProbe
	ctx, stop := context.WithTimeout(context.Background(), time.Duration(p.MaxRunSeconds)*time.Second)
	w := &liteLiveWorker{s: s, p: p, profileSHA: s.cfg.LiteLLMLiveProfileSHA256, ctx: ctx, stop: stop, out: out}
	defer stop()
	finish := func(err error) {
		if err != nil {
			probe.Issues = append(probe.Issues, err.Error())
			if probe.Status == "STOPPED_WITH_BENIGN_CONTINUITY" {
				probe.Status = "INCONCLUSIVE_AFTER_LANDED"
			}
		}
		if probe.Status == "UNKNOWN" && probe.InitialAcceptedWork {
			probe.Status = "INCONCLUSIVE_AFTER_LANDED"
		}
		probe.Accepted = probe.Status == "STOPPED_WITH_BENIGN_CONTINUITY"
		r.OutcomeClass = "litellm-live-" + probe.Status
		r.Status = "done"
		if !probe.Accepted {
			r.Status = "partial"
		}
		r.Outcome = ""
		r.Action = ""
		r.Actuated = false
		r.Containment = ""
		r.DefendedPod = ""
		if probe.Accepted {
			r.Outcome = "DEFENDED"
			r.Action = "litellm-client-revoke"
			r.Actuated = true
			r.DefendedPod = p.Pods[0].Name
			r.Containment = "client-revoked"
		}
		if out != "" {
			b, _ := json.Marshal(probe)
			_ = publishMongoAuditFile(out, "terminal.json", b, 1<<20)
		}
		publishAttack(r)
		if e := s.persistAttack(r); e != nil {
			r.Status = "partial"
			r.PersistenceError = "LiteLLM Live outcome persistence unavailable"
			publishAttack(r)
		}
	}
	if out == "" || os.MkdirAll(out, 0700) != nil {
		finish(errors.New("private LiteLLM Live receipt directory unavailable"))
		return
	}
	if err := w.save("profile.json", raw); err != nil {
		finish(err)
		return
	}
	err := w.execute(probe)
	finish(err)
}

func (w *liteLiveWorker) save(name string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 1<<20 || strings.ContainsAny(name, "/\\") {
		return errors.New("LiteLLM receipt bound")
	}
	return publishMongoAuditFile(w.out, name, raw, 1<<20)
}
func (w *liteLiveWorker) saveJSON(name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return w.save(name, raw)
}

// kube never forces the workstation EKS context inside the console Pod. The
// installed service-account projection is the runtime authority.
func (w *liteLiveWorker) kube(label string, args ...string) (map[string]any, error) {
	if w.reads >= 110 {
		return nil, errors.New("LiteLLM Kubernetes read budget")
	}
	w.reads++
	out, err := w.s.cfg.execText(25*time.Second, "kubectl", args...)
	if err != nil || len(out) == 0 || len(out) > 1<<20 {
		return nil, fmt.Errorf("LiteLLM source read unavailable: %s", label)
	}
	if err = w.save(fmt.Sprintf("kube-%03d-%s.json", w.reads, label), []byte(out)); err != nil {
		return nil, err
	}
	var value map[string]any
	if availabilityDecode([]byte(out), &value) != nil {
		return nil, fmt.Errorf("LiteLLM source malformed: %s", label)
	}
	return value, nil
}

func liteMeta(value map[string]any) map[string]any    { return availabilityMeta(value) }
func liteStr(value map[string]any, key string) string { return availabilityString(value, key) }
func liteInt(value map[string]any, key string) int64 {
	if n, ok := value[key].(float64); ok && n >= 0 && n == float64(int64(n)) {
		return int64(n)
	}
	return -1
}

func (w *liteLiveWorker) snapshot(label string) (liteLiveSnapshot, error) {
	var out liteLiveSnapshot
	cluster, e := w.kube(label+"-cluster", "get", "namespace", "kube-system", "-o", "json")
	if e != nil {
		return out, e
	}
	ns, e := w.kube(label+"-namespace", "get", "namespace", "litellm", "-o", "json")
	if e != nil {
		return out, e
	}
	dep, e := w.kube(label+"-deployment", "-n", "litellm", "get", "deployment", "litellm", "-o", "json")
	if e != nil {
		return out, e
	}
	svc, e := w.kube(label+"-service", "-n", "litellm", "get", "service", "litellm", "-o", "json")
	if e != nil {
		return out, e
	}
	slices, e := w.kube(label+"-slices", "-n", "litellm", "get", "endpointslices", "-l", "kubernetes.io/service-name=litellm", "-o", "json")
	if e != nil {
		return out, e
	}
	pods, e := w.kube(label+"-pods", "-n", "litellm", "get", "pods", "-l", "app=litellm", "-o", "json")
	if e != nil {
		return out, e
	}
	source, e := w.kube(label+"-source", "-n", "litellm", "get", "configmap", "phorvex-litellm-admission-gateway", "-o", "json")
	if e != nil {
		return out, e
	}
	clients, e := w.kube(label+"-clients", "-n", "litellm", "get", "configmap", "phorvex-litellm-live-clients", "-o", "json")
	if e != nil {
		return out, e
	}
	policyCM, e := w.kube(label+"-policy-cm", "-n", "litellm", "get", "configmap", "phorvex-litellm-client-policy", "-o", "json")
	if e != nil {
		return out, e
	}
	policy, e := w.kube(label+"-policy", "-n", "litellm", "get", "phorvexpolicy", w.p.PolicyName, "-o", "json")
	if e != nil {
		return out, e
	}
	out.ClusterUID = availabilityUID(cluster)
	out.NamespaceUID = availabilityUID(ns)
	out.DeploymentUID = availabilityUID(dep)
	out.ServiceUID = availabilityUID(svc)
	out.SourceConfigMapUID = availabilityUID(source)
	out.ClientsConfigMapUID = availabilityUID(clients)
	out.PolicyConfigMapUID = availabilityUID(policyCM)
	out.PolicyConfigMapRV = liteStr(liteMeta(policyCM), "resourceVersion")
	out.PolicyUID = availabilityUID(policy)
	out.PolicyGeneration = liteInt(liteMeta(policy), "generation")
	if out.ClusterUID != w.p.ClusterUID || out.NamespaceUID != w.p.NamespaceUID || out.DeploymentUID != w.p.DeploymentUID ||
		out.ServiceUID != w.p.ServiceUID || out.SourceConfigMapUID != w.p.SourceConfigMapUID ||
		out.ClientsConfigMapUID != w.p.ClientsConfigMapUID || out.PolicyConfigMapUID != w.p.PolicyConfigMapUID ||
		out.PolicyUID != w.p.PolicyUID || out.PolicyGeneration != w.p.PolicyGeneration ||
		liteStr(liteMeta(source), "name") != "phorvex-litellm-admission-gateway" || source["immutable"] != true ||
		liteStr(liteMeta(clients), "name") != "phorvex-litellm-live-clients" || clients["immutable"] != true {
		return out, errors.New("LiteLLM installed source or policy identity drift")
	}
	sourceData := availabilityMap(source["data"])
	clientsData := availabilityMap(clients["data"])
	if len(sourceData) != 1 || liteSHA([]byte(liteStr(sourceData, "gateway.py"))) != w.p.SourceSHA256 ||
		len(clientsData) != 1 || liteSHA([]byte(liteStr(clientsData, "clients.json"))) != w.p.ClientsSHA256 {
		return out, errors.New("LiteLLM immutable source bytes differ")
	}
	var config struct {
		Version        int    `json:"version"`
		AttackerSHA256 string `json:"attackerSHA256"`
		ControlSHA256  string `json:"controlSHA256"`
		ModelAlias     string `json:"modelAlias"`
	}
	if availabilityDecode([]byte(liteStr(clientsData, "clients.json")), &config) != nil || config.Version != 1 ||
		config.AttackerSHA256 != w.p.AttackerSHA256 || config.ControlSHA256 != w.p.ControlSHA256 || config.ModelAlias != w.p.ModelAlias {
		return out, errors.New("LiteLLM owned-client binding differs")
	}
	var state struct {
		Version      int    `json:"version"`
		Active       bool   `json:"active"`
		Revision     int64  `json:"revision"`
		OperationID  string `json:"operationId"`
		ClientSHA256 string `json:"clientSHA256"`
	}
	stateRaw := []byte(liteStr(availabilityMap(policyCM["data"]), "state.json"))
	if availabilityDecode(stateRaw, &state) != nil || state.Version != 1 || state.ClientSHA256 != w.p.AttackerSHA256 ||
		(state.Active && (state.Revision < 1 || state.OperationID == "")) || (!state.Active && (state.Revision != 0 || state.OperationID != "")) {
		return out, errors.New("LiteLLM policy state differs")
	}
	canonical, _ := json.Marshal(map[string]any{"active": state.Active, "clientSHA256": state.ClientSHA256, "operationId": state.OperationID, "revision": state.Revision, "version": state.Version})
	if !bytes.Equal(stateRaw, canonical) {
		return out, errors.New("LiteLLM policy JSON is not canonical")
	}
	out.Active = state.Active
	out.Revision = state.Revision
	out.OperationID = state.OperationID
	ports, _ := availabilityMap(svc["spec"])["ports"].([]any)
	if len(ports) != 1 || liteInt(availabilityMap(ports[0]), "port") != 4000 ||
		liteInt(availabilityMap(ports[0]), "targetPort") != 4001 ||
		liteStr(availabilityMap(ports[0]), "protocol") != "TCP" ||
		liteStr(availabilityMap(availabilityMap(svc["spec"])["selector"]), "app") != "litellm" {
		return out, errors.New("LiteLLM Service gateway route differs")
	}
	items, _ := slices["items"].([]any)
	if len(items) != 1 {
		return out, errors.New("LiteLLM EndpointSlice cardinality differs")
	}
	slicePorts, _ := availabilityMap(items[0])["ports"].([]any)
	if len(slicePorts) != 1 || liteInt(availabilityMap(slicePorts[0]), "port") != 4001 ||
		liteStr(availabilityMap(slicePorts[0]), "protocol") != "TCP" {
		return out, errors.New("LiteLLM EndpointSlice port differs")
	}
	endpoints, _ := availabilityMap(items[0])["endpoints"].([]any)
	if len(endpoints) != 2 {
		return out, errors.New("LiteLLM EndpointSlice ready target count differs")
	}
	podItems, _ := pods["items"].([]any)
	if len(podItems) != 2 {
		return out, errors.New("LiteLLM Pod cardinality differs")
	}
	out.PodIPs = map[string]string{}
	for _, pin := range w.p.Pods {
		var found map[string]any
		for _, raw := range podItems {
			p := availabilityMap(raw)
			if liteStr(liteMeta(p), "name") == pin.Name {
				found = p
			}
		}
		if found == nil || availabilityUID(found) != pin.UID || liteStr(availabilityMap(found["status"]), "phase") != "Running" {
			return out, errors.New("LiteLLM Pod incarnation differs")
		}
		cs, _ := availabilityMap(found["status"])["containerStatuses"].([]any)
		if len(cs) != 2 {
			return out, errors.New("LiteLLM gateway container not ready")
		}
		backend, gateway := "", ""
		for _, c := range cs {
			row := availabilityMap(c)
			if row["ready"] != true {
				return out, errors.New("LiteLLM container not ready")
			}
			switch liteStr(row, "name") {
			case "litellm":
				backend = liteStr(row, "imageID")
			case "litellm-admission-gateway":
				gateway = liteStr(row, "imageID")
			}
		}
		if backend != pin.BackendImageID || gateway != pin.GatewayImageID {
			return out, errors.New("LiteLLM container source differs")
		}
		var gatewaySpecImage string
		containers, _ := availabilityMap(found["spec"])["containers"].([]any)
		for _, c := range containers {
			row := availabilityMap(c)
			if liteStr(row, "name") == "litellm-admission-gateway" {
				gatewaySpecImage = liteStr(row, "image")
			}
		}
		if gatewaySpecImage != w.p.GatewayImage {
			return out, errors.New("LiteLLM reviewed gateway image differs")
		}
		annotations := availabilityMap(liteMeta(found)["annotations"])
		if liteStr(annotations, "phorvex.ai/litellm-gateway-source-sha256") != w.p.SourceSHA256 ||
			liteStr(annotations, "phorvex.ai/litellm-gateway-image") != w.p.GatewayImage ||
			liteStr(annotations, "phorvex.ai/litellm-client-policy-configmap-uid") != w.p.PolicyConfigMapUID ||
			liteStr(annotations, "phorvex.ai/litellm-live-service-uid") != w.p.ServiceUID ||
			liteStr(annotations, "phorvex.ai/litellm-owned-client-sha256") != w.p.AttackerSHA256 {
			return out, errors.New("LiteLLM Pod gateway annotation differs")
		}
		ip := liteStr(availabilityMap(found["status"]), "podIP")
		if ip == "" {
			return out, errors.New("LiteLLM Pod IP missing")
		}
		matching := 0
		for _, epRaw := range endpoints {
			ep := availabilityMap(epRaw)
			ref := availabilityMap(ep["targetRef"])
			cond := availabilityMap(ep["conditions"])
			addr, _ := ep["addresses"].([]any)
			if liteStr(ref, "uid") == pin.UID && liteStr(ref, "name") == pin.Name && cond["ready"] == true && len(addr) == 1 && addr[0] == ip {
				matching++
			}
		}
		if matching != 1 {
			return out, errors.New("LiteLLM Service target binding differs")
		}
		out.PodIPs[pin.UID] = ip
		out.Pods = append(out.Pods, pin)
	}
	return out, nil
}

func liteSameSource(a, b liteLiveSnapshot) bool {
	if a.ClusterUID != b.ClusterUID || a.NamespaceUID != b.NamespaceUID || a.DeploymentUID != b.DeploymentUID || a.ServiceUID != b.ServiceUID ||
		a.SourceConfigMapUID != b.SourceConfigMapUID || a.ClientsConfigMapUID != b.ClientsConfigMapUID ||
		a.PolicyConfigMapUID != b.PolicyConfigMapUID || a.PolicyUID != b.PolicyUID || a.PolicyGeneration != b.PolicyGeneration || len(a.Pods) != len(b.Pods) {
		return false
	}
	for i := range a.Pods {
		if a.Pods[i] != b.Pods[i] || a.PodIPs[a.Pods[i].UID] != b.PodIPs[b.Pods[i].UID] {
			return false
		}
	}
	return true
}

func (w *liteLiveWorker) loadTokens() error {
	read := func(path string, expected string) (string, error) {
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) < 24 || len(raw) > 257 {
			return "", errors.New("owned client token unavailable")
		}
		token := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(token, "sk-") || liteSHA([]byte(token)) != expected {
			return "", errors.New("owned client token digest differs")
		}
		return token, nil
	}
	var err error
	w.attackerToken, err = read("/etc/phorvex-litellm-live/attacker-token", w.p.AttackerSHA256)
	if err != nil {
		return err
	}
	w.controlToken, err = read("/etc/phorvex-litellm-live/control-token", w.p.ControlSHA256)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile("/etc/phorvex-litellm-status/token")
	if err != nil || len(raw) < 32 || len(raw) > 257 {
		return errors.New("status token unavailable")
	}
	w.statusToken = strings.TrimSpace(string(raw))
	return nil
}

func litePrompt(scenario string, index int) string {
	if scenario == "ai2-unbounded-consumption" {
		return "Reply with the single word OK."
	}
	return []string{"Reply with the single word BLUE.", "What is 2 plus 2? Reply with one digit.", "Reply with the single word GREEN.", "What is 3 plus 5? Reply with one digit."}[index]
}

func (w *liteLiveWorker) call(label, token, prompt string) (liteLiveCall, error) {
	var out liteLiveCall
	request, _ := json.Marshal(map[string]any{"model": w.p.ModelAlias, "messages": []map[string]string{{"role": "user", "content": prompt}}, "max_tokens": 16, "temperature": 0, "stream": false})
	if err := w.save(label+"-request.json", request); err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(w.ctx, 40*time.Second)
	defer stop()
	req, err := http.NewRequestWithContext(ctx, "POST", liteLiveServiceURL, bytes.NewReader(request))
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 40 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return out, errors.New("exact LiteLLM Service request unresolved")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return out, errors.New("LiteLLM Service response bound")
	}
	if err = w.save(label+"-response.json", body); err != nil {
		return out, err
	}
	out.Status = response.StatusCode
	out.GatewayPodUID = response.Header.Get("X-Phorvex-Gateway-Pod-UID")
	out.BodySHA256 = liteSHA(body)
	if out.GatewayPodUID != w.p.Pods[0].UID && out.GatewayPodUID != w.p.Pods[1].UID {
		return out, errors.New("LiteLLM response gateway Pod UID differs")
	}
	if response.StatusCode == 429 {
		var denied struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if availabilityDecode(body, &denied) == nil && denied.Error.Code == "PHORVEX_CLIENT_REVOKED" {
			out.Class = "REVOKED"
			return out, nil
		}
		return out, errors.New("LiteLLM 429 denial identity differs")
	}
	if response.StatusCode != 200 {
		return out, errors.New("LiteLLM real completion not accepted")
	}
	var completed struct {
		Object  string `json:"object"`
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			Prompt     int64 `json:"prompt_tokens"`
			Completion int64 `json:"completion_tokens"`
			Total      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if availabilityDecode(body, &completed) != nil || completed.Object != "chat.completion" || completed.ID == "" || completed.Model == "" ||
		len(completed.Choices) != 1 || completed.Choices[0].Message.Role != "assistant" || strings.TrimSpace(completed.Choices[0].Message.Content) == "" ||
		completed.Usage.Prompt < 0 || completed.Usage.Completion <= 0 || completed.Usage.Total != completed.Usage.Prompt+completed.Usage.Completion {
		return out, errors.New("LiteLLM accepted response lacked actual model completion/usage")
	}
	out.Class = "ACCEPTED_MODEL_COMPLETION"
	out.CompletionID = completed.ID
	out.Model = completed.Model
	out.UsageTokens = completed.Usage.Total
	return out, nil
}

func (w *liteLiveWorker) statuses(snapshot liteLiveSnapshot, label string) (map[string]liteLiveStatus, error) {
	out := map[string]liteLiveStatus{}
	for i, pod := range snapshot.Pods {
		ctx, stop := context.WithTimeout(w.ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", "http://"+snapshot.PodIPs[pod.UID]+":4002/v1/admission/state", nil)
		if err != nil {
			stop()
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+w.statusToken)
		response, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
		if err != nil {
			stop()
			return nil, errors.New("LiteLLM exact gateway readback unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		_ = response.Body.Close()
		stop()
		if err != nil || response.StatusCode != 200 || len(body) > 4096 {
			return nil, errors.New("LiteLLM exact gateway status invalid")
		}
		if err = w.save(fmt.Sprintf("%s-status-%d.json", label, i), body); err != nil {
			return nil, err
		}
		var state liteLiveStatus
		if availabilityDecode(body, &state) != nil || !state.Ready || state.Version != 1 || state.PodUID != pod.UID ||
			state.SourceSHA256 != w.p.SourceSHA256 || state.ConfigMapUID != w.p.PolicyConfigMapUID || state.ClientSHA256 != w.p.AttackerSHA256 {
			return nil, errors.New("LiteLLM authenticated gateway identity differs")
		}
		out[pod.UID] = state
	}
	return out, nil
}

func liteCounterSum(states map[string]liteLiveStatus, role string, field string) int64 {
	var n int64
	for _, s := range states {
		var c liteLiveCounters
		if role == "attacker" {
			c = s.Counters.Attacker
		} else {
			c = s.Counters.Control
		}
		switch field {
		case "forwarded":
			n += c.ForwardedRequests
		case "completed":
			n += c.UpstreamCompletions
		case "denied":
			n += c.DeniedRequests
		case "usage":
			n += c.UsageTokens
		}
	}
	return n
}

func liteJournalName(policyUID, clientSHA string) string {
	sum := sha256.Sum256([]byte(policyUID + ":" + clientSHA))
	return "phorvex-litellm-revoke-" + hex.EncodeToString(sum[:12])
}

func (w *liteLiveWorker) execute(probe *liteLLMLiveProbeResult) (err error) {
	if err = w.loadTokens(); err != nil {
		return err
	}
	before, err := w.snapshot("before")
	if err != nil {
		return err
	}
	if before.Active || before.Revision != 0 || before.OperationID != "" {
		return errors.New("LiteLLM client policy already active")
	}
	preStatus, err := w.statuses(before, "before")
	if err != nil {
		return err
	}
	for _, state := range preStatus {
		if state.Active || state.Revision != 0 || state.OperationID != "" {
			return errors.New("LiteLLM gateway pre-state differs")
		}
	}
	count := 2
	if probe.Scenario == "ai2-query-extraction" {
		count = 3
	}
	for i := 0; i < count; i++ {
		call, e := w.call(fmt.Sprintf("before-attacker-%d", i), w.attackerToken, litePrompt(probe.Scenario, i))
		if e != nil {
			return e
		}
		if call.Class != "ACCEPTED_MODEL_COMPLETION" {
			return errors.New("LiteLLM original attacker work not accepted")
		}
		probe.InitialUsageTokens += call.UsageTokens
	}
	control, err := w.call("before-control", w.controlToken, "Reply with the single word OK.")
	if err != nil || control.Class != "ACCEPTED_MODEL_COMPLETION" {
		return errors.New("LiteLLM original benign control unavailable")
	}
	postBaseline, err := w.snapshot("post-baseline")
	if err != nil || !liteSameSource(before, postBaseline) || postBaseline.Active || postBaseline.Revision != 0 || postBaseline.PolicyConfigMapRV != before.PolicyConfigMapRV {
		return errors.New("LiteLLM original source/policy drift")
	}
	baselineStates, err := w.statuses(postBaseline, "post-baseline")
	if err != nil {
		return err
	}
	if liteCounterSum(baselineStates, "attacker", "completed")-liteCounterSum(preStatus, "attacker", "completed") != int64(count) ||
		liteCounterSum(baselineStates, "attacker", "usage")-liteCounterSum(preStatus, "attacker", "usage") != probe.InitialUsageTokens ||
		liteCounterSum(baselineStates, "control", "completed")-liteCounterSum(preStatus, "control", "completed") != 1 {
		return errors.New("LiteLLM original upstream counter/usage receipt differs")
	}
	probe.InitialAcceptedWork = true
	probe.Status = "LANDED_UNPROTECTED"
	return w.afterOriginal(probe, before, baselineStates)
}

func (w *liteLiveWorker) afterOriginal(probe *liteLLMLiveProbeResult, before liteLiveSnapshot, baselineStates map[string]liteLiveStatus) (err error) {
	preEvent, err := w.snapshot("pre-event")
	if err != nil || !liteSameSource(before, preEvent) || preEvent.Active || preEvent.Revision != 0 ||
		preEvent.PolicyConfigMapRV != before.PolicyConfigMapRV {
		return errors.New("LiteLLM immediate pre-event policy/source differs")
	}
	var auditProfile guardrailAvailabilityProfile
	auditProfile.Fixture.PodName = w.p.Pods[0].Name
	auditProfile.Fixture.PodUID = w.p.Pods[0].UID
	auditProfile.Fixture.PolicyUID = w.p.PolicyUID
	auditProfile.Fixture.ClusterUID = w.p.ClusterUID
	audit := &availabilityWorker{rm: &RunManager{cfg: w.s.cfg}, ctx: w.ctx, out: w.out,
		p: auditProfile, deadline: time.Now().Add(600 * time.Second), auditNamespace: "litellm",
		before: availabilitySnapshot{TargetPodUID: w.p.Pods[0].UID, PolicyUID: w.p.PolicyUID, ClusterUID: w.p.ClusterUID},
		t:      availabilityTerminal{Schema: "litellm-live-audit-v1", RunID: filepath.Base(w.out)}}
	w.audit = audit
	auditStart, err := audit.auditStart()
	if err != nil {
		return err
	}
	created, err := w.createEvent(probe.Scenario, time.Now().UTC())
	if err != nil {
		return err
	}
	probe.SignalMode = "TEST_INJECTED"
	probe.EventUID = created.UID
	defer func() {
		if e := w.deleteEvent(created); e != nil && err == nil {
			err = e
		}
	}()
	receipt, err := w.pollJournal(created)
	if err != nil {
		return err
	}
	after, err := w.snapshot("post-action")
	if err != nil || !liteSameSource(before, after) || !after.Active || after.Revision != 1 ||
		after.OperationID != liteStr(receipt, "operationId") {
		return errors.New("LiteLLM post-action policy state differs")
	}
	statuses, err := w.statuses(after, "post-action")
	if err != nil {
		return err
	}
	for _, state := range statuses {
		if !state.Active || state.Revision != 1 || state.OperationID != after.OperationID {
			return errors.New("LiteLLM both gateways did not activate exact operation")
		}
	}
	probe.TerminalJournal = true
	probe.BothGatewaysActive = true
	// Replay the exact next attacker query only after both routes show the
	// selected operation. A 429 alone is insufficient: neither gateway may
	// forward additional attacker work to the actual LiteLLM process.
	replayIndex := 0
	if probe.Scenario == "ai2-query-extraction" {
		replayIndex = 3
	}
	replay, err := w.call("after-attacker-replay", w.attackerToken, litePrompt(probe.Scenario, replayIndex))
	if err != nil || replay.Class != "REVOKED" {
		probe.Status = "ATTACK_CONTINUES"
		return errors.New("LiteLLM equivalent attacker replay was not revoked")
	}
	control, err := w.call("after-control", w.controlToken, "Reply with the single word OK.")
	if err != nil || control.Class != "ACCEPTED_MODEL_COMPLETION" {
		probe.Status = "BENIGN_REGRESSION"
		return errors.New("LiteLLM ordinary authorized completion regressed")
	}
	final, err := w.snapshot("post-replay")
	if err != nil || !liteSameSource(before, final) || !final.Active || final.Revision != 1 || final.OperationID != after.OperationID {
		return errors.New("LiteLLM final source/policy state differs")
	}
	finalStatuses, err := w.statuses(final, "post-replay")
	if err != nil {
		return err
	}
	if liteCounterSum(finalStatuses, "attacker", "forwarded") != liteCounterSum(baselineStates, "attacker", "forwarded") ||
		liteCounterSum(finalStatuses, "attacker", "completed") != liteCounterSum(baselineStates, "attacker", "completed") ||
		liteCounterSum(finalStatuses, "attacker", "denied") != liteCounterSum(baselineStates, "attacker", "denied")+1 ||
		liteCounterSum(finalStatuses, "control", "completed") != liteCounterSum(baselineStates, "control", "completed")+1 {
		return errors.New("LiteLLM attacker replay or benign upstream counters differ")
	}
	probe.ReplayBlockedBeforeUpstream = true
	probe.BenignContinuity = true
	terminal, err := audit.auditClose(auditStart, created)
	if err != nil || !terminal.CoverageComplete || terminal.Status != "COMPLETE" || terminal.UnboundTargetRows == nil || *terminal.UnboundTargetRows != 0 {
		return errors.New("authenticated LiteLLM decision audit incomplete")
	}
	if err = w.saveJSON("audit-terminal.json", terminal); err != nil {
		return err
	}
	selected := 0
	for _, decision := range terminal.TargetRows {
		if decision.EventCoverage != "EXACT_TRUSTED_EVENT_OBSERVED" || !decision.Selected || decision.Action != "litellm-client-revoke" {
			continue
		}
		if decision.DecisionID != liteStr(receipt, "selectionDecisionId") || decision.TickID != liteStr(receipt, "tickId") ||
			decision.AssetUID != created.TargetPodUID || decision.PolicyUID != w.p.PolicyUID || decision.ExactEventUID != created.UID ||
			decision.ExactEventCreator != w.p.EventCreator {
			return errors.New("LiteLLM selected decision and protected journal differ")
		}
		selected++
		probe.SelectedAction = decision.Action
		probe.SelectionDecisionID = decision.DecisionID
		if decision.Actuated {
			probe.DispatchPath = "SELECTED_ACTUATED"
		} else if decision.DispatchOutcome == "dispatch-error" || decision.TopLevelDispatchOutcome == "dispatch-error" {
			probe.DispatchPath = "TERMINAL_CONFIRMED_AFTER_DISPATCH_ERROR"
		} else {
			return errors.New("LiteLLM selected action lacks demonstrated dispatch path")
		}
	}
	if selected != 1 {
		return errors.New("LiteLLM exact event did not produce one selected native revoke")
	}
	if liteStr(receipt, "operationId") != probe.SelectionDecisionID || liteStr(receipt, "selectionDecisionId") != probe.SelectionDecisionID {
		return errors.New("LiteLLM native operation and selected decision differ")
	}
	probe.Status = "STOPPED_WITH_BENIGN_CONTINUITY"
	return nil
}

func (w *liteLiveWorker) createEvent(objective string, observedAt time.Time) (*availabilityEvent, error) {
	correlation := fmt.Sprintf("%x-%x", observedAt.UnixNano(), liteLiveSequence.Add(1))
	name := "redteam-litellm-client-" + correlation
	observation := map[string]any{
		"version": 1, "clientSHA256": w.p.AttackerSHA256,
		"configMapUID": w.p.PolicyConfigMapUID, "serviceUID": w.p.ServiceUID,
		"targetPodUID": w.p.Pods[0].UID, "peerPodUID": w.p.Pods[1].UID,
		"requestPath": "/v1/chat/completions", "objective": objective,
		"policyName": w.p.PolicyName, "policyUID": w.p.PolicyUID,
		"policyGeneration": w.p.PolicyGeneration, "observedAt": observedAt.Format(time.RFC3339Nano),
	}
	note, _ := json.Marshal(observation)
	object := map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name,
			"labels":      map[string]string{"phorvex.ai/redteam": "true", "phorvex.ai/test-injected": "true", "phorvex.ai/attack-correlation": correlation},
			"annotations": map[string]string{"phorvex.ai/console-target-pod-uid": w.p.Pods[0].UID, liteLiveAnnotation: string(note)}},
		"spec": map[string]any{"description": "TEST_INJECTED after actual scoped LiteLLM client work",
			"targets":      []string{"litellm/" + w.p.Pods[0].Name},
			"rule":         map[string]string{"type": liteLiveRule, "threatLevel": "critical", "source": "redteam"},
			"anomalyScore": "0.95"},
	}
	manifest, _ := json.Marshal(object)
	if err := w.save("event-intent.json", manifest); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(w.out, "litellm-event-*.json")
	if err != nil {
		return nil, errors.New("LiteLLM private event manifest unavailable")
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(manifest)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, errors.New("LiteLLM event manifest persistence unavailable")
	}
	createdRaw, err := w.s.cfg.execText(15*time.Second, "kubectl", "create", "-f", file.Name(), "-o", "json")
	if err != nil || len(createdRaw) > 64<<10 {
		return nil, errors.New("LiteLLM one event create unresolved; reconcile exact candidate")
	}
	if err = w.save("event-create-reply.json", []byte(createdRaw)); err != nil {
		return nil, err
	}
	var created map[string]any
	if availabilityDecode([]byte(createdRaw), &created) != nil || availabilityUID(created) == "" ||
		liteStr(liteMeta(created), "name") != name ||
		liteStr(availabilityMap(liteMeta(created)["annotations"]), "phorvex.ai/creator-identity") != w.p.EventCreator ||
		liteStr(availabilityMap(liteMeta(created)["annotations"]), liteLiveAnnotation) != string(note) {
		return nil, errors.New("LiteLLM event admission provenance differs")
	}
	return &availabilityEvent{UID: availabilityUID(created), Name: name,
		ResourceVersion: liteStr(liteMeta(created), "resourceVersion"), CreatorIdentity: w.p.EventCreator,
		Correlation: correlation, TargetPodUID: w.p.Pods[0].UID, RuleType: liteLiveRule, Source: "redteam"}, nil
}

func (w *liteLiveWorker) pollJournal(event *availabilityEvent) (map[string]any, error) {
	name := liteJournalName(w.p.PolicyUID, w.p.AttackerSHA256)
	deadline := time.Now().Add(180 * time.Second)
	for i := 0; i < 36 && time.Now().Before(deadline); i++ {
		row, err := w.kube(fmt.Sprintf("journal-%02d", i), "-n", "phorvex-system", "get", "configmap", name, "-o", "json")
		if err == nil {
			var receipt map[string]any
			if availabilityDecode([]byte(liteStr(availabilityMap(row["data"]), "receipt")), &receipt) == nil &&
				liteStr(receipt, "phase") == "terminal-full" {
				if liteInt(receipt, "version") != 1 || liteStr(receipt, "eventName") != event.Name ||
					liteStr(receipt, "eventUID") != event.UID || liteStr(receipt, "targetUID") != event.TargetPodUID ||
					liteStr(receipt, "peerUID") != w.p.Pods[1].UID || liteStr(receipt, "policyName") != w.p.PolicyName ||
					liteStr(receipt, "policyUID") != w.p.PolicyUID || liteInt(receipt, "policyGeneration") != w.p.PolicyGeneration ||
					liteStr(receipt, "clientSHA256") != w.p.AttackerSHA256 || liteStr(receipt, "configMapUID") != w.p.PolicyConfigMapUID ||
					liteStr(receipt, "serviceUID") != w.p.ServiceUID || liteStr(receipt, "sourceSHA256") != w.p.SourceSHA256 ||
					liteStr(receipt, "tickId") == "" || liteStr(receipt, "selectionDecisionId") == "" ||
					liteStr(receipt, "operationId") != liteStr(receipt, "selectionDecisionId") {
					return nil, errors.New("LiteLLM protected terminal journal identity differs")
				}
				if err = w.saveJSON("journal-terminal.json", row); err != nil {
					return nil, err
				}
				return receipt, nil
			}
		}
		select {
		case <-w.ctx.Done():
			return nil, errors.New("LiteLLM journal observation deadline exhausted")
		case <-time.After(5 * time.Second):
		}
	}
	return nil, errors.New("LiteLLM protected terminal journal not observed")
}

func (w *liteLiveWorker) deleteEvent(event *availabilityEvent) error {
	if event == nil || event.UID == "" || event.Name == "" {
		return errors.New("LiteLLM exact event cleanup identity absent")
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("LiteLLM cleanup in-cluster authority unavailable")
	}
	client, err := dynamic.NewForConfig(rc)
	if err != nil {
		return errors.New("LiteLLM cleanup client unavailable")
	}
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	uid := types.UID(event.UID)
	if err = client.Resource(securityEventGVR).Delete(ctx, event.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil {
		return errors.New("LiteLLM exact event cleanup unresolved")
	}
	_, err = client.Resource(securityEventGVR).Get(ctx, event.Name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		return errors.New("LiteLLM exact event absence not confirmed")
	}
	return w.saveJSON("event-cleanup.json", map[string]string{"name": event.Name, "uid": event.UID, "status": "ABSENT"})
}
