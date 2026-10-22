package console

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
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

	"github.com/phorvex/phorvex/internal/litellmclient"

	"github.com/phorvex/phorvex/internal/eventtrust"
	corev1 "k8s.io/api/core/v1"
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
var liteLiveBusy atomic.Bool

type liteLivePod struct {
	Name           string `json:"name"`
	UID            string `json:"uid"`
	BackendImageID string `json:"backendImageID"`
	GatewayImageID string `json:"gatewayImageID"`
}

type liteLiveEntry struct {
	Active       bool   `json:"active"`
	ClientSHA256 string `json:"clientSHA256"`
	OperationID  string `json:"operationId"`
}

type liteLLMLiveProfile struct {
	Version             int    `json:"version"`
	SourceSHA256        string `json:"sourceSHA256"`
	GatewayImage        string `json:"gatewayImage"`
	ClientsSHA256       string `json:"clientsSHA256"`
	SeedSHA256          string `json:"seedSHA256"`
	PolicyName          string `json:"policyName"`
	ModelAlias          string `json:"modelAlias"`
	EventCreator        string `json:"eventCreator"`
	AuditSourceIdentity string `json:"auditSourceIdentity"`
	MaxRunSeconds       int    `json:"maxRunSeconds"`
}

type liteLiveCounters struct {
	ForwardedRequests   int64 `json:"forwardedRequests"`
	UpstreamCompletions int64 `json:"upstreamCompletions"`
	DeniedRequests      int64 `json:"deniedRequests"`
	UsageTokens         int64 `json:"usageTokens"`
}

type liteLiveStatus struct {
	Version      int              `json:"version"`
	PodUID       string           `json:"podUID"`
	SourceSHA256 string           `json:"sourceSHA256"`
	SeedSHA256   string           `json:"seedSHA256"`
	ConfigMapUID string           `json:"configMapUID"`
	ClientSHA256 string           `json:"clientSHA256"`
	Active       bool             `json:"active"`
	Revision     int64            `json:"revision"`
	OperationID  string           `json:"operationId"`
	Role         string           `json:"role"`
	Ready        bool             `json:"ready"`
	Counters     liteLiveCounters `json:"counters"`
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
	EntryCount          int64             `json:"entryCount"`
	Active              bool              `json:"active"`
	Revision            int64             `json:"revision"`
	OperationID         string            `json:"operationId"`
	Entries             []liteLiveEntry   `json:"entries"`
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
	BackendBypassRejected       bool     `json:"backendBypassRejected"`
	DefenseScope                string   `json:"defenseScope"`
	Issues                      []string `json:"issues"`
}

type liteLiveWorker struct {
	s             *Server
	record        *attackRecord
	p             liteLLMLiveProfile
	profileSHA    string
	ctx           context.Context
	stop          context.CancelFunc
	out           string
	reads         int
	readLimit     int
	attackerToken string
	controlToken  string
	attackerSHA   string
	controlSHA    string
	bound         liteLiveSnapshot
	priorReceipts map[string]string
	statusToken   string
	audit         *availabilityWorker
}

func liteSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func parseLiteLiveProfile(raw []byte) (liteLLMLiveProfile, error) {
	var p liteLLMLiveProfile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 16<<10 || dec.Decode(&p) != nil || dec.Decode(new(any)) != io.EOF ||
		p.Version != 2 || !litellmclient.ApprovedRuntime(p.SourceSHA256, p.GatewayImage) ||
		!staticSHA256.MatchString(p.ClientsSHA256) || !staticSHA256.MatchString(p.SeedSHA256) ||
		p.PolicyName != "litellm-defense" || p.ModelAlias != "gpt-4o-mini" ||
		p.EventCreator != eventtrust.Injector() ||
		p.AuditSourceIdentity == "" || p.MaxRunSeconds != 900 {
		return p, errors.New("reviewed LiteLLM Live profile invalid")
	}
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
	if !liteLiveBusy.CompareAndSwap(false, true) {
		writeJSON(w, 409, map[string]string{"error": "a LiteLLM Live run is already active"})
		return
	}
	if err = s.persistEffectIntent("/api/litellm/live/fire", actorOf(r), "litellm", input.Scenario); err != nil {
		liteLiveBusy.Store(false)
		writeJSON(w, 503, map[string]string{"error": "LiteLLM Live intent persistence unavailable"})
		return
	}
	started := s.cfg.now().UTC()
	id := "atk-" + strconv.FormatInt(started.UnixNano(), 36) + strconv.FormatUint(liteLiveSequence.Add(1), 36)
	probe := &liteLLMLiveProbeResult{Status: "UNKNOWN", Scenario: input.Scenario, SignalMode: "NONE",
		DefenseScope: "owned trial credential on the LiteLLM Service route", Issues: []string{}}
	record := &attackRecord{ID: id, FiredAt: started.Format(time.RFC3339Nano), Service: "litellm", Namespace: "litellm",
		Attack: input.Scenario, AttackID: input.Scenario, MITRE: "query-channel", Expected: "litellm-client-revoke",
		EvidenceKind: "litellm-live-client-policy", OutcomeClass: "litellm-live-UNKNOWN", Status: "running", LiteLLMLiveProbe: probe,
		ProducerRoute: liteLiveServiceURL, ResultSchema: "litellm-live-v1",
		ObservationStart: started.Format(time.RFC3339Nano), ObservationEnd: started.Add(900 * time.Second).Format(time.RFC3339Nano), started: started, accepted: started}
	publishAttack(record)
	go s.runLiteLive(record, p, raw)
	writeJSON(w, 200, map[string]any{"ok": true, "attackId": id, "scenario": input.Scenario, "status": "running",
		"message": "Real LiteLLM Service calls are measuring. A test signal is injected only after independently accepted original work and benign control. Final defense is scoped to the owned trial credential on the Service route and requires selected native policy activation, both gateway readbacks, stopped replay, and benign continuity."})
}

func (s *Server) runLiteLive(r *attackRecord, p liteLLMLiveProfile, raw []byte) {
	defer liteLiveBusy.Store(false)
	out := s.cfg.statePath(filepath.Join("litellm-live", r.ID))
	probe := r.LiteLLMLiveProbe
	ctx, stop := context.WithTimeout(context.Background(), time.Duration(p.MaxRunSeconds)*time.Second)
	w := &liteLiveWorker{s: s, record: r, p: p, profileSHA: s.cfg.LiteLLMLiveProfileSHA256, ctx: ctx, stop: stop, out: out}
	defer stop()
	finish := func(err error) {
		liteFinalizeProbe(r, probe, w.bound, err,
			func(raw []byte) error {
				if out == "" {
					return errors.New("private LiteLLM Live receipt path unavailable")
				}
				return publishMongoAuditFile(out, "terminal.json", raw, 1<<20)
			}, s.persistAttack, publishAttack)
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
	// Bind the live-probe attack to its brain decision's objective math + economics while the
	// audit window is still fresh. No-op unless the run recorded a selected decision id.
	s.attachLiveProbeDecision("", r)
	finish(err)
}

// The private receipt records evidence only; its accepted flag is always false.
// Defense credit is carried only by the durable attack record after this
// receipt succeeds. A failed record write therefore leaves no private success
// claim to roll back or accidentally preserve.
func liteFinalizeProbe(r *attackRecord, probe *liteLLMLiveProbeResult, bound liteLiveSnapshot,
	runErr error, writeTerminal func([]byte) error, persist func(*attackRecord) error,
	publish func(*attackRecord)) {
	if runErr != nil {
		probe.Issues = append(probe.Issues, runErr.Error())
		if probe.Status == "STOPPED_WITH_BENIGN_CONTINUITY" {
			probe.Status = "INCONCLUSIVE_AFTER_LANDED"
		}
	}
	if probe.Status == "UNKNOWN" && probe.InitialAcceptedWork {
		probe.Status = "INCONCLUSIVE_AFTER_LANDED"
	}
	probe.Accepted = probe.Status == "STOPPED_WITH_BENIGN_CONTINUITY"
	write := func() error {
		candidate := *probe
		candidate.Accepted = false
		raw, err := json.Marshal(map[string]any{"kind": "litellm-live-evidence-v1",
			"probe": candidate, "verdictRequiresAttackRecord": true})
		if err != nil {
			return err
		}
		return writeTerminal(raw)
	}
	if err := write(); err != nil {
		probe.Accepted = false
		probe.Status = "INCONCLUSIVE_TERMINAL_PERSISTENCE"
		probe.Issues = append(probe.Issues, "private LiteLLM Live terminal receipt unavailable")
	}
	apply := func() {
		r.OutcomeClass = "litellm-live-" + probe.Status
		r.Status = "partial"
		r.Outcome, r.Action, r.Containment, r.DefendedPod = "", "", "", ""
		r.Actuated = false
		if probe.Accepted {
			r.Status = "done"
			r.Outcome = "DEFENDED"
			r.Action = "litellm-client-revoke"
			r.Actuated = true
			if len(bound.Pods) == 2 {
				r.DefendedPod = bound.Pods[0].Name
			}
			r.Containment = "client-revoked"
		}
	}
	apply()
	if err := persist(r); err != nil {
		probe.Accepted = false
		probe.Status = "INCONCLUSIVE_PERSISTENCE_ERROR"
		probe.Issues = append(probe.Issues, "LiteLLM Live outcome persistence unavailable")
		r.PersistenceError = "LiteLLM Live outcome persistence unavailable"
		apply()
	}
	publish(r)
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
	limit := w.readLimit
	if limit == 0 {
		limit = 110
	}
	if w.reads >= limit {
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
	if !litellmclient.ApprovedRuntime(w.p.SourceSHA256, w.p.GatewayImage) {
		return out, errors.New("LiteLLM reviewed source digest invalid")
	}
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
	sourceName := ""
	template := availabilityMap(availabilityMap(dep["spec"])["template"])
	annotations := availabilityMap(liteMeta(template)["annotations"])
	if liteStr(annotations, "phorvex.ai/litellm-gateway-source-sha256") != w.p.SourceSHA256 {
		return out, errors.New("LiteLLM Deployment source annotation differs")
	}
	volumes, _ := availabilityMap(template["spec"])["volumes"].([]any)
	for _, raw := range volumes {
		volume := availabilityMap(raw)
		if liteStr(volume, "name") == "litellm-live-gateway-source" {
			sourceName = liteStr(availabilityMap(volume["configMap"]), "name")
		}
	}
	if sourceName != litellmclient.ApprovedSourceConfigMap(w.p.SourceSHA256) {
		return out, errors.New("LiteLLM Deployment immutable source name differs")
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
	source, e := w.kube(label+"-source", "-n", "litellm", "get", "configmap", sourceName, "-o", "json")
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
	if out.ClusterUID == "" || out.NamespaceUID == "" || out.DeploymentUID == "" || out.ServiceUID == "" ||
		out.SourceConfigMapUID == "" || out.ClientsConfigMapUID == "" || out.PolicyConfigMapUID == "" ||
		out.PolicyUID == "" || out.PolicyGeneration < 1 ||
		liteStr(liteMeta(source), "name") != sourceName || source["immutable"] != true ||
		liteStr(liteMeta(clients), "name") != "phorvex-litellm-live-clients" || clients["immutable"] != true ||
		liteStr(liteMeta(policy), "name") != w.p.PolicyName {
		return out, errors.New("LiteLLM installed source or policy identity drift")
	}
	policySpec := availabilityMap(policy["spec"])
	selector := availabilityMap(availabilityMap(policySpec["selector"])["matchLabels"])
	triggers := availabilityMap(policySpec["triggers"])
	if liteStr(selector, "r6th.io/rotation-target") != "true" || len(selector) != 1 ||
		liteStr(policySpec, "mode") != "active" || triggers["reactiveOnly"] != true || triggers["eventDriven"] != true {
		return out, errors.New("LiteLLM dedicated policy scope differs")
	}
	enabled, _ := availabilityMap(policySpec["actions"])["enabled"].([]any)
	allowed := false
	for _, action := range enabled {
		if action == "litellm-client-revoke" {
			allowed = true
		}
	}
	if len(enabled) < 2 || !allowed {
		return out, errors.New("LiteLLM ordinary action alternatives unavailable")
	}
	sourceData := availabilityMap(source["data"])
	clientsData := availabilityMap(clients["data"])
	if len(sourceData) != 1 || liteSHA([]byte(liteStr(sourceData, "gateway.py"))) != w.p.SourceSHA256 ||
		len(clientsData) != 1 || liteSHA([]byte(liteStr(clientsData, "clients.json"))) != w.p.ClientsSHA256 {
		return out, errors.New("LiteLLM immutable source bytes differ")
	}
	var config struct {
		Version    int    `json:"version"`
		SeedSHA256 string `json:"seedSHA256"`
		ModelAlias string `json:"modelAlias"`
	}
	if availabilityDecode([]byte(liteStr(clientsData, "clients.json")), &config) != nil || config.Version != 2 ||
		config.SeedSHA256 != w.p.SeedSHA256 || config.ModelAlias != w.p.ModelAlias {
		return out, errors.New("LiteLLM owned-client binding differs")
	}
	var state struct {
		Version  int             `json:"version"`
		Revision int64           `json:"revision"`
		Entries  []liteLiveEntry `json:"entries"`
	}
	stateRaw := []byte(liteStr(availabilityMap(policyCM["data"]), "state.json"))
	if availabilityDecode(stateRaw, &state) != nil || state.Version != 2 || state.Revision != int64(len(state.Entries)) ||
		state.Revision < 0 || state.Revision > 256 {
		return out, errors.New("LiteLLM policy state differs")
	}
	previous := ""
	for _, entry := range state.Entries {
		if !entry.Active || !staticSHA256.MatchString(entry.ClientSHA256) || entry.ClientSHA256 <= previous || entry.OperationID == "" {
			return out, errors.New("LiteLLM policy historical entry invalid")
		}
		previous = entry.ClientSHA256
		if entry.ClientSHA256 == w.attackerSHA {
			out.Active, out.OperationID = true, entry.OperationID
		}
	}
	canonical, _ := json.Marshal(map[string]any{"entries": state.Entries, "revision": state.Revision, "version": state.Version})
	if !bytes.Equal(stateRaw, canonical) {
		return out, errors.New("LiteLLM policy JSON is not canonical")
	}
	out.Revision = state.Revision
	out.EntryCount = state.Revision
	out.Entries = state.Entries
	ports, _ := availabilityMap(svc["spec"])["ports"].([]any)
	if len(ports) != 1 || liteInt(availabilityMap(ports[0]), "port") != 4000 ||
		liteInt(availabilityMap(ports[0]), "targetPort") != 4001 ||
		liteStr(availabilityMap(ports[0]), "protocol") != "TCP" ||
		liteStr(availabilityMap(availabilityMap(svc["spec"])["selector"]), "app") != "litellm" {
		return out, errors.New("LiteLLM Service gateway route differs")
	}
	items, _ := slices["items"].([]any)
	if len(items) == 0 || len(items) > 8 {
		return out, errors.New("LiteLLM EndpointSlice inventory differs")
	}
	podItems, _ := pods["items"].([]any)
	if len(podItems) != 2 {
		return out, errors.New("LiteLLM Pod cardinality differs")
	}
	out.PodIPs = map[string]string{}
	for _, raw := range podItems {
		found := availabilityMap(raw)
		pin := liteLivePod{Name: liteStr(liteMeta(found), "name"), UID: availabilityUID(found)}
		if pin.Name == "" || pin.UID == "" || liteStr(availabilityMap(found["status"]), "phase") != "Running" ||
			liteStr(availabilityMap(liteMeta(found)["labels"]), "r6th.io/rotation-target") != "true" {
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
		if !mongoPinnedImage.MatchString(backend) || !mongoPinnedImage.MatchString(gateway) ||
			!strings.HasSuffix(gateway, w.p.GatewayImage[strings.LastIndex(w.p.GatewayImage, "@sha256:"):]) {
			return out, errors.New("LiteLLM container source differs")
		}
		pin.BackendImageID, pin.GatewayImageID = backend, gateway
		var sourcePod corev1.Pod
		podRaw, marshalErr := json.Marshal(found)
		if marshalErr != nil || json.Unmarshal(podRaw, &sourcePod) != nil ||
			litellmclient.ValidateGatewaySourceBinding(&sourcePod, w.p.SourceSHA256, w.p.GatewayImage) != nil {
			return out, errors.New("LiteLLM reviewed Pod gateway source binding differs")
		}

		annotations := availabilityMap(liteMeta(found)["annotations"])
		if liteStr(annotations, "phorvex.ai/litellm-gateway-source-sha256") != w.p.SourceSHA256 ||
			liteStr(annotations, "phorvex.ai/litellm-gateway-image") != w.p.GatewayImage ||
			liteStr(annotations, "phorvex.ai/litellm-client-policy-configmap-uid") != out.PolicyConfigMapUID ||
			liteStr(annotations, "phorvex.ai/litellm-live-service-uid") != out.ServiceUID ||
			liteStr(annotations, "phorvex.ai/litellm-trial-seed-sha256") != w.p.SeedSHA256 {
			return out, errors.New("LiteLLM Pod gateway annotation differs")
		}
		ip := liteStr(availabilityMap(found["status"]), "podIP")
		if ip == "" {
			return out, errors.New("LiteLLM Pod IP missing")
		}
		out.PodIPs[pin.UID] = ip
		out.Pods = append(out.Pods, pin)
	}
	sort.Slice(out.Pods, func(i, j int) bool { return out.Pods[i].Name < out.Pods[j].Name })
	if out.Pods[0].UID == out.Pods[1].UID || out.Pods[0].Name == out.Pods[1].Name {
		return out, errors.New("LiteLLM Pod identities ambiguous")
	}
	if err := liteReadyEndpointBindings(items, out.Pods, out.PodIPs); err != nil {
		return out, err
	}
	return out, nil
}

func liteReadyEndpointBindings(items []any, pods []liteLivePod, ips map[string]string) error {
	wanted := make(map[string]liteLivePod, len(pods))
	for _, pod := range pods {
		wanted[pod.UID] = pod
	}
	seen := map[string]bool{}
	for _, raw := range items {
		slice := availabilityMap(raw)
		ports, _ := slice["ports"].([]any)
		if len(ports) != 1 || liteInt(availabilityMap(ports[0]), "port") != 4001 ||
			liteStr(availabilityMap(ports[0]), "protocol") != "TCP" {
			return errors.New("LiteLLM EndpointSlice port differs")
		}
		endpoints, _ := slice["endpoints"].([]any)
		for _, item := range endpoints {
			ep := availabilityMap(item)
			if availabilityMap(ep["conditions"])["ready"] != true {
				continue
			}
			ref := availabilityMap(ep["targetRef"])
			uid := liteStr(ref, "uid")
			pod, ok := wanted[uid]
			addresses, _ := ep["addresses"].([]any)
			if !ok || seen[uid] || liteStr(ref, "kind") != "Pod" ||
				liteStr(ref, "name") != pod.Name || len(addresses) != 1 || addresses[0] != ips[uid] {
				return errors.New("LiteLLM Service ready target binding differs")
			}
			seen[uid] = true
		}
	}
	if len(seen) != len(wanted) {
		return errors.New("LiteLLM Service ready target count differs")
	}
	return nil
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

func litePriorEntriesPreserved(before, after liteLiveSnapshot) bool {
	if len(after.Entries) < len(before.Entries) {
		return false
	}
	entries := make(map[string]liteLiveEntry, len(after.Entries))
	for _, entry := range after.Entries {
		entries[entry.ClientSHA256] = entry
	}
	for _, entry := range before.Entries {
		if entries[entry.ClientSHA256] != entry {
			return false
		}
	}
	return true
}

func (w *liteLiveWorker) loadTokens() error {
	seed, err := os.ReadFile("/etc/phorvex-litellm-live/seed")
	if err != nil || len(seed) < 32 || len(seed) > 64 || liteSHA(seed) != w.p.SeedSHA256 {
		return errors.New("reviewed LiteLLM trial seed unavailable")
	}
	nonceBytes := make([]byte, 16)
	if _, err = rand.Read(nonceBytes); err != nil {
		return errors.New("fresh LiteLLM run nonce unavailable")
	}
	nonce := hex.EncodeToString(nonceBytes)
	derive := func(role string) string {
		mac := hmac.New(sha256.New, seed)
		_, _ = mac.Write([]byte("phorvex-litellm-live-v2:" + nonce + ":" + role))
		return "sk-phx2-" + role + "-" + nonce + "-" + hex.EncodeToString(mac.Sum(nil))
	}
	w.attackerToken, w.controlToken = derive("a"), derive("c")
	w.attackerSHA, w.controlSHA = liteSHA([]byte(w.attackerToken)), liteSHA([]byte(w.controlToken))
	raw, err := os.ReadFile("/etc/phorvex-litellm-status/token")
	if err != nil || len(raw) < 32 || len(raw) > 257 {
		return errors.New("status token unavailable")
	}
	w.statusToken = strings.TrimSpace(string(raw))
	return nil
}

// The installed vLLM prompt-injection guardrail (ProtectAI DeBERTa v2, threshold 0.5) scores
// "Reply with the single word OK." and "...BLUE." as injections (0.78) and refuses them, so a run
// never obtained its first accepted completion. Every prompt below was checked to pass it.
const liteBenignControlPrompt = "What is 4 plus 5? Reply with one digit."

func litePrompt(scenario string, index int) string {
	if scenario == "ai2-unbounded-consumption" {
		return "What is 1 plus 1? Reply with one digit."
	}
	return []string{"What is 6 minus 1? Reply with one digit.", "What is 2 plus 2? Reply with one digit.", "Reply with the single word GREEN.", "What is 3 plus 5? Reply with one digit."}[index]
}

func liteHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
			MaxResponseHeaderBytes: 8192},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
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
	response, err := liteHTTPClient(40 * time.Second).Do(req)
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
	if len(w.bound.Pods) != 2 || (out.GatewayPodUID != w.bound.Pods[0].UID && out.GatewayPodUID != w.bound.Pods[1].UID) {
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

func (w *liteLiveWorker) statuses(snapshot liteLiveSnapshot, label, clientSHA, role string) (map[string]liteLiveStatus, error) {
	out := map[string]liteLiveStatus{}
	for i, pod := range snapshot.Pods {
		ctx, stop := context.WithTimeout(w.ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", "http://"+snapshot.PodIPs[pod.UID]+":4002/v1/admission/state?clientSHA256="+clientSHA, nil)
		if err != nil {
			stop()
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+w.statusToken)
		response, err := liteHTTPClient(8 * time.Second).Do(req)
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
		if availabilityDecode(body, &state) != nil || !state.Ready || state.Version != 2 || state.PodUID != pod.UID ||
			state.SourceSHA256 != w.p.SourceSHA256 || state.SeedSHA256 != w.p.SeedSHA256 ||
			state.ConfigMapUID != snapshot.PolicyConfigMapUID || state.ClientSHA256 != clientSHA ||
			(role != "" && state.Role != role) {
			return nil, errors.New("LiteLLM authenticated gateway identity differs")
		}
		out[pod.UID] = state
	}
	return out, nil
}

// The owned token is a gateway credential, not a LiteLLM backend master key.
// Check the exact backend PodIPs directly so the defended result never implies
// that the gateway policy also protects a leaked master key or raw PodIP route.
func (w *liteLiveWorker) backendBypassControl(snapshot liteLiveSnapshot, label string) error {
	for i, pod := range snapshot.Pods {
		ctx, stop := context.WithTimeout(w.ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://"+snapshot.PodIPs[pod.UID]+":4000/v1/models", nil)
		if err != nil {
			stop()
			return errors.New("LiteLLM exact backend control URL unavailable")
		}
		req.Header.Set("Authorization", "Bearer "+w.attackerToken)
		response, err := liteHTTPClient(8 * time.Second).Do(req)
		if err != nil {
			stop()
			return errors.New("LiteLLM direct backend owned-token control unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
		_ = response.Body.Close()
		stop()
		if readErr != nil || len(body) > 8192 ||
			!liteBackendAuthRejected(response.StatusCode, body) {
			return errors.New("LiteLLM owned token unexpectedly reached backend authorization")
		}
		if err = w.saveJSON(fmt.Sprintf("%s-backend-%d.json", label, i), map[string]any{
			"podUID": pod.UID, "status": response.StatusCode, "bodySHA256": liteSHA(body),
			"classification": "BACKEND_AUTH_REJECTED"}); err != nil {
			return err
		}
	}
	return nil
}

func liteBackendAuthRejected(status int, body []byte) bool {
	if status == http.StatusUnauthorized {
		return true
	}
	return status == http.StatusBadRequest &&
		strings.Contains(strings.ToLower(string(body)), "no connected db")
}

func liteCounterSum(states map[string]liteLiveStatus, field string) int64 {
	var n int64
	for _, s := range states {
		c := s.Counters
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

func liteJournalName() string { return "phorvex-litellm-revoke-journal" }

func liteJournalRows(row map[string]any) ([]map[string]any, error) {
	meta := liteMeta(row)
	data := availabilityMap(row["data"])
	if availabilityUID(row) == "" || liteStr(meta, "name") != liteJournalName() ||
		liteStr(availabilityMap(meta["labels"]), "phorvex.ai/litellm-client-revoke-journal") != "v2" || len(data) != 1 {
		return nil, errors.New("LiteLLM protected journal authority differs")
	}
	raw := []byte(liteStr(data, "receipts.json"))
	var doc struct {
		Version  int              `json:"version"`
		Receipts []map[string]any `json:"receipts"`
	}
	if len(raw) == 0 || len(raw) > 256<<10 || availabilityDecode(raw, &doc) != nil ||
		doc.Version != 2 || len(doc.Receipts) > 256 {
		return nil, errors.New("LiteLLM protected journal payload differs")
	}
	canonical, _ := json.Marshal(map[string]any{"receipts": doc.Receipts, "version": doc.Version})
	if !bytes.Equal(raw, canonical) {
		return nil, errors.New("LiteLLM protected journal canonical bytes differ")
	}
	previous := ""
	for _, receipt := range doc.Receipts {
		clientSHA := liteStr(receipt, "clientSHA256")
		if !staticSHA256.MatchString(clientSHA) || clientSHA <= previous {
			return nil, errors.New("LiteLLM protected journal order differs")
		}
		previous = clientSHA
	}
	return doc.Receipts, nil
}

func (w *liteLiveWorker) journalBefore(snapshot liteLiveSnapshot) error {
	row, err := w.kube("before-journal", "-n", "phorvex-system", "get", "configmap", liteJournalName(), "-o", "json")
	if err != nil {
		return err
	}
	receipts, err := liteJournalRows(row)
	if err != nil {
		return err
	}
	w.priorReceipts, err = litePriorJournal(snapshot, receipts)
	return err
}

func litePriorJournal(snapshot liteLiveSnapshot, receipts []map[string]any) (map[string]string, error) {
	if len(receipts) < int(snapshot.Revision) || len(receipts) >= 256 ||
		len(snapshot.Entries) != int(snapshot.Revision) {
		return nil, errors.New("LiteLLM prior protected journal and policy revision differ")
	}
	entries := make(map[string]liteLiveEntry, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		entries[entry.ClientSHA256] = entry
	}
	prior := map[string]string{}
	terminal := 0
	for _, receipt := range receipts {
		clientSHA := liteStr(receipt, "clientSHA256")
		entry, exists := entries[clientSHA]
		switch liteStr(receipt, "phase") {
		case "terminal-full":
			if !exists || !entry.Active || entry.OperationID != liteStr(receipt, "operationId") ||
				liteStr(receipt, "abortReason") != "" {
				return nil, errors.New("LiteLLM prior terminal and deny entry differ")
			}
			terminal++
		case "aborted":
			reason := liteStr(receipt, "abortReason")
			if exists || (reason != "pre-cas-authority-changed" && reason != "definitive-policy-conflict") {
				return nil, errors.New("LiteLLM prior aborted operation has a deny entry or invalid reason")
			}
		default:
			return nil, errors.New("LiteLLM prior protected operation unresolved")
		}
		b, _ := json.Marshal(receipt)
		prior[clientSHA] = liteSHA(b)
	}
	if terminal != int(snapshot.Revision) {
		return nil, errors.New("LiteLLM protected journal terminals do not match active policy entries")
	}
	return prior, nil
}

func (w *liteLiveWorker) execute(probe *liteLLMLiveProbeResult) (err error) {
	if err = w.loadTokens(); err != nil {
		return err
	}
	before, err := w.snapshot("before")
	if err != nil {
		return err
	}
	w.bound = before
	w.record.Pod, w.record.TargetUID = before.Pods[0].Name, before.Pods[0].UID
	publishAttack(w.record)
	if before.Active || before.OperationID != "" || before.EntryCount >= 256 {
		return errors.New("fresh LiteLLM client unavailable or deny registry full")
	}
	if err = w.journalBefore(before); err != nil {
		return err
	}
	preStatus, err := w.statuses(before, "before-attacker", w.attackerSHA, "")
	if err != nil {
		return err
	}
	for _, state := range preStatus {
		if state.Active || state.Revision != before.Revision || state.OperationID != "" || state.Role != "" {
			return errors.New("LiteLLM gateway pre-state differs")
		}
	}
	preControl, err := w.statuses(before, "before-control", w.controlSHA, "")
	if err != nil {
		return err
	}
	if err = w.backendBypassControl(before, "before"); err != nil {
		return err
	}
	count := 2
	if probe.Scenario == "ai2-query-extraction" {
		count = 3
	}
	seen := map[string]bool{}
	actual := 0
	for i := 0; i < 12 && (i < count || len(seen) < 2); i++ {
		promptIndex := i
		if promptIndex >= count {
			promptIndex = i % count
		}
		call, e := w.call(fmt.Sprintf("before-attacker-%d", i), w.attackerToken, litePrompt(probe.Scenario, promptIndex))
		if e != nil {
			return e
		}
		if call.Class != "ACCEPTED_MODEL_COMPLETION" {
			return errors.New("LiteLLM original attacker work not accepted")
		}
		seen[call.GatewayPodUID] = true
		actual++
		probe.InitialUsageTokens += call.UsageTokens
	}
	if len(seen) != 2 {
		return errors.New("LiteLLM real Service did not route original work to both exact gateways")
	}
	control, err := w.call("before-control", w.controlToken, liteBenignControlPrompt)
	if err != nil || control.Class != "ACCEPTED_MODEL_COMPLETION" {
		return errors.New("LiteLLM original benign control unavailable")
	}
	postBaseline, err := w.snapshot("post-baseline")
	if err != nil || !liteSameSource(before, postBaseline) || postBaseline.Active ||
		postBaseline.Revision != before.Revision || postBaseline.PolicyConfigMapRV != before.PolicyConfigMapRV {
		return errors.New("LiteLLM original source/policy drift")
	}
	baselineStates, err := w.statuses(postBaseline, "post-baseline-attacker", w.attackerSHA, "attacker")
	if err != nil {
		return err
	}
	baselineControl, err := w.statuses(postBaseline, "post-baseline-control", w.controlSHA, "")
	if err != nil {
		return err
	}
	if liteCounterSum(baselineStates, "completed")-liteCounterSum(preStatus, "completed") != int64(actual) ||
		liteCounterSum(baselineStates, "usage")-liteCounterSum(preStatus, "usage") != probe.InitialUsageTokens ||
		liteCounterSum(baselineControl, "completed")-liteCounterSum(preControl, "completed") != 1 {
		return errors.New("LiteLLM original upstream counter/usage receipt differs")
	}
	probe.InitialAcceptedWork = true
	probe.Status = "LANDED_UNPROTECTED"
	return w.afterOriginal(probe, before, baselineStates, baselineControl)
}

func (w *liteLiveWorker) afterOriginal(probe *liteLLMLiveProbeResult, before liteLiveSnapshot, baselineStates, baselineControl map[string]liteLiveStatus) (err error) {
	preEvent, err := w.snapshot("pre-event")
	if err != nil || !liteSameSource(before, preEvent) || preEvent.Active || preEvent.Revision != before.Revision ||
		preEvent.PolicyConfigMapRV != before.PolicyConfigMapRV {
		return errors.New("LiteLLM immediate pre-event policy/source differs")
	}
	var auditProfile guardrailAvailabilityProfile
	auditProfile.Fixture.PodName = before.Pods[0].Name
	auditProfile.Fixture.PodUID = before.Pods[0].UID
	auditProfile.Fixture.PolicyUID = before.PolicyUID
	auditProfile.Fixture.ClusterUID = before.ClusterUID
	audit := &availabilityWorker{rm: &RunManager{cfg: w.s.cfg}, ctx: w.ctx, out: w.out,
		p: auditProfile, deadline: time.Now().Add(600 * time.Second), auditNamespace: "litellm",
		before: availabilitySnapshot{TargetPodUID: before.Pods[0].UID, PolicyUID: before.PolicyUID, ClusterUID: before.ClusterUID},
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
	if err != nil || !liteSameSource(before, after) || !litePriorEntriesPreserved(before, after) ||
		!after.Active || after.Revision != before.Revision+1 ||
		after.OperationID != liteStr(receipt, "operationId") {
		return errors.New("LiteLLM post-action policy state differs")
	}
	statuses, err := w.statuses(after, "post-action-attacker", w.attackerSHA, "attacker")
	if err != nil {
		return err
	}
	for _, state := range statuses {
		if !state.Active || state.Revision != after.Revision || state.OperationID != after.OperationID {
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
	control, err := w.call("after-control", w.controlToken, liteBenignControlPrompt)
	if err != nil || control.Class != "ACCEPTED_MODEL_COMPLETION" {
		probe.Status = "BENIGN_REGRESSION"
		return errors.New("LiteLLM ordinary authorized completion regressed")
	}
	final, err := w.snapshot("post-replay")
	if err != nil || !liteSameSource(before, final) || !litePriorEntriesPreserved(after, final) ||
		!final.Active || final.Revision != after.Revision || final.OperationID != after.OperationID {
		return errors.New("LiteLLM final source/policy state differs")
	}
	finalStatuses, err := w.statuses(final, "post-replay-attacker", w.attackerSHA, "attacker")
	if err != nil {
		return err
	}
	finalControl, err := w.statuses(final, "post-replay-control", w.controlSHA, "")
	if err != nil {
		return err
	}
	if liteCounterSum(finalStatuses, "forwarded") != liteCounterSum(baselineStates, "forwarded") ||
		liteCounterSum(finalStatuses, "completed") != liteCounterSum(baselineStates, "completed") ||
		liteCounterSum(finalStatuses, "denied") != liteCounterSum(baselineStates, "denied")+1 ||
		liteCounterSum(finalControl, "completed") != liteCounterSum(baselineControl, "completed")+1 {
		return errors.New("LiteLLM attacker replay or benign upstream counters differ")
	}
	if err = w.backendBypassControl(final, "after"); err != nil {
		return err
	}
	probe.BackendBypassRejected = true
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
			decision.AssetUID != created.TargetPodUID || decision.PolicyUID != before.PolicyUID || decision.ExactEventUID != created.UID ||
			decision.ExactEventCreator != w.p.EventCreator {
			return errors.New("LiteLLM selected decision and protected journal differ")
		}
		selected++
		probe.SelectedAction = decision.Action
		probe.SelectionDecisionID = decision.DecisionID
		if row, ok := audit.decisionRecords[decision.DecisionID]; ok {
			bindDecisionRecord(w.record, &row)
		}
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
		"version": 2, "clientSHA256": w.attackerSHA,
		"configMapUID": w.bound.PolicyConfigMapUID, "serviceUID": w.bound.ServiceUID,
		"clientsConfigMapUID": w.bound.ClientsConfigMapUID, "seedSHA256": w.p.SeedSHA256,
		"targetPodUID": w.bound.Pods[0].UID, "peerPodUID": w.bound.Pods[1].UID,
		"requestPath": "/v1/chat/completions", "objective": objective,
		"policyName": w.p.PolicyName, "policyUID": w.bound.PolicyUID,
		"policyGeneration": w.bound.PolicyGeneration, "observedAt": observedAt.Format(time.RFC3339Nano),
	}
	note, _ := json.Marshal(observation)
	object := map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name,
			"labels":      map[string]string{"phorvex.ai/redteam": "true", "phorvex.ai/test-injected": "true", "phorvex.ai/attack-correlation": correlation},
			"annotations": map[string]string{"phorvex.ai/console-target-pod-uid": w.bound.Pods[0].UID, liteLiveAnnotation: string(note)}},
		"spec": map[string]any{"description": "TEST_INJECTED after actual scoped LiteLLM client work",
			"targets":      []string{"litellm/" + w.bound.Pods[0].Name},
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
		Correlation: correlation, TargetPodUID: w.bound.Pods[0].UID, RuleType: liteLiveRule, Source: "redteam"}, nil
}

func (w *liteLiveWorker) pollJournal(event *availabilityEvent) (map[string]any, error) {
	name := liteJournalName()
	deadline := time.Now().Add(180 * time.Second)
	for i := 0; i < 36 && time.Now().Before(deadline); i++ {
		row, err := w.kube(fmt.Sprintf("journal-%02d", i), "-n", "phorvex-system", "get", "configmap", name, "-o", "json")
		if err == nil {
			receipts, parseErr := liteJournalRows(row)
			if parseErr != nil || len(receipts) < len(w.priorReceipts) || len(receipts) > len(w.priorReceipts)+1 {
				return nil, errors.New("LiteLLM protected journal array differs")
			}
			preserved := 0
			for _, prior := range receipts {
				clientSHA := liteStr(prior, "clientSHA256")
				if priorHash, ok := w.priorReceipts[clientSHA]; ok {
					preserved++
					b, _ := json.Marshal(prior)
					if liteSHA(b) != priorHash {
						return nil, errors.New("LiteLLM prior protected receipt changed")
					}
				}
			}
			if preserved != len(w.priorReceipts) {
				return nil, errors.New("LiteLLM prior protected receipts missing")
			}
			if len(receipts) == len(w.priorReceipts) {
				goto nextPoll
			}
			matched := 0
			for _, receipt := range receipts {
				clientSHA := liteStr(receipt, "clientSHA256")
				if clientSHA != w.attackerSHA {
					if _, ok := w.priorReceipts[clientSHA]; !ok {
						return nil, errors.New("LiteLLM prior protected receipt missing")
					}
					continue
				}
				matched++
				if liteStr(receipt, "phase") == "aborted" {
					return nil, errors.New("LiteLLM protected operation proved no-write; no defense credit")
				}
				if liteStr(receipt, "phase") != "terminal-full" {
					continue
				}
				if liteInt(receipt, "version") != 2 || liteStr(receipt, "abortReason") != "" ||
					liteStr(receipt, "eventName") != event.Name ||
					liteStr(receipt, "eventUID") != event.UID || liteStr(receipt, "targetUID") != event.TargetPodUID ||
					liteStr(receipt, "peerUID") != w.bound.Pods[1].UID || liteStr(receipt, "policyName") != w.p.PolicyName ||
					liteStr(receipt, "policyUID") != w.bound.PolicyUID || liteInt(receipt, "policyGeneration") != w.bound.PolicyGeneration ||
					liteStr(receipt, "configMapUID") != w.bound.PolicyConfigMapUID ||
					liteStr(receipt, "clientsConfigMapUID") != w.bound.ClientsConfigMapUID ||
					liteStr(receipt, "seedSHA256") != w.p.SeedSHA256 ||
					liteStr(receipt, "serviceUID") != w.bound.ServiceUID || liteStr(receipt, "sourceSHA256") != w.p.SourceSHA256 ||
					liteStr(receipt, "tickId") == "" || liteStr(receipt, "selectionDecisionId") == "" ||
					liteStr(receipt, "operationId") != liteStr(receipt, "selectionDecisionId") {
					return nil, errors.New("LiteLLM protected terminal journal identity differs")
				}
				if err = w.saveJSON("journal-terminal.json", row); err != nil {
					return nil, err
				}
				return receipt, nil
			}
			if matched != 1 {
				return nil, errors.New("LiteLLM protected journal target receipt missing")
			}
		}
	nextPoll:
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
