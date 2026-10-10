package verificationloop

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/slo"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type ready struct {
	PublicURL   string `json:"public_url"`
	AdminURL    string `json:"admin_url"`
	ObserverURL string `json:"observer_url"`
	Source      string `json:"source_sha256"`
}
type countedClient struct {
	client.Client
	policyWrites, journalWrites int
}

func (c *countedClient) Update(ctx context.Context, o client.Object, opts ...client.UpdateOption) error {
	err := c.Client.Update(ctx, o, opts...)
	if err == nil {
		if o.GetNamespace() == endpointlease.Namespace && o.GetName() == endpointlease.PolicyConfigMapName {
			c.policyWrites++
		}
		if o.GetNamespace() == opns && o.GetName() == endpointlease.JournalName {
			c.journalWrites++
		}
	}
	return err
}

type replayInput struct {
	ReconProfile string
	Clock        time.Time
	Policy       model.Policy
	Views        []*model.WorkloadView
	State        decision.OwnerState
	Capabilities map[string]capabilityObservation
}
type capabilityObservation struct {
	Nil         bool
	Eligibility actionset.Eligibility
}

// Run launches only a private envtest control plane. Kubernetes image/readiness
// metadata is fixture input: no kubelet, CNI or GPU inference is claimed.
func Run(parent context.Context, o Options) (report *Report, runErr error) {
	report = &Report{Schema: "phorvex.verification-loop.local.v1", Scope: "private-real-apiserver-and-local-credential-admission-with-synthetic-downstream", Verdict: "INCOMPLETE", StartedAt: time.Now().UTC(), GitSHA: o.GitSHA, Artifacts: map[string]string{}, BrainFilesSHA256: map[string]string{}, Limitations: []string{"No production cluster access or claim; no kubelet, CNI, GPU, real vLLM inference, rollout or deployed-image verification.", "Pod readiness, owner links, EndpointSlice membership and container image IDs are explicit fixture metadata on a real API server.", "The Python API transport uses local envtest mTLS credentials, not deployed service-account projection.", "Fixed logical admin port 8443 is mapped to a verified TLS loopback socket by the explicit test transport; no status response is synthesized.", "Local sampled legitimate-request latency is measured; formal action SLO remains unknown and modeled cost is not measured cost.", "Exact replay preserves the original actual API identities, frozen clock, views, owner state and capability observations. Fresh physical episodes require separate semantic comparison."}}
	if o.OutputDir == "" {
		return report, errors.New("--out is required")
	}
	if o.Timeout <= 0 || o.HoldDuration <= 0 || o.HoldInterval <= 0 || o.MaxLegitimateLatency <= 0 {
		return report, errors.New("timeouts and hold durations must be positive")
	}
	if err := os.MkdirAll(o.OutputDir, 0750); err != nil {
		return report, err
	}
	entries, err := os.ReadDir(o.OutputDir)
	if err != nil {
		return report, err
	}
	if len(entries) != 0 {
		return report, errors.New("evidence directory must be empty; previous evidence is never overwritten")
	}
	defer func() {
		report.FinishedAt = time.Now().UTC()
		for _, p := range report.Probes {
			if strings.HasPrefix(p.Name, "B-") || p.Name == "clean-B" || p.Name == "attack-baseline-B" {
				report.LegitimateSamples++
				if p.LatencyMS > report.LegitimateMaxLatencyMS {
					report.LegitimateMaxLatencyMS = p.LatencyMS
				}
				if !report.DispatchStartedAt.IsZero() && !p.RequestStartedAt.IsZero() && p.RequestStartedAt.Before(report.DispatchFinishedAt) && p.RequestFinishedAt.After(report.DispatchStartedAt) {
					report.LegitimateDispatchOverlaps++
				}
			}
		}
		if runErr != nil {
			report.Error = runErr.Error()
			if report.Verdict != "LANDED" && report.Verdict != "DECLINED" && report.Verdict != "NOT_LANDED" {
				report.Verdict = "INCOMPLETE"
			}
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(o.OutputDir, "report.json"), append(raw, '\n'), 0640)
		}
		runErr = errors.Join(runErr, err)
	}()
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	o.RepoRoot, err = filepath.Abs(o.RepoRoot)
	if err != nil {
		return report, err
	}
	if o.GitSHA == "" || o.GitSHA == "unknown" {
		return report, errors.New("a concrete --git-sha or pinned binary build identity is required")
	}
	report.GitSHAProvenance = "Build/caller-supplied revision label; actual executing binary, decision files, harness files and dependencies are separately hashed (uncommitted harness may differ from this revision)."
	report.FixtureFilesSHA256 = map[string]string{}
	report.ToolFilesSHA256 = map[string]string{}
	if executable, err := os.Executable(); err == nil {
		if raw, err := os.ReadFile(executable); err == nil {
			report.ExecutableSHA256 = SHA256(raw)
		} else {
			return report, err
		}
	} else {
		return report, err
	}
	for _, pattern := range []string{"phorvex/internal/verificationloop/*.go", "phorvex/cmd/verification-loop/*.go", "build/test-harness/fixtures/verification-loop/*.py", "phorvex/go.mod", "phorvex/go.sum"} {
		paths, err := filepath.Glob(filepath.Join(o.RepoRoot, pattern))
		if err != nil {
			return report, err
		}
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				return report, err
			}
			rel, _ := filepath.Rel(o.RepoRoot, path)
			report.FixtureFilesSHA256[rel] = SHA256(raw)
		}
	}
	for _, name := range []string{"kube-apiserver", "etcd"} {
		if _, err := os.Stat(filepath.Join(o.Assets, name)); err != nil {
			return report, fmt.Errorf("private envtest assets: %w", err)
		}
		raw, err := os.ReadFile(filepath.Join(o.Assets, name))
		if err != nil {
			return report, err
		}
		report.ToolFilesSHA256[name] = SHA256(raw)
	}
	brainFiles, err := filepath.Glob(filepath.Join(o.RepoRoot, "phorvex/internal/decision/*.go"))
	if err != nil {
		return report, err
	}
	for _, path := range brainFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return report, err
		}
		rel, _ := filepath.Rel(o.RepoRoot, path)
		report.BrainFilesSHA256[rel] = SHA256(raw)
	}
	report.FormalSLO, _ = slo.Classify(model.ActionEndpointLeaseRevoke)
	tmp, err := os.MkdirTemp("", "phorvex-verification-loop-")
	if err != nil {
		return report, err
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			report.CleanupErrors = append(report.CleanupErrors, err.Error())
			runErr = errors.Join(runErr, err)
		}
	}()
	local := false
	env := &envtest.Environment{UseExistingCluster: &local, BinaryAssetsDirectory: o.Assets, CRDDirectoryPaths: []string{filepath.Join(o.RepoRoot, "phorvex/config/crd/bases"), filepath.Join(o.RepoRoot, "build/phoenix-extended/config/crd/bases")}, ErrorIfCRDPathMissing: true, ControlPlaneStartTimeout: 30 * time.Second, ControlPlaneStopTimeout: 15 * time.Second}
	env.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	if err := ctx.Err(); err != nil {
		return report, err
	}
	cfg, err := env.Start()
	if err != nil {
		if stopErr := env.Stop(); stopErr != nil {
			report.CleanupErrors = append(report.CleanupErrors, stopErr.Error())
		}
		return report, fmt.Errorf("private API start: %w", err)
	}
	defer func() {
		if err := env.Stop(); err != nil {
			report.CleanupErrors = append(report.CleanupErrors, err.Error())
			runErr = errors.Join(runErr, err)
		}
	}()
	scheme, err := newScheme()
	if err != nil {
		return report, err
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return report, err
	}
	f, err := provision(ctx, c, cfg, o.RepoRoot, tmp)
	if err != nil {
		return report, fmt.Errorf("provision local API objects: %w", err)
	}
	defer func() {
		captureCtx, captureCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer captureCancel()
		if err := writeAPIArtifacts(captureCtx, f, report, o.OutputDir); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("retaining API evidence: %w", err))
		}
	}()
	report.Limitations = append(report.Limitations, "SecurityEvent creator annotation and allowlist are explicit TEST_INJECTED fixture claims; events are created by the private envtest admin client, not an authenticated production console.", "The fixed initial local policy uses UCW recon, reactive-only event handling and a one-second anti-over-rotation window with real wall-clock maturation; it does not validate production's five-minute setting.", "Legitimate requests are sampled before/around/after dispatch. Recorded timestamps define any actual overlap; continuous availability is not claimed.", "Resolved model.Policy is an explicit recorded local input to the production engine, not a claim that the full production manager policy-resolution path ran. The real API PhorvexPolicy authorizes exact dispatch scope/actions and declares the case timing.")
	report.SourceSHA256 = f.source
	if err := ingest.ConfigureEndpointLeaseApprovedAuthority(f.source, f.proxyImage, f.engineImage); err != nil {
		return report, err
	}
	defer func() { _ = ingest.ConfigureEndpointLeaseApprovedAuthority("", "", "") }()
	previousTrust := ingest.EventTrust()
	ingest.ConfigureEventTrust(ingest.NewTrustedDetectors([]string{creator}))
	defer ingest.ConfigureEventTrust(previousTrust)
	runtimeCfg, _ := json.Marshal(f.config)
	configPath, err := privateFile(tmp, "runtime-config.json", runtimeCfg)
	if err != nil {
		return report, err
	}
	logFile, err := os.OpenFile(filepath.Join(o.OutputDir, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return report, err
	}
	defer logFile.Close()
	cmd := exec.CommandContext(ctx, o.Python, filepath.Join(o.RepoRoot, "build/test-harness/fixtures/verification-loop/runtime_fixture.py"), "--config", configPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err = cmd.Start(); err != nil {
		return report, err
	}
	processDone := make(chan error, 1)
	go func() { processDone <- cmd.Wait() }()
	defer func() {
		select {
		case <-processDone:
			return
		default:
		}
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-processDone:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-processDone
		}
	}()
	var rt ready
	if err = waitReady(ctx, processDone, f.config["ready_file"].(string), &rt); err != nil {
		return report, err
	}
	if rt.Source != f.source {
		return report, errors.New("executing runtime source digest differs")
	}
	stage := func(name string, passed bool, detail string) {
		report.Stages = append(report.Stages, Stage{name, passed, detail})
	}
	stage("private-runtime-ready", true, "Real envtest API, API-generated UIDs/resourceVersions, production Python admission source and verified TLS listener")
	// The case's initial policy has a one-second identity retention window.
	// Observe real elapsed time; do not backdate identity or rewrite the policy.
	select {
	case <-ctx.Done():
		return report, ctx.Err()
	case <-time.After(time.Second):
	}
	cc := &countedClient{Client: c}
	native := actuator.NewNativeActuator(cc)
	native.Reader = c
	native.JournalNamespace = opns
	native.SetServingSecurity(f.security)
	native.SetEndpointLeaseApprovedSourceSHA256(f.source)
	native.SetEndpointLeaseApprovedProxyImage(f.proxyImage)
	native.SetEndpointLeaseApprovedEngineImage(f.engineImage)
	adminURL, err := url.Parse(rt.AdminURL)
	if err != nil {
		return report, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(f.ca) {
		return report, errors.New("runtime CA invalid")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: tlsName}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != fixturePodIP+":8443" {
			return nil, fmt.Errorf("unexpected status destination %s", address)
		}
		return dialer.DialContext(ctx, network, adminURL.Host)
	}}
	defer transport.CloseIdleConnections()
	native.EndpointLeaseStatusTransport = transport
	native.EndpointLeaseStatusToken = f.admin
	if err = native.EnsurePolicy(ctx, actuator.TenantTarget{Tenant: "local-verification", Namespace: f.policy.Namespace, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID)}); err != nil {
		return report, err
	}
	initialState, initialJournal := f.state.Data[endpointlease.PolicyKey], f.journal.Data[endpointlease.JournalKey]
	for name, obj := range map[string]any{"policy-initial.json": f.state, "journal-initial.json": f.journal} {
		raw, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return report, err
		}
		if err = artifact(report, o.OutputDir, name, raw); err != nil {
			return report, err
		}
	}
	probe := func(name, credential string, allowed bool) (Probe, error) {
		p := performProbe(ctx, rt, f.admin, name, credential)
		report.Probes = append(report.Probes, p)
		checkErr := ValidateProbe(p, allowed, o.MaxLegitimateLatency)
		if checkErr != nil && !allowed && ValidateProbe(p, true, o.MaxLegitimateLatency) == nil {
			report.Verdict = "LANDED"
		}
		return p, checkErr
	}
	if _, err = probe("clean-A-no-actuation", f.a, true); err != nil {
		return report, err
	}
	if _, err = probe("clean-B", f.b, true); err != nil {
		return report, err
	}
	pol := model.Policy{Tenant: "local-verification", Namespace: f.policy.Namespace, Mode: "active", DryRun: false, Lambda: cost.DefaultLambdaSeed, NormSparsity: 0.4, FlowDisruption: 0.6, WeightSecrets: 0.8, BlastRadiusFromGraph: true, MaxMovesPerTick: 1, ProactiveFloor: time.Hour, AntiOverRotationWindow: time.Second, MinAvailableReplicas: 1, ReactiveOnly: true, EventDriven: true, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), PolicyGeneration: f.policy.Generation, TickID: SHA256([]byte("local-verification-tick\x00" + string(f.policy.UID))), BrainImage: "local-build:" + o.GitSHA, GitSHA: o.GitSHA, TraceEnabled: true, EnabledActions: map[model.Action]bool{model.ActionEndpointLeaseRevoke: true, model.ActionEndpointRotate: true, model.ActionRotate: true}}
	clock := time.Now().UTC()
	views, err := collectView(ctx, f, clock)
	if err != nil {
		return report, err
	}
	report.CleanDecisions, _, _, err = choose(ctx, native, views, pol, clock)
	if err != nil {
		return report, err
	}
	if selected(report.CleanDecisions) != nil {
		return report, errors.New("clean control unexpectedly selected a mutation")
	}
	if err = unchanged(ctx, f, initialState, initialJournal, cc); err != nil {
		return report, err
	}
	stage("clean-and-no-actuation-control", true, "A and B still reach downstream, no mutation selected, API policy/journal unchanged")
	a, err := probe("attack-baseline-A", f.a, true)
	if err != nil {
		if ValidateProbe(a, false, o.MaxLegitimateLatency) == nil {
			report.Verdict = "NOT_LANDED"
		}
		return report, err
	}
	b, err := probe("attack-baseline-B", f.b, true)
	if err != nil {
		return report, err
	}
	live, err := endpointlease.ValidateLive(ctx, c, string(f.pod.UID), f.source, f.proxyImage, f.engineImage)
	if err != nil {
		return report, err
	}
	obs := endpointlease.Observation{Version: 1, ScenarioID: "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED", PolicyName: pol.PolicyName, PolicyUID: pol.PolicyUID, PolicyGeneration: pol.PolicyGeneration, TargetPodUID: string(f.pod.UID), ServiceUID: live.ServiceUID, PolicyConfigMapUID: live.PolicyUID, ProxySourceSHA256: f.source, SecretUID: live.SecretUID, SeedSHA256: live.SeedSHA256, PriorRevision: live.State.Revision, RevokedClientHMAC: f.aID, RetainedClientHMAC: f.bID, AcceptedStatus: a.Status, AcceptedResponseSHA256: a.BodySHA256, RetainedBaselineStatus: b.Status, RetainedBaselineResponseSHA256: b.BodySHA256, ObservedAt: time.Now().UTC()}
	stale := obs
	stale.ObservedAt = stale.ObservedAt.Add(-61 * time.Second)
	staleEvent, err := createEvent(ctx, f, "stale-lease-probe", stale)
	if err != nil {
		return report, err
	}
	staleRaw, _ := json.MarshalIndent(staleEvent, "", "  ")
	if err = artifact(report, o.OutputDir, "stale-security-event.json", staleRaw); err != nil {
		return report, err
	}
	staleClock := time.Now().UTC()
	staleViews, err := collectView(ctx, f, staleClock)
	if err != nil {
		return report, err
	}
	report.StaleDecisions, _, _, err = choose(ctx, native, staleViews, pol, staleClock)
	if err != nil {
		return report, err
	}
	if selected(report.StaleDecisions) != nil {
		return report, errors.New("stale observation selected a mutation")
	}
	if err = unchanged(ctx, f, initialState, initialJournal, cc); err != nil {
		return report, err
	}
	if err = c.Delete(ctx, staleEvent); err != nil {
		return report, err
	}
	stage("stale-observation-refusal", true, "Real ingest rejected a 61-second-old observation; no dispatch or API mutation")
	obs.ObservedAt = time.Now().UTC()
	event, err := createEvent(ctx, f, "accepted-lease-probe", obs)
	if err != nil {
		return report, err
	}
	eventRaw, _ := json.MarshalIndent(event, "", "  ")
	if err = artifact(report, o.OutputDir, "security-event.json", eventRaw); err != nil {
		return report, err
	}
	clock = time.Now().UTC()
	report.DecisionClock = clock
	views, err = collectView(ctx, f, clock)
	if err != nil {
		return report, err
	}
	if len(views) != 1 || !views[0].Pod.HasBoundEndpointLeaseObservation() {
		return report, errors.New("fresh trusted real SecurityEvent did not bind typed lease evidence")
	}
	var input replayInput
	report.Decisions, input, report.ShadowStateUnchanged, err = choose(ctx, native, views, pol, clock)
	if err != nil {
		return report, err
	}
	if !report.ShadowStateUnchanged {
		return report, errors.New("shadow evaluation changed owner state")
	}
	var buf bytes.Buffer
	if err = gob.NewEncoder(&buf).Encode(input); err != nil {
		return report, err
	}
	if err = artifact(report, o.OutputDir, "replay-input.gob", buf.Bytes()); err != nil {
		return report, err
	}
	policyFields := map[string]any{}
	policyValue := reflect.ValueOf(input.Policy)
	policyType := policyValue.Type()
	for i := 0; i < policyType.NumField(); i++ {
		if policyType.Field(i).Type.Kind() != reflect.Func {
			policyFields[policyType.Field(i).Name] = policyValue.Field(i).Interface()
		}
	}
	readable, err := json.MarshalIndent(map[string]any{"recon_profile": input.ReconProfile, "decision_clock": input.Clock, "model_policy": policyFields, "views": input.Views, "owner_state": input.State, "capabilities": input.Capabilities}, "", "  ")
	if err != nil {
		return report, err
	}
	if err = artifact(report, o.OutputDir, "resolved-model-input.json", readable); err != nil {
		return report, err
	}
	chosen := selected(report.Decisions)
	if chosen == nil {
		report.Verdict = "DECLINED"
		stage("normal-brain-selection", false, "Brain declined; no action dispatched")
		return report, errors.New("normal brain declined the confirmed attack")
	}
	if chosen.Action != model.ActionEndpointLeaseRevoke || !chosen.Feasible || chosen.DryRun || chosen.Trace == nil {
		return report, fmt.Errorf("normal brain selected an unexpected or infeasible action: %s", chosen.Action)
	}
	stage("normal-brain-selection", true, chosen.Reason)
	report.ReplayExact, err = replay(input, report.Decisions)
	if err != nil {
		return report, err
	}
	if !report.ReplayExact {
		return report, errors.New("exact snapshot shadow replay differed")
	}
	stage("exact-frozen-snapshot-replay", true, "Fresh unmodified brain retained original API identities, owner state, clock and recorded capability observations; byte-identical canonical traces")
	traceRaw, err := canonicalTraces(report.Decisions)
	if err != nil {
		return report, err
	}
	if err = artifact(report, o.OutputDir, "selection-traces.json", traceRaw); err != nil {
		return report, err
	}
	viewObs := views[0].Pod.EndpointLeaseObservation
	req := actuator.Request{Tenant: pol.Tenant, Namespace: chosen.Namespace, Pod: chosen.Pod, Action: chosen.Action, Reason: chosen.Reason, TargetUID: views[0].Pod.UID, OperationID: chosen.Trace.DecisionID, TickID: chosen.Trace.TickID, PolicyName: pol.PolicyName, PolicyUID: pol.PolicyUID, PolicyGeneration: pol.PolicyGeneration, EndpointLeaseObservation: viewObs}
	if viewObs.EventUID != string(event.UID) {
		return report, errors.New("selected observation event identity differs")
	}
	if o.SkipDispatch {
		if _, err = probe("A-selected-but-dispatch-withheld", f.a, true); err != nil {
			return report, err
		}
		if _, err = probe("B-dispatch-withheld", f.b, true); err != nil {
			return report, err
		}
		if err = unchanged(ctx, f, initialState, initialJournal, cc); err != nil {
			return report, err
		}
		if err = writeAPIArtifacts(ctx, f, report, o.OutputDir); err != nil {
			return report, err
		}
		report.Verdict = "LANDED"
		stage("dispatch-withheld-negative-control", false, "The real brain selected a defense, but native dispatch was withheld: A still reaches downstream and no policy or journal changed")
		return report, errors.New("negative control: selected defense without dispatch leaves attack landed")
	}
	// Legitimate requests overlap actual native dispatch. Only this worker probes
	// during dispatch so downstream-counter deltas remain unambiguous.
	bgCtx, bgCancel := context.WithCancel(ctx)
	bgResult := make(chan []Probe, 1)
	bgStarted := make(chan struct{})
	go func() {
		var probes []Probe
		close(bgStarted)
		for {
			p := performProbe(ctx, rt, f.admin, "B-during-dispatch", f.b)
			probes = append(probes, p)
			select {
			case <-bgCtx.Done():
				bgResult <- probes
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	<-bgStarted
	report.DispatchStartedAt = time.Now().UTC()
	result, dispatchErr := native.Actuate(ctx, req)
	report.DispatchFinishedAt = time.Now().UTC()
	report.Dispatch = &result
	bgCancel()
	bgProbes := <-bgResult
	report.Probes = append(report.Probes, bgProbes...)
	for _, p := range bgProbes {
		if err = ValidateProbe(p, true, o.MaxLegitimateLatency); err != nil {
			return report, err
		}
	}
	overlaps := 0
	for _, p := range bgProbes {
		if p.RequestStartedAt.Before(report.DispatchFinishedAt) && p.RequestFinishedAt.After(report.DispatchStartedAt) {
			overlaps++
		}
	}
	if overlaps == 0 {
		return report, errors.New("local legitimate sampling did not overlap actual native dispatch; availability evidence incomplete")
	}
	if dispatchErr != nil {
		return report, fmt.Errorf("native dispatch: %w", dispatchErr)
	}
	if !result.Emitted || result.Handler != string(chosen.Action) || result.Actuator != "native" {
		return report, errors.New("native handler did not confirm actual emission")
	}
	if cc.policyWrites != 1 || cc.journalWrites != 2 {
		return report, fmt.Errorf("unexpected native successful policy/journal writes %d/%d", cc.policyWrites, cc.journalWrites)
	}
	if err = verifyTerminal(ctx, f, req.OperationID, req.TickID); err != nil {
		return report, err
	}
	stage("native-effect-and-terminal-journal", true, "One real API resourceVersion update, durable prepared/terminal journal, verified runtime status and original-process drain")
	if o.UnavailableAuthority {
		if err = c.Delete(ctx, f.state); err != nil {
			return report, err
		}
		p := performProbe(ctx, rt, f.admin, "A-authority-unavailable", f.a)
		report.Probes = append(report.Probes, p)
		stage("unavailable-authority-negative-control", false, "Private durable policy was removed: outage is not containment")
		if p.Status != 503 || p.BeforeCalls != p.AfterCalls || !strings.Contains(p.RawBody, "lease_unavailable") {
			return report, errors.New("authority-negative-control did not produce expected no-downstream 503")
		}
		return report, errors.New("negative control: 503 lease_unavailable cannot establish a defended verdict")
	}
	if p, probeErr := probe("A-after-native", f.a, false); probeErr != nil {
		if ValidateProbe(p, true, o.MaxLegitimateLatency) == nil {
			report.Verdict = "LANDED"
		}
		return report, probeErr
	}
	report.BaselineToConfirmedDenialMS = float64(time.Since(a.At)) / float64(time.Millisecond)
	if _, err = probe("B-after-native", f.b, true); err != nil {
		return report, err
	}
	holdStart := time.Now()
	for {
		if _, err = probe("A-hold", f.a, false); err != nil {
			return report, err
		}
		if _, err = probe("B-hold", f.b, true); err != nil {
			return report, err
		}
		if time.Since(holdStart) >= o.HoldDuration {
			break
		}
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case <-time.After(o.HoldInterval):
		}
	}
	report.HoldElapsedMS = float64(time.Since(holdStart)) / float64(time.Millisecond)
	stage("behavioral-denial-and-local-legitimate-hold", true, fmt.Sprintf("A gets exact 401 unauthorized with no downstream operation; B succeeds within %.0f ms; actual hold %.0f ms", float64(o.MaxLegitimateLatency)/float64(time.Millisecond), report.HoldElapsedMS))
	if err = writeAPIArtifacts(ctx, f, report, o.OutputDir); err != nil {
		return report, err
	}
	report.Verdict = "LOCAL_RUNTIME_DEFENDED"
	return report, nil
}

func waitReady(ctx context.Context, done chan error, path string, out *ready) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if raw, err := os.ReadFile(path); err == nil {
			if json.Unmarshal(raw, out) == nil && out.PublicURL != "" && out.AdminURL != "" && out.ObserverURL != "" {
				return nil
			}
		}
		select {
		case err := <-done:
			done <- err
			return fmt.Errorf("runtime exited before readiness: %v", err)
		case <-deadline.C:
			return errors.New("runtime readiness timeout; see runtime.log")
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func performProbe(ctx context.Context, rt ready, admin, name, credential string) Probe {
	p := Probe{Name: name, At: time.Now().UTC()}
	p.Nonce = SHA256([]byte(name + "\x00" + p.At.Format(time.RFC3339Nano)))[:32]
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer hc.CloseIdleConnections()
	count := func() (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rt.ObserverURL+"/stats", nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		resp, err := hc.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return 0, fmt.Errorf("observer status %d", resp.StatusCode)
		}
		var value struct {
			Calls int `json:"call_count"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&value)
		return value.Calls, err
	}
	var err error
	p.BeforeCalls, err = count()
	if err != nil {
		p.Error = err.Error()
		return p
	}
	raw, _ := json.Marshal(map[string]string{"nonce": p.Nonce})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rt.PublicURL+"/v1/completions", bytes.NewReader(raw))
	if err != nil {
		p.Error = err.Error()
		return p
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	p.RequestStartedAt = start.UTC()
	resp, err := hc.Do(req)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.LatencyMS = float64(time.Since(start)) / float64(time.Millisecond)
	p.Status = resp.StatusCode
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8193))
	_ = resp.Body.Close()
	p.RequestFinishedAt = time.Now().UTC()
	p.LatencyMS = float64(time.Since(start)) / float64(time.Millisecond)
	if readErr != nil || len(body) > 8192 {
		p.Error = "probe body unreadable or oversized"
		return p
	}
	p.RawBody = string(body)
	if json.Valid(body) {
		p.Body = body
	} else {
		p.Error = "probe returned non-JSON body"
	}
	p.BodySHA256 = SHA256(body)
	p.AfterCalls, err = count()
	if err != nil {
		p.Error = err.Error()
	}
	return p
}

func collectView(ctx context.Context, f *fixture, clock time.Time) ([]*model.WorkloadView, error) {
	snap, err := ingest.CollectSnapshot(ctx, f.client, clock, nil, f.client)
	if err != nil {
		return nil, err
	}
	if !snap.EventInventoryComplete {
		return nil, errors.New("real event inventory incomplete")
	}
	for _, p := range snap.Pods {
		if p.UID == string(f.pod.UID) {
			return []*model.WorkloadView{{Pod: p, Phase: model.PhaseWarm, Events: ingest.EvidenceEvents(snap.EventByPod[p.Namespace+"/"+p.Name]), OutcomeEvents: snap.EventByPod[p.Namespace+"/"+p.Name], ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: clock.Sub(p.StartedAt), model.VarSession: clock.Sub(p.StartedAt)}}}, nil
		}
	}
	return nil, errors.New("real ingested target missing")
}

func capabilityKey(v *model.WorkloadView, a model.Action, keys []string) string {
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	return v.Pod.UID + "\x00" + string(a) + "\x00" + strings.Join(keys, "\x00")
}
func choose(ctx context.Context, native *actuator.NativeActuator, views []*model.WorkloadView, pol model.Policy, clock time.Time) ([]model.Decision, replayInput, bool, error) {
	e := decision.NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		return nil, replayInput{}, false, errors.New("production UCW profile unavailable")
	}
	e.Recon = profile
	e.Now = func() time.Time { return clock }
	input := replayInput{ReconProfile: profile.Name(), Clock: clock, Policy: pol, Views: views, State: e.ExportOwnerState(pol.Owner()), Capabilities: map[string]capabilityObservation{}}
	e.ShadowCapability = func(v *model.WorkloadView, a model.Action, keys []string) *actionset.Eligibility {
		ok, why := native.SupportsAction(ctx, a, actuator.Target{Namespace: v.Pod.Namespace, Pod: v.Pod.Name, UID: v.Pod.UID, Labels: v.Pod.Labels, PolicyName: pol.PolicyName, PolicyUID: pol.PolicyUID, ServiceAccount: v.Pod.ServiceAccount})
		var el *actionset.Eligibility
		if !ok {
			el = &actionset.Eligibility{Excluded: true, Kind: "capability-unsupported", Detail: why}
		}
		recorded := capabilityObservation{Nil: el == nil}
		if el != nil {
			recorded.Eligibility = *el
		}
		input.Capabilities[capabilityKey(v, a, keys)] = recorded
		return el
	}
	ds, err := e.DecideShadowChecked(views, pol)
	unchanged := reflect.DeepEqual(input.State, e.ExportOwnerState(pol.Owner()))
	if err != nil {
		return ds, input, unchanged, err
	}
	for _, d := range ds {
		if d.Trace == nil {
			return ds, input, unchanged, errors.New("trace missing")
		}
		if err := d.Trace.Validate(); err != nil {
			return ds, input, unchanged, err
		}
		if d.Trace.DualUpdate.Applied {
			return ds, input, unchanged, errors.New("shadow trace claims dual update")
		}
	}
	return ds, input, unchanged, nil
}

func canonicalTraces(ds []model.Decision) ([]byte, error) {
	traces := make([]model.DecisionTraceV2, 0, len(ds))
	for _, d := range ds {
		if d.Trace == nil {
			return nil, errors.New("trace missing")
		}
		if err := d.Trace.Validate(); err != nil {
			return nil, err
		}
		traces = append(traces, d.Trace.Canonical())
	}
	return json.Marshal(traces)
}
func replay(input replayInput, want []model.Decision) (bool, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(input); err != nil {
		return false, err
	}
	var copy replayInput
	if err := gob.NewDecoder(&buf).Decode(&copy); err != nil {
		return false, err
	}
	e := decision.NewCoverageEngine()
	profile, ok := recon.Registry.Get(copy.ReconProfile)
	if !ok {
		return false, errors.New("production UCW profile unavailable")
	}
	e.Recon = profile
	e.Now = func() time.Time { return copy.Clock }
	if err := e.RestoreOwnerState(copy.State); err != nil {
		return false, err
	}
	var missed string
	e.ShadowCapability = func(v *model.WorkloadView, a model.Action, keys []string) *actionset.Eligibility {
		key := capabilityKey(v, a, keys)
		el, ok := copy.Capabilities[key]
		if !ok {
			missed = key
			return &actionset.Eligibility{Excluded: true, Kind: "capability-unsupported", Detail: "unrecorded capability"}
		}
		if el.Nil {
			return nil
		}
		value := el.Eligibility
		return &value
	}
	got, err := e.DecideShadowChecked(copy.Views, copy.Policy)
	if err != nil {
		return false, err
	}
	if missed != "" {
		return false, errors.New("replay consumed an unrecorded capability observation")
	}
	a, err := canonicalTraces(want)
	if err != nil {
		return false, err
	}
	b, err := canonicalTraces(got)
	return bytes.Equal(a, b), err
}
func selected(ds []model.Decision) *model.Decision {
	for i := range ds {
		if ds[i].Selected {
			return &ds[i]
		}
	}
	return nil
}
func unchanged(ctx context.Context, f *fixture, state, journal string, cc *countedClient) error {
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.state), f.state); err != nil {
		return err
	}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.journal), f.journal); err != nil {
		return err
	}
	if f.state.Data[endpointlease.PolicyKey] != state || f.journal.Data[endpointlease.JournalKey] != journal || cc.policyWrites != 0 || cc.journalWrites != 0 {
		return errors.New("refusal control mutated policy or journal")
	}
	return nil
}
func createEvent(ctx context.Context, f *fixture, name string, obs endpointlease.Observation) (*amtdv1beta1.SecurityEvent, error) {
	raw, _ := json.Marshal(obs)
	var generic any
	_ = json.Unmarshal(raw, &generic)
	raw, _ = json.Marshal(generic)
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: string(f.pod.UID), endpointlease.ObservationAnnotation: string(raw)}}, Spec: amtdv1beta1.SecurityEventSpec{Description: "Explicit synthetic accepted credential-reuse probe", Targets: []string{f.pod.Namespace + "/" + f.pod.Name}, Rule: amtdv1beta1.Rule{Type: endpointlease.RuleType, Source: "redteam"}}}
	return event, f.client.Create(ctx, event)
}
func verifyTerminal(ctx context.Context, f *fixture, operation, tick string) error {
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.state), f.state); err != nil {
		return err
	}
	state, err := endpointlease.ParseState(f.state.Data[endpointlease.PolicyKey])
	if err != nil {
		return err
	}
	if state.Revision != 1 || state.LastOperationID != operation || len(state.AllowedClientHMACs) != 1 || state.AllowedClientHMACs[0] != f.bID {
		return errors.New("durable state does not prove exact selected cutover")
	}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.journal), f.journal); err != nil {
		return err
	}
	var doc struct {
		Receipts []struct {
			Phase     string `json:"phase"`
			Operation string `json:"operationID"`
			Decision  string `json:"decisionID"`
			Tick      string `json:"tickID"`
		}
	}
	if err := json.Unmarshal([]byte(f.journal.Data[endpointlease.JournalKey]), &doc); err != nil {
		return err
	}
	if len(doc.Receipts) != 1 || doc.Receipts[0].Phase != "terminal-full" || doc.Receipts[0].Operation != operation || doc.Receipts[0].Decision != operation || doc.Receipts[0].Tick != tick {
		return errors.New("native protected terminal receipt unavailable")
	}
	return nil
}
func artifact(r *Report, dir, name string, raw []byte) error {
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0640); err != nil {
		return err
	}
	r.Artifacts[name] = SHA256(raw)
	return nil
}
func writeAPIArtifacts(ctx context.Context, f *fixture, r *Report, dir string) error {
	var errs []error
	for _, item := range []struct {
		name   string
		object client.Object
	}{{"policy-final.json", f.state}, {"journal-final.json", f.journal}, {"pod-fixture.json", f.pod}, {"selecting-policy.json", f.policy}} {
		err := f.client.Get(ctx, client.ObjectKeyFromObject(item.object), item.object)
		var value any = item.object
		if apierrors.IsNotFound(err) {
			value = map[string]any{"observed_absent": true, "namespace": item.object.GetNamespace(), "name": item.object.GetName()}
		} else if err != nil {
			errs = append(errs, err)
			continue
		}
		raw, err := json.MarshalIndent(value, "", "  ")
		if err == nil {
			err = artifact(r, dir, item.name, raw)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ReplayFile re-evaluates a recorded local snapshot in a fresh shadow brain.
// It opens no API connection and dispatches nothing.
func ReplayFile(path string, want []model.Decision) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var input replayInput
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&input); err != nil {
		return false, err
	}
	return replay(input, want)
}
