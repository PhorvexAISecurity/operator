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

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	if !ValidArm(o.Arm) {
		return report, fmt.Errorf("unknown arm %q", o.Arm)
	}
	if o.Arm != "" && o.Arm != ArmIntervention && (o.SkipDispatch || o.UnavailableAuthority) {
		return report, errors.New("a study arm cannot be combined with a negative control")
	}
	if !ValidScenario(o.Scenario) {
		return report, fmt.Errorf("unknown scenario %q", o.Scenario)
	}
	scenario := o.Scenario
	if scenario == "" {
		scenario = ScenarioLease
	}
	if scenario != ScenarioLease && !studyArm(o.Arm) {
		return report, errors.New("token and combined scenarios run study arms only")
	}
	hasLease, hasToken := scenario != ScenarioToken, scenario != ScenarioLease
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
	report.Scenario = scenario
	f, err := provision(ctx, c, cfg, o.RepoRoot, tmp, scenario)
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
	primary, err := startRuntime(ctx, o, tmp, f.config, "runtime")
	if err != nil {
		return report, err
	}
	defer primary.stop()
	rt := primary.ready
	if rt.Source != f.source {
		return report, errors.New("executing runtime source digest differs")
	}
	var rtPeer ready
	if f.peer != nil {
		peer, err := startRuntime(ctx, o, tmp, f.peerConfig, "runtime-b")
		if err != nil {
			return report, err
		}
		defer peer.stop()
		if rtPeer = peer.ready; rtPeer.Source != f.source {
			return report, errors.New("executing peer runtime source digest differs")
		}
		report.Limitations = append(report.Limitations, "Two replicas run two instances of the shipped admission runtime, one per Pod identity, reading the same lease policy. The stolen Pod-bound bearer is minted by TokenRequest bound to the target Pod's UID, as the kubelet projection binds it, and replayed at the private API server; that API server's authentication cache is the production default.")
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
	statusHosts := map[string]string{fixturePodIP + ":8443": adminURL.Host}
	if f.peer != nil {
		peerAdmin, err := url.Parse(rtPeer.AdminURL)
		if err != nil {
			return report, err
		}
		statusHosts[fixturePeerIP+":8443"] = peerAdmin.Host
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: tlsName}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, ok := statusHosts[address]
		if !ok {
			return nil, fmt.Errorf("unexpected status destination %s", address)
		}
		return dialer.DialContext(ctx, network, host)
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
	// The token attacker exfiltrates the target Pod's bound bearer before any detection.
	var tokenClient kubernetes.Interface
	if hasToken {
		admin, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return report, err
		}
		stolen, err := stealPodBoundToken(ctx, admin, f.pod)
		if err != nil {
			return report, err
		}
		tc := rest.AnonymousClientConfig(cfg)
		tc.BearerToken, tc.Timeout = stolen, 5*time.Second
		if tokenClient, err = kubernetes.NewForConfig(tc); err != nil {
			return report, err
		}
		t := performTokenProbe(ctx, tokenClient, "attack-baseline-T")
		report.Probes = append(report.Probes, t)
		if t.Status != http.StatusCreated {
			report.Verdict = "NOT_LANDED"
			return report, errors.New("stolen Pod-bound bearer did not authenticate before the decision")
		}
	}
	var event *amtdv1beta1.SecurityEvent
	var obs endpointlease.Observation
	if hasLease {
		live, err := endpointlease.ValidateLive(ctx, c, string(f.pod.UID), f.source, f.proxyImage, f.engineImage)
		if err != nil {
			return report, err
		}
		obs = endpointlease.Observation{Version: 1, ScenarioID: "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED", PolicyName: pol.PolicyName, PolicyUID: pol.PolicyUID, PolicyGeneration: pol.PolicyGeneration, TargetPodUID: string(f.pod.UID), ServiceUID: live.ServiceUID, PolicyConfigMapUID: live.PolicyUID, ProxySourceSHA256: f.source, SecretUID: live.SecretUID, SeedSHA256: live.SeedSHA256, PriorRevision: live.State.Revision, RevokedClientHMAC: f.aID, RetainedClientHMAC: f.bID, AcceptedStatus: a.Status, AcceptedResponseSHA256: a.BodySHA256, RetainedBaselineStatus: b.Status, RetainedBaselineResponseSHA256: b.BodySHA256, ObservedAt: time.Now().UTC()}
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
	}
	if hasToken {
		tokenEvent, err := createTokenEvent(ctx, f, "accepted-pod-bound-token")
		if err != nil {
			return report, err
		}
		raw, _ := json.MarshalIndent(tokenEvent, "", "  ")
		if err = artifact(report, o.OutputDir, "token-security-event.json", raw); err != nil {
			return report, err
		}
	}
	if hasLease {
		obs.ObservedAt = time.Now().UTC()
		if event, err = createEvent(ctx, f, "accepted-lease-probe", obs); err != nil {
			return report, err
		}
		eventRaw, _ := json.MarshalIndent(event, "", "  ")
		if err = artifact(report, o.OutputDir, "security-event.json", eventRaw); err != nil {
			return report, err
		}
	}
	clock = time.Now().UTC()
	report.DecisionClock = clock
	views, err = collectView(ctx, f, clock)
	if err != nil {
		return report, err
	}
	if len(views) != 1 || hasLease && !views[0].Pod.HasBoundEndpointLeaseObservation() {
		return report, errors.New("fresh trusted real SecurityEvent did not bind typed lease evidence")
	}
	if hasToken && !podBoundTokenBound(views[0]) {
		return report, errors.New("fresh trusted Pod-bound token event did not bind to the projected capability")
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
	if scenario == ScenarioLease {
		if chosen == nil {
			report.Verdict = "DECLINED"
			stage("normal-brain-selection", false, "Brain declined; no action dispatched")
			return report, errors.New("normal brain declined the confirmed attack")
		}
		if chosen.Action != model.ActionEndpointLeaseRevoke || !chosen.Feasible || chosen.DryRun || chosen.Trace == nil {
			return report, fmt.Errorf("normal brain selected an unexpected or infeasible action: %s", chosen.Action)
		}
	} else if chosen != nil && (!chosen.Feasible || chosen.DryRun || chosen.Trace == nil) {
		return report, fmt.Errorf("normal brain selected an infeasible action: %s", chosen.Action)
	}
	// Study scenarios beyond the reviewed lease case record whatever the brain selects.
	trace := firstTrace(report.Decisions)
	if chosen != nil {
		trace = chosen.Trace
		stage("normal-brain-selection", true, chosen.Reason)
	} else {
		stage("normal-brain-selection", false, "Brain declined; study arms still branch from this decision")
	}
	if trace == nil {
		return report, errors.New("decision trace unavailable")
	}
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
	req := actuator.Request{Tenant: pol.Tenant, Namespace: views[0].Pod.Namespace, Pod: views[0].Pod.Name, TargetUID: views[0].Pod.UID, OperationID: trace.DecisionID, TickID: trace.TickID, PolicyName: pol.PolicyName, PolicyUID: pol.PolicyUID, PolicyGeneration: pol.PolicyGeneration, EndpointLeaseObservation: viewObs}
	if chosen != nil {
		req.Action, req.Reason = chosen.Action, chosen.Reason
	}
	if hasLease && (viewObs == nil || viewObs.EventUID != string(event.UID)) {
		return report, errors.New("selected observation event identity differs")
	}
	// Two-replica probes name the runtime that served them; the one-replica case is unchanged.
	tag := func(p Probe, replica string) Probe {
		if f.peer != nil {
			p.Replica = replica
		}
		return p
	}
	// reobserve asks the unchanged brain what it sees on the same pod after a branch: which facts
	// it still mints (claimed invalidation) and what it would select now.
	reobserve := func() {
		uid := string(f.pod.UID)
		report.PostTarget = "same pod " + f.pod.Namespace + "/" + f.pod.Name + " uid=" + uid
		if report.StudyAction == string(model.ActionRotate) && report.Dispatch != nil && report.Dispatch.Emitted {
			// The evicted pod is gone; observe the workload where production would: its replacement.
			replacement, err := replaceEvictedPod(ctx, f)
			if err != nil {
				report.PostObservationError = "replacement: " + err.Error()
				return
			}
			uid = string(replacement.UID)
			report.PostTarget = "harness-simulated ReplicaSet replacement " + replacement.Namespace + "/" + replacement.Name + " uid=" + uid
			serving := rt
			if f.peer != nil {
				serving = rtPeer // the evicted Pod's own runtime no longer serves
			}
			report.Probes = append(report.Probes, tag(performProbe(ctx, serving, f.admin, "A-after-replacement", f.a), "b"), tag(performProbe(ctx, serving, f.admin, "B-after-replacement", f.b), "b"))
			if tokenClient != nil {
				report.Probes = append(report.Probes, performTokenProbe(ctx, tokenClient, "T-after-replacement"))
			}
		}
		report.PostDecisionClock = time.Now().UTC()
		postViews, err := collectViewOf(ctx, f, uid, report.PostDecisionClock)
		if err != nil {
			report.PostObservationError = err.Error()
			return
		}
		if len(postViews) == 0 {
			report.PostObservationError = "no view of the target pod after the branch"
			return
		}
		post, _, _, err := choose(ctx, native, postViews, pol, report.PostDecisionClock)
		if err != nil {
			report.PostObservationError = err.Error()
			return
		}
		report.PostDecisions = post
	}
	if studyArm(o.Arm) {
		// Security Gain validation branch: the same fresh episode up to the brain's decision,
		// then the selected, a competing, or no action. Probes are recorded, never asserted.
		report.Arm = o.Arm
		retired := false // with two replicas, the evicted Pod's runtime stops serving
		recordRound := func(suffix string) {
			if f.peer == nil || !retired {
				report.Probes = append(report.Probes, tag(performProbe(ctx, rt, f.admin, "A-"+suffix, f.a), "a"), tag(performProbe(ctx, rt, f.admin, "B-"+suffix, f.b), "a"))
			}
			if f.peer != nil {
				report.Probes = append(report.Probes, tag(performProbe(ctx, rtPeer, f.admin, "A-"+suffix, f.a), "b"), tag(performProbe(ctx, rtPeer, f.admin, "B-"+suffix, f.b), "b"))
			}
			if tokenClient != nil {
				report.Probes = append(report.Probes, performTokenProbe(ctx, tokenClient, "T-"+suffix))
			}
		}
		var action model.Action
		switch o.Arm {
		case ArmSelected:
			action = req.Action // empty when the brain declined
		case ArmCFRotate:
			action = model.ActionRotate
		case ArmCFEndpointRotate:
			action = model.ActionEndpointRotate
		case ArmCFEndpointLeaseRevoke:
			action = model.ActionEndpointLeaseRevoke
		}
		switch {
		case o.Arm == ArmBaseline:
			stage("study-baseline-no-dispatch", true, "The brain selected "+string(req.Action)+"; this branch withholds every action")
		case action == "":
			stage("study-selected-declined", true, "The brain declined; nothing to dispatch")
		default:
			report.StudyAction = string(action)
			dispatch := req
			dispatch.Action = action
			stageName := "study-selected-dispatch"
			if o.Arm != ArmSelected {
				stageName = "study-counterfactual-dispatch"
				report.CounterfactualAction = string(action)
				dispatch.OperationID = req.OperationID + "-counterfactual-" + string(action)
				dispatch.Reason = "Security Gain validation counterfactual: " + string(action) + " instead of the selected " + string(req.Action)
			}
			// A native rotate requires the selecting policy's own effective grace cap,
			// exactly as the manager would resolve it.
			if action == model.ActionRotate {
				if graceCap, capErr := f.policy.Spec.EffectiveMaxGracePeriodSeconds(); capErr == nil {
					dispatch.MaxGracePeriodSeconds = graceCap
				}
			}
			report.DispatchStartedAt = time.Now().UTC()
			result, dispatchErr := native.Actuate(ctx, dispatch)
			report.DispatchFinishedAt = time.Now().UTC()
			report.Dispatch = &result
			detail := fmt.Sprintf("emitted=%v handler=%s", result.Emitted, result.Handler)
			if dispatchErr != nil {
				detail += "; " + dispatchErr.Error()
			}
			stage(stageName, dispatchErr == nil && result.Emitted, detail)
			retired = action == model.ActionRotate && result.Emitted
		}
		holdStart := time.Now()
		for {
			recordRound("study-hold")
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
		reobserve()
		if err = writeAPIArtifacts(ctx, f, report, o.OutputDir); err != nil {
			return report, err
		}
		report.Verdict = "STUDY_ARM_RECORDED"
		return report, nil
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
	if o.Arm == ArmIntervention {
		report.Arm = ArmIntervention
	}
	reobserve()
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

// runtimeProcess is one instance of the shipped Python admission runtime.
type runtimeProcess struct {
	ready ready
	stop  func()
}

func startRuntime(ctx context.Context, o Options, tmp string, config map[string]any, name string) (*runtimeProcess, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	configPath, err := privateFile(tmp, name+"-config.json", raw)
	if err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(filepath.Join(o.OutputDir, name+".log"), os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, o.Python, filepath.Join(o.RepoRoot, "build/test-harness/fixtures/verification-loop/runtime_fixture.py"), "--config", configPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err = cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	processDone := make(chan error, 1)
	go func() { processDone <- cmd.Wait() }()
	stop := func() {
		defer logFile.Close()
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
	}
	p := &runtimeProcess{stop: stop}
	if err = waitReady(ctx, processDone, config["ready_file"].(string), &p.ready); err != nil {
		stop()
		return nil, err
	}
	return p, nil
}

// stealPodBoundToken mints exactly the bearer the kubelet projects into the target Pod:
// default API audience, bound to that Pod's UID. It stands for a token exfiltrated from it.
func stealPodBoundToken(ctx context.Context, cs kubernetes.Interface, pod *corev1.Pod) (string, error) {
	expiry := int64(3607)
	tr, err := cs.CoreV1().ServiceAccounts(pod.Namespace).CreateToken(ctx, pod.Spec.ServiceAccountName, &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &expiry, BoundObjectRef: &authnv1.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: pod.Name, UID: pod.UID}}}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	if tr.Status.Token == "" {
		return "", errors.New("bound token request returned no bearer")
	}
	return tr.Status.Token, nil
}

// performTokenProbe replays the stolen bearer at the private API server. Success is
// authentication as the Pod's ServiceAccount (201); denial is the API server's exact 401.
func performTokenProbe(ctx context.Context, cs kubernetes.Interface, name string) Probe {
	p := Probe{Name: name, At: time.Now().UTC(), Capability: CapabilityPodBoundToken}
	start := time.Now()
	p.RequestStartedAt = start.UTC()
	review, err := cs.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	p.RequestFinishedAt = time.Now().UTC()
	p.LatencyMS = float64(time.Since(start)) / float64(time.Millisecond)
	var body map[string]any
	switch {
	case err == nil:
		p.Status, body = http.StatusCreated, map[string]any{"authenticated": true, "username": review.Status.UserInfo.Username}
	case apierrors.IsUnauthorized(err):
		p.Status, body = http.StatusUnauthorized, map[string]any{"error": "unauthorized"}
	default:
		p.Error = err.Error()
		return p
	}
	raw, _ := json.Marshal(body)
	p.Body, p.RawBody, p.BodySHA256 = raw, string(raw), SHA256(raw)
	return p
}

func createTokenEvent(ctx context.Context, f *fixture, name string) (*amtdv1beta1.SecurityEvent, error) {
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: string(f.pod.UID)}}, Spec: amtdv1beta1.SecurityEventSpec{Description: "Explicit synthetic Pod-bound API bearer observation", Targets: []string{f.pod.Namespace + "/" + f.pod.Name}, Rule: amtdv1beta1.Rule{Type: model.AttackVectorPodBoundAPIAuth, ThreatLevel: "critical", Source: "PhorvexE2EDetector"}}}
	return event, f.client.Create(ctx, event)
}

// podBoundTokenBound reports whether ingestion projected the token capability and the
// trusted typed event is eligible to steer it, as the recon profile requires.
func podBoundTokenBound(v *model.WorkloadView) bool {
	if !v.Pod.HasPodBoundKubeAPIAuth() {
		return false
	}
	for _, e := range v.Events {
		if model.PodBoundAPIAuthEventEligible(e, v.Pod, 0) {
			return true
		}
	}
	return false
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
	return collectViewOf(ctx, f, string(f.pod.UID), clock)
}

func collectViewOf(ctx context.Context, f *fixture, uid string, clock time.Time) ([]*model.WorkloadView, error) {
	snap, err := ingest.CollectSnapshot(ctx, f.client, clock, nil, f.client)
	if err != nil {
		return nil, err
	}
	if !snap.EventInventoryComplete {
		return nil, errors.New("real event inventory incomplete")
	}
	for _, p := range snap.Pods {
		if p.UID == uid {
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
func firstTrace(ds []model.Decision) *model.DecisionTraceV2 {
	for i := range ds {
		if ds[i].Trace != nil {
			return ds[i].Trace
		}
	}
	return nil
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
