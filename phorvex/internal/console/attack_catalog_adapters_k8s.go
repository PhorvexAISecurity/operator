package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	k8sCataloguePhysicalSchema = "phorvex.attack-catalogue-k8s-physical.v1"
	k8sCatalogueCleanupSchema  = "phorvex.attack-catalogue-k8s-cleanup.v1"

	k8sCatalogueFamilyQuarantine     = "quarantine"
	k8sCatalogueFamilyPodRotate      = "pod-rotate"
	k8sCatalogueFamilyControllerStop = "controller-stop"

	k8sCatalogueQuarantineOracle = "k8s-pod-quarantine.v1"
	k8sCatalogueRotateOracle     = "k8s-pod-uid-rotation.v1"
	k8sCatalogueControllerOracle = "k8s-controller-stop-rotate-eviction.v1"
)

// These IDs are the reviewed membership in the embedded catalogue and the
// matching fires.d farm specifications. Keeping the set explicit prevents a new
// metadata row from silently acquiring launch authority through a family label.
var k8sCatalogueIDs = map[string][]string{
	k8sCatalogueFamilyQuarantine: {
		"AML.T0025", "AML.T0049", "AML.T0050", "AML.T0085", "AML.T0085.000", "AML.T0085.001",
		"AML.T0119", "AML.T0122", "ASI05:2026", "MCP05:2025", "MS-EX-application-exploit-(r",
		"MS-EX-bashcmd-inside-contain", "MS-IM-resource-hijacking", "MS-IN-application-vulnerabil",
		"MS-LA-arp-poisoning-and-ip-s", "MS-LA-cluster-internal-netwo", "T1059", "T1059.001",
		"T1059.004", "T1059.005", "T1059.006", "T1059.007", "T1059.011", "T1068", "T1133",
		"T1190", "T1204", "T1204.001", "T1204.002", "T1204.004", "T1496", "T1496.001", "T1496.002",
	},
	k8sCatalogueFamilyPodRotate: {
		"MS-DE-clear-container-logs", "MS-EX-ssh-server-running-ins", "T1036.002", "T1036.003",
		"T1036.006", "T1036.008", "T1036.009", "T1036.011", "T1053", "T1053.002", "T1053.003",
		"T1053.006", "T1070", "T1070.003", "T1070.004", "T1070.006", "T1070.007", "T1070.009",
		"T1070.010", "T1078.003", "T1098.004", "T1098.007", "T1136.001", "T1499.004", "T1543",
		"T1685", "T1685.003",
	},
	k8sCatalogueFamilyControllerStop: {
		"AML.T0074", "AML.T0103", "ASI10:2026", "MCP09:2025", "MS-DE-pod-or-container-name-",
		"MS-EX-new-container", "T1036", "T1036.004", "T1036.005", "T1610",
	},
}

type k8sCatalogueProfile struct {
	Key              string
	Family           string
	Lane             string
	Namespace        string
	Deployment       string
	Service          string
	PolicyName       string
	Selector         string
	ExpectedAction   string
	NativeAction     string
	EnabledActions   []string
	DetectorIdentity string
	Oracle           string
	MinReady         int
	MinAvailable     int
	TargetMinAge     time.Duration
}

func k8sCatalogueProfileForFamily(family string) (k8sCatalogueProfile, error) {
	base := k8sCatalogueProfile{Deployment: "demo-api", Service: "demo-api", PolicyName: "demo-api-defense",
		Selector: "app.kubernetes.io/name=demo-api", MinReady: 3, MinAvailable: 2}
	switch family {
	case k8sCatalogueFamilyQuarantine:
		base.Key, base.Family, base.Lane, base.Namespace = "farm-p1-quarantine-v1", family, "p1", "p1-demo"
		base.ExpectedAction, base.NativeAction = string(model.ActionQuarantine), string(model.ActionQuarantine)
		base.EnabledActions = []string{string(model.ActionRotate), string(model.ActionQuarantine)}
		base.Oracle = k8sCatalogueQuarantineOracle
	case k8sCatalogueFamilyPodRotate:
		base.Key, base.Family, base.Lane, base.Namespace = "farm-p2-pod-rotate-v1", family, "p2", "p2-demo"
		base.ExpectedAction, base.NativeAction = string(model.ActionRotate), string(model.ActionRotate)
		base.EnabledActions = []string{string(model.ActionRotate)}
		base.Oracle, base.TargetMinAge = k8sCatalogueRotateOracle, 100*time.Second
	case k8sCatalogueFamilyControllerStop:
		base.Key, base.Family, base.Lane, base.Namespace = "farm-p4-controller-stop-v1", family, "p4", "p4-demo"
		// The reviewed bucket calls the outcome controller-stop. Its proven
		// product primitive is native rotate (accepted Pod Eviction), not the
		// unrelated attacker-controller retirement action of the same name.
		base.ExpectedAction, base.NativeAction = string(model.ActionControllerStop), string(model.ActionRotate)
		base.EnabledActions = []string{string(model.ActionRotate)}
		base.Oracle, base.TargetMinAge = k8sCatalogueControllerOracle, 100*time.Second
	default:
		return k8sCatalogueProfile{}, fmt.Errorf("unsupported Kubernetes catalogue family %q", family)
	}
	base.DetectorIdentity = "system:serviceaccount:" + base.Lane + ":" + base.Lane + "-attacks"
	return base, nil
}

func (p k8sCatalogueProfile) validate() error {
	want, err := k8sCatalogueProfileForFamily(p.Family)
	if err != nil {
		return err
	}
	if p.Key != want.Key || p.Lane != want.Lane || p.Namespace != want.Namespace || p.Deployment != want.Deployment ||
		p.Service != want.Service || p.PolicyName != want.PolicyName || p.Selector != want.Selector ||
		p.ExpectedAction != want.ExpectedAction || p.NativeAction != want.NativeAction ||
		p.DetectorIdentity != want.DetectorIdentity || p.Oracle != want.Oracle || p.MinReady != want.MinReady ||
		p.MinAvailable != want.MinAvailable || p.TargetMinAge != want.TargetMinAge ||
		!slices.Equal(p.EnabledActions, want.EnabledActions) {
		return fmt.Errorf("Kubernetes catalogue profile %q differs from its reviewed fixed profile", p.Key)
	}
	return nil
}

func k8sCatalogueIDAllowed(family, id string) bool {
	return slices.Contains(k8sCatalogueIDs[family], id)
}

func validateK8sCatalogueBinding(entry attackcatalog.Entry, profile k8sCatalogueProfile) error {
	if err := profile.validate(); err != nil {
		return err
	}
	if !k8sCatalogueIDAllowed(profile.Family, entry.ID) || entry.Family != profile.Family ||
		entry.ExpectedAction != profile.ExpectedAction || entry.Mode != "lane" || entry.Lane != profile.Lane ||
		entry.Expected != "DEFENDED" || !entry.ReactiveCompatible || strings.TrimSpace(entry.EventType) == "" {
		return fmt.Errorf("catalogue ID %q does not match fixed Kubernetes profile %q", entry.ID, profile.Key)
	}
	return nil
}

type k8sCatalogueClusterFactory func(k8sCatalogueProfile) (k8sCatalogueCluster, error)

// newK8sCatalogueAdapters constructs the 70 reviewed exact-ID adapters for the
// central registry. Metadata alone never invokes it.
func newK8sCatalogueAdapters(s *Server, cfg Config) ([]AttackCatalogAdapter, error) {
	return newK8sCatalogueAdaptersWithFactory(s, cfg, func(profile k8sCatalogueProfile) (k8sCatalogueCluster, error) {
		return newKubernetesK8sCatalogueCluster(cfg, profile)
	})
}

func newK8sCatalogueAdaptersWithFactory(s *Server, cfg Config, factory k8sCatalogueClusterFactory) ([]AttackCatalogAdapter, error) {
	if factory == nil {
		return nil, errors.New("Kubernetes catalogue cluster factory is required")
	}
	entries, err := attackcatalog.Entries()
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for family, ids := range k8sCatalogueIDs {
		for _, id := range ids {
			if allowed[id] {
				return nil, fmt.Errorf("Kubernetes catalogue ID %q is assigned to more than one family", id)
			}
			allowed[id] = true
		}
		if _, err = k8sCatalogueProfileForFamily(family); err != nil {
			return nil, err
		}
	}
	out := make([]AttackCatalogAdapter, 0, len(allowed))
	for _, entry := range entries {
		if !allowed[entry.ID] {
			continue
		}
		profile, profileErr := k8sCatalogueProfileForFamily(entry.Family)
		if profileErr != nil {
			return nil, profileErr
		}
		if profileErr = validateK8sCatalogueBinding(entry, profile); profileErr != nil {
			return nil, profileErr
		}
		out = append(out, &k8sAttackCatalogAdapter{server: s, cfg: cfg, entry: entry, profile: profile, clusterFactory: factory})
		delete(allowed, entry.ID)
	}
	if len(out) != 70 || len(allowed) != 0 {
		return nil, fmt.Errorf("Kubernetes catalogue adapter coverage changed: built=%d missing=%d", len(out), len(allowed))
	}
	return out, nil
}

type k8sCatalogueSignal struct {
	Name      string
	UID       string
	Creator   string
	CreatedAt time.Time
}

type k8sCataloguePodIdentity struct {
	Name      string    `json:"name"`
	UID       string    `json:"uid"`
	StartTime time.Time `json:"startTime"`
}

type k8sCatalogueFixture struct {
	CatalogueID       string
	ProfileKey        string
	Namespace         string
	NamespaceUID      string
	DeploymentUID     string
	ServiceUID        string
	PolicyName        string
	PolicyUID         string
	PolicyGeneration  int64
	ExecutionMode     AttackCatalogExecutionMode
	ReactiveOnly      bool
	Target            k8sCataloguePodIdentity
	BaselineReadyPods []k8sCataloguePodIdentity
	SiblingUIDs       []string
	NetworkPolicyName string
}

func (f k8sCatalogueFixture) validate(entry attackcatalog.Entry, profile k8sCatalogueProfile) error {
	if err := validateK8sCatalogueBinding(entry, profile); err != nil {
		return err
	}
	if f.CatalogueID != entry.ID || f.ProfileKey != profile.Key || f.Namespace != profile.Namespace ||
		f.NamespaceUID == "" || f.DeploymentUID == "" || f.ServiceUID == "" || f.PolicyName != profile.PolicyName ||
		f.PolicyUID == "" || f.PolicyGeneration < 1 || f.Target.Name == "" || f.Target.UID == "" || f.Target.StartTime.IsZero() ||
		len(f.BaselineReadyPods) < profile.MinReady || len(f.SiblingUIDs) != len(f.BaselineReadyPods)-1 ||
		(f.ExecutionMode != AttackCatalogExecutionActive && f.ExecutionMode != AttackCatalogExecutionDryRun) {
		return errors.New("Kubernetes catalogue preflight returned an incomplete or substituted fixture")
	}
	seenTarget := 0
	seen := map[string]bool{}
	for _, pod := range f.BaselineReadyPods {
		if pod.Name == "" || pod.UID == "" || pod.StartTime.IsZero() || seen[pod.UID] {
			return errors.New("Kubernetes catalogue preflight returned invalid baseline Pod identities")
		}
		seen[pod.UID] = true
		if pod.UID == f.Target.UID && pod.Name == f.Target.Name {
			seenTarget++
		}
	}
	if seenTarget != 1 {
		return errors.New("Kubernetes catalogue target is not one exact baseline Pod")
	}
	for _, uid := range f.SiblingUIDs {
		if uid == f.Target.UID || !seen[uid] {
			return errors.New("Kubernetes catalogue sibling identity differs from the baseline")
		}
	}
	if profile.Family == k8sCatalogueFamilyQuarantine && f.NetworkPolicyName == "" {
		return errors.New("quarantine preflight returned no exact NetworkPolicy identity")
	}
	return nil
}

type k8sCatalogueCluster interface {
	Preflight(context.Context, attackcatalog.Entry, k8sCatalogueProfile) (k8sCatalogueFixture, error)
	CreateSignal(context.Context, attackcatalog.Entry, k8sCatalogueProfile, k8sCatalogueFixture, string) (k8sCatalogueSignal, error)
	Physical(context.Context, attackcatalog.Entry, k8sCatalogueProfile, k8sCatalogueFixture, k8sCatalogueSignal) (AttackCatalogPhysicalResult, error)
	Cleanup(context.Context, attackcatalog.Entry, k8sCatalogueProfile, k8sCatalogueFixture, k8sCatalogueSignal, string, string) AttackCatalogCleanupResult
}

// k8sCatalogueRetryVerifier is the read-only cluster oracle used only to release
// a stale single-active-run gate. It never mutates cleanup state and never
// contributes to a DEFENDED verdict.
type k8sCatalogueRetryVerifier interface {
	ReconcileRetrySafety(context.Context, attackcatalog.Entry, k8sCatalogueProfile, AttackCatalogResult) (AttackCatalogRetrySafety, error)
}

type k8sCataloguePreparation struct {
	entry      attackcatalog.Entry
	profile    k8sCatalogueProfile
	cluster    k8sCatalogueCluster
	fixture    k8sCatalogueFixture
	signal     k8sCatalogueSignal
	decisionID string
}

func (p *k8sCataloguePreparation) ExecutionMode() AttackCatalogExecutionMode {
	return p.fixture.ExecutionMode
}

func (p *k8sCataloguePreparation) TriggerMode() AttackCatalogTriggerMode {
	if p.fixture.ReactiveOnly {
		return AttackCatalogTriggerReactive
	}
	return AttackCatalogTriggerProactiveReactive
}

func (p *k8sCataloguePreparation) EvidenceTenant() string { return p.fixture.Namespace }

type k8sAttackCatalogAdapter struct {
	server         *Server
	cfg            Config
	entry          attackcatalog.Entry
	profile        k8sCatalogueProfile
	clusterFactory k8sCatalogueClusterFactory
}

func (a *k8sAttackCatalogAdapter) CatalogueID() string { return a.entry.ID }

func (a *k8sAttackCatalogAdapter) Availability() AttackCatalogAdapterAvailability {
	availability := AttackCatalogAdapterAvailability{TargetLabel: a.profile.Key + " (server-fixed)", FixtureTenant: a.profile.Namespace,
		UnavailableReason: fmt.Sprintf("%s reviewed Kubernetes profile is unavailable in this deployment.", a.entry.ID)}
	if validateK8sCatalogueBinding(a.entry, a.profile) != nil || !a.cfg.AttackCatalogEnabled {
		return availability
	}
	if a.cfg.Service == ServiceConsole {
		availability.UnavailableReason = fmt.Sprintf("%s is served by the attacks service; no attacks-service runtime is active here.", a.entry.ID)
		return availability
	}
	if a.cfg.AuditSource == nil || a.cfg.AttackCatalogAuthorizationTenant == "" {
		return availability
	}
	availability.Available = true
	availability.UnavailableReason = ""
	availability.RuntimeContext = defaultTargetID
	availability.RunnableNote = fmt.Sprintf("Server-fixed %s/%s validation; all profile and workload identities are re-read before signal creation.", a.profile.Lane, a.profile.Family)
	return availability
}

func (a *k8sAttackCatalogAdapter) Destination() (runDestination, error) {
	if err := validateK8sCatalogueBinding(a.entry, a.profile); err != nil {
		return runDestination{}, err
	}
	if a.cfg.AttackCatalogAuthorizationTenant == "" {
		return runDestination{}, fmt.Errorf("%s Kubernetes catalogue authorization destination is unavailable", a.entry.ID)
	}
	if a.cfg.Service != ServiceConsole && (!a.cfg.AttackCatalogEnabled || a.cfg.AuditSource == nil) {
		return runDestination{}, fmt.Errorf("%s Kubernetes catalogue adapter is unavailable in this attacks-service deployment", a.entry.ID)
	}
	if a.cfg.Service == ServiceConsole && a.cfg.AttacksURL == "" {
		return runDestination{}, fmt.Errorf("%s attacks-service proxy destination is unavailable", a.entry.ID)
	}
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{a.cfg.AttackCatalogAuthorizationTenant},
		ScopeTarget: defaultTargetID, ScopeTenant: a.cfg.AttackCatalogAuthorizationTenant}, nil
}

func (a *k8sAttackCatalogAdapter) Preflight(ctx context.Context, run AttackCatalogRunContext) (AttackCatalogPreparation, error) {
	if run.CatalogueID != a.entry.ID || run.ExpectedAction != a.entry.ExpectedAction || run.ReactiveCompatible != a.entry.ReactiveCompatible {
		return nil, fmt.Errorf("%s adapter received a substituted catalogue identity", a.entry.ID)
	}
	if err := validateK8sCatalogueBinding(a.entry, a.profile); err != nil {
		return nil, err
	}
	if a.server == nil || a.clusterFactory == nil {
		return nil, fmt.Errorf("%s Kubernetes catalogue runtime is unavailable", a.entry.ID)
	}
	cluster, err := a.clusterFactory(a.profile)
	if err != nil {
		return nil, err
	}
	fixture, err := cluster.Preflight(ctx, a.entry, a.profile)
	if err != nil {
		return nil, err
	}
	if err = fixture.validate(a.entry, a.profile); err != nil {
		return nil, err
	}
	return &k8sCataloguePreparation{entry: a.entry, profile: a.profile, cluster: cluster, fixture: fixture}, nil
}

func (a *k8sAttackCatalogAdapter) Execute(ctx context.Context, run AttackCatalogRunContext, prepared AttackCatalogPreparation) (AttackCatalogObservation, error) {
	p, ok := prepared.(*k8sCataloguePreparation)
	if !ok || p == nil || p.cluster == nil || p.entry != a.entry || p.profile.Key != a.profile.Key ||
		run.CatalogueID != a.entry.ID || run.ExpectedAction != a.entry.ExpectedAction ||
		run.ReactiveCompatible != a.entry.ReactiveCompatible {
		return AttackCatalogObservation{}, fmt.Errorf("%s preflight state or exact ID binding changed", a.entry.ID)
	}
	if err := p.fixture.validate(a.entry, a.profile); err != nil {
		return AttackCatalogObservation{}, err
	}
	observation := AttackCatalogObservation{Reason: "bounded Kubernetes family validation did not complete before its deadline"}
	// Create is the first mutation. Mark it before the call so an ambiguous
	// transport outcome is always reconciled by the exact cleanup path.
	observation.MutationStarted = true
	signal, err := p.cluster.CreateSignal(ctx, a.entry, a.profile, p.fixture, run.RunID)
	p.signal = signal
	if err != nil {
		return observation, err
	}
	observation.Launched = true
	observation.Signal = AttackCatalogSignalResult{Created: true, Name: signal.Name, UID: signal.UID,
		Creator: signal.Creator, TargetUID: p.fixture.Target.UID, CreatedAt: attackCatalogTime(signal.CreatedAt)}
	interval := a.cfg.AttackCatalogPollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		rows, auditErr := a.server.readAttackCatalogAudit(ctx)
		if auditErr == nil {
			for _, row := range rows {
				observed, decision, actuator := k8sCatalogueDecision(row, p)
				if !observed {
					continue
				}
				observation.Signal.Observed = true
				if !observation.Actuator.ReceiptObserved || actuator.ReceiptObserved {
					observation.Decision, observation.Actuator = decision, actuator
				}
				if actuator.ReceiptObserved {
					p.decisionID = decision.ID
				}
			}
		}
		physical, physicalErr := p.cluster.Physical(ctx, a.entry, a.profile, p.fixture, p.signal)
		if physicalErr == nil {
			observation.PhysicalValidation = physical
		}
		if observation.Signal.Observed && observation.Actuator.ReceiptObserved && observation.PhysicalValidation.Validated {
			observation.DefensiveChainComplete = true
			return observation, nil
		}
		if p.fixture.ExecutionMode == AttackCatalogExecutionDryRun && observation.Signal.Observed {
			observation.Reason = "dry-run decision was observed without an accepted actuator receipt"
			return observation, nil
		}
		select {
		case <-ctx.Done():
			switch {
			case observation.Actuator.ReceiptObserved && !observation.PhysicalValidation.Validated:
				observation.Reason = "accepted actuator receipt was observed but the Kubernetes family physical oracle did not pass"
			case observation.Signal.Created && !observation.Signal.Observed:
				observation.Reason = "signal was admitted but no exact event-bound decision was observed"
			}
			return observation, nil
		case <-ticker.C:
		}
	}
}

func (a *k8sAttackCatalogAdapter) Cleanup(ctx context.Context, run AttackCatalogRunContext, prepared AttackCatalogPreparation) AttackCatalogCleanupResult {
	p, ok := prepared.(*k8sCataloguePreparation)
	if !ok || p == nil || p.cluster == nil || run.CatalogueID != a.entry.ID || run.ExpectedAction != a.entry.ExpectedAction ||
		run.ReactiveCompatible != a.entry.ReactiveCompatible || p.entry != a.entry || p.profile.Key != a.profile.Key {
		return AttackCatalogCleanupResult{Attempted: true, Reason: fmt.Sprintf("%s exact cleanup state changed", a.entry.ID)}
	}
	return p.cluster.Cleanup(ctx, a.entry, a.profile, p.fixture, p.signal, p.decisionID, run.RunID)
}

func (a *k8sAttackCatalogAdapter) supportsRetryReconcile() bool {
	return a != nil && a.clusterFactory != nil && validateK8sCatalogueBinding(a.entry, a.profile) == nil
}

// ReconcileRetrySafety independently re-reads the fixed Kubernetes fixture and
// the prior run's exact identities. A clean answer only releases the retry gate;
// the historical verdict and evidence remain unchanged.
func (a *k8sAttackCatalogAdapter) ReconcileRetrySafety(ctx context.Context, persisted AttackCatalogResult) (AttackCatalogRetrySafety, error) {
	safety := AttackCatalogRetrySafety{CheckedAt: time.Now().UTC()}
	if !a.supportsRetryReconcile() || persisted.CatalogueID != a.entry.ID || persisted.Family != a.profile.Family || persisted.RunID == "" {
		return safety, errors.New("Kubernetes catalogue retry reconciliation binding is invalid")
	}
	cluster, err := a.clusterFactory(a.profile)
	if err != nil {
		return safety, err
	}
	verifier, ok := cluster.(k8sCatalogueRetryVerifier)
	if !ok {
		return safety, errors.New("Kubernetes catalogue cluster has no read-only retry verifier")
	}
	return verifier.ReconcileRetrySafety(ctx, a.entry, a.profile, persisted)
}

func (a *k8sAttackCatalogAdapter) ValidateDefended(result AttackCatalogResult) error {
	if err := validateK8sCatalogueBinding(a.entry, a.profile); err != nil {
		return err
	}
	if result.CatalogueID != a.entry.ID || result.ExpectedAction != a.profile.ExpectedAction ||
		result.ExecutionMode != AttackCatalogExecutionActive || result.Signal.Creator != a.profile.DetectorIdentity {
		return errors.New("Kubernetes catalogue result differs from its exact active profile")
	}
	var physical k8sCataloguePhysicalEvidence
	if err := decodeStrictK8sCatalogueEvidence(result.PhysicalValidation.Evidence, &physical); err != nil {
		return fmt.Errorf("Kubernetes physical evidence: %w", err)
	}
	if physical.Schema != k8sCataloguePhysicalSchema || physical.CatalogueID != a.entry.ID ||
		physical.Profile != a.profile.Key || physical.Family != a.profile.Family || physical.Lane != a.profile.Lane ||
		physical.Namespace != a.profile.Namespace || physical.LogicalAction != a.profile.ExpectedAction ||
		physical.NativeAction != a.profile.NativeAction || physical.PolicyName != a.profile.PolicyName ||
		physical.PolicyUID == "" || physical.PolicyGeneration < 1 || physical.DeploymentUID == "" || physical.ServiceUID == "" ||
		physical.TargetName == "" || physical.TargetUID == "" || physical.TargetUID != result.Signal.TargetUID ||
		physical.ReadyReplicas < a.profile.MinAvailable || physical.AvailableReplicas < a.profile.MinAvailable ||
		!physical.AvailabilityHeld || !physical.SiblingsIntact || !physical.ReplacementReady || !physical.TargetEndpointAbsent ||
		result.PhysicalValidation.Oracle != a.profile.Oracle {
		return errors.New("Kubernetes family physical oracle evidence is incomplete or belongs to another profile")
	}
	podObject := "Pod/" + a.profile.Namespace + "/" + physical.TargetName
	if result.Actuator.Handler != a.profile.NativeAction || !slices.Contains(result.Actuator.ObjectsTouched, podObject) {
		return errors.New("Kubernetes family accepted actuator receipt is not bound to the exact target Pod")
	}
	switch a.profile.Family {
	case k8sCatalogueFamilyQuarantine:
		npObject := "NetworkPolicy/" + a.profile.Namespace + "/" + physical.NetworkPolicyName
		if !physical.TargetQuarantined || physical.TargetGone || !physical.NetworkPolicyValid ||
			physical.NetworkPolicyName == "" || physical.NetworkPolicyUID == "" ||
			len(result.Actuator.ObjectsTouched) != 2 || !slices.Contains(result.Actuator.ObjectsTouched, npObject) {
			return errors.New("quarantine label, deny-all NetworkPolicy and accepted object receipt are required")
		}
	case k8sCatalogueFamilyPodRotate, k8sCatalogueFamilyControllerStop:
		if !physical.TargetGone || physical.TargetQuarantined || physical.NetworkPolicyName != "" || physical.NetworkPolicyUID != "" ||
			len(result.Actuator.ObjectsTouched) != 1 {
			return errors.New("exact old-Pod absence and clean replacement are required for rotation")
		}
	default:
		return errors.New("unknown Kubernetes catalogue family")
	}
	var cleanup k8sCatalogueCleanupEvidence
	if err := decodeStrictK8sCatalogueEvidence(result.Cleanup.Evidence, &cleanup); err != nil {
		return fmt.Errorf("Kubernetes cleanup evidence: %w", err)
	}
	if cleanup.Schema != k8sCatalogueCleanupSchema || cleanup.CatalogueID != a.entry.ID || cleanup.RunID != result.RunID || cleanup.Profile != a.profile.Key ||
		cleanup.Family != a.profile.Family || cleanup.TargetUID != physical.TargetUID || cleanup.SignalName != result.Signal.Name ||
		cleanup.SignalUID != result.Signal.UID || !cleanup.EventAbsent || !cleanup.FamilyArtifactsAbsent ||
		!cleanup.CapacityRecordsAbsent || !cleanup.ReadyRestored || !result.Cleanup.EventDeleted || !result.Cleanup.MarkerDeleted {
		return errors.New("retry-safe exact Kubernetes cleanup evidence is incomplete")
	}
	return nil
}

func (a *k8sAttackCatalogAdapter) DefendedReason() string {
	switch a.profile.Family {
	case k8sCatalogueFamilyQuarantine:
		return "exact signal-bound quarantine decision, accepted Pod+NetworkPolicy receipt, in-place isolation oracle, availability control and exact cleanup passed"
	case k8sCatalogueFamilyPodRotate:
		return "exact signal-bound rotate decision, accepted Pod Eviction receipt, clean UID replacement oracle, availability control and exact cleanup passed"
	case k8sCatalogueFamilyControllerStop:
		return "exact controller-stop bucket signal, mapped native rotate decision and receipt, clean UID replacement oracle, availability control and exact cleanup passed"
	default:
		return "exact Kubernetes catalogue defensive chain and cleanup passed"
	}
}

func k8sCatalogueDecision(rec audit.Record, p *k8sCataloguePreparation) (bool, AttackCatalogDecisionResult, AttackCatalogActuatorResult) {
	f, signal, profile := p.fixture, p.signal, p.profile
	if rec.Kind != "phorvex.decision" || !validAttackCatalogReceiptTime(rec.Time, signal.CreatedAt) || rec.Namespace != f.Namespace || rec.Pod != f.Target.Name ||
		rec.DecisionTrace == nil || rec.DecisionTrace.DecisionID == "" || rec.DecisionTrace.PolicyNamespace != f.Namespace ||
		rec.DecisionTrace.PolicyName != f.PolicyName || rec.DecisionTrace.PolicyUID != f.PolicyUID ||
		rec.DecisionTrace.AssetNamespace != f.Namespace || rec.DecisionTrace.AssetName != f.Target.Name ||
		rec.DecisionTrace.AssetUID != f.Target.UID || rec.DecisionTrace.SelectedAction != rec.Action ||
		rec.Action != profile.NativeAction || rec.DryRun != (f.ExecutionMode == AttackCatalogExecutionDryRun) ||
		rec.DecisionTrace.DryRun != rec.DryRun || rec.DecisionTrace.DispatchOutcome != rec.DispatchOutcome {
		return false, AttackCatalogDecisionResult{}, AttackCatalogActuatorResult{}
	}
	matches := 0
	for _, event := range rec.Events {
		if event.EventUID == signal.UID && event.Name == signal.Name && event.Type == p.entry.EventType &&
			event.Source == profile.Lane+"-attacks" && event.ThreatLevel == "critical" && event.CreatorIdentity == signal.Creator &&
			event.TargetPodUID == f.Target.UID && event.TrustVerdict == "trusted" && event.TargetsPod &&
			event.TimestampPresent && event.Weight > 0 {
			matches++
		}
	}
	if matches != 1 {
		return false, AttackCatalogDecisionResult{}, AttackCatalogActuatorResult{}
	}
	decision := AttackCatalogDecisionResult{Observed: true, ID: rec.DecisionTrace.DecisionID, Selected: rec.Selected,
		Feasible: rec.Feasible, Action: profile.ExpectedAction, DispatchOutcome: rec.DecisionTrace.DispatchOutcome,
		ObservedAt: attackCatalogTime(rec.Time)}
	actuator := AttackCatalogActuatorResult{Handler: rec.Handler, ObjectsTouched: slices.Clone(rec.ObjectsTouched)}
	podObject := "Pod/" + f.Namespace + "/" + f.Target.Name
	receipt := acceptedAttackCatalogAuditReceipt(rec, signal.CreatedAt, profile.NativeAction, profile.NativeAction) &&
		slices.Contains(rec.ObjectsTouched, podObject)
	if profile.NativeAction == string(model.ActionRotate) {
		grace := rec.GracefulTermination
		receipt = receipt && grace != nil && grace.PolicyNamespace == f.Namespace && grace.PolicyName == f.PolicyName &&
			grace.PolicyUID == f.PolicyUID && grace.PolicyGeneration == f.PolicyGeneration && grace.PodUID == f.Target.UID &&
			grace.PodResourceVersion != "" && grace.PolicyGraceCapSeconds > 0 && grace.WorkloadGraceSeconds >= 0 &&
			grace.EffectiveGracePeriodSeconds >= 0 && grace.EffectiveGracePeriodSeconds <= grace.PolicyGraceCapSeconds &&
			grace.TerminationStatus == "unconfirmed" && len(rec.ObjectsTouched) == 1
	} else {
		npObject := "NetworkPolicy/" + f.Namespace + "/" + f.NetworkPolicyName
		receipt = receipt && slices.Contains(rec.ObjectsTouched, npObject) && len(rec.ObjectsTouched) == 2
	}
	actuator.ReceiptObserved = receipt
	if actuator.ReceiptObserved {
		actuator.AcceptedAt = attackCatalogTime(rec.Time)
	}
	return true, decision, actuator
}

type k8sCataloguePhysicalEvidence struct {
	Schema               string   `json:"schema"`
	CatalogueID          string   `json:"catalogueID"`
	Profile              string   `json:"profile"`
	Family               string   `json:"family"`
	Lane                 string   `json:"lane"`
	Namespace            string   `json:"namespace"`
	LogicalAction        string   `json:"logicalAction"`
	NativeAction         string   `json:"nativeAction"`
	PolicyName           string   `json:"policyName"`
	PolicyUID            string   `json:"policyUID"`
	PolicyGeneration     int64    `json:"policyGeneration"`
	DeploymentUID        string   `json:"deploymentUID"`
	ServiceUID           string   `json:"serviceUID"`
	TargetName           string   `json:"targetName"`
	TargetUID            string   `json:"targetUID"`
	ReadyReplicas        int      `json:"readyReplicas"`
	AvailableReplicas    int      `json:"availableReplicas"`
	SiblingUIDs          []string `json:"siblingUIDs"`
	ReplacementUIDs      []string `json:"replacementUIDs"`
	EndpointUIDs         []string `json:"endpointUIDs"`
	AvailabilityHeld     bool     `json:"availabilityHeld"`
	SiblingsIntact       bool     `json:"siblingsIntact"`
	ReplacementReady     bool     `json:"replacementReady"`
	TargetEndpointAbsent bool     `json:"targetEndpointAbsent"`
	TargetGone           bool     `json:"targetGone"`
	TargetQuarantined    bool     `json:"targetQuarantined"`
	NetworkPolicyName    string   `json:"networkPolicyName,omitempty"`
	NetworkPolicyUID     string   `json:"networkPolicyUID,omitempty"`
	NetworkPolicyValid   bool     `json:"networkPolicyValid"`
}

type k8sCatalogueCleanupEvidence struct {
	Schema                string `json:"schema"`
	CatalogueID           string `json:"catalogueID"`
	RunID                 string `json:"runID"`
	Profile               string `json:"profile"`
	Family                string `json:"family"`
	TargetUID             string `json:"targetUID"`
	SignalName            string `json:"signalName"`
	SignalUID             string `json:"signalUID"`
	EventAbsent           bool   `json:"eventAbsent"`
	FamilyArtifactsAbsent bool   `json:"familyArtifactsAbsent"`
	CapacityRecordsAbsent bool   `json:"capacityRecordsAbsent"`
	ReadyRestored         bool   `json:"readyRestored"`
}

func decodeStrictK8sCatalogueEvidence(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return errors.New("evidence is absent")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("evidence has trailing JSON")
	}
	return nil
}

var _ AttackCatalogAdapter = (*k8sAttackCatalogAdapter)(nil)
var _ AttackCatalogRetryReconciler = (*k8sAttackCatalogAdapter)(nil)
var _ AttackCatalogPreparation = (*k8sCataloguePreparation)(nil)
