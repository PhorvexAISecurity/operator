package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	nativeRouteScenario       = "c2-native-route-cutover"
	nativeEndpointScenario    = "c2-native-endpoint-cutover"
	nativeRouteReceiptSchema  = "phorvex.native-route-catalogue.receipt.v1"
	nativeRouteMaxOutputBytes = 32 * 1024
	nativeRouteIdentitySchema = "phorvex.native-route-catalogue.identity.v1"
	nativeRouteKey            = "phorvex.ai/route-key"
	nativeRouteBridgeKey      = "phorvex.ai/route-bridge"
	nativeRouteEpochKey       = "phorvex.ai/route-epoch"
	nativeEndpointEpochKey    = "phorvex.ai/endpoint-epoch"
	nativeOperationLabel      = "phorvex.ai/operation-journal"
	nativeGuardLabel          = "phorvex.ai/route-target-guard"
)

func init() {
	core.RegisterScenario(&c2NativeRouteCutover{action: "route-rotate", name: nativeRouteScenario})
	core.RegisterScenario(&c2NativeRouteCutover{action: "endpoint-rotate", name: nativeEndpointScenario})
}

// c2NativeRouteCutover is a typed handoff to the production-entrypoint adapter.
// Fixture creation and terminal cleanup remain with the external exact-UID
// supervisor; this scenario can only run the two fixed selector-cutover actions.
type c2NativeRouteCutover struct {
	action       string
	name         string
	receipt      nativeRouteReceipt
	evidence     map[string]string
	authority    config.NativeRouteFixtureConfig
	runAuthority nativeRouteAdapterRun
}

type nativeRouteReceipt struct {
	Schema                  string                    `json:"schema"`
	SourceRevision          string                    `json:"sourceRevision"`
	Action                  string                    `json:"action"`
	Fixture                 nativeRouteReceiptFixture `json:"fixture"`
	StartedAt               string                    `json:"startedAt"`
	FinishedAt              string                    `json:"finishedAt"`
	Status                  string                    `json:"status"`
	Baseline                *nativeRouteState         `json:"baseline"`
	Forward                 *nativeRouteState         `json:"forward"`
	Restored                *nativeRouteState         `json:"restored"`
	ForwardResult           nativeRouteResult         `json:"forwardResult"`
	ReconciliationAttempted bool                      `json:"reconciliationAttempted"`
	ReconciliationResult    *nativeRouteResult        `json:"reconciliationResult"`
	ReconciliationError     string                    `json:"reconciliationError"`
	RollbackAttempted       bool                      `json:"rollbackAttempted"`
	RollbackError           string                    `json:"rollbackError"`
	HTTP                    []nativeRouteHTTP         `json:"http"`
	Writes                  []nativeRouteWrite        `json:"writes"`
	WriteJournalSchema      string                    `json:"writeJournalSchema"`
	WriteJournalSHA256      string                    `json:"writeJournalSHA256"`
	WriteJournalBytes       int64                     `json:"writeJournalBytes"`
	AvailabilityInterrupted bool                      `json:"availabilityInterrupted"`
	Errors                  []string                  `json:"errors"`
}

type nativeRouteReceiptFixture struct {
	Nonce               string `json:"nonce"`
	Tenant              string `json:"tenant"`
	Namespace           string `json:"namespace"`
	NamespaceUID        string `json:"namespaceUID"`
	JournalNamespace    string `json:"journalNamespace"`
	JournalNamespaceUID string `json:"journalNamespaceUID"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	TargetName          string `json:"targetName"`
	TargetUID           string `json:"targetUID"`
	PeerName            string `json:"peerName"`
	PeerUID             string `json:"peerUID"`
	ServiceName         string `json:"serviceName"`
	ServiceUID          string `json:"serviceUID"`
	OperationID         string `json:"operationID"`
}

type nativeRouteAdapterConfig struct {
	Schema             string                `json:"schema"`
	Kubeconfig         string                `json:"kubeconfig"`
	Context            string                `json:"context"`
	MaxDurationSeconds int                   `json:"maxDurationSeconds"`
	Run                nativeRouteAdapterRun `json:"run"`
}

type nativeRouteAdapterRun struct {
	Schema         string                        `json:"schema"`
	SourceRevision string                        `json:"sourceRevision"`
	Action         string                        `json:"action"`
	Fixture        nativeRouteAdapterFixture     `json:"fixture"`
	Observation    nativeRouteAdapterObservation `json:"observation"`
}

type nativeRouteAdapterFixture struct {
	Nonce               string `json:"nonce"`
	Tenant              string `json:"tenant"`
	Namespace           string `json:"namespace"`
	NamespaceUID        string `json:"namespaceUID"`
	JournalNamespace    string `json:"journalNamespace"`
	JournalNamespaceUID string `json:"journalNamespaceUID"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	TargetName          string `json:"targetName"`
	TargetUID           string `json:"targetUID"`
	PeerName            string `json:"peerName"`
	PeerUID             string `json:"peerUID"`
	ServiceName         string `json:"serviceName"`
	ServiceUID          string `json:"serviceUID"`
	OperationID         string `json:"operationID"`
}

type nativeRouteAdapterObservation struct {
	TargetURL                  string `json:"targetURL"`
	PeerURL                    string `json:"peerURL"`
	ServiceURL                 string `json:"serviceURL"`
	SampleIntervalMillis       int    `json:"sampleIntervalMillis"`
	RequestTimeoutMillis       int    `json:"requestTimeoutMillis"`
	MinSamplesPerEndpointPhase int    `json:"minSamplesPerEndpointPhase"`
}

type nativeRouteResult struct {
	Note                string          `json:"Note"`
	NoEffect            string          `json:"NoEffect"`
	Actuator            string          `json:"Actuator"`
	AMTDName            string          `json:"AMTDName"`
	EventName           string          `json:"EventName"`
	EventUID            string          `json:"EventUID"`
	RuleType            string          `json:"RuleType"`
	RuleThreatLevel     string          `json:"RuleThreatLevel"`
	RuleSource          string          `json:"RuleSource"`
	Handler             string          `json:"Handler"`
	Emitted             bool            `json:"Emitted"`
	ObjectsTouched      []string        `json:"ObjectsTouched"`
	MutationKind        string          `json:"MutationKind"`
	RollbackRef         string          `json:"RollbackRef"`
	GracefulTermination json.RawMessage `json:"GracefulTermination"`
}

type nativeRouteHTTP struct {
	Sequence             int64                    `json:"sequence"`
	Phase                string                   `json:"phase"`
	Endpoint             string                   `json:"endpoint"`
	StartedAt            string                   `json:"startedAt"`
	FinishedAt           string                   `json:"finishedAt"`
	Status               int                      `json:"status"`
	Bytes                int                      `json:"bytes"`
	SHA256               string                   `json:"sha256"`
	Body                 string                   `json:"body"`
	Identity             *nativeRouteHTTPIdentity `json:"identity"`
	Error                string                   `json:"error"`
	TerminalCancellation bool                     `json:"terminalCancellation"`
}

type nativeRouteWrite struct {
	Sequence   int    `json:"sequence"`
	Method     string `json:"method"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Error      string `json:"error"`
}

type nativeRouteHTTPIdentity struct {
	Schema        string `json:"schema"`
	Nonce         string `json:"nonce"`
	Role          string `json:"role"`
	PodUID        string `json:"podUID"`
	ProcessMarker string `json:"processMarker"`
}

type nativeRoutePod struct {
	Name            string            `json:"name"`
	UID             string            `json:"uid"`
	ResourceVersion string            `json:"resourceVersion"`
	PodIP           string            `json:"podIP"`
	PodIPs          []string          `json:"podIPs"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
	ContainerIDs    map[string]string `json:"containerIDs"`
	RestartCounts   map[string]int32  `json:"restartCounts"`
	Ready           bool              `json:"ready"`
}

type nativeRouteService struct {
	Name            string               `json:"name"`
	UID             string               `json:"uid"`
	ResourceVersion string               `json:"resourceVersion"`
	ClusterIP       string               `json:"clusterIP"`
	ClusterIPs      []string             `json:"clusterIPs"`
	Ports           []corev1.ServicePort `json:"ports"`
	Selector        map[string]string    `json:"selector"`
}

type nativeRouteJournal struct {
	Name            string            `json:"name"`
	UID             string            `json:"uid"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	DataSHA256      string            `json:"dataSHA256"`
	DataBytes       int               `json:"dataBytes"`
}

type nativeRouteState struct {
	Phase               string               `json:"phase"`
	ObservedAt          string               `json:"observedAt"`
	NamespaceUID        string               `json:"namespaceUID"`
	JournalNamespaceUID string               `json:"journalNamespaceUID"`
	PolicyUID           string               `json:"policyUID"`
	PolicyGeneration    int64                `json:"policyGeneration"`
	Target              nativeRoutePod       `json:"target"`
	Peer                nativeRoutePod       `json:"peer"`
	Service             nativeRouteService   `json:"service"`
	ReadyMembers        []string             `json:"readyMembers"`
	Journal             []nativeRouteJournal `json:"journal"`
}

func (s *c2NativeRouteCutover) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               s.name,
		Category:           core.CategoryR6Claimed,
		Source:             "Post25 native selector-cutover catalogue adapter",
		R6ResponseTag:      core.R6Partial,
		BenignControl:      true,
		Realism:            core.RealismExecutable,
		Mechanism:          "an exact source-bound adapter invokes NativeActuator for one fixed action, observes application identities, and rolls the same protected operation back",
		ClaimLimits:        "selector rekey and bounded HTTP behavior only; no locator, credential, session, security-efficacy, universal-availability, or installed-brain claim",
		OracleDescription:  "require a complete source/fixture-bound receipt, reversible native result, exact rollback, retained HTTP attempts, and no failed admitted write",
		CleanupDescription: "the adapter rolls back its protected operation; a separately reviewed supervisor owns exact fixture namespace cleanup",
		R6Justification:    "directly exercises the production native route engine while preserving a narrow benign measurement boundary",
	}
}

func (s *c2NativeRouteCutover) Setup(ctx context.Context, env *core.Env) error {
	s.receipt = nativeRouteReceipt{}
	s.evidence = nil
	fixture, err := s.fixture(env)
	if err != nil {
		return err
	}
	s.authority = *fixture
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != fixture.NamespaceUID || ns.DeletionTimestamp != nil {
		return fmt.Errorf("native route fixture Namespace authority differs: %w", err)
	}
	if err := validateNativeRouteArtifact(fixture.AdapterBinary, fixture.AdapterBinarySHA256, true); err != nil {
		return fmt.Errorf("native route adapter binary: %w", err)
	}
	if err := validateNativeRouteArtifact(fixture.AdapterConfig, fixture.AdapterConfigSHA256, false); err != nil {
		return fmt.Errorf("native route adapter config: %w", err)
	}
	if err := validateNativeRouteAdapterConfig(fixture.AdapterConfig, env.Config.Context, env.Config.Namespace, fixture); err != nil {
		return err
	}
	adapterConfig, err := loadNativeRouteAdapterConfig(fixture.AdapterConfig)
	if err != nil {
		return err
	}
	s.runAuthority = adapterConfig.Run
	if _, err := os.Lstat(fixture.ReceiptPath); !os.IsNotExist(err) {
		return errors.New("native route receipt path already exists or cannot be inspected")
	}
	return nil
}

func (s *c2NativeRouteCutover) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	fixture, err := s.fixture(env)
	if err != nil {
		return core.AttackResult{}, err
	}
	command := exec.CommandContext(ctx, fixture.AdapterBinary, "-config", fixture.AdapterConfig, "-output", fixture.ReceiptPath)
	stdout, stderr := &nativeRouteBoundedBuffer{max: nativeRouteMaxOutputBytes}, &nativeRouteBoundedBuffer{max: nativeRouteMaxOutputBytes}
	command.Stdout, command.Stderr = stdout, stderr
	started := time.Now()
	runErr := command.Run()
	receiptRaw, readErr := os.ReadFile(fixture.ReceiptPath)
	parseErr := strictNativeRouteReceipt(receiptRaw, &s.receipt)
	if parseErr == nil {
		parseErr = validateNativeRouteReceiptAuthority(s.receipt, fixture)
	}
	if parseErr == nil {
		parseErr = validateNativeRouteRunAuthority(s.receipt, s.runAuthority)
	}
	receiptSum := sha256.Sum256(receiptRaw)
	s.evidence = map[string]string{
		"schema":                  nativeRouteReceiptSchema,
		"action":                  s.action,
		"sourceRevision":          fixture.SourceRevision,
		"namespaceUID":            fixture.NamespaceUID,
		"receiptSHA256":           hex.EncodeToString(receiptSum[:]),
		"receiptBytes":            strconv.Itoa(len(receiptRaw)),
		"httpSamples":             strconv.Itoa(len(s.receipt.HTTP)),
		"writeSamples":            strconv.Itoa(len(s.receipt.Writes)),
		"writeJournalSHA256":      s.receipt.WriteJournalSHA256,
		"writeJournalBytes":       strconv.FormatInt(s.receipt.WriteJournalBytes, 10),
		"availabilityInterrupted": strconv.FormatBool(s.receipt.AvailabilityInterrupted),
		"elapsedMillis":           strconv.FormatInt(time.Since(started).Milliseconds(), 10),
		"stdoutSHA256":            fmt.Sprintf("%x", sha256.Sum256(stdout.Bytes())),
		"stderrSHA256":            fmt.Sprintf("%x", sha256.Sum256(stderr.Bytes())),
	}
	if err := errors.Join(runErr, readErr, parseErr); err != nil {
		s.evidence["oracleStatus"] = "incomplete"
		return core.AttackResult{Stages: []string{"native-adapter-attempted"}, Commands: []string{"native-route-catalogue -config <private> -output <private>"}, BenchmarkEvidence: s.evidence}, err
	}
	s.evidence["oracleStatus"] = s.receipt.Status
	return core.AttackResult{Stages: []string{"native-selector-cutover", "native-protected-rollback"}, Commands: []string{"native-route-catalogue -config <private> -output <private>"}, BenchmarkEvidence: s.evidence}, nil
}

func (s *c2NativeRouteCutover) SuccessOracle(context.Context, *core.Env) (core.OracleResult, error) {
	if err := validateNativeRouteReceiptAuthority(s.receipt, &s.authority); err != nil {
		return core.OracleResult{Achieved: false, ObservedState: err.Error(), Evidence: s.evidence}, nil
	}
	if err := validateNativeRouteRunAuthority(s.receipt, s.runAuthority); err != nil {
		return core.OracleResult{Achieved: false, ObservedState: err.Error(), Evidence: s.evidence}, nil
	}
	if s.receipt.Schema != nativeRouteReceiptSchema || s.receipt.Status != "COMPLETE" || s.receipt.Action != s.action || s.receipt.ForwardResult.Actuator != "native" || s.receipt.ForwardResult.Handler != s.action || !s.receipt.ForwardResult.Emitted || s.receipt.ForwardResult.MutationKind != "reversible" || s.receipt.ForwardResult.RollbackRef == "" || !s.receipt.RollbackAttempted || s.receipt.RollbackError != "" || len(s.receipt.Errors) != 0 || s.receipt.Baseline == nil || s.receipt.Forward == nil || s.receipt.Restored == nil || s.receipt.WriteJournalSchema != "phorvex.native-route-catalogue.write-journal.v1" || len(s.receipt.WriteJournalSHA256) != 64 || s.receipt.WriteJournalBytes <= 0 {
		return core.OracleResult{Achieved: false, ObservedState: "native route receipt incomplete or mismatched", Evidence: s.evidence}, nil
	}
	if err := validateNativeRouteTypedEvidence(s.receipt); err != nil {
		return core.OracleResult{Achieved: false, ObservedState: err.Error(), Evidence: s.evidence}, nil
	}
	return core.OracleResult{Achieved: true, ObservedState: "production native selector cutover and exact protected rollback completed", Evidence: s.evidence}, nil
}

func (*c2NativeRouteCutover) Teardown(context.Context, *core.Env) error { return nil }

func (s *c2NativeRouteCutover) fixture(env *core.Env) (*config.NativeRouteFixtureConfig, error) {
	fixture := env.Config.NativeRouteFixture
	if fixture == nil || fixture.Action != s.action || env.Config.ExpectedNamespaceUID != fixture.NamespaceUID || env.Config.Namespace == "" {
		return nil, errors.New("native route fixture handoff is unavailable or mismatched")
	}
	return fixture, nil
}

func validateNativeRouteArtifact(path, wantSHA string, executable bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || executable && info.Mode().Perm()&0o111 == 0 || !executable && info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 256<<20 {
		return fmt.Errorf("artifact metadata differs: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, io.LimitReader(f, 256<<20+1))
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		return fmt.Errorf("artifact SHA-256=%s, want %s", got, wantSHA)
	}
	return nil
}

func strictNativeRouteReceipt(raw []byte, out *nativeRouteReceipt) error {
	if len(raw) == 0 || len(raw) > 8<<20 {
		return errors.New("native route receipt is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("native route receipt decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("native route receipt has trailing content")
	}
	return nil
}

func validateNativeRouteReceiptAuthority(receipt nativeRouteReceipt, fixture *config.NativeRouteFixtureConfig) error {
	if fixture == nil || receipt.SourceRevision != fixture.SourceRevision || receipt.Action != fixture.Action || receipt.Fixture.NamespaceUID != fixture.NamespaceUID || receipt.Fixture.JournalNamespaceUID != fixture.JournalNamespaceUID || receipt.Fixture.PolicyUID != fixture.PolicyUID || receipt.Fixture.PolicyGeneration != fixture.PolicyGeneration || receipt.Fixture.TargetUID != fixture.TargetUID || receipt.Fixture.PeerUID != fixture.PeerUID || receipt.Fixture.ServiceUID != fixture.ServiceUID || receipt.Fixture.OperationID != fixture.OperationID {
		return errors.New("native route receipt source or fixture authority differs")
	}
	return nil
}

func validateNativeRouteRunAuthority(receipt nativeRouteReceipt, run nativeRouteAdapterRun) error {
	want := run.Fixture
	got := receipt.Fixture
	if run.Schema != "phorvex.native-route-catalogue.config.v1" || receipt.SourceRevision != run.SourceRevision || receipt.Action != run.Action || got.Nonce != want.Nonce || got.Tenant != want.Tenant || got.Namespace != want.Namespace || got.NamespaceUID != want.NamespaceUID || got.JournalNamespace != want.JournalNamespace || got.JournalNamespaceUID != want.JournalNamespaceUID || got.PolicyName != want.PolicyName || got.PolicyUID != want.PolicyUID || got.PolicyGeneration != want.PolicyGeneration || got.TargetName != want.TargetName || got.TargetUID != want.TargetUID || got.PeerName != want.PeerName || got.PeerUID != want.PeerUID || got.ServiceName != want.ServiceName || got.ServiceUID != want.ServiceUID || got.OperationID != want.OperationID {
		return errors.New("native route receipt differs from the hash-bound adapter run authority")
	}
	return nil
}

func nativeRouteJournalNames(f nativeRouteReceiptFixture) (string, string) {
	service := sha256.Sum256([]byte("route-service/" + f.ServiceUID))
	target := sha256.Sum256([]byte("route-target/" + f.TargetUID))
	return fmt.Sprintf("phorvex-route-service-%x", service[:20]), fmt.Sprintf("phorvex-route-target-%x", target[:20])
}

func nativeRouteHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func nativeRouteStablePod(a, b nativeRoutePod) bool {
	return a.Name == b.Name && a.UID == b.UID && a.PodIP == b.PodIP && reflect.DeepEqual(a.PodIPs, b.PodIPs) && reflect.DeepEqual(a.ContainerIDs, b.ContainerIDs) && reflect.DeepEqual(a.RestartCounts, b.RestartCounts) && a.Ready && b.Ready
}

func nativeRouteEqualWithout(a, b map[string]string, keys ...string) bool {
	copyMap := func(in map[string]string) map[string]string {
		out := make(map[string]string, len(in))
		for key, value := range in {
			out[key] = value
		}
		return out
	}
	a, b = copyMap(a), copyMap(b)
	for _, key := range keys {
		delete(a, key)
		delete(b, key)
	}
	return reflect.DeepEqual(a, b)
}

func validateNativeRouteStateEvidence(receipt nativeRouteReceipt) error {
	baseline, forward, restored := receipt.Baseline, receipt.Forward, receipt.Restored
	if baseline == nil || forward == nil || restored == nil || baseline.Phase != "baseline" || forward.Phase != "forward" || restored.Phase != "restored" {
		return errors.New("native route state phases are absent or out of contract")
	}
	for _, state := range []*nativeRouteState{baseline, forward, restored} {
		if _, err := time.Parse(time.RFC3339Nano, state.ObservedAt); err != nil || state.NamespaceUID != receipt.Fixture.NamespaceUID || state.JournalNamespaceUID != receipt.Fixture.JournalNamespaceUID || state.PolicyUID != receipt.Fixture.PolicyUID || state.PolicyGeneration != receipt.Fixture.PolicyGeneration || state.Target.Name != receipt.Fixture.TargetName || state.Target.UID != receipt.Fixture.TargetUID || state.Peer.Name != receipt.Fixture.PeerName || state.Peer.UID != receipt.Fixture.PeerUID || state.Service.Name != receipt.Fixture.ServiceName || state.Service.UID != receipt.Fixture.ServiceUID {
			return errors.New("native route state authority or observation time differs")
		}
	}
	if !nativeRouteStablePod(baseline.Target, forward.Target) || !nativeRouteStablePod(baseline.Peer, forward.Peer) || !nativeRouteStablePod(baseline.Target, restored.Target) || !nativeRouteStablePod(baseline.Peer, restored.Peer) || !reflect.DeepEqual(baseline.Peer.Labels, forward.Peer.Labels) || !reflect.DeepEqual(baseline.Peer.Annotations, forward.Peer.Annotations) || !reflect.DeepEqual(baseline.Target.Labels, restored.Target.Labels) || !reflect.DeepEqual(baseline.Target.Annotations, restored.Target.Annotations) || !reflect.DeepEqual(baseline.Peer.Labels, restored.Peer.Labels) || !reflect.DeepEqual(baseline.Peer.Annotations, restored.Peer.Annotations) {
		return errors.New("native route state changed a retained Pod identity, process, or unrelated metadata")
	}
	if baseline.Service.ClusterIP != forward.Service.ClusterIP || baseline.Service.ClusterIP != restored.Service.ClusterIP || !reflect.DeepEqual(baseline.Service.ClusterIPs, forward.Service.ClusterIPs) || !reflect.DeepEqual(baseline.Service.ClusterIPs, restored.Service.ClusterIPs) || !reflect.DeepEqual(baseline.Service.Ports, forward.Service.Ports) || !reflect.DeepEqual(baseline.Service.Ports, restored.Service.Ports) || !reflect.DeepEqual(baseline.Service.Selector, restored.Service.Selector) {
		return errors.New("native route state changed the Service locator or failed exact restoration")
	}
	epoch, otherEpoch := nativeRouteEpochKey, nativeEndpointEpochKey
	if receipt.Action == "endpoint-rotate" {
		epoch, otherEpoch = nativeEndpointEpochKey, nativeRouteEpochKey
	}
	if forward.Target.Labels[nativeRouteKey] == "" || forward.Target.Labels[nativeRouteKey] == baseline.Target.Labels[nativeRouteKey] || forward.Service.Selector[nativeRouteKey] != forward.Target.Labels[nativeRouteKey] || forward.Target.Labels[nativeRouteBridgeKey] != "" || forward.Service.Selector[nativeRouteBridgeKey] != "" || forward.Target.Annotations[epoch] == "" || forward.Target.Annotations[epoch] == baseline.Target.Annotations[epoch] || forward.Target.Annotations[otherEpoch] != baseline.Target.Annotations[otherEpoch] || !nativeRouteEqualWithout(baseline.Target.Labels, forward.Target.Labels, nativeRouteKey, nativeRouteBridgeKey) || !nativeRouteEqualWithout(baseline.Target.Annotations, forward.Target.Annotations, epoch) || !nativeRouteEqualWithout(baseline.Service.Selector, forward.Service.Selector, nativeRouteKey, nativeRouteBridgeKey) {
		return errors.New("native route forward state does not prove the exact selector rekey and action epoch")
	}
	wantRestored := []string{receipt.Fixture.PeerUID, receipt.Fixture.TargetUID}
	sort.Strings(wantRestored)
	if !reflect.DeepEqual(baseline.ReadyMembers, wantRestored) || !reflect.DeepEqual(forward.ReadyMembers, []string{receipt.Fixture.TargetUID}) || !reflect.DeepEqual(restored.ReadyMembers, wantRestored) || len(baseline.Journal) != 0 || len(restored.Journal) != 0 || len(forward.Journal) != 1 {
		return errors.New("native route membership or protected journal phases differ")
	}
	serviceJournal, _ := nativeRouteJournalNames(receipt.Fixture)
	journal := forward.Journal[0]
	if journal.Name != serviceJournal || journal.UID == "" || journal.ResourceVersion == "" || journal.Labels[nativeOperationLabel] != "v1" || journal.Labels[nativeGuardLabel] != "" || !nativeRouteHex(journal.DataSHA256, sha256.Size) || journal.DataBytes <= 0 {
		return errors.New("native route forward protected journal identity differs")
	}
	wantRefPrefix := receipt.Fixture.JournalNamespace + "/" + journal.Name + "@" + journal.UID + "#"
	if !strings.HasPrefix(receipt.ForwardResult.RollbackRef, wantRefPrefix) || !nativeRouteHex(strings.TrimPrefix(receipt.ForwardResult.RollbackRef, wantRefPrefix), 20) {
		return errors.New("native route rollback reference does not bind the retained journal UID")
	}
	return nil
}

func validateNativeRouteHTTPEvidence(receipt nativeRouteReceipt) error {
	if len(receipt.HTTP) == 0 || len(receipt.HTTP) > 4096 {
		return errors.New("native route HTTP evidence count differs")
	}
	markers := map[string]string{}
	phaseCounts := map[string]map[string]int{}
	availabilityInterrupted := false
	for index, row := range receipt.HTTP {
		if row.Sequence != int64(index+1) || row.Endpoint != "target" && row.Endpoint != "peer" && row.Endpoint != "service" {
			return errors.New("native route HTTP sequence or endpoint differs")
		}
		started, startErr := time.Parse(time.RFC3339Nano, row.StartedAt)
		finished, finishErr := time.Parse(time.RFC3339Nano, row.FinishedAt)
		if startErr != nil || finishErr != nil || finished.Before(started) || row.Bytes < len(row.Body) {
			return errors.New("native route HTTP timestamp or length differs")
		}
		if row.Endpoint == "service" && row.Error != "" && !row.TerminalCancellation {
			availabilityInterrupted = true
		}
		if row.Error != "" {
			if row.Identity != nil {
				return errors.New("native route failed HTTP row carries contradictory identity or cancellation")
			}
			if row.Status == 0 {
				if row.Bytes != 0 || row.Body != "" || row.SHA256 != "" {
					return errors.New("native route transport-error row carries an unbound response body")
				}
			} else if row.Bytes != len(row.Body) || !nativeRouteHex(row.SHA256, sha256.Size) || fmt.Sprintf("%x", sha256.Sum256([]byte(row.Body))) != row.SHA256 {
				return errors.New("native route HTTP error response length or digest differs")
			}
			continue
		}
		if row.Status != 200 || row.Bytes != len(row.Body) || !nativeRouteHex(row.SHA256, sha256.Size) || fmt.Sprintf("%x", sha256.Sum256([]byte(row.Body))) != row.SHA256 || row.Identity == nil {
			return errors.New("native route successful HTTP row lacks exact response evidence")
		}
		var bodyIdentity nativeRouteHTTPIdentity
		decoder := json.NewDecoder(strings.NewReader(row.Body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&bodyIdentity); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !reflect.DeepEqual(bodyIdentity, *row.Identity) || row.Identity.Schema != nativeRouteIdentitySchema || row.Identity.Nonce != receipt.Fixture.Nonce || row.Identity.ProcessMarker == "" {
			return errors.New("native route HTTP body and typed identity differ")
		}
		wantUID, wantRole := receipt.Fixture.TargetUID, "target"
		if row.Endpoint == "peer" {
			wantUID, wantRole = receipt.Fixture.PeerUID, "peer"
		}
		if row.Endpoint != "service" && (row.Identity.PodUID != wantUID || row.Identity.Role != wantRole) {
			return errors.New("native route direct HTTP identity differs")
		}
		if marker := markers[row.Identity.PodUID]; marker != "" && marker != row.Identity.ProcessMarker {
			return errors.New("native route HTTP process marker changed across phases")
		}
		markers[row.Identity.PodUID] = row.Identity.ProcessMarker
		if row.Endpoint == "service" {
			allowed := row.Identity.PodUID == receipt.Fixture.TargetUID && row.Identity.Role == "target"
			if row.Phase != "forward-stable" {
				allowed = allowed || row.Identity.PodUID == receipt.Fixture.PeerUID && row.Identity.Role == "peer"
			}
			if !allowed {
				return errors.New("native route Service HTTP identity differs from phase membership")
			}
		}
		if phaseCounts[row.Phase] == nil {
			phaseCounts[row.Phase] = map[string]int{}
		}
		phaseCounts[row.Phase][row.Endpoint]++
	}
	if markers[receipt.Fixture.TargetUID] == "" || markers[receipt.Fixture.PeerUID] == "" || markers[receipt.Fixture.TargetUID] == markers[receipt.Fixture.PeerUID] {
		return errors.New("native route HTTP evidence lacks distinct stable target and peer processes")
	}
	for _, phase := range []string{"baseline", "forward-stable", "rollback-stable"} {
		for _, endpoint := range []string{"target", "peer", "service"} {
			if phaseCounts[phase][endpoint] == 0 {
				return fmt.Errorf("native route HTTP evidence lacks %s/%s", phase, endpoint)
			}
		}
	}
	if receipt.AvailabilityInterrupted != availabilityInterrupted {
		return errors.New("native route availability flag differs from retained Service errors")
	}
	return nil
}

func validateNativeRouteWriteEvidence(receipt nativeRouteReceipt) error {
	if len(receipt.Writes) == 0 || len(receipt.Writes) > 96 {
		return errors.New("native route write evidence count differs")
	}
	serviceJournal, targetGuard := nativeRouteJournalNames(receipt.Fixture)
	allowedJournal := map[string]bool{serviceJournal: true, targetGuard: true}
	seen := map[string]bool{}
	for index, row := range receipt.Writes {
		if row.Sequence != index+1 || row.Error != "" {
			return errors.New("native route write sequence or result differs")
		}
		started, startErr := time.Parse(time.RFC3339Nano, row.StartedAt)
		finished, finishErr := time.Parse(time.RFC3339Nano, row.FinishedAt)
		if startErr != nil || finishErr != nil || finished.Before(started) {
			return errors.New("native route write timestamps differ")
		}
		allowed := false
		switch row.Kind {
		case "*v1.Pod":
			allowed = row.Method == "PATCH" && row.Namespace == receipt.Fixture.Namespace && row.Name == receipt.Fixture.TargetName && row.UID == receipt.Fixture.TargetUID
			seen["target-patch"] = seen["target-patch"] || allowed
		case "*v1.Service":
			allowed = row.Method == "UPDATE" && row.Namespace == receipt.Fixture.Namespace && row.Name == receipt.Fixture.ServiceName && row.UID == receipt.Fixture.ServiceUID
			seen["service-update"] = seen["service-update"] || allowed
		case "*v1.ConfigMap":
			allowed = (row.Method == "CREATE" || row.Method == "UPDATE" || row.Method == "DELETE") && row.Namespace == receipt.Fixture.JournalNamespace && allowedJournal[row.Name]
			if allowed && row.Name == serviceJournal && row.Method == "CREATE" {
				seen["journal-create"] = row.UID == receipt.Forward.Journal[0].UID
			}
			if allowed && row.Name == serviceJournal && row.Method == "DELETE" {
				seen["journal-delete"] = row.UID == receipt.Forward.Journal[0].UID
			}
		}
		if !allowed {
			return fmt.Errorf("native route write escaped exact authority: %s %s %s/%s", row.Method, row.Kind, row.Namespace, row.Name)
		}
	}
	for _, key := range []string{"target-patch", "service-update", "journal-create", "journal-delete"} {
		if !seen[key] {
			return fmt.Errorf("native route write evidence lacks %s", key)
		}
	}
	wantObjects := []string{"Pod/" + receipt.Fixture.Namespace + "/" + receipt.Fixture.TargetName, "Service/" + receipt.Fixture.Namespace + "/" + receipt.Fixture.ServiceName, "ConfigMap/" + receipt.Fixture.JournalNamespace + "/" + serviceJournal}
	if !reflect.DeepEqual(receipt.ForwardResult.ObjectsTouched, wantObjects) {
		return errors.New("native route forward result object authority differs")
	}
	return nil
}

func validateNativeRouteTypedEvidence(receipt nativeRouteReceipt) error {
	started, startErr := time.Parse(time.RFC3339Nano, receipt.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, receipt.FinishedAt)
	if startErr != nil || finishErr != nil || finished.Before(started) || !nativeRouteHex(receipt.WriteJournalSHA256, sha256.Size) {
		return errors.New("native route receipt timing or write-journal digest differs")
	}
	if err := validateNativeRouteStateEvidence(receipt); err != nil {
		return err
	}
	if err := validateNativeRouteHTTPEvidence(receipt); err != nil {
		return err
	}
	return validateNativeRouteWriteEvidence(receipt)
}

func loadNativeRouteAdapterConfig(path string) (nativeRouteAdapterConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nativeRouteAdapterConfig{}, err
	}
	var wire nativeRouteAdapterConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nativeRouteAdapterConfig{}, fmt.Errorf("native route adapter config decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nativeRouteAdapterConfig{}, errors.New("native route adapter config has trailing content")
	}
	return wire, nil
}

func validateNativeRouteAdapterConfig(path, contextName, namespace string, authority *config.NativeRouteFixtureConfig) error {
	wire, err := loadNativeRouteAdapterConfig(path)
	if err != nil {
		return err
	}
	f := wire.Run.Fixture
	if wire.Schema != "phorvex.native-route-catalogue.command.v1" || wire.Context != contextName || wire.MaxDurationSeconds < 30 || wire.MaxDurationSeconds > 180 || wire.Run.Schema != "phorvex.native-route-catalogue.config.v1" || wire.Run.SourceRevision != authority.SourceRevision || wire.Run.Action != authority.Action || f.Namespace != namespace || f.NamespaceUID != authority.NamespaceUID || f.JournalNamespaceUID != authority.JournalNamespaceUID || f.PolicyUID != authority.PolicyUID || f.PolicyGeneration != authority.PolicyGeneration || f.TargetUID != authority.TargetUID || f.PeerUID != authority.PeerUID || f.ServiceUID != authority.ServiceUID || f.OperationID != authority.OperationID {
		return errors.New("native route adapter config source, context, or fixture authority differs")
	}
	return nil
}

type nativeRouteBoundedBuffer struct {
	max int
	b   bytes.Buffer
}

func (b *nativeRouteBoundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - b.b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.b.Write(p)
	}
	return n, nil
}

func (b *nativeRouteBoundedBuffer) Bytes() []byte { return b.b.Bytes() }
