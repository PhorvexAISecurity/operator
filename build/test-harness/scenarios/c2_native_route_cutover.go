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
	"strconv"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	nativeRouteScenario       = "c2-native-route-cutover"
	nativeEndpointScenario    = "c2-native-endpoint-cutover"
	nativeRouteReceiptSchema  = "phorvex.native-route-catalogue.receipt.v1"
	nativeRouteMaxOutputBytes = 32 * 1024
)

func init() {
	core.RegisterScenario(&c2NativeRouteCutover{action: "route-rotate", name: nativeRouteScenario})
	core.RegisterScenario(&c2NativeRouteCutover{action: "endpoint-rotate", name: nativeEndpointScenario})
}

// c2NativeRouteCutover is a typed handoff to the production-entrypoint adapter.
// Fixture creation and terminal cleanup remain with the external exact-UID
// supervisor; this scenario can only run the two fixed selector-cutover actions.
type c2NativeRouteCutover struct {
	action    string
	name      string
	receipt   nativeRouteReceipt
	evidence  map[string]string
	authority config.NativeRouteFixtureConfig
}

type nativeRouteReceipt struct {
	Schema                  string                    `json:"schema"`
	SourceRevision          string                    `json:"sourceRevision"`
	Action                  string                    `json:"action"`
	Fixture                 nativeRouteReceiptFixture `json:"fixture"`
	StartedAt               string                    `json:"startedAt"`
	FinishedAt              string                    `json:"finishedAt"`
	Status                  string                    `json:"status"`
	Baseline                json.RawMessage           `json:"baseline"`
	Forward                 json.RawMessage           `json:"forward"`
	Restored                json.RawMessage           `json:"restored"`
	ForwardResult           nativeRouteResult         `json:"forwardResult"`
	ReconciliationAttempted bool                      `json:"reconciliationAttempted"`
	ReconciliationResult    json.RawMessage           `json:"reconciliationResult"`
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
	NamespaceUID        string `json:"namespaceUID"`
	JournalNamespaceUID string `json:"journalNamespaceUID"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	TargetUID           string `json:"targetUID"`
	PeerUID             string `json:"peerUID"`
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
	Actuator     string `json:"Actuator"`
	Handler      string `json:"Handler"`
	Emitted      bool   `json:"Emitted"`
	MutationKind string `json:"MutationKind"`
	RollbackRef  string `json:"RollbackRef"`
}

type nativeRouteHTTP struct {
	Endpoint string `json:"endpoint"`
	Error    string `json:"error"`
}

type nativeRouteWrite struct {
	Method    string `json:"method"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Error     string `json:"error"`
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
	if s.receipt.Schema != nativeRouteReceiptSchema || s.receipt.Status != "COMPLETE" || s.receipt.Action != s.action || s.receipt.ForwardResult.Actuator != "native" || s.receipt.ForwardResult.Handler != s.action || !s.receipt.ForwardResult.Emitted || s.receipt.ForwardResult.MutationKind != "reversible" || s.receipt.ForwardResult.RollbackRef == "" || !s.receipt.RollbackAttempted || s.receipt.RollbackError != "" || len(s.receipt.Errors) != 0 || len(s.receipt.Baseline) == 0 || len(s.receipt.Forward) == 0 || len(s.receipt.Restored) == 0 || s.receipt.WriteJournalSchema != "phorvex.native-route-catalogue.write-journal.v1" || len(s.receipt.WriteJournalSHA256) != 64 || s.receipt.WriteJournalBytes <= 0 {
		return core.OracleResult{Achieved: false, ObservedState: "native route receipt incomplete or mismatched", Evidence: s.evidence}, nil
	}
	if len(s.receipt.HTTP) == 0 || len(s.receipt.Writes) == 0 {
		return core.OracleResult{Achieved: false, ObservedState: "native route receipt lacks producer evidence", Evidence: s.evidence}, nil
	}
	for _, write := range s.receipt.Writes {
		if write.Error != "" {
			return core.OracleResult{Achieved: false, ObservedState: "native route receipt contains a failed admitted write", Evidence: s.evidence}, nil
		}
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
	var wire struct {
		Schema                  string            `json:"schema"`
		SourceRevision          string            `json:"sourceRevision"`
		Action                  string            `json:"action"`
		Fixture                 json.RawMessage   `json:"fixture"`
		StartedAt               string            `json:"startedAt"`
		FinishedAt              string            `json:"finishedAt"`
		Status                  string            `json:"status"`
		Baseline                json.RawMessage   `json:"baseline"`
		Forward                 json.RawMessage   `json:"forward"`
		Restored                json.RawMessage   `json:"restored"`
		ForwardResult           json.RawMessage   `json:"forwardResult"`
		ReconciliationAttempted bool              `json:"reconciliationAttempted"`
		ReconciliationResult    json.RawMessage   `json:"reconciliationResult"`
		ReconciliationError     string            `json:"reconciliationError"`
		RollbackAttempted       bool              `json:"rollbackAttempted"`
		RollbackError           string            `json:"rollbackError"`
		HTTP                    []json.RawMessage `json:"http"`
		Writes                  []json.RawMessage `json:"writes"`
		WriteJournalSchema      string            `json:"writeJournalSchema"`
		WriteJournalSHA256      string            `json:"writeJournalSHA256"`
		WriteJournalBytes       int64             `json:"writeJournalBytes"`
		AvailabilityInterrupted bool              `json:"availabilityInterrupted"`
		Errors                  []string          `json:"errors"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("native route receipt decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("native route receipt has trailing content")
	}
	*out = nativeRouteReceipt{Schema: wire.Schema, SourceRevision: wire.SourceRevision, Action: wire.Action, StartedAt: wire.StartedAt, FinishedAt: wire.FinishedAt, Status: wire.Status, Baseline: wire.Baseline, Forward: wire.Forward, Restored: wire.Restored, ReconciliationAttempted: wire.ReconciliationAttempted, ReconciliationResult: wire.ReconciliationResult, ReconciliationError: wire.ReconciliationError, RollbackAttempted: wire.RollbackAttempted, RollbackError: wire.RollbackError, WriteJournalSchema: wire.WriteJournalSchema, WriteJournalSHA256: wire.WriteJournalSHA256, WriteJournalBytes: wire.WriteJournalBytes, AvailabilityInterrupted: wire.AvailabilityInterrupted, Errors: wire.Errors}
	if err := json.Unmarshal(wire.Fixture, &out.Fixture); err != nil {
		return fmt.Errorf("native route fixture receipt decode: %w", err)
	}
	if err := json.Unmarshal(wire.ForwardResult, &out.ForwardResult); err != nil {
		return fmt.Errorf("native route result decode: %w", err)
	}
	for _, item := range wire.HTTP {
		var observation nativeRouteHTTP
		if err := json.Unmarshal(item, &observation); err != nil {
			return fmt.Errorf("native route HTTP receipt decode: %w", err)
		}
		out.HTTP = append(out.HTTP, observation)
	}
	for _, item := range wire.Writes {
		var write nativeRouteWrite
		if err := json.Unmarshal(item, &write); err != nil {
			return fmt.Errorf("native route write receipt decode: %w", err)
		}
		out.Writes = append(out.Writes, write)
	}
	return nil
}

func validateNativeRouteReceiptAuthority(receipt nativeRouteReceipt, fixture *config.NativeRouteFixtureConfig) error {
	if fixture == nil || receipt.SourceRevision != fixture.SourceRevision || receipt.Action != fixture.Action || receipt.Fixture.NamespaceUID != fixture.NamespaceUID || receipt.Fixture.JournalNamespaceUID != fixture.JournalNamespaceUID || receipt.Fixture.PolicyUID != fixture.PolicyUID || receipt.Fixture.PolicyGeneration != fixture.PolicyGeneration || receipt.Fixture.TargetUID != fixture.TargetUID || receipt.Fixture.PeerUID != fixture.PeerUID || receipt.Fixture.ServiceUID != fixture.ServiceUID || receipt.Fixture.OperationID != fixture.OperationID {
		return errors.New("native route receipt source or fixture authority differs")
	}
	return nil
}

func validateNativeRouteAdapterConfig(path, contextName, namespace string, authority *config.NativeRouteFixtureConfig) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var wire nativeRouteAdapterConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("native route adapter config decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("native route adapter config has trailing content")
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
