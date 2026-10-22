// Package voiceadmissionpolicy defines the independently attested, one-way
// Voice media admission boundary. Legacy application policy hashes remain intact.
package voiceadmissionpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	Namespace       = "voice"
	ConfigMapName   = "voice-session-admission-policy"
	RuleKey         = "rule.json"
	StatePath       = "/v1/voice-session-admission/state"
	ModeObserve     = "observe"
	ModeEnforce     = "require-twilio-signature"
	ScenarioID      = "voice-unauthenticated-media-admission"
	EventType       = "phorvex.attack.voice-session-admission"
	EventAnnotation = "phorvex.ai/voice-admission-observation-v1"
	JournalName     = "phorvex-voice-admission-journal"
	JournalLabel    = "phorvex.ai/voice-admission-journal"
	MaxBytes        = 8192
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidSHA(s string) bool { return shaPattern.MatchString(s) }
func ValidUID(s string) bool { return uidPattern.MatchString(s) }

type Rule struct {
	Version               int    `json:"version"`
	DeploymentUID         string `json:"deploymentUID"`
	SecurityPolicyUID     string `json:"securityPolicyUID"`
	WrapperCMUID          string `json:"wrapperCMUID"`
	AdmissionSourceSHA256 string `json:"admissionSourceSHA256"`
	LegacyBundleSHA256    string `json:"legacyBundleSHA256"`
	AuthProfileSHA256     string `json:"authProfileSHA256"`
	Revision              uint64 `json:"revision"`
	Mode                  string `json:"mode"`
	OperationID           string `json:"operationId"`
}

func (r Rule) Bytes() []byte {
	b, _ := json.Marshal(map[string]any{"version": r.Version, "deploymentUID": r.DeploymentUID, "securityPolicyUID": r.SecurityPolicyUID, "wrapperCMUID": r.WrapperCMUID, "admissionSourceSHA256": r.AdmissionSourceSHA256, "legacyBundleSHA256": r.LegacyBundleSHA256, "authProfileSHA256": r.AuthProfileSHA256, "revision": r.Revision, "mode": r.Mode, "operationId": r.OperationID})
	return b
}
func Digest(b []byte) string  { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (r Rule) SHA256() string { return Digest(r.Bytes()) }
func (r Rule) Valid() bool {
	return r.Version == 1 && ValidUID(r.DeploymentUID) && ValidUID(r.SecurityPolicyUID) && ValidUID(r.WrapperCMUID) && ValidSHA(r.AdmissionSourceSHA256) && ValidSHA(r.LegacyBundleSHA256) && ValidSHA(r.AuthProfileSHA256) && ((r.Revision == 0 && r.Mode == ModeObserve && r.OperationID == "") || (r.Revision == 1 && r.Mode == ModeEnforce && ValidSHA(r.OperationID)))
}
func Parse(raw string) (Rule, error) {
	var r Rule
	if len(raw) == 0 || len(raw) > MaxBytes || json.Unmarshal([]byte(raw), &r) != nil || !r.Valid() || !bytes.Equal([]byte(raw), r.Bytes()) {
		return Rule{}, errors.New("Voice admission rule invalid or noncanonical")
	}
	return r, nil
}
func Enforce(prior Rule, operationID string) (Rule, error) {
	if !prior.Valid() || prior.Revision != 0 || prior.Mode != ModeObserve || !ValidSHA(operationID) {
		return Rule{}, errors.New("Voice admission transition must be observe revision zero to enforced revision one")
	}
	next := prior
	next.Revision = 1
	next.Mode = ModeEnforce
	next.OperationID = operationID
	return next, nil
}

func OperationID(deploymentUID, policyCMUID, securityPolicyUID string, generation int64, eventUID, tickID, decisionID, priorRuleSHA string) (string, error) {
	if !ValidUID(deploymentUID) || !ValidUID(policyCMUID) || !ValidUID(securityPolicyUID) || generation <= 0 || !ValidUID(eventUID) || !ValidSHA(priorRuleSHA) || tickID == "" || decisionID == "" || len(tickID) > 253 || len(decisionID) > 253 || strings.ContainsRune(tickID, '\x00') || strings.ContainsRune(decisionID, '\x00') {
		return "", errors.New("Voice admission operation authority invalid")
	}
	return Digest([]byte(strings.Join([]string{"phorvex.voice-session-admission.enforce.v1", deploymentUID, policyCMUID, securityPolicyUID, strconv.FormatInt(generation, 10), eventUID, tickID, decisionID, priorRuleSHA}, "\x00"))), nil
}

// EventAssertion is a test-generated observation of actual unsigned audio use.
// ProviderEvidenceSHA256 identifies the producer's independently correlated
// provider/transcript proof. Neither a handshake nor a claimed SID establishes loss.
type EventAssertion struct {
	Version                  int    `json:"version"`
	ScenarioID               string `json:"scenarioId"`
	CaseID                   string `json:"caseId"`
	RunSHA256                string `json:"runSHA256"`
	SessionID                string `json:"sessionID"`
	DeploymentUID            string `json:"deploymentUID"`
	PodUID                   string `json:"podUID"`
	AdmissionSourceSHA256    string `json:"admissionSourceSHA256"`
	LegacyBundleSHA256       string `json:"legacyBundleSHA256"`
	AuthProfileSHA256        string `json:"authProfileSHA256"`
	PolicyCMUID              string `json:"policyCMUID"`
	PolicyResourceVersion    string `json:"policyResourceVersion"`
	RuleSHA256               string `json:"ruleSHA256"`
	SelectedRevision         uint64 `json:"selectedRevision"`
	SecurityPolicyUID        string `json:"securityPolicyUID"`
	SecurityPolicyGeneration int64  `json:"securityPolicyGeneration"`
	ObservedAtUnixMs         int64  `json:"observedAtUnixMs"`
	EvidenceSource           string `json:"evidenceSource"`
	Observed                 bool   `json:"observed"`
	Authenticated            bool   `json:"authenticated"`
	SentAudioFrames          uint64 `json:"sentAudioFrames"`
	SentAudioBytes           uint64 `json:"sentAudioBytes"`
	ReceiptSHA256            string `json:"receiptSHA256"`
	ProviderEvidenceSHA256   string `json:"providerEvidenceSHA256"`
}

func (a EventAssertion) Valid() bool {
	return a.Version == 1 && a.ScenarioID == ScenarioID && a.CaseID != "" && len(a.CaseID) <= 128 && !strings.ContainsRune(a.CaseID, '\x00') && ValidSHA(a.RunSHA256) && ValidUID(a.SessionID) && ValidUID(a.DeploymentUID) && ValidUID(a.PodUID) && ValidSHA(a.AdmissionSourceSHA256) && ValidSHA(a.LegacyBundleSHA256) && ValidSHA(a.AuthProfileSHA256) && ValidUID(a.PolicyCMUID) && a.PolicyResourceVersion != "" && len(a.PolicyResourceVersion) <= 128 && ValidSHA(a.RuleSHA256) && a.SelectedRevision == 0 && ValidUID(a.SecurityPolicyUID) && a.SecurityPolicyGeneration > 0 && a.ObservedAtUnixMs > 0 && a.EvidenceSource == "TEST_INJECTED" && a.Observed && !a.Authenticated && a.SentAudioFrames > 0 && a.SentAudioFrames <= 100000 && a.SentAudioBytes > 0 && a.SentAudioBytes <= 16777216 && ValidSHA(a.ReceiptSHA256) && ValidSHA(a.ProviderEvidenceSHA256)
}
func ParseEvent(raw string) (EventAssertion, error) {
	var a EventAssertion
	if err := ExactDecode([]byte(raw), &a); err != nil || !a.Valid() {
		return EventAssertion{}, errors.New("Voice admission event assertion invalid")
	}
	return a, nil
}

type State struct {
	Version               int    `json:"version"`
	PodUID                string `json:"podUID"`
	DeploymentUID         string `json:"deploymentUID"`
	PolicyCMUID           string `json:"policyCMUID"`
	PolicyResourceVersion string `json:"policyResourceVersion"`
	RuleSHA256            string `json:"ruleSHA256"`
	Revision              uint64 `json:"revision"`
	Mode                  string `json:"mode"`
	OperationID           string `json:"operationId"`
	AdmissionSourceSHA256 string `json:"admissionSourceSHA256"`
	LegacyBundleSHA256    string `json:"legacyBundleSHA256"`
	AuthProfileSHA256     string `json:"authProfileSHA256"`
	ObservedAtUnixMs      int64  `json:"observedAtUnixMs"`
	PendingUnsigned       uint64 `json:"pendingUnsigned"`
	ActiveUnsigned        uint64 `json:"activeUnsigned"`
	ActiveSigned          uint64 `json:"activeSigned"`
	TransitionPending     bool   `json:"transitionPending"`
	Settled               bool   `json:"settled"`
	DisconnectsDelivered  uint64 `json:"disconnectsDelivered"`
	DelegatesCompleted    uint64 `json:"delegatesCompleted"`
}

func ParseState(raw []byte) (State, error) {
	var s State
	if err := ExactDecode(raw, &s); err != nil {
		return State{}, err
	}
	if s.Version != 1 || !ValidUID(s.PodUID) || !ValidUID(s.DeploymentUID) || !ValidUID(s.PolicyCMUID) || s.PolicyResourceVersion == "" || len(s.PolicyResourceVersion) > 128 || !ValidSHA(s.RuleSHA256) || !ValidSHA(s.AdmissionSourceSHA256) || !ValidSHA(s.LegacyBundleSHA256) || !ValidSHA(s.AuthProfileSHA256) || s.ObservedAtUnixMs <= 0 || s.PendingUnsigned > 100000 || s.ActiveUnsigned > 100000 || s.ActiveSigned > 100000 || (s.DisconnectsDelivered > (1<<53)-1 || s.DelegatesCompleted > (1<<53)-1) || !((s.Revision == 0 && s.Mode == ModeObserve && s.OperationID == "" && !s.Settled) || (s.Revision == 1 && s.Mode == ModeEnforce && ValidSHA(s.OperationID))) || (s.Settled && (s.TransitionPending || s.PendingUnsigned != 0 || s.ActiveUnsigned != 0)) {
		return State{}, errors.New("Voice admission state identity or barrier invalid")
	}
	return s, nil
}

type SessionReceipt struct {
	Version               int    `json:"version"`
	SessionID             string `json:"sessionID"`
	RunSHA256             string `json:"runSHA256"`
	CallSIDHash           string `json:"callSIDHash"`
	PodUID                string `json:"podUID"`
	DeploymentUID         string `json:"deploymentUID"`
	AdmissionSourceSHA256 string `json:"admissionSourceSHA256"`
	LegacyBundleSHA256    string `json:"legacyBundleSHA256"`
	AuthProfileSHA256     string `json:"authProfileSHA256"`
	AdmissionRuleSHA256   string `json:"admissionRuleSHA256"`
	AdmissionRevision     uint64 `json:"admissionRevision"`
	Authenticated         bool   `json:"authenticated"`
	ConnectedAtUnixMs     int64  `json:"connectedAtUnixMs"`
	ObservedAtUnixMs      int64  `json:"observedAtUnixMs"`
	DisconnectedAtUnixMs  int64  `json:"disconnectedAtUnixMs"`
	Stage                 string `json:"stage"`
	ReceivedAudioFrames   uint64 `json:"receivedAudioFrames"`
	SentAudioFrames       uint64 `json:"sentAudioFrames"`
	SentAudioBytes        uint64 `json:"sentAudioBytes"`
	DisconnectDelivered   bool   `json:"disconnectDelivered"`
	DelegateCompleted     bool   `json:"delegateCompleted"`
}

func ParseSession(raw []byte) (SessionReceipt, error) {
	var s SessionReceipt
	if ExactDecode(raw, &s) != nil || s.Version != 1 || !ValidUID(s.SessionID) || !ValidSHA(s.RunSHA256) || (s.CallSIDHash != "" && !ValidSHA(s.CallSIDHash)) || !ValidUID(s.PodUID) || !ValidUID(s.DeploymentUID) || !ValidSHA(s.AdmissionSourceSHA256) || !ValidSHA(s.LegacyBundleSHA256) || !ValidSHA(s.AuthProfileSHA256) || !ValidSHA(s.AdmissionRuleSHA256) || s.AdmissionRevision > 1 || s.ConnectedAtUnixMs <= 0 || s.ObservedAtUnixMs < s.ConnectedAtUnixMs || s.DisconnectedAtUnixMs < 0 || (s.DisconnectedAtUnixMs > 0 && (s.DisconnectedAtUnixMs < s.ConnectedAtUnixMs || s.DisconnectedAtUnixMs > s.ObservedAtUnixMs)) || (s.Stage != "pending" && s.Stage != "pipeline-observed" && s.Stage != "closed" && s.Stage != "rejected") || (s.CallSIDHash == "" && (s.Stage == "pipeline-observed" || s.ReceivedAudioFrames != 0 || s.SentAudioFrames != 0 || s.SentAudioBytes != 0)) || s.ReceivedAudioFrames > 100000 || s.SentAudioFrames > 100000 || s.SentAudioBytes > 16777216 {
		return SessionReceipt{}, errors.New("Voice admission session receipt invalid")
	}
	return s, nil
}

type ProviderEvidence struct {
	Version               int    `json:"version"`
	SessionID             string `json:"sessionID"`
	RunSHA256             string `json:"runSHA256"`
	CallSIDHash           string `json:"callSIDHash"`
	PodUID                string `json:"podUID"`
	DeploymentUID         string `json:"deploymentUID"`
	AdmissionSourceSHA256 string `json:"admissionSourceSHA256"`
	LegacyBundleSHA256    string `json:"legacyBundleSHA256"`
	AuthProfileSHA256     string `json:"authProfileSHA256"`
	ObservedAtUnixMs      int64  `json:"observedAtUnixMs"`
	STTFrames             uint64 `json:"sttFrames"`
	ModelTextFrames       uint64 `json:"modelTextFrames"`
	ModelCompletions      uint64 `json:"modelCompletions"`
	TTSAudioFrames        uint64 `json:"ttsAudioFrames"`
	TTSAudioBytes         uint64 `json:"ttsAudioBytes"`
	STTTextSHA256         string `json:"sttTextSHA256"`
	ModelTextSHA256       string `json:"modelTextSHA256"`
}

func ParseProviderEvidence(raw []byte) (ProviderEvidence, error) {
	var p ProviderEvidence
	if ExactDecode(raw, &p) != nil || p.Version != 1 || !ValidUID(p.SessionID) || !ValidSHA(p.RunSHA256) || !ValidSHA(p.CallSIDHash) || !ValidUID(p.PodUID) || !ValidUID(p.DeploymentUID) || !ValidSHA(p.AdmissionSourceSHA256) || !ValidSHA(p.LegacyBundleSHA256) || !ValidSHA(p.AuthProfileSHA256) || p.ObservedAtUnixMs <= 0 || p.STTFrames == 0 || p.STTFrames > 100000 || p.ModelTextFrames == 0 || p.ModelTextFrames > 100000 || p.ModelCompletions == 0 || p.ModelCompletions > 1000 || p.TTSAudioFrames == 0 || p.TTSAudioFrames > 100000 || p.TTSAudioBytes == 0 || p.TTSAudioBytes > 16777216 || !ValidSHA(p.STTTextSHA256) || !ValidSHA(p.ModelTextSHA256) {
		return ProviderEvidence{}, errors.New("Voice admission actual provider evidence invalid")
	}
	return p, nil
}

// CanonicalBytes matches Python's sorted-key compact UTF-8 evidence encoding.
func CanonicalBytes(v any) []byte {
	raw, _ := json.Marshal(v)
	var fields any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	_ = d.Decode(&fields)
	b, _ := json.Marshal(fields)
	return b
}

// ProviderReceipt is the production observer receipt, retained as a naming alias
// for consumers that use the same frozen producer-evidence contract.
type ProviderReceipt = ProviderEvidence

func ValidateEvidence(e Evidence, a EventAssertion) error {
	s, p := e.Session, e.Provider
	if !a.Valid() || s.ObservedAtUnixMs > a.ObservedAtUnixMs+1000 || p.ObservedAtUnixMs > a.ObservedAtUnixMs+1000 || a.ObservedAtUnixMs-s.ObservedAtUnixMs > 60000 || a.ObservedAtUnixMs-p.ObservedAtUnixMs > 60000 || s.Stage != "pipeline-observed" || s.DisconnectDelivered || s.DelegateCompleted || s.DisconnectedAtUnixMs != 0 || !ValidSHA(s.CallSIDHash) || s.Authenticated || s.AdmissionRevision != 0 || s.ReceivedAudioFrames == 0 || s.SentAudioFrames == 0 || s.SentAudioBytes == 0 || s.SentAudioFrames != a.SentAudioFrames || s.SentAudioBytes != a.SentAudioBytes || s.SessionID != a.SessionID || p.SessionID != a.SessionID || s.RunSHA256 != a.RunSHA256 || p.RunSHA256 != a.RunSHA256 || s.PodUID != a.PodUID || p.PodUID != a.PodUID || s.DeploymentUID != a.DeploymentUID || p.DeploymentUID != a.DeploymentUID || s.AdmissionSourceSHA256 != a.AdmissionSourceSHA256 || p.AdmissionSourceSHA256 != a.AdmissionSourceSHA256 || s.LegacyBundleSHA256 != a.LegacyBundleSHA256 || p.LegacyBundleSHA256 != a.LegacyBundleSHA256 || s.AuthProfileSHA256 != a.AuthProfileSHA256 || p.AuthProfileSHA256 != a.AuthProfileSHA256 || s.CallSIDHash != p.CallSIDHash || s.AdmissionRuleSHA256 != a.RuleSHA256 || Digest(CanonicalBytes(s)) != a.ReceiptSHA256 || Digest(CanonicalBytes(p)) != a.ProviderEvidenceSHA256 {
		return errors.New("Voice admission observed producer/session proof differs from event")
	}
	if _, err := ParseSession(CanonicalBytes(s)); err != nil {
		return err
	}
	if _, err := ParseProviderEvidence(CanonicalBytes(p)); err != nil {
		return err
	}
	return nil
}

type Evidence struct {
	Session  SessionReceipt   `json:"session"`
	Provider ProviderEvidence `json:"provider"`
}

func ParseEvidence(raw []byte) (Evidence, error) {
	var envelope struct {
		Session  json.RawMessage `json:"session"`
		Provider json.RawMessage `json:"provider"`
	}
	if err := ExactDecode(raw, &envelope); err != nil {
		return Evidence{}, err
	}
	s, err := ParseSession(envelope.Session)
	if err != nil {
		return Evidence{}, err
	}
	p, err := ParseProviderEvidence(envelope.Provider)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{Session: s, Provider: p}, nil
}

// ExactDecode rejects duplicate, missing, unknown, and trailing fields, including
// false/zero values that a plain struct decoder would silently manufacture.
func ExactDecode(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return errors.New("Voice admission object bounds")
	}
	shape, _ := json.Marshal(dst)
	var expected map[string]json.RawMessage
	_ = json.Unmarshal(shape, &expected)
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errors.New("Voice admission object expected")
	}
	seen := map[string]bool{}
	for d.More() {
		t, e = d.Token()
		name, ok := t.(string)
		if e != nil || !ok || seen[name] {
			return errors.New("Voice admission duplicate key")
		}
		if _, ok = expected[name]; !ok {
			return fmt.Errorf("Voice admission unexpected key %s", name)
		}
		seen[name] = true
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(v, []byte("null")) {
			return errors.New("Voice admission field invalid")
		}
	}
	t, e = d.Token()
	if e != nil || t != json.Delim('}') || len(seen) != len(expected) {
		return errors.New("Voice admission object incomplete")
	}
	if d.Decode(new(any)) == nil {
		return errors.New("Voice admission trailing object")
	}
	var extra any
	if json.Unmarshal(raw, &extra) != nil {
		return errors.New("Voice admission trailing bytes")
	}
	return json.Unmarshal(raw, dst)
}
