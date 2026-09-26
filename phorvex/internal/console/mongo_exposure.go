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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
	"sigs.k8s.io/yaml"
)

const mongoExposureConfig = "mongo-exposure-baseline"
const mongoExposureNamespace = "document-store"

var mongoRunID = regexp.MustCompile(`^run-[1-9][0-9]*$`)
var mongoNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)
var mongoSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var mongoPinnedImage = regexp.MustCompile(`^[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$`)
var mongoKubeUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// MongoExposureResult reports configuration exposure and audit coverage. The
// synthetic read is never a security response or actuator efficacy verdict.
type MongoExposureResult struct {
	Schema           string                  `json:"schema"`
	Accepted         bool                    `json:"accepted"`
	Finding          string                  `json:"finding"`
	ObservedFinding  string                  `json:"observedFinding"`
	ClientRead       string                  `json:"clientRead"`
	LegitimateBefore string                  `json:"legitimateBefore"`
	LegitimateAfter  string                  `json:"legitimateAfter"`
	Cleanup          string                  `json:"cleanup"`
	BrainTrace       string                  `json:"brainTrace"`
	BrainDecisions   []mongoExposureDecision `json:"brainDecisions"`
	SecurityOutcome  string                  `json:"securityOutcome"`
	RawReplySHA256   string                  `json:"rawReplySHA256"`
	RawReplyBytes    int                     `json:"rawReplyBytes"`
	SourcePodUID     string                  `json:"sourcePodUID"`
	ClientPodUID     string                  `json:"clientPodUID"`
	PolicyUID        string                  `json:"policyUID"`
	Issues           []string                `json:"issues"`
}

type mongoExposureDecision struct {
	DecisionID string `json:"decisionID"`
	PolicyUID  string `json:"policyUID"`
	// PolicyGeneration is copied from the pinned policy API source snapshot.
	// DecisionTraceV2 does not record the generation consumed by this decision.
	PolicyGeneration  int64                  `json:"policyGeneration"`
	TargetPodUID      string                 `json:"targetPodUID"`
	Action            string                 `json:"action"`
	ActionStatus      string                 `json:"actionStatus"`
	ReasonSHA256      string                 `json:"reasonSHA256"`
	ReasonCode        string                 `json:"reasonCode"`
	ReasonText        string                 `json:"reasonText"`
	DispatchOutcome   string                 `json:"dispatchOutcome"`
	CandidateStatuses []mongoCandidateStatus `json:"candidateStatuses"`
	ObservedAt        string                 `json:"observedAt"`
}
type mongoCandidateStatus struct {
	Action        string `json:"action"`
	Status        string `json:"status"`
	ExclusionKind string `json:"exclusionKind"`
	Scored        bool   `json:"scored"`
}

type mongoSourceEvidence struct {
	NamespaceUID       string `json:"namespaceUID"`
	DeploymentUID      string `json:"deploymentUID"`
	ReplicaSetUID      string `json:"replicaSetUID"`
	PodName            string `json:"podName"`
	PodUID             string `json:"podUID"`
	PodIP              string `json:"podIP"`
	NodeName           string `json:"nodeName"`
	ContainerID        string `json:"containerID"`
	ImageID            string `json:"imageID"`
	PVCUID             string `json:"pvcUID"`
	ServiceUID         string `json:"serviceUID"`
	EndpointSliceUID   string `json:"endpointSliceUID"`
	PolicyUID          string `json:"policyUID"`
	PolicyGeneration   int64  `json:"policyGeneration"`
	PolicySpecSHA256   string `json:"policySpecSHA256"`
	ManagerPodUID      string `json:"managerPodUID"`
	ManagerContainerID string `json:"managerContainerID"`
	ManagerImageID     string `json:"managerImageID"`
}
type mongoArtifactEvidence struct {
	Schema               string              `json:"schema"`
	RunID                string              `json:"runId"`
	Nonce                string              `json:"nonce"`
	Namespace            string              `json:"namespace"`
	ClusterUID           string              `json:"clusterUID"`
	Source               mongoSourceEvidence `json:"source"`
	Database             string              `json:"database"`
	Collection           string              `json:"collection"`
	CollectionUUID       string              `json:"collectionUUID"`
	ServerVersion        string              `json:"serverVersion"`
	DocumentSHA256       string              `json:"documentSHA256"`
	ClientPodName        string              `json:"clientPodName"`
	ClientPodUID         string              `json:"clientPodUID"`
	ClientContainerID    string              `json:"clientContainerID"`
	ClientImageID        string              `json:"clientImageID"`
	ClientRead           string              `json:"clientRead"`
	ClientDocumentSHA256 string              `json:"clientDocumentSHA256"`
	RawReplySHA256       string              `json:"rawReplySHA256"`
	RawReplyBytes        int                 `json:"rawReplyBytes"`
	LegitimateBefore     string              `json:"legitimateBefore"`
	LegitimateAfter      string              `json:"legitimateAfter"`
	ObservedFinding      string              `json:"observedFinding"`
	Validity             string              `json:"validity"`
	Cleanup              string              `json:"cleanup"`
	SecurityOutcome      string              `json:"securityOutcome"`
	StartedAt            string              `json:"startedAt"`
	ObservationEndedAt   string              `json:"observationEndedAt"`
	FinishedAt           string              `json:"finishedAt"`
}
type mongoTerminalEvidence struct {
	Schema             string `json:"schema"`
	RunID              string `json:"runId"`
	Nonce              string `json:"nonce"`
	NamespaceUID       string `json:"namespaceUID"`
	ArtifactSHA256     string `json:"artifactSHA256"`
	CollectionAbsent   bool   `json:"collectionAbsent"`
	ClientPodAbsent    bool   `json:"clientPodAbsent"`
	NamespacePreserved bool   `json:"namespacePreserved"`
	Cleanup            string `json:"cleanup"`
}
type mongoRuntimeConfig struct {
	Context              string `json:"context"`
	Namespace            string `json:"namespace"`
	OutDir               string `json:"outDir"`
	MongoExposureFixture struct {
		RunID          string `json:"runID"`
		Nonce          string `json:"nonce"`
		ClusterUID     string `json:"clusterUID"`
		MongoImageID   string `json:"mongoImageID"`
		ManagerImageID string `json:"managerImageID"`
	} `json:"mongoExposureFixture"`
}
type mongoAuditStart struct {
	Schema         string                 `json:"schema"`
	RunID          string                 `json:"runId"`
	SourceIdentity string                 `json:"sourceIdentity"`
	ConfigSHA256   string                 `json:"configSHA256"`
	Segment        audittransport.Segment `json:"segment"`
	Offset         int64                  `json:"offset"`
	ObservedAt     string                 `json:"observedAt"`
}
type mongoAuditTerminal struct {
	Schema         string                  `json:"schema"`
	RunID          string                  `json:"runId"`
	StartSHA256    string                  `json:"startSHA256"`
	ArtifactSHA256 string                  `json:"artifactSHA256"`
	SourceIdentity string                  `json:"sourceIdentity"`
	Segment        audittransport.Segment  `json:"segment"`
	Offset         int64                   `json:"offset"`
	ObservedAt     string                  `json:"observedAt"`
	BrainTrace     string                  `json:"brainTrace"`
	BrainDecisions []mongoExposureDecision `json:"brainDecisions"`
	IssueCode      string                  `json:"issueCode,omitempty"`
	WindowSHA256   string                  `json:"windowSHA256"`
	WindowBytes    int                     `json:"windowBytes"`
	ObservationEnd string                  `json:"observationEnd"`
}

type mongoPhaseEvidence struct {
	Schema   string `json:"schema"`
	RunID    string `json:"runId"`
	Nonce    string `json:"nonce"`
	Phase    string `json:"phase"`
	Resource string `json:"resource"`
	Name     string `json:"name"`
	Identity string `json:"identity"`
	At       string `json:"at"`
}

func mongoPhaseChainMatches(out string, a mongoArtifactEvidence, started, observed, finished time.Time) bool {
	raw, err := readNATSResponseSizedFile(out, "mongo-exposure-phases.jsonl", 64<<10)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return false
	}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	if len(lines) != 12 {
		return false
	}
	collection := a.Database + "." + a.Collection
	want := []struct{ phase, resource, name, identity string }{
		{"CREATE_INTENT", "collection", collection, ""}, {"CREATE_ACK", "collection", collection, ""},
		{"UUID_CONFIRMED", "collection", collection, a.CollectionUUID}, {"INSERT_INTENT", "document", a.Nonce, ""},
		{"INSERT_ACK", "document", a.Nonce, a.Nonce}, {"CREATE_INTENT", "pod", a.ClientPodName, ""},
		{"CREATED", "pod", a.ClientPodName, a.ClientPodUID}, {"DELETE_INTENT", "pod", a.ClientPodName, a.ClientPodUID},
		{"ABSENT", "pod", a.ClientPodName, a.ClientPodUID}, {"DROP_INTENT", "collection", collection, a.CollectionUUID},
		{"DROP_ACK", "collection", collection, a.CollectionUUID}, {"ABSENT", "collection", collection, a.CollectionUUID},
	}
	previous := started
	for i, line := range lines {
		if rejectAmbiguousMongoJSON(line) != nil {
			return false
		}
		var got mongoPhaseEvidence
		if json.Unmarshal(line, &got) != nil || got.Schema != "mongo-exposure-phase-v1" || got.RunID != a.RunID || got.Nonce != a.Nonce || got.Phase != want[i].phase || got.Resource != want[i].resource || got.Name != want[i].name || got.Identity != want[i].identity {
			return false
		}
		at, err := time.Parse(time.RFC3339Nano, got.At)
		if err != nil || at.Before(previous) || at.After(finished) || i <= 6 && at.After(observed) || i >= 7 && at.Before(observed) {
			return false
		}
		previous = at
	}
	return true
}

func mongoHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func rejectAmbiguousMongoJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		v, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				k, ok := key.(string)
				if err != nil || !ok || seen[strings.ToLower(k)] {
					return errors.New("duplicate Mongo JSON key")
				}
				seen[strings.ToLower(k)] = true
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("Mongo JSON object incomplete")
			}
		case '[':
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("Mongo JSON array incomplete")
			}
		default:
			return errors.New("Mongo JSON delimiter invalid")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("Mongo JSON trailing bytes")
	}
	return nil
}

func mongoDocumentHash(nonce string) string {
	raw, _ := json.Marshal(map[string]string{"_id": nonce, "nonce": nonce, "payload": "synthetic-mongo-exposure-v1", "state": "initial"})
	return mongoHash(raw)
}

func mongoReply(raw []byte, nonce string) (string, string, error) {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.Valid(raw) || bytes.Count(raw, []byte{'\n'}) > 1 {
		return "", "", errors.New("Mongo original reply bound invalid")
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if !strings.HasPrefix(line, "CAT_MONGO_JSON=") || strings.ContainsAny(line, "\r\n") {
		return "", "", errors.New("Mongo original reply framing invalid")
	}
	body := []byte(strings.TrimPrefix(line, "CAT_MONGO_JSON="))
	if rejectAmbiguousMongoJSON(body) != nil {
		return "", "", errors.New("Mongo original reply JSON ambiguous")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 4 {
		return "", "", errors.New("Mongo original reply fields invalid")
	}
	for _, key := range []string{"ok", "code", "codeName", "rows"} {
		if _, ok := fields[key]; !ok {
			return "", "", errors.New("Mongo original reply field missing")
		}
	}
	var ok bool
	var code json.Number
	var codeName string
	var rows []json.RawMessage
	if json.Unmarshal(fields["ok"], &ok) != nil || json.Unmarshal(fields["code"], &code) != nil || json.Unmarshal(fields["codeName"], &codeName) != nil || json.Unmarshal(fields["rows"], &rows) != nil {
		return "", "", errors.New("Mongo original reply types invalid")
	}
	n, err := code.Int64()
	if err != nil {
		return "", "", errors.New("Mongo original reply code invalid")
	}
	if !ok && n == 13 && codeName == "Unauthorized" && len(rows) == 0 {
		return "MONGO_AUTH_DENIED", "", nil
	}
	if !ok || n != 0 || codeName != "" {
		return "UNKNOWN_SERVER_REFUSAL", "", nil
	}
	if len(rows) == 0 {
		return "UNKNOWN_DOCUMENT_ABSENT", "", nil
	}
	if len(rows) != 1 || rejectAmbiguousMongoJSON(rows[0]) != nil {
		return "", "", errors.New("Mongo original reply document invalid")
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(rows[0], &doc) != nil || len(doc) != 4 {
		return "", "", errors.New("Mongo original reply document fields invalid")
	}
	want := map[string]string{"_id": nonce, "nonce": nonce, "payload": "synthetic-mongo-exposure-v1", "state": "initial"}
	for key, value := range want {
		var got string
		if json.Unmarshal(doc[key], &got) != nil || got != value {
			return "", "", errors.New("Mongo original reply document differs")
		}
	}
	return "UNAUTHENTICATED_EXACT_READ", mongoDocumentHash(nonce), nil
}

// Called synchronously by Start after sealing the run-specific config and
// before launching the harness. A missing authenticated audit cannot be
// retroactively substituted with a later window.
func (rm *RunManager) captureMongoAuditStart(id, out string) error {
	if rm.cfg.AuditSource == nil || rm.cfg.AuditSourceIdentity == "" {
		return errors.New("authenticated audit source unavailable")
	}
	configRaw, err := readBoundedFile(filepath.Join(rm.cfg.runsDir(), "configs", id+".yaml"), 64<<10)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	m, err := rm.cfg.AuditSource.Manifest(ctx)
	if err != nil || len(m.Segments) == 0 || m.Segments[0].ID != "live" {
		return errors.New("authenticated audit manifest unavailable")
	}
	seg := m.Segments[0]
	if seg.Size > 0 {
		end, err := rm.cfg.AuditSource.Chunk(ctx, seg, seg.Size-1)
		if err != nil || len(end) != 1 || end[0] != '\n' {
			return errors.New("audit start offset is not a complete row")
		}
	}
	checkpoint := mongoAuditStart{Schema: "mongo-exposure-audit-start-v1", RunID: id, SourceIdentity: rm.cfg.AuditSourceIdentity, ConfigSHA256: mongoHash(configRaw), Segment: seg, Offset: seg.Size, ObservedAt: time.Unix(0, m.FetchedAt).UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	if err := os.Mkdir(rm.cfg.runOutputPath(out), 0o700); err != nil {
		return err
	}
	return atomicWriteState(filepath.Join(rm.cfg.runOutputPath(out), "mongo-exposure-audit-start.json"), raw)
}

func readMongoRuntime(cfg Config, id, out string, checkpoint mongoAuditStart) (mongoRuntimeConfig, error) {
	var runtime mongoRuntimeConfig
	raw, err := readBoundedFile(filepath.Join(cfg.runsDir(), "configs", id+".yaml"), 64<<10)
	if err != nil || mongoHash(raw) != checkpoint.ConfigSHA256 {
		return runtime, errors.New("Mongo run config differs from pre-mutation checkpoint")
	}
	if yaml.Unmarshal(raw, &runtime) != nil || runtime.Namespace != mongoExposureNamespace || runtime.OutDir != cfg.runOutputPath(out) || runtime.MongoExposureFixture.RunID != id || !mongoNonce.MatchString(runtime.MongoExposureFixture.Nonce) || runtime.Context == "" || runtime.Context == "in-cluster" {
		return runtime, errors.New("Mongo runtime authority differs")
	}
	return runtime, nil
}

func mongoReason(raw string) (code, text string) {
	switch raw {
	case "":
		return "NONE", ""
	case "reactive-only: no direct foothold":
		return "REACTIVE_ONLY_NO_DIRECT_FOOTHOLD", "Policy requires a qualifying direct event for this workload; none was observed in this decision, so no action was attempted."
	default:
		return "OTHER_RECORDED_REASON", ""
	}
}

func projectMongoDecision(rec audit.Record, source mongoSourceEvidence, startAt, terminalAt time.Time) (mongoExposureDecision, error) {
	var row mongoExposureDecision
	t := rec.DecisionTrace
	traceAt, traceErr := time.Parse(time.RFC3339Nano, func() string {
		if t == nil {
			return ""
		}
		return t.Timestamp
	}())
	if traceErr != nil || rec.Time.IsZero() || rec.Time.Before(startAt) || rec.Time.After(terminalAt) || traceAt.Before(startAt) || traceAt.After(terminalAt) || traceAt.After(rec.Time.Add(2*time.Second)) || rec.Time.Sub(traceAt) > 30*time.Second {
		return row, errors.New("Mongo decision clock is outside sealed audit window")
	}
	if t == nil || t.Validate() != nil || t.PolicyUID != source.PolicyUID || t.AssetUID != source.PodUID || t.PolicyNamespace != mongoExposureNamespace || t.AssetNamespace != mongoExposureNamespace || t.AssetName != source.PodName || t.TenantName != "mongo" || rec.Tenant != "mongo" || rec.Namespace != mongoExposureNamespace || rec.Pod != source.PodName || rec.Action != t.SelectedAction || rec.DispatchOutcome != t.DispatchOutcome {
		return row, errors.New("exact Mongo decision trace invalid")
	}
	actions, err := model.DecisionTraceActions(t.ActionVocabularyVersion)
	if err != nil || len(t.ActionStatus) != len(actions) {
		return row, errors.New("Mongo decision action vocabulary invalid")
	}
	allowed := make(map[string]bool, len(actions))
	for _, action := range actions {
		allowed[string(action)] = true
	}
	if t.SelectedAction != string(model.ActionNoop) && !allowed[t.SelectedAction] {
		return row, errors.New("Mongo selected action outside decision vocabulary")
	}
	for _, candidate := range t.Candidates {
		if !allowed[candidate.Action] {
			return row, errors.New("Mongo candidate outside decision vocabulary")
		}
	}
	row.CandidateStatuses = make([]mongoCandidateStatus, 0, len(t.ActionStatus))
	row.ActionStatus = "no-action-selected"
	for i, status := range t.ActionStatus {
		if status.Action != string(actions[i]) || status.Status == "" {
			return row, errors.New("Mongo candidate accounting differs")
		}
		row.CandidateStatuses = append(row.CandidateStatuses, mongoCandidateStatus{Action: status.Action, Status: status.Status, ExclusionKind: status.ExclusionKind, Scored: status.Scored})
		if status.Action == t.SelectedAction {
			row.ActionStatus = status.Status
		}
	}
	reason := t.NoopReason
	if reason == "" {
		reason = rec.Reason
	}
	row.ReasonCode, row.ReasonText = mongoReason(reason)
	if row.ReasonCode == "REACTIVE_ONLY_NO_DIRECT_FOOTHOLD" && (t.SelectedAction != string(model.ActionNoop) || t.DispatchOutcome != model.DispatchNotAttempted || t.NoopReason != reason) {
		row.ReasonCode, row.ReasonText = "OTHER_RECORDED_REASON", ""
	}
	row.DecisionID, row.PolicyUID, row.PolicyGeneration, row.TargetPodUID = t.DecisionID, t.PolicyUID, source.PolicyGeneration, t.AssetUID
	row.Action, row.DispatchOutcome, row.ObservedAt = t.SelectedAction, model.SafeDispatchOutcome(t.DispatchOutcome), rec.Time.UTC().Format(time.RFC3339Nano)
	row.ReasonSHA256 = mongoHash([]byte(reason))
	if row.DecisionID == "" || row.DispatchOutcome == "" || row.ObservedAt == "" {
		return mongoExposureDecision{}, errors.New("Mongo decision identity or dispatch unavailable")
	}
	return row, nil
}

func projectMongoAuditBytes(raw []byte, source mongoSourceEvidence, startAt, endAt time.Time) ([]mongoExposureDecision, string, error) {
	if len(raw) == 0 {
		return []mongoExposureDecision{}, "UNKNOWN", nil
	}
	if raw[len(raw)-1] != '\n' {
		return nil, "GAP", errors.New("audit terminal row incomplete")
	}
	rows := make([]mongoExposureDecision, 0)
	seen := make(map[string]bool)
	for _, line := range bytes.Split(raw[:len(raw)-1], []byte{'\n'}) {
		if len(line) == 0 || len(line) > 4<<20 || rejectAmbiguousMongoJSON(line) != nil {
			return nil, "GAP", errors.New("audit row invalid or ambiguous")
		}
		var head struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(line, &head) != nil || head.Kind == "" {
			return nil, "GAP", errors.New("audit row invalid")
		}
		if head.Kind != "phorvex.decision" {
			continue
		}
		var rec audit.Record
		if json.Unmarshal(line, &rec) != nil {
			return nil, "GAP", errors.New("audit decision invalid")
		}
		if rec.Namespace != mongoExposureNamespace || rec.Pod != source.PodName {
			continue
		}
		if rec.DecisionTrace == nil || rec.DecisionTrace.AssetUID != source.PodUID {
			return nil, "GAP", errors.New("same-name Mongo decision lacks exact source incarnation")
		}
		traceAt, traceErr := time.Parse(time.RFC3339Nano, rec.DecisionTrace.Timestamp)
		if traceErr != nil {
			return nil, "GAP", errors.New("same-name Mongo decision timestamp invalid")
		}
		// The authenticated terminal is taken after the harness exits. Normal
		// manager ticks during cleanup are outside the declared observation.
		if traceAt.After(endAt) && rec.Time.After(endAt) {
			continue
		}
		if rec.DecisionTrace.PolicyUID != source.PolicyUID {
			continue
		}
		row, err := projectMongoDecision(rec, source, startAt, endAt)
		if err != nil || seen[row.DecisionID] || len(rows) >= 64 {
			return nil, "GAP", errors.New("audit target decision invalid, duplicate or over bound")
		}
		seen[row.DecisionID] = true
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return rows, "UNKNOWN", nil
	}
	return rows, "JOINED", nil
}

func (rm *RunManager) readMongoAuditWindow(ctx context.Context, start mongoAuditStart, source mongoSourceEvidence, observationEnd time.Time) ([]mongoExposureDecision, string, audittransport.Segment, time.Time, []byte, error) {
	startAt, parseErr := time.Parse(time.RFC3339Nano, start.ObservedAt)
	if rm.cfg.AuditSource == nil || start.SourceIdentity != rm.cfg.AuditSourceIdentity || start.Schema != "mongo-exposure-audit-start-v1" || start.Segment.ID != "live" || start.Offset != start.Segment.Size {
		return nil, "GAP", audittransport.Segment{}, time.Time{}, nil, errors.New("audit checkpoint identity differs")
	}
	if parseErr != nil || startAt.IsZero() || observationEnd.IsZero() || observationEnd.Before(startAt) {
		return nil, "GAP", audittransport.Segment{}, time.Time{}, nil, errors.New("audit checkpoint or observation time invalid")
	}
	m, err := rm.cfg.AuditSource.Manifest(ctx)
	if err != nil || len(m.Segments) == 0 {
		return nil, "GAP", audittransport.Segment{}, time.Time{}, nil, errors.New("audit terminal manifest unavailable")
	}
	seg := m.Segments[0]
	terminalAt := time.Unix(0, m.FetchedAt).UTC()
	if seg.ID != "live" || seg.Generation != start.Segment.Generation || seg.Anchor != start.Segment.Anchor || seg.Size < start.Offset || seg.Size-start.Offset > 64<<20 || observationEnd.After(terminalAt) {
		return nil, "GAP", seg, terminalAt, nil, errors.New("audit terminal generation, size or observation time differs")
	}
	if seg.Size == start.Offset {
		return []mongoExposureDecision{}, "UNKNOWN", seg, terminalAt, []byte{}, nil
	}
	reader := rm.cfg.AuditSource.Open(ctx, seg)
	defer reader.Close()
	raw := make([]byte, 0, seg.Size-start.Offset)
	for at := start.Offset; at < seg.Size; {
		size := min(int64(1<<20), seg.Size-at)
		chunk := make([]byte, size)
		if _, err := reader.ReadAt(chunk, at); err != nil {
			return nil, "GAP", seg, terminalAt, nil, errors.New("audit contiguous read failed")
		}
		at += size
		raw = append(raw, chunk...)
	}
	rows, state, err := projectMongoAuditBytes(raw, source, startAt, observationEnd)
	if err != nil {
		return nil, "GAP", seg, terminalAt, raw, err
	}
	return rows, state, seg, terminalAt, raw, nil
}

func publishMongoAuditFile(out, name string, raw []byte, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("Mongo audit terminal absent or oversized")
	}
	root, err := natsResponseRoot(out)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err = root.Lstat(name); err == nil {
		return errors.New("Mongo audit terminal already sealed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(name+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = root.Link(name+".tmp", name); err != nil {
		return err
	}
	if err = root.Remove(name + ".tmp"); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func publishMongoAuditTerminal(out string, raw []byte) error {
	return publishMongoAuditFile(out, "mongo-exposure-audit-terminal.json", raw, 256<<10)
}

// Seal once, after the original harness process exits. All later GETs consume
// these immutable bytes; a future manager append/rotation cannot rewrite the
// historical decision set for this run.
func (rm *RunManager) sealMongoAudit(id, out string) error {
	startRaw, err := readNATSResponseSizedFile(out, "mongo-exposure-audit-start.json", 4096)
	if err != nil || rejectAmbiguousMongoJSON(startRaw) != nil {
		return errors.New("Mongo audit start unavailable for terminal seal")
	}
	var start mongoAuditStart
	if json.Unmarshal(startRaw, &start) != nil || start.RunID != id {
		return errors.New("Mongo audit start run differs")
	}
	artifactRaw, err := readNATSResponseSizedFile(out, "mongo-exposure.json", 64<<10)
	if err != nil || rejectAmbiguousMongoJSON(artifactRaw) != nil {
		return errors.New("Mongo artifact unavailable for audit seal")
	}
	var a mongoArtifactEvidence
	if json.Unmarshal(artifactRaw, &a) != nil || a.RunID != id || a.Source.PodUID == "" || a.Source.PolicyUID == "" {
		return errors.New("Mongo artifact target unavailable for audit seal")
	}
	observationEnd, observationErr := time.Parse(time.RFC3339Nano, a.ObservationEndedAt)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var rows []mongoExposureDecision
	var state string
	var segment audittransport.Segment
	var at time.Time
	var original []byte
	var readErr error
	if observationErr == nil {
		rows, state, segment, at, original, readErr = rm.readMongoAuditWindow(ctx, start, a.Source, observationEnd)
	} else {
		state, readErr = "GAP", errors.New("Mongo observation-end marker absent")
	}
	terminal := mongoAuditTerminal{Schema: "mongo-exposure-audit-terminal-v1", RunID: id, StartSHA256: mongoHash(startRaw), ArtifactSHA256: mongoHash(artifactRaw), SourceIdentity: start.SourceIdentity, Segment: segment, Offset: segment.Size, ObservedAt: at.Format(time.RFC3339Nano), BrainTrace: state, BrainDecisions: rows, ObservationEnd: a.ObservationEndedAt}
	if readErr != nil {
		terminal.IssueCode = "AUDIT_GAP"
		terminal.BrainDecisions = []mongoExposureDecision{}
	} else {
		terminal.WindowSHA256 = mongoHash(original)
		terminal.WindowBytes = len(original)
		if len(original) > 0 {
			if err := publishMongoAuditFile(out, "mongo-exposure-audit-original.jsonl", original, 64<<20); err != nil {
				return err
			}
		}
	}
	raw, err := json.Marshal(terminal)
	if err != nil {
		return err
	}
	return publishMongoAuditTerminal(out, raw)
}

func (rm *RunManager) readMongoExposureResult(id, out string) (MongoExposureResult, error) {
	result := MongoExposureResult{Schema: "mongo-exposure-result-v1", Finding: "UNKNOWN", ObservedFinding: "UNKNOWN", ClientRead: "UNKNOWN", LegitimateBefore: "UNKNOWN", LegitimateAfter: "UNKNOWN", Cleanup: "UNCONFIRMED", BrainTrace: "UNKNOWN", BrainDecisions: []mongoExposureDecision{}, SecurityOutcome: "NOT_EVALUATED", Issues: []string{}}
	checkpointRaw, err := readNATSResponseSizedFile(out, "mongo-exposure-audit-start.json", 4096)
	if err != nil {
		return result, fmt.Errorf("pre-mutation audit checkpoint unavailable: %w", err)
	}
	if rejectAmbiguousMongoJSON(checkpointRaw) != nil {
		return result, errors.New("audit checkpoint JSON ambiguous")
	}
	var start mongoAuditStart
	if json.Unmarshal(checkpointRaw, &start) != nil || start.RunID != id || !mongoSHA.MatchString(start.ConfigSHA256) {
		return result, errors.New("audit checkpoint identity invalid")
	}
	runtime, err := readMongoRuntime(rm.cfg, id, filepath.Base(out), start)
	if err != nil {
		return result, err
	}
	artifactRaw, err := readNATSResponseSizedFile(out, "mongo-exposure.json", 64<<10)
	if err != nil {
		return result, err
	}
	terminalRaw, err := readNATSResponseSizedFile(out, "mongo-exposure-terminal.json", 4096)
	if err != nil {
		return result, err
	}
	if rejectAmbiguousMongoJSON(artifactRaw) != nil || rejectAmbiguousMongoJSON(terminalRaw) != nil {
		return result, errors.New("Mongo terminal JSON ambiguous")
	}
	var a mongoArtifactEvidence
	var t mongoTerminalEvidence
	if json.Unmarshal(artifactRaw, &a) != nil || json.Unmarshal(terminalRaw, &t) != nil {
		return result, errors.New("Mongo terminal JSON invalid")
	}
	if a.Schema != "mongo-exposure-artifact-v1" || t.Schema != "mongo-exposure-terminal-v1" || a.RunID != id || t.RunID != id || a.Nonce != runtime.MongoExposureFixture.Nonce || t.Nonce != a.Nonce || a.Namespace != mongoExposureNamespace || a.ClusterUID != runtime.MongoExposureFixture.ClusterUID || a.SecurityOutcome != "NOT_EVALUATED" || a.Source.NamespaceUID == "" || t.NamespaceUID != a.Source.NamespaceUID || t.ArtifactSHA256 != mongoHash(artifactRaw) || a.Source.ImageID != runtime.MongoExposureFixture.MongoImageID || a.Source.ManagerImageID != runtime.MongoExposureFixture.ManagerImageID || a.Database != "cc_"+a.Nonce || a.Collection != "owned_"+a.Nonce || a.ClientPodName != "cat-mongo-read-"+a.Nonce[:12] || a.DocumentSHA256 != mongoDocumentHash(a.Nonce) || a.CollectionUUID != "" && !mongoNonce.MatchString(a.CollectionUUID) {
		return result, errors.New("Mongo artifact, checkpoint, source or terminal identity differs")
	}
	startedAt, startedErr := time.Parse(time.RFC3339Nano, a.StartedAt)
	endedAt, endedErr := time.Parse(time.RFC3339Nano, a.ObservationEndedAt)
	finishedAt, finishedErr := time.Parse(time.RFC3339Nano, a.FinishedAt)
	if startedErr != nil || finishedErr != nil || startedAt.IsZero() || finishedAt.Before(startedAt) || endedErr == nil && (endedAt.Before(startedAt) || endedAt.After(finishedAt)) {
		return result, errors.New("Mongo artifact run timestamps invalid")
	}
	result.SourcePodUID, result.ClientPodUID, result.PolicyUID = a.Source.PodUID, a.ClientPodUID, a.Source.PolicyUID
	for _, v := range []string{a.Source.DeploymentUID, a.Source.ReplicaSetUID, a.Source.PodUID, a.Source.PodName, a.Source.ContainerID, a.Source.PVCUID, a.Source.ServiceUID, a.Source.EndpointSliceUID, a.Source.PolicyUID, a.Source.ManagerPodUID, a.Source.ManagerContainerID} {
		if v == "" {
			return result, errors.New("Mongo source chain incomplete")
		}
	}
	if a.Source.PolicyGeneration < 1 || !mongoSHA.MatchString(a.Source.PolicySpecSHA256) || a.ServerVersion != "7.0.40" {
		return result, errors.New("Mongo policy or server version differs")
	}
	if a.ClientRead == "UNAUTHENTICATED_EXACT_READ" || a.ClientRead == "MONGO_AUTH_DENIED" {
		result.ClientRead = a.ClientRead
	}
	if a.LegitimateBefore == "EXACT_READ" {
		result.LegitimateBefore = a.LegitimateBefore
	}
	if a.LegitimateAfter == "EXACT_READ" {
		result.LegitimateAfter = a.LegitimateAfter
	}
	if a.ObservedFinding == "EXPOSED" {
		result.ObservedFinding = "EXPOSED"
	}
	if a.Cleanup == "CONFIRMED_ABSENT" && t.Cleanup == a.Cleanup && t.CollectionAbsent && t.ClientPodAbsent && t.NamespacePreserved {
		result.Cleanup = a.Cleanup
	}
	if a.RawReplyBytes > 0 {
		if a.RawReplyBytes > 4096 || !mongoSHA.MatchString(a.RawReplySHA256) {
			return result, errors.New("Mongo original reply digest invalid")
		}
		original, err := readNATSResponseSizedFile(out, "mongo-exposure-original-reply.log", 4096)
		if err != nil || len(original) != a.RawReplyBytes || mongoHash(original) != a.RawReplySHA256 {
			return result, errors.New("Mongo original reply bytes differ")
		}
		status, digest, err := mongoReply(original, a.Nonce)
		if err != nil || status != a.ClientRead || digest != a.ClientDocumentSHA256 {
			return result, errors.New("Mongo original reply does not support projected client read")
		}
		result.RawReplyBytes, result.RawReplySHA256 = a.RawReplyBytes, a.RawReplySHA256
	}
	auditRaw, err := readNATSResponseSizedFile(out, "mongo-exposure-audit-terminal.json", 256<<10)
	if err != nil {
		return result, fmt.Errorf("sealed Mongo audit terminal unavailable: %w", err)
	}
	if rejectAmbiguousMongoJSON(auditRaw) != nil {
		return result, errors.New("sealed Mongo audit terminal JSON ambiguous")
	}
	var auditEnd mongoAuditTerminal
	if json.Unmarshal(auditRaw, &auditEnd) != nil || auditEnd.Schema != "mongo-exposure-audit-terminal-v1" || auditEnd.RunID != id || auditEnd.StartSHA256 != mongoHash(checkpointRaw) || auditEnd.ArtifactSHA256 != mongoHash(artifactRaw) || auditEnd.SourceIdentity != start.SourceIdentity || auditEnd.ObservationEnd != a.ObservationEndedAt || len(auditEnd.BrainDecisions) > 64 || auditEnd.BrainTrace != "JOINED" && auditEnd.BrainTrace != "UNKNOWN" && auditEnd.BrainTrace != "GAP" {
		return result, errors.New("sealed Mongo audit identity or state differs")
	}
	if auditEnd.BrainTrace != "GAP" && (auditEnd.Segment.ID != "live" || auditEnd.Segment.Generation != start.Segment.Generation || auditEnd.Segment.Anchor != start.Segment.Anchor || auditEnd.Offset != auditEnd.Segment.Size || auditEnd.Offset < start.Offset || auditEnd.Offset-start.Offset > 64<<20 || endedErr != nil) {
		return result, errors.New("sealed Mongo decision window invalid")
	}
	if auditEnd.BrainTrace != "GAP" {
		checkpointAt, err1 := time.Parse(time.RFC3339Nano, start.ObservedAt)
		terminalAt, err2 := time.Parse(time.RFC3339Nano, auditEnd.ObservedAt)
		if err1 != nil || err2 != nil || startedAt.Before(checkpointAt) || terminalAt.Before(finishedAt) || endedAt.After(terminalAt) || auditEnd.WindowBytes != int(auditEnd.Offset-start.Offset) || !mongoSHA.MatchString(auditEnd.WindowSHA256) {
			return result, errors.New("sealed Mongo audit chronology or receipt invalid")
		}
		var original []byte
		if auditEnd.WindowBytes > 0 {
			original, err = readNATSResponseSizedFile(out, "mongo-exposure-audit-original.jsonl", 64<<20)
			if err != nil {
				return result, errors.New("sealed Mongo original audit bytes unavailable")
			}
		}
		if len(original) != auditEnd.WindowBytes || mongoHash(original) != auditEnd.WindowSHA256 {
			return result, errors.New("sealed Mongo original audit digest differs")
		}
		rows, state, err := projectMongoAuditBytes(original, a.Source, checkpointAt, endedAt)
		if err != nil || state != auditEnd.BrainTrace || !reflect.DeepEqual(rows, auditEnd.BrainDecisions) {
			return result, errors.New("sealed Mongo decision projection differs from original audit")
		}
	}
	if auditEnd.BrainTrace == "JOINED" && len(auditEnd.BrainDecisions) == 0 {
		return result, errors.New("sealed Mongo joined decision set empty")
	}
	if auditEnd.BrainTrace != "JOINED" && len(auditEnd.BrainDecisions) != 0 {
		return result, errors.New("unjoined Mongo audit carries decisions")
	}
	if auditEnd.BrainTrace == "GAP" && auditEnd.IssueCode != "AUDIT_GAP" || auditEnd.BrainTrace != "GAP" && auditEnd.IssueCode != "" {
		return result, errors.New("Mongo audit gap marker differs")
	}
	result.BrainTrace, result.BrainDecisions = auditEnd.BrainTrace, auditEnd.BrainDecisions
	if result.BrainTrace == "GAP" {
		result.Issues = append(result.Issues, "authenticated manager audit window incomplete")
	}
	if result.BrainTrace == "UNKNOWN" {
		result.Issues = append(result.Issues, "no exact target decision observed in complete audit window")
	}
	if a.ClientRead == "UNAUTHENTICATED_EXACT_READ" && a.ClientDocumentSHA256 == a.DocumentSHA256 && mongoSHA.MatchString(a.DocumentSHA256) && a.ObservedFinding == "EXPOSED" && a.Validity == "MEASUREMENT_COMPLETE" && result.LegitimateBefore == "EXACT_READ" && result.LegitimateAfter == "EXACT_READ" && result.Cleanup == "CONFIRMED_ABSENT" && result.BrainTrace == "JOINED" && result.RawReplyBytes > 0 && a.CollectionUUID != "" && a.ClientPodUID != "" && a.ClientContainerID != "" && a.ClientImageID != "" && mongoPhaseChainMatches(out, a, startedAt, endedAt, finishedAt) {
		result.Accepted, result.Finding = true, "EXPOSED"
	} else {
		result.Issues = append(result.Issues, "full synthetic read, legitimate controls, audit join or exact cleanup unverified")
	}
	return result, nil
}

func (rm *RunManager) MongoExposureResult(id string) (*MongoExposureResult, error) {
	rm.mu.Lock()
	st := rm.runs[id]
	out := rm.runOut[id]
	if st == nil || st.Config != mongoExposureConfig {
		rm.mu.Unlock()
		return nil, nil
	}
	state := st.State
	rm.mu.Unlock()
	if out == "" || strings.Contains(out, "..") {
		return nil, errors.New("Mongo run output unavailable")
	}
	result, err := rm.readMongoExposureResult(id, rm.cfg.runOutputPath(out))
	if err != nil {
		return nil, err
	}
	if state != "done" {
		result.Accepted = false
		result.Finding = "UNKNOWN"
		result.Issues = append(result.Issues, "run terminal state is not done")
	}
	return &result, nil
}
