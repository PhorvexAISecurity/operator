package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	newstackNamespace        = "phorvex-staging"
	newstackLaneName         = "phorvex-newstack-loop-lock"
	newstackRunLabel         = "phorvex.ai/newstack-run"
	newstackFixtureLabel     = "phorvex.ai/newstack-fixture"
	newstackIntentAnnotation = "phorvex.ai/newstack-intent"
	newstackFireRoute        = "/api/newstack/fire"
	newstackFixtureImage     = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
	newstackMaxDuration      = 300 * time.Second
)

var newstackIDPattern = regexp.MustCompile(`^ns-[0-9a-f]{32}$`)

type newstackCase struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Action     string `json:"expectedActuator"`
	Fixture    string `json:"fixture"`
	Class      string `json:"class"`
	Limitation string `json:"limitation"`
}

var newstackCases = []newstackCase{
	{"newstack:voice-rotate", "Voice fixture pod-resident foothold replacement", "rotate", "voice", "proactive-hygiene", "Disposable process marker simulates pod-resident foothold state; no exploit session, real Voice pipeline or natural detection is installed. Replacement clears this marker; reinfection prevention is not measured."},
	{"newstack:litellm-rotate", "LiteLLM fixture pod-resident foothold replacement", "rotate", "litellm", "proactive-hygiene", "Disposable process marker simulates pod-resident foothold state; no exploit session, real inference pipeline or natural detection is installed. Replacement clears this marker; reinfection prevention is not measured."},
	{"newstack:crm-refund-revoke", "CRM fixture exact-order refund revocation", "crm-refund-revoke", "crm-refund", "cross-record-refund", "A real refund of another synthetic account's order lands before a test-injected signal. The fixture intentionally has no caller authentication; defense covers the single denied order on every replica."},
}

type newstackObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
}

type newstackSample struct {
	At             string   `json:"at"`
	Ready          int      `json:"ready"`
	ReadyEndpoints int      `json:"readyEndpoints"`
	PodUIDs        []string `json:"podUIDs"`
}

type newstackRun struct {
	Schema                string                  `json:"schema"`
	RunID                 string                  `json:"runId"`
	CaseID                string                  `json:"caseId"`
	Namespace             string                  `json:"namespace"`
	Status                string                  `json:"status"`
	Verdict               string                  `json:"verdict"`
	Phase                 string                  `json:"phase"`
	StartedAt             string                  `json:"startedAt"`
	BaselineAt            string                  `json:"baselineAt,omitempty"`
	FinishedAt            string                  `json:"finishedAt,omitempty"`
	Actor                 string                  `json:"actor"`
	SignalMode            string                  `json:"signalMode"`
	Class                 string                  `json:"class"`
	Limitation            string                  `json:"limitation"`
	FixtureImage          string                  `json:"fixtureImage"`
	FixtureSHA256         string                  `json:"fixtureSHA256"`
	Objects               []newstackObject        `json:"objects"`
	LockUID               string                  `json:"lockUID,omitempty"`
	TargetPod             string                  `json:"targetPod,omitempty"`
	TargetUID             string                  `json:"targetUID,omitempty"`
	PeerUID               string                  `json:"peerUID,omitempty"`
	ReplacementUID        string                  `json:"replacementUID,omitempty"`
	PolicyUID             string                  `json:"policyUID,omitempty"`
	PolicyGeneration      int64                   `json:"policyGeneration,omitempty"`
	ServiceUID            string                  `json:"serviceUID,omitempty"`
	GuardUID              string                  `json:"guardUID,omitempty"`
	BaselineLanded        bool                    `json:"baselineLanded"`
	EveryReplicaDenied    bool                    `json:"everyReplicaDenied"`
	ReplayDenied          bool                    `json:"replayDenied"`
	LegitimateSucceeded   bool                    `json:"legitimateSucceeded"`
	OldUIDAbsent          bool                    `json:"oldUIDAbsent"`
	MarkerCleared         bool                    `json:"markerCleared"`
	Recovered             bool                    `json:"recovered"`
	AvailabilitySamples   []newstackSample        `json:"availabilitySamples"`
	MinimumReady          int                     `json:"minimumReady"`
	MinimumReadyEndpoints int                     `json:"minimumReadyEndpoints"`
	AvailabilitySampling  string                  `json:"availabilitySampling"`
	Stimulus              *attackStimulusEvidence `json:"stimulus,omitempty"`
	Decision              *decisionEvidence       `json:"decision,omitempty"`
	CleanupComplete       bool                    `json:"cleanupComplete"`
	PostflightClean       bool                    `json:"postflightClean"`
	Issues                []string                `json:"issues"`
}

func newstackCaseByID(id string) (newstackCase, bool) {
	for _, item := range newstackCases {
		if item.ID == id {
			return item, true
		}
	}
	return newstackCase{}, false
}

func (s *Server) newstackEnabled() error {
	if !s.cfg.NewstackLoopsEnabled || s.cfg.PodNamespace != newstackNamespace {
		return errors.New("newstack loops require PHORVEX_NEWSTACK_LOOPS_ENABLED=true and POD_NAMESPACE=phorvex-staging")
	}
	if s.cfg.AuditSource == nil || s.cfg.AuditSourceIdentity == "" {
		return errors.New("authenticated remote brain audit source is required")
	}
	if s.cfg.StateDir == "" {
		return errors.New("durable attacks state directory is required")
	}
	if s.cfg.NewstackIdentityPolicy == "" {
		return errors.New("PHORVEX_EVENT_IDENTITY_POLICY must name the installed creator identity guard")
	}
	return nil
}

func newstackQuery(r *http.Request, key string) (string, bool) {
	q := r.URL.Query()
	if key == "" {
		return "", len(q) == 0
	}
	if len(q) != 1 || len(q[key]) != 1 || q.Get(key) == "" {
		return "", false
	}
	return q.Get(key), true
}

func newstackRequest(w http.ResponseWriter, r *http.Request) (newstackCase, bool) {
	if _, ok := newstackQuery(r, ""); !ok {
		writeJSON(w, 400, map[string]string{"error": "query parameters are not accepted"})
		return newstackCase{}, false
	}
	var body struct {
		CaseID string `json:"caseId"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "body must contain only caseId"})
		return newstackCase{}, false
	}
	item, ok := newstackCaseByID(body.CaseID)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "unknown newstack caseId"})
	}
	return item, ok
}

func (s *Server) newstackCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := newstackQuery(r, ""); !ok {
		writeJSON(w, 400, map[string]string{"error": "query parameters are not accepted"})
		return
	}
	enabled, reason := true, ""
	if err := s.newstackEnabled(); err != nil {
		enabled, reason = false, err.Error()
	}
	writeJSON(w, 200, map[string]any{"schema": "newstack-catalog-v1", "namespace": newstackNamespace, "items": newstackCases, "enabled": enabled, "reason": reason, "fireEndpoint": newstackFireRoute, "maximumSeconds": 300})
}

func (s *Server) newstackCheck(w http.ResponseWriter, r *http.Request) {
	id, ok := newstackQuery(r, "caseId")
	item, known := newstackCaseByID(id)
	if !ok || !known {
		writeJSON(w, 400, map[string]string{"error": "exact caseId query is required"})
		return
	}
	if err := s.newstackEnabled(); err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	runtime, err := s.newstackRuntime(nil)
	if err == nil {
		err = runtime.preflight(ctx, item)
	}
	if err != nil {
		writeJSON(w, 409, map[string]any{"ok": false, "caseId": id, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "caseId": id, "namespace": newstackNamespace, "fixtureImage": newstackFixtureImage, "signalMode": "TEST_INJECTED_AFTER_REAL_FIXTURE_STIMULUS", "limitation": item.Limitation})
}

func (s *Server) newstackFire(w http.ResponseWriter, r *http.Request) {
	item, ok := newstackRequest(w, r)
	if !ok {
		return
	}
	if err := s.newstackEnabled(); err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	unlock, err := s.newstackLocalLock()
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	defer unlock()
	id, err := newstackID()
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "run identity unavailable"})
		return
	}
	now := time.Now().UTC()
	run := &newstackRun{Schema: "newstack-run-v1", RunID: "ns-" + id, CaseID: item.ID, Namespace: newstackNamespace, Status: "running", Verdict: "UNKNOWN", Phase: "intent", StartedAt: now.Format(time.RFC3339Nano), Actor: actorOf(r), SignalMode: "TEST_INJECTED_AFTER_REAL_FIXTURE_STIMULUS", Class: item.Class, Limitation: item.Limitation, FixtureImage: newstackFixtureImage, FixtureSHA256: crmFixtureSHA(), Objects: []newstackObject{}, Issues: []string{}, AvailabilitySamples: []newstackSample{}, AvailabilitySampling: "one-second Kubernetes Ready and EndpointSlice samples; no claim about unsampled intervals"}
	if err = s.newstackSave(run); err != nil {
		writeJSON(w, 503, map[string]string{"error": "exact run intent could not be persisted"})
		return
	}
	runtime, err := s.newstackRuntime(run)
	if err != nil {
		run.Issues = append(run.Issues, err.Error())
		run.Status = "done"
		run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = s.newstackSave(run)
		writeJSON(w, 503, run)
		return
	}
	// Foreground execution survives caller cancellation, and a deferred finalizer
	// owns bounded cleanup even if an unexpected panic interrupts the runner.
	if err = runtime.runWithCleanup(item); err != nil {
		run.Issues = append(run.Issues, err.Error())
	}
	run.Status = "done"
	if !run.CleanupComplete && run.LockUID != "" {
		run.Status = "cleanup-required"
		run.Verdict = "UNKNOWN"
	}
	run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err = s.newstackSave(run); err != nil {
		writeJSON(w, 503, map[string]any{"error": "terminal run persistence unavailable", "runId": run.RunID})
		return
	}
	writeJSON(w, 200, run)
}

func (s *Server) newstackResult(w http.ResponseWriter, r *http.Request) {
	id, ok := newstackQuery(r, "runId")
	if !ok || !newstackIDPattern.MatchString(id) {
		writeJSON(w, 400, map[string]string{"error": "exact runId query is required"})
		return
	}
	run, err := s.newstackLoad(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "exact newstack run unavailable"})
		return
	}
	writeJSON(w, 200, run)
}

func (s *Server) newstackCleanup(w http.ResponseWriter, r *http.Request) {
	item, ok := newstackRequest(w, r)
	if !ok {
		return
	}
	if err := s.newstackEnabled(); err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	unlock, err := s.newstackLocalLock()
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	defer unlock()
	runtime, err := s.newstackRuntime(nil)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	lock := &corev1.ConfigMap{}
	err = runtime.kube.Get(ctx, types.NamespacedName{Namespace: newstackNamespace, Name: newstackLaneName}, lock)
	if apierrors.IsNotFound(err) {
		if clean, scanErr := runtime.orphans(ctx, item); scanErr != nil || !clean {
			writeJSON(w, 409, map[string]string{"error": "shared lane is absent but fixture inventory remains or is unreadable; retained exact-run reconciliation is required"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "caseId": item.ID, "cleanupComplete": true, "postflightClean": true, "message": "shared lane and fixture inventory are clear"})
		return
	}
	if err != nil || !newstackIDPattern.MatchString(lock.Labels[newstackRunLabel]) || lock.Data["caseId"] != item.ID {
		writeJSON(w, 409, map[string]string{"error": "shared lane is unavailable or belongs to another case"})
		return
	}
	run, err := s.newstackLoad(lock.Labels[newstackRunLabel])
	if err != nil || run.CaseID != item.ID || (run.LockUID != "" && run.LockUID != string(lock.UID)) || lock.Annotations[newstackIntentAnnotation] != run.RunID {
		writeJSON(w, 409, map[string]string{"error": "crash cleanup requires the retained exact run and lane UID"})
		return
	}
	runtime.run = run
	run.LockUID = string(lock.UID)
	if err = s.newstackSave(run); err == nil {
		err = runtime.cleanup(ctx)
	}
	run.Status = "done"
	run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		run.Status = "cleanup-required"
		run.Verdict = "UNKNOWN"
		run.Issues = append(run.Issues, "crash cleanup: "+err.Error())
	}
	if saveErr := s.newstackSave(run); saveErr != nil {
		writeJSON(w, 503, map[string]string{"error": "cleanup result persistence unavailable"})
		return
	}
	code := 200
	if err != nil {
		code = 409
	}
	writeJSON(w, code, run)
}

func (s *Server) newstackLocalLock() (func(), error) {
	if err := os.MkdirAll(filepath.Join(s.cfg.StateDir, "newstack"), 0700); err != nil {
		return nil, errors.New("newstack state unavailable")
	}
	file, err := os.OpenFile(filepath.Join(s.cfg.StateDir, "newstack", "lane.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("newstack local lane unavailable")
	}
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		file.Close()
		return nil, errors.New("one newstack run or cleanup is already active")
	}
	return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
}

func (s *Server) newstackSave(run *newstackRun) error {
	if !newstackIDPattern.MatchString(run.RunID) || run.Namespace != newstackNamespace {
		return errors.New("invalid run identity")
	}
	dir := filepath.Join(s.cfg.StateDir, "newstack", run.RunID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	err = parent.Sync()
	_ = parent.Close()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "record-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(append(raw, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(dir, "record.json")); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *Server) newstackLoad(id string) (*newstackRun, error) {
	if !newstackIDPattern.MatchString(id) {
		return nil, errors.New("invalid run identity")
	}
	raw, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "newstack", id, "record.json"))
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.New("run record unavailable")
	}
	var run newstackRun
	if json.Unmarshal(raw, &run) != nil || run.Schema != "newstack-run-v1" || run.RunID != id || run.Namespace != newstackNamespace {
		return nil, errors.New("run record identity differs")
	}
	if _, ok := newstackCaseByID(run.CaseID); !ok {
		return nil, errors.New("run case differs")
	}
	return &run, nil
}

func newstackObjectRef(object client.Object) newstackObject {
	gvk := object.GetObjectKind().GroupVersionKind()
	return newstackObject{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Namespace: object.GetNamespace(), Name: object.GetName(), UID: string(object.GetUID())}
}

func newstackOwned(object client.Object, run *newstackRun) bool {
	return object.GetLabels()[newstackRunLabel] == run.RunID && object.GetAnnotations()[newstackIntentAnnotation] == run.RunID && (object.GetNamespace() == newstackNamespace || object.GetNamespace() == "")
}

func (w *newstackRuntime) savePhase(phase string) error {
	w.run.Phase = phase
	return w.server.newstackSave(w.run)
}

func newstackResourceName(item newstackCase, run *newstackRun) string {
	if item.Fixture == "crm-refund" {
		return "crm"
	}
	return "newstack-" + item.Fixture + "-" + strings.TrimPrefix(run.RunID, "ns-")[:12]
}

func newstackConflict(kind, name string) error {
	return fmt.Errorf("refusing existing %s %s; collision cleanup is required", kind, name)
}
