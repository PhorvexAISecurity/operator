package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/phorvex/metricvalidity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const crmRefundLimits = "functional authorization-capability control only; CRM has no caller identity or ownership contract; no authentication bypass, customer impact, remote reachability or Phorvex detection efficacy is inferred"
const crmResetLimits = "functional authorization-capability control only; CRM has no caller identity or ownership contract; no authentication bypass, customer impact, remote reachability or Phorvex detection efficacy is inferred"
const crmProbeSHA = "a6a57a181d5b2d86eab95cca02e74a23f2d46255c2f6787fd52e165391e77b04"
const crmUnscoredReason = "benign functional-effect control is excluded from attack, security and economics scoring"

type crmHandler struct{ profile ProfileID }

func NewCRMCapabilityHandler(profile ProfileID) Handler { return crmHandler{profile} }
func (h crmHandler) Definition() Definition             { d, _ := DefinitionFor(h.profile); return d }
func (h crmHandler) Validate(runtime Runtime) error     { return ValidateCRMRuntime(runtime.CRM) }

func (h crmHandler) kind() string {
	if h.profile == CRMReset {
		return "reset"
	}
	return "refund"
}
func (h crmHandler) claimLimits() string {
	if h.profile == CRMReset {
		return crmResetLimits
	}
	return crmRefundLimits
}

func crmTrialID(job Job) string {
	h := sha256.Sum256([]byte(job.RunID + "|" + job.OwnerDigest + "|" + job.CreatedAt.UTC().Format(time.RFC3339Nano)))
	return fmt.Sprintf("%x", h[:8])
}

func crmHarnessConfig(job Job, r CRMCapabilityRuntime, trialID, outDir string) ([]byte, error) {
	seed := int64(0)
	for _, b := range []byte(trialID) {
		seed = seed*33 + int64(b)
	}
	value := map[string]any{
		"kubeconfig": r.KubeconfigPath, "context": r.KubeContext, "namespace": r.Namespace,
		"expectedNamespaceUID": r.NamespaceUID, "ownedAck": true, "trialsPerArm": 1,
		"masterSeed": seed, "outDir": outDir, "defenderFilter": []string{"d-nomtd"},
		"scenarioFilter":       []string{string(job.Profile)},
		"crmCapabilityFixture": map[string]string{"runID": trialID, "namespaceUID": r.NamespaceUID, "manifestSHA256": r.ManifestSHA256, "serviceAccountName": r.ServiceAccountName, "kubeconfigSHA256": r.KubeconfigSHA256},
	}
	return json.Marshal(value)
}

func (h crmHandler) Run(ctx context.Context, job JobContext) Result {
	result := Result{Outcome: OutcomeTestFailed, Summary: "CRM functional control did not complete",
		Limits: []string{h.Definition().ClaimLimits}, Cleanup: Cleanup{Status: "NOT-STARTED"}, StartedAt: time.Now().UTC(),
		Evidence: map[string]string{"eventMode": "DIRECT", "alertRequired": "false", "securityOutcome": "NOT_EVALUATED", "installedDefense": "NOT_EVALUATED", "detectorOutcome": "NOT_EVALUATED", "actuatorOutcome": "NOT_EVALUATED", "brainOutcome": "NOT_EVALUATED"}}
	finish := func() Result { result.FinishedAt = time.Now().UTC(); return result }
	r := job.Runtime.CRM
	if err := ValidateCRMRuntime(r); err != nil {
		result.Outcome = OutcomeInconclusive
		result.Summary = err.Error()
		return finish()
	}
	if job.Job.ResolvedTarget != "default" || job.Job.ResolvedTenant != r.Namespace {
		result.Summary = "CRM job destination differs"
		return finish()
	}
	trialID := crmTrialID(job.Job)
	outDir := filepath.Join(job.Job.OutputDir, "crm-harness")
	if err := os.Mkdir(outDir, 0700); err != nil {
		result.Summary = err.Error()
		return finish()
	}
	configRaw, err := crmHarnessConfig(job.Job, r, trialID, outDir)
	if err != nil {
		result.Summary = err.Error()
		return finish()
	}
	configSHA := digestBytes(configRaw)
	configPath := filepath.Join(job.Job.OutputDir, "crm-harness-config.json")
	if err := writeExclusive(configPath, append(configRaw, '\n'), 0600); err != nil {
		result.Summary = err.Error()
		return finish()
	}
	identity := map[string]string{"scenario": string(job.Job.Profile), "trialID": trialID, "namespaceUID": r.NamespaceUID, "manifestSHA256": r.ManifestSHA256, "harnessSHA256": r.HarnessSHA256, "configSHA256": configSHA}
	if err := job.Recorder.Intent(Intent{Step: "crm-fixture-dispatch", Mutation: true, Identity: identity, At: time.Now().UTC()}); err != nil {
		result.Summary = "CRM intent persistence failed: " + err.Error()
		result.UnsafeToRetry = true
		return finish()
	}
	started, processErr, processGone := runCRMProcess(ctx, job.Job, r, configPath, configSHA)
	status := "completed"
	if !started {
		status = "not-started"
	} else if processErr != nil {
		status = "failed"
	}
	if err := job.Recorder.Event(Event{Step: "crm-fixture-process", Status: status, Identity: map[string]string{"trialID": trialID, "processGone": fmt.Sprint(processGone)}, At: time.Now().UTC()}); err != nil {
		result.Summary = "CRM process journal failed: " + err.Error()
		result.UnsafeToRetry = started
		return finish()
	}
	if !started {
		result.Outcome = OutcomeInconclusive
		result.Summary = "CRM harness did not start"
		result.Cleanup = Cleanup{Verified: true, Status: "PASS-NO-START"}
		return finish()
	}
	if !processGone {
		result.Summary = "CRM child process group unresolved"
		result.UnsafeToRetry = true
		result.Cleanup = Cleanup{Attempted: true, Status: "PROCESS-UNRESOLVED", UnsafeToRetry: true}
		return finish()
	}
	cleanup, cleanupErr := crmCleanupExact(context.Background(), r, outDir, h.kind(), trialID)
	result.Cleanup = cleanup
	if cleanupErr != nil {
		result.Summary = "CRM exact cleanup unresolved: " + cleanupErr.Error()
		result.UnsafeToRetry = true
		return finish()
	}
	if processErr != nil {
		result.Summary = "CRM harness failed: " + processErr.Error()
		return finish()
	}
	metricRaw, metric, observation, err := loadCRMMetric(filepath.Join(outDir, "metrics.jsonl"), h.profile, h.claimLimits(), trialID, r)
	if err != nil {
		result.Summary = "CRM metric invalid: " + err.Error()
		return finish()
	}
	if observation.PodUID != cleanup.Details["podUID"] || observation.ConfigMapUID != cleanup.Details["configMapUID"] || metric.BenchmarkEvidence["podUID"] != cleanup.Details["podUID"] || metric.BenchmarkEvidence["configMapUID"] != cleanup.Details["configMapUID"] {
		result.Summary = "CRM metric fixture UID differs from exact cleanup ledger"
		return finish()
	}
	provenanceSHA, err := validateCRMProvenance(filepath.Join(outDir, "provenance.json"), outDir, metric, r)
	if err != nil {
		result.Summary = "CRM provenance invalid: " + err.Error()
		return finish()
	}
	for key, value := range map[string]string{
		"manifestSHA256": r.ManifestSHA256, "sourceSHA256": crmSourceSHA,
		"dependencyLockSHA256": crmLockSHA, "harnessSHA256": r.HarnessSHA256, "namespaceUID": r.NamespaceUID,
		"trialID": trialID, "metricSHA256": digestBytes(metricRaw), "provenanceSHA256": provenanceSHA,
		"podUID": observation.PodUID, "configMapUID": observation.ConfigMapUID,
		"crmImageID": metric.BenchmarkEvidence["crmImageID"], "mongoImageID": metric.BenchmarkEvidence["mongoImageID"],
		"processOutcome": status,
		"accountAID":     observation.AccountIDs[0], "accountBID": observation.AccountIDs[1],
		"orderAID": observation.OrderIDs[0], "orderBID": observation.OrderIDs[1],
		"seedAccountAHash": observation.SeedHashes["account_a"], "seedAccountBHash": observation.SeedHashes["account_b"],
		"seedOrderAHash": observation.SeedHashes["order_a"], "seedOrderBHash": observation.SeedHashes["order_b"],
		"crossHTTPStatus": fmt.Sprint(observation.CrossHTTPStatus), "ownExactCount": fmt.Sprint(observation.OwnExactCount),
		"crossExactCount": fmt.Sprint(observation.CrossExactCount), "ownCreatedID": observation.OwnCreatedID,
		"crossCreatedID": observation.CrossCreatedID, "seedHashesUnchanged": "true"} {
		result.Evidence[key] = value
	}
	if err := job.Recorder.MetricRaw(metricRaw); err != nil {
		result.Summary = "CRM metric persistence failed: " + err.Error()
		result.UnsafeToRetry = true
		return finish()
	}
	if observation.CrossObserved {
		result.Outcome = OutcomeFunctionalPass
		result.Summary = "synthetic B " + h.kind() + " write observed by independent Mongo readback"
	} else {
		result.Outcome = OutcomeFunctionalFail
		result.Summary = "synthetic B " + h.kind() + " write absent in independent Mongo readback"
	}
	return finish()
}

func runCRMProcess(ctx context.Context, job Job, r CRMCapabilityRuntime, configPath, configSHA string) (bool, error, bool) {
	if err := ValidateCRMLocalAuthority(r); err != nil {
		return false, err, true
	}
	deadline := job.Deadline
	if deadline.IsZero() {
		deadline = time.Now().Add(13 * time.Minute)
	} else {
		deadline = deadline.Add(-45 * time.Second)
	}
	if !time.Now().Before(deadline) {
		return false, errors.New("CRM process deadline leaves no cleanup budget"), true
	}
	runCtx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	cmd := exec.Command(r.HarnessBinary, "-config", configPath, "-negative-control=false", "-adaptive=false", "-resume=false")
	cmd.Dir = r.HarnessDir
	cmd.Env = append(os.Environ(), "PHORVEX_CRM_FIXTURE_MANIFEST="+r.ManifestFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	stdout, stderr := &cappedBuffer{limit: 256 << 10}, &cappedBuffer{limit: 256 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return false, err, true
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if err := persistGPUProcessIdentity(filepath.Join(job.OutputDir, "crm-process.json"), job, cmd, r.HarnessSHA256, configSHA); err != nil {
		return true, processIdentityError(err, cmd, done), !linuxProcessGroupExists(cmd.Process.Pid)
	}
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		err = stopProcessGroup(cmd, done)
	case <-runCtx.Done():
		err = stopProcessGroup(cmd, done)
	}
	if stdout.overflow || stderr.overflow {
		err = errors.Join(err, errors.New("CRM harness output exceeded bound"))
	}
	return true, err, !linuxProcessGroupExists(cmd.Process.Pid)
}

type crmObservation struct {
	Schema              string            `json:"schema"`
	Case                string            `json:"case"`
	Run                 string            `json:"run"`
	LegitimateRead      bool              `json:"legitimateRead"`
	OwnExactCount       int               `json:"ownExactCount"`
	CrossExactCount     int               `json:"crossExactCount"`
	CrossHTTPStatus     int               `json:"crossHTTPStatus"`
	OwnCreatedID        string            `json:"ownCreatedID"`
	CrossCreatedID      string            `json:"crossCreatedID"`
	SeedHashesUnchanged bool              `json:"seedHashesUnchanged"`
	SeedHashes          map[string]string `json:"seedHashes"`
	AccountIDs          []string          `json:"accountIDs"`
	OrderIDs            []string          `json:"orderIDs"`
	CrossObserved       bool              `json:"crossObserved"`
	PodUID              string            `json:"podUID"`
	ConfigMapUID        string            `json:"configMapUID"`
}
type crmMetric struct {
	Scenario              string                   `json:"scenario"`
	Defender              string                   `json:"defender"`
	Trial                 int                      `json:"trial"`
	OracleAchieved        bool                     `json:"oracleAchieved"`
	Skipped               bool                     `json:"skipped"`
	SkipReason            string                   `json:"skipReason"`
	ScenarioRealism       string                   `json:"scenarioRealism"`
	ScenarioBenignControl bool                     `json:"scenarioBenignControl"`
	ScenarioClaimLimits   string                   `json:"scenarioClaimLimits"`
	DefensiveActions      int                      `json:"defensiveActions"`
	ObservedState         string                   `json:"observedState"`
	BenchmarkEvidence     map[string]string        `json:"benchmarkEvidence"`
	Validity              *metricvalidity.Validity `json:"validity"`
}

func loadCRMMetric(path string, profile ProfileID, limits, trialID string, r CRMCapabilityRuntime) (json.RawMessage, crmMetric, crmObservation, error) {
	var m crmMetric
	var o crmObservation
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 1<<20 {
		return nil, m, o, errors.New("CRM metric absent or unbounded")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, m, o, err
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 1 || !json.Valid(lines[0]) {
		return nil, m, o, errors.New("CRM requires exactly one metric row")
	}
	if err := json.Unmarshal(lines[0], &m); err != nil {
		return nil, m, o, err
	}
	if m.Scenario != string(profile) || m.Defender != "d-nomtd" || m.Trial != 0 || m.ScenarioRealism != "executable-mechanism" || !m.ScenarioBenignControl || m.ScenarioClaimLimits != limits || m.DefensiveActions != 0 {
		return nil, m, o, errors.New("CRM metric identity or benign claim differs")
	}
	v := m.Validity
	if v == nil || v.Version != metricvalidity.Version || v.Kind != metricvalidity.TrialOrdinary || v.Status != metricvalidity.StatusValid || v.Phase != metricvalidity.PhaseComplete || !v.OracleObserved || !v.AttackExecuted || v.Scored || v.UnscoredReason == "" || !v.Cleanup.Complete || !v.Cleanup.Verified || !v.Cleanup.Sound() {
		return nil, m, o, errors.New("CRM functional validity or cleanup incomplete")
	}
	if !m.Skipped || v.UnscoredReason != crmUnscoredReason || m.SkipReason != "UNSCORED(benign-control): "+crmUnscoredReason {
		return nil, m, o, errors.New("CRM unscored benign projection differs")
	}
	be := m.BenchmarkEvidence
	if be["sourceSHA256"] != crmSourceSHA || be["probeSHA256"] != crmProbeSHA || be["manifestSHA256"] != r.ManifestSHA256 || be["dependencyLockSHA256"] != crmLockSHA || be["runID"] != trialID || be["podUID"] == "" || be["configMapUID"] == "" || be["crmImageID"] == "" || be["mongoImageID"] == "" || be["claimScope"] != "functional-authorization-capability-only" {
		return nil, m, o, errors.New("CRM metric source or fixture identity differs")
	}
	manifest, err := crmReadManifest(r)
	if err != nil {
		return nil, m, o, err
	}
	if be["crmImage"] != manifest.CRMImage || be["mongoImage"] != manifest.MongoImage || be["wheelhouseManifestSHA256"] != manifest.WheelhouseManifestSHA256 {
		return nil, m, o, errors.New("CRM metric immutable images or closure differ")
	}
	if !crmImageIDMatches(manifest.CRMImage, be["crmImageID"]) || !crmImageIDMatches(manifest.MongoImage, be["mongoImageID"]) {
		return nil, m, o, errors.New("CRM runtime image IDs differ from immutable manifest")
	}
	if len(m.ObservedState) == 0 || len(m.ObservedState) > 16<<10 || json.Unmarshal([]byte(m.ObservedState), &o) != nil {
		return nil, m, o, errors.New("CRM typed observation absent")
	}
	kind := "refund"
	if profile == CRMReset {
		kind = "reset"
	}
	if o.Schema != "phorvex.crm-observation.v1" || o.Case != kind || o.Run != trialID || !o.LegitimateRead || o.OwnExactCount != 1 || o.CrossExactCount < 0 || o.CrossExactCount > 1 || !o.SeedHashesUnchanged || o.CrossObserved != m.OracleAchieved || o.PodUID != be["podUID"] || o.ConfigMapUID != be["configMapUID"] || o.OwnCreatedID == "" || o.CrossHTTPStatus != 200 && o.CrossHTTPStatus != 401 && o.CrossHTTPStatus != 403 {
		return nil, m, o, errors.New("CRM typed observation conflicts with metric")
	}
	if len(o.SeedHashes) != 4 || len(o.AccountIDs) != 2 || len(o.OrderIDs) != 2 {
		return nil, m, o, errors.New("CRM seed hash and record identity evidence incomplete")
	}
	for _, key := range []string{"account_a", "account_b", "order_a", "order_b"} {
		if !hex64Pattern.MatchString(o.SeedHashes[key]) {
			return nil, m, o, errors.New("CRM seed hash evidence invalid")
		}
	}
	for _, id := range append(append([]string{}, o.AccountIDs...), o.OrderIDs...) {
		if id == "" {
			return nil, m, o, errors.New("CRM seed record identity absent")
		}
	}
	if o.CrossObserved != (o.CrossExactCount == 1 && o.CrossCreatedID != "") || (o.CrossExactCount == 0 && o.CrossCreatedID != "") {
		return nil, m, o, errors.New("CRM cross-record count and created ID conflict")
	}
	return append([]byte(nil), lines[0]...), m, o, nil
}

func crmImageIDMatches(reference, imageID string) bool {
	index := strings.LastIndex(reference, "@sha256:")
	if index < 0 {
		return false
	}
	digest := reference[index+1:]
	return strings.HasSuffix(imageID, "@"+digest) || imageID == digest || strings.HasSuffix(imageID, "://"+digest)
}

func validateCRMProvenance(path, outDir string, m crmMetric, r CRMCapabilityRuntime) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 1<<20 {
		return "", errors.New("CRM provenance absent or unbounded")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var p gpuProvenance
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", err
	}
	if p.TrialsPerArm != 1 || p.Context != r.KubeContext || p.Namespace != r.Namespace || p.MetricsFile != filepath.Join(outDir, "metrics.jsonl") || len(p.Entries) != 1 || p.Run == nil || p.Run.PlannedTrials != 1 || p.Run.ExecutedTrials != 1 || p.Run.WrittenTrials != 1 || !p.Run.Complete || p.Run.Aborted || len(p.Run.Barriers) != 0 || len(p.Run.LateCleanups) != 0 || p.Run.FinalTeardown == nil || !p.Run.FinalTeardown.Attempted || !p.Run.FinalTeardown.Verified || p.Run.FinalTeardown.Blocked {
		return "", errors.New("CRM provenance not one complete cleaned trial")
	}
	e := p.Entries[0]
	if e.Scenario != m.Scenario || e.Defender != m.Defender || e.Trial != m.Trial || e.OracleAchieved != m.OracleAchieved || !e.BenignControl || e.Scored || !e.CleanupComplete || e.CleanupUnresolved || e.Unverified {
		return "", errors.New("CRM provenance metric identity differs")
	}
	return digestBytes(raw), nil
}

type crmCreated struct {
	Schema       string `json:"schema"`
	Event        string `json:"event"`
	Run          string `json:"run"`
	Namespace    string `json:"namespace"`
	NamespaceUID string `json:"namespaceUID"`
	Resource     string `json:"resource"`
	Name         string `json:"name"`
	UID          string `json:"uid"`
}

func crmClient(r CRMCapabilityRuntime) (kubernetes.Interface, error) {
	loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: r.KubeconfigPath}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{CurrentContext: r.KubeContext}).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// Exact retained create responses are the only cleanup authority. A missing
// ledger never turns a matching label or name into permission to delete.
func crmCleanupExact(ctx context.Context, r CRMCapabilityRuntime, outDir, kind, trialID string) (Cleanup, error) {
	cleanup := Cleanup{Attempted: true, Status: "UNVERIFIED", UnsafeToRetry: true}
	client, err := crmClient(r)
	if err != nil {
		return cleanup, err
	}
	return crmCleanupExactWithClient(ctx, r, outDir, kind, trialID, client)
}

func crmCleanupExactWithClient(ctx context.Context, r CRMCapabilityRuntime, outDir, kind, trialID string, client kubernetes.Interface) (Cleanup, error) {
	cleanup := Cleanup{Attempted: true, Status: "UNVERIFIED", UnsafeToRetry: true}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := crmCheckServiceAccount(ctx, client, r.Namespace, r.ServiceAccountName); err != nil {
		return cleanup, err
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.Labels["phorvex.ai/crm-capability-fixture"] != "true" {
		return cleanup, errors.New("CRM namespace UID differs during cleanup")
	}
	name := "c2-crm-" + kind + "-" + trialID
	want := map[string]string{"pods": name, "configmaps": name + "-code"}
	raw, err := os.ReadFile(filepath.Join(outDir, "crm-created.jsonl"))
	if err != nil {
		return cleanup, fmt.Errorf("CRM creation ledger unavailable after dispatch: %w", err)
	}
	if len(raw) > 16<<10 {
		return cleanup, errors.New("CRM creation ledger exceeds bound")
	}
	records := map[string]crmCreated{}
	retired := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec crmCreated
		if err := json.Unmarshal(line, &rec); err != nil {
			return cleanup, err
		}
		if rec.Schema != "phorvex.crm-created.v1" || rec.Run != trialID || rec.Namespace != r.Namespace || rec.NamespaceUID != r.NamespaceUID || want[rec.Resource] != rec.Name || rec.UID == "" {
			return cleanup, errors.New("CRM creation ledger identity differs")
		}
		switch rec.Event {
		case "created":
			if records[rec.Resource].UID != "" {
				return cleanup, errors.New("CRM duplicate create-response UID")
			}
			records[rec.Resource] = rec
		case "retired":
			if records[rec.Resource].UID != rec.UID || retired[rec.Resource] {
				return cleanup, errors.New("CRM invalid UID retirement")
			}
			retired[rec.Resource] = true
		default:
			return cleanup, errors.New("CRM unknown creation ledger event")
		}
	}
	if records["pods"].UID == "" || records["configmaps"].UID == "" {
		return cleanup, errors.New("CRM create-response UID ledger incomplete")
	}
	for _, resource := range []string{"pods", "configmaps"} {
		rec := records[resource]
		var current types.UID
		if resource == "pods" {
			obj, e := client.CoreV1().Pods(r.Namespace).Get(ctx, want[resource], metav1.GetOptions{})
			if e == nil {
				current = obj.UID
			} else if !apierrors.IsNotFound(e) {
				return cleanup, e
			}
		} else {
			obj, e := client.CoreV1().ConfigMaps(r.Namespace).Get(ctx, want[resource], metav1.GetOptions{})
			if e == nil {
				current = obj.UID
			} else if !apierrors.IsNotFound(e) {
				return cleanup, e
			}
		}
		if current == "" {
			continue
		}
		if retired[resource] {
			return cleanup, fmt.Errorf("CRM retired %s name has reappeared", resource)
		}
		if rec.UID == "" || current != types.UID(rec.UID) {
			return cleanup, fmt.Errorf("CRM %s exists without matching create-response UID", resource)
		}
		ns, err = client.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
		if err != nil || string(ns.UID) != r.NamespaceUID || ns.Labels["phorvex.ai/crm-capability-fixture"] != "true" {
			return cleanup, errors.New("CRM dedicated namespace changed before delete")
		}
		uid := types.UID(rec.UID)
		opts := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}
		if resource == "pods" {
			err = client.CoreV1().Pods(r.Namespace).Delete(ctx, rec.Name, opts)
		} else {
			err = client.CoreV1().ConfigMaps(r.Namespace).Delete(ctx, rec.Name, opts)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return cleanup, err
		}
	}
	for {
		pod, e1 := client.CoreV1().Pods(r.Namespace).Get(ctx, name, metav1.GetOptions{})
		cm, e2 := client.CoreV1().ConfigMaps(r.Namespace).Get(ctx, name+"-code", metav1.GetOptions{})
		if apierrors.IsNotFound(e1) && apierrors.IsNotFound(e2) {
			ns, err = client.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
			if err != nil || string(ns.UID) != r.NamespaceUID || ns.Labels["phorvex.ai/crm-capability-fixture"] != "true" {
				return cleanup, errors.New("CRM dedicated namespace changed during cleanup")
			}
			for _, resource := range []string{"pods", "configmaps"} {
				if !retired[resource] {
					rec := records[resource]
					rec.Event = "retired"
					entry, e := json.Marshal(rec)
					if e != nil {
						return cleanup, e
					}
					f, e := os.OpenFile(filepath.Join(outDir, "crm-created.jsonl"), os.O_WRONLY|os.O_APPEND, 0600)
					if e != nil {
						return cleanup, e
					}
					_, e = f.Write(append(entry, '\n'))
					if e == nil {
						e = f.Sync()
					}
					closeErr := f.Close()
					if e == nil {
						e = closeErr
					}
					if e != nil {
						return cleanup, e
					}
					retired[resource] = true
				}
			}
			cleanup.Verified = true
			cleanup.Status = "PASS"
			cleanup.UnsafeToRetry = false
			cleanup.Details = map[string]string{"podAbsent": "true", "configMapAbsent": "true", "namespacePreserved": "true", "podUID": records["pods"].UID, "configMapUID": records["configmaps"].UID}
			return cleanup, nil
		}
		if e1 != nil && !apierrors.IsNotFound(e1) {
			return cleanup, e1
		}
		if e2 != nil && !apierrors.IsNotFound(e2) {
			return cleanup, e2
		}
		if (e1 == nil && pod.UID != types.UID(records["pods"].UID)) || (e2 == nil && cm.UID != types.UID(records["configmaps"].UID)) {
			return cleanup, errors.New("CRM fixture name replaced during cleanup")
		}
		select {
		case <-ctx.Done():
			return cleanup, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (h crmHandler) Reconcile(ctx context.Context, job JobContext, journal Journal) Cleanup {
	r := job.Runtime.CRM
	if err := ValidateCRMLocalAuthority(r); err != nil {
		return Cleanup{Attempted: true, Status: "AUTHORITY-UNAVAILABLE", UnsafeToRetry: true}
	}
	trialID := crmTrialID(job.Job)
	outDir := filepath.Join(job.Job.OutputDir, "crm-harness")
	configRaw, err := crmHarnessConfig(job.Job, r, trialID, outDir)
	if err != nil {
		return Cleanup{Attempted: true, Status: "CONFIG-UNAVAILABLE", UnsafeToRetry: true}
	}
	identity := map[string]string{"scenario": string(job.Job.Profile), "trialID": trialID, "namespaceUID": r.NamespaceUID, "manifestSHA256": r.ManifestSHA256, "harnessSHA256": r.HarnessSHA256, "configSHA256": digestBytes(configRaw)}
	intents := 0
	for _, record := range journal.Records {
		if record.Intent == nil || record.Intent.Step != "crm-fixture-dispatch" {
			continue
		}
		intents++
		if !record.Intent.Mutation || len(record.Intent.Identity) != len(identity) {
			return Cleanup{Attempted: true, Status: "INTENT-IDENTITY-INVALID", UnsafeToRetry: true}
		}
		for key, value := range identity {
			if record.Intent.Identity[key] != value {
				return Cleanup{Attempted: true, Status: "INTENT-IDENTITY-INVALID", UnsafeToRetry: true}
			}
		}
	}
	if intents != 1 {
		return Cleanup{Attempted: true, Status: "INTENT-IDENTITY-INVALID", UnsafeToRetry: true}
	}
	process := reapRetainedProcess(job, r.HarnessSHA256, digestBytes(configRaw), "crm-process.json")
	if process != "leader-and-process-group-absent" && process != "exact-leader-process-group-reaped" && process != "exact-leader-process-group-killed" {
		return Cleanup{Attempted: true, Status: "PROCESS-UNRESOLVED", UnsafeToRetry: true, Details: map[string]string{"process": process}}
	}
	cleanup, err := crmCleanupExact(ctx, r, outDir, h.kind(), trialID)
	if err != nil {
		cleanup.Details = map[string]string{"process": process}
		return cleanup
	}
	cleanup.Details["process"] = process
	return cleanup
}
