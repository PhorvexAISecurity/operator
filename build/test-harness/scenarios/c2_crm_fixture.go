package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	crmfixture "github.com/r6security/phoenix-test-harness/fixtures/crm"
	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	crmInstalledSourceSHA = "328f37a8d6d3692fb3bd6d4db2637e72d54becf8e9e4396d5e47f4ab5f909350"
	crmInstalledBaseImage = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
	crmDependencyLockSHA  = "50143dfea339319c70edcc4e37c5d852031446f5e609ef4f538c68a0436f956a"
	crmFixtureManifestEnv = "PHORVEX_CRM_FIXTURE_MANIFEST"
	crmFixtureSchema      = "phorvex.crm-fixture.v1"
	crmFixtureTimeout     = 25 * time.Second
)

var crmDigestImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
var crmSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var crmExpectedDependencies = map[string]string{
	"fastapi": "0.115.14", "pydantic": "2.13.4", "pymongo": "4.17.0", "uvicorn": "0.30.6",
}

// A manifest is supplied explicitly by the owner who has built/pulled the
// dependency-closed image. Missing authority means a reported abstention.
type crmFixtureManifest struct {
	Schema                   string            `json:"schema"`
	CRMImage                 string            `json:"crmImage"`
	MongoImage               string            `json:"mongoImage"`
	BaseImageDigest          string            `json:"baseImageDigest"`
	SourceSHA256             string            `json:"sourceSHA256"`
	DependencyLockSHA256     string            `json:"dependencyLockSHA256"`
	WheelhouseManifestSHA256 string            `json:"wheelhouseManifestSHA256"`
	Dependencies             map[string]string `json:"dependencies"`
}

type crmDependencyLock struct {
	Schema       string            `json:"schema"`
	Python       string            `json:"python"`
	Packages     map[string]string `json:"packages"`
	SourceSHA256 string            `json:"sourceSHA256"`
}

type crmProbeReceipt struct {
	Schema              int               `json:"schema"`
	Phase               string            `json:"phase"`
	Case                string            `json:"case"`
	Run                 string            `json:"run"`
	AccountIDs          []string          `json:"account_ids"`
	OrderIDs            []string          `json:"order_ids"`
	BaselineHashes      map[string]string `json:"baseline_hashes"`
	LegitimateRead      bool              `json:"legitimate_read"`
	AppointmentID       string            `json:"appointment_id"`
	OwnRefundID         string            `json:"own_refund_id"`
	CrossRefundID       string            `json:"cross_refund_id"`
	OwnOrderID          string            `json:"own_order_id"`
	CrossOrderID        string            `json:"cross_order_id"`
	OwnResetAccountID   string            `json:"own_reset_account_id"`
	CrossResetAccountID string            `json:"cross_reset_account_id"`
	CrossStatus         int               `json:"cross_status"`
	OwnExactCount       int               `json:"own_exact_count"`
	CrossExactCount     int               `json:"cross_exact_count"`
	AppointmentCount    int               `json:"appointment_exact_count"`
	OwnCreatedID        string            `json:"own_created_id"`
	CrossCreatedID      string            `json:"cross_created_id"`
	OwnAccountID        string            `json:"own_account_id"`
	CrossAccountID      string            `json:"cross_account_id"`
}

type crmCapabilityScenario struct {
	kind             string
	unavailable      string
	manifest         crmFixtureManifest
	manifestSHA      string
	lock             crmDependencyLock
	probeSHA         string
	name             string
	configMapName    string
	run              string
	podUID           types.UID
	configMapUID     types.UID
	crmImageID       string
	mongoImageID     string
	crmContainerID   string
	mongoContainerID string
	podIP            string
	nodeName         string
	seed             crmProbeReceipt
	execution        crmProbeReceipt
}

func crmFixtureFiles() (app, probe []byte, err error) {
	app, probe = crmfixture.AppSource, crmfixture.ProbeSource
	if fmt.Sprintf("%x", sha256.Sum256(app)) != crmInstalledSourceSHA {
		return nil, nil, errors.New("CRM fixture source differs from installed source SHA-256")
	}
	if len(probe) == 0 || len(probe) > 128*1024 {
		return nil, nil, errors.New("CRM probe source size invalid")
	}
	return app, probe, nil
}

func crmLoadDependencyLock() (crmDependencyLock, error) {
	var lock crmDependencyLock
	raw := crmfixture.DependencyLock
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != crmDependencyLockSHA {
		return lock, errors.New("CRM dependency lock SHA-256 differs")
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return lock, err
	}
	if lock.Schema != "phorvex.crm-installed-dependencies.v1" || lock.SourceSHA256 != crmInstalledSourceSHA || lock.Python != "3.11.15" || len(lock.Packages) != 18 {
		return lock, errors.New("CRM dependency lock contents invalid")
	}
	return lock, nil
}

func crmLoadManifest(path string) (crmFixtureManifest, string, error) {
	var manifest crmFixtureManifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifest, "", err
	}
	if len(raw) == 0 || len(raw) > 16*1024 {
		return manifest, "", errors.New("CRM fixture manifest size invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, "", err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return manifest, "", errors.New("CRM fixture manifest has trailing data")
	}
	if manifest.Schema != crmFixtureSchema || manifest.SourceSHA256 != crmInstalledSourceSHA || manifest.BaseImageDigest != crmInstalledBaseImage || manifest.DependencyLockSHA256 != crmDependencyLockSHA || !crmSHA256.MatchString(manifest.WheelhouseManifestSHA256) {
		return manifest, "", errors.New("CRM fixture manifest source/base provenance differs")
	}
	if !crmDigestImage.MatchString(manifest.CRMImage) || !crmDigestImage.MatchString(manifest.MongoImage) {
		return manifest, "", errors.New("CRM fixture images must be immutable sha256 references")
	}
	if len(manifest.Dependencies) != len(crmExpectedDependencies) {
		return manifest, "", errors.New("CRM dependency manifest has wrong package set")
	}
	for name, want := range crmExpectedDependencies {
		if manifest.Dependencies[name] != want {
			return manifest, "", fmt.Errorf("CRM dependency %s version differs", name)
		}
	}
	return manifest, fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func (s *crmCapabilityScenario) setup(ctx context.Context, env *core.Env, kind string) error {
	*s = crmCapabilityScenario{kind: kind}
	path := strings.TrimSpace(os.Getenv(crmFixtureManifestEnv))
	if path == "" {
		s.unavailable = "immutable CRM fixture image/dependency manifest is not configured"
		return nil
	}
	manifest, manifestSHA, err := crmLoadManifest(path)
	if err != nil {
		return fmt.Errorf("invalid CRM fixture manifest: %w", err)
	}
	app, probe, err := crmFixtureFiles()
	if err != nil {
		return err
	}
	lock, err := crmLoadDependencyLock()
	if err != nil {
		return err
	}
	if env.Rand == nil {
		return errors.New("CRM fixture requires deterministic trial RNG")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	if err := env.EnsureNamespace(ctx); err != nil {
		return err
	}
	s.manifest, s.manifestSHA = manifest, manifestSHA
	s.lock = lock
	s.probeSHA = fmt.Sprintf("%x", sha256.Sum256(probe))
	s.run = fmt.Sprintf("%016x", env.Rand.Uint64())
	s.name = "c2-crm-" + kind + "-" + s.run
	s.configMapName = s.name + "-code"
	labels := env.OwnedLabels(map[string]string{"app": "c2-crm-fixture", "case": kind})
	immutable := true
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: s.configMapName, Namespace: env.Config.Namespace, Labels: labels,
			Annotations: map[string]string{"fixture.phorvex.ai/crm-source-sha256": crmInstalledSourceSHA,
				"fixture.phorvex.ai/crm-probe-sha256": s.probeSHA, "fixture.phorvex.ai/manifest-sha256": manifestSHA}},
		Immutable: &immutable, Data: map[string]string{"app.py": string(app), "probe.py": string(probe)},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	s.configMapUID = cm.UID
	if err := env.RecordCreatedUID("configmaps", s.configMapName, cm.UID); err != nil {
		return err
	}
	noToken := false
	activeDeadline := int64(600)
	mongoDiskLimit := resource.MustParse("256Mi")
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: env.Config.Namespace, Labels: labels,
			Annotations: map[string]string{"fixture.phorvex.ai/crm-source-sha256": crmInstalledSourceSHA,
				"fixture.phorvex.ai/crm-probe-sha256": s.probeSHA, "fixture.phorvex.ai/manifest-sha256": manifestSHA}},
		Spec: corev1.PodSpec{AutomountServiceAccountToken: &noToken, ActiveDeadlineSeconds: &activeDeadline, RestartPolicy: corev1.RestartPolicyNever,
			Volumes: []corev1.Volume{
				{Name: "code", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: s.configMapName}}}},
				{Name: "mongo-data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &mongoDiskLimit}}},
			},
			Containers: []corev1.Container{
				{Name: "mongo", Image: manifest.MongoImage, ImagePullPolicy: corev1.PullIfNotPresent,
					Command:      []string{"mongod", "--bind_ip", "127.0.0.1", "--port", "27017", "--quiet"},
					Resources:    corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("256Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("1Gi")}},
					VolumeMounts: []corev1.VolumeMount{{Name: "mongo-data", MountPath: "/data/db"}}},
				{Name: "crm", Image: manifest.CRMImage, ImagePullPolicy: corev1.PullIfNotPresent,
					WorkingDir: "/app", Command: []string{"uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8080"},
					Resources:      corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("512Mi")}},
					Env:            []corev1.EnvVar{{Name: "MONGO_URI", Value: "mongodb://127.0.0.1:27017"}},
					VolumeMounts:   []corev1.VolumeMount{{Name: "code", MountPath: "/app", ReadOnly: true}},
					ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read(1024)"}}}, PeriodSeconds: 2, TimeoutSeconds: 3}},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	s.podUID = pod.UID
	if err := env.RecordCreatedUID("pods", s.name, pod.UID); err != nil {
		return err
	}
	if err := env.WaitForPodRunning(ctx, s.name, 120*time.Second); err != nil {
		return err
	}
	if err := s.verifyRuntime(ctx, env); err != nil {
		return err
	}
	seed, err := s.probe(ctx, env, "seed")
	if err != nil {
		return err
	}
	if len(seed.AccountIDs) != 2 || len(seed.OrderIDs) != 2 || len(seed.BaselineHashes) != 4 {
		return errors.New("CRM synthetic seed receipt incomplete")
	}
	s.seed = seed
	return nil
}

const crmRuntimeVerification = `import hashlib,importlib.metadata as m,json,platform
from pathlib import Path
raw=Path('/app/app.py').read_bytes()
probe=Path('/app/probe.py').read_bytes()
packages={}
for d in m.distributions():
 name=d.metadata['Name'].lower().replace('_','-');packages[name]=d.version
out={'source_sha256':hashlib.sha256(raw).hexdigest(),'probe_sha256':hashlib.sha256(probe).hexdigest(),'python':platform.python_version(),'packages':packages}
print(json.dumps(out,sort_keys=True))`

func (s *crmCapabilityScenario) verifyIdentity(ctx context.Context, env *core.Env) error {
	expectedLabels := env.OwnedLabels(map[string]string{"app": "c2-crm-fixture", "case": s.kind})
	labelsMatch := func(actual map[string]string) bool {
		for key, value := range expectedLabels {
			if actual[key] != value {
				return false
			}
		}
		return true
	}
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, s.configMapName, metav1.GetOptions{})
	if err != nil || cm.UID != s.configMapUID || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || !labelsMatch(cm.Labels) {
		return fmt.Errorf("CRM fixture immutable ConfigMap identity changed: %v", err)
	}
	if len(cm.Data) != 2 || fmt.Sprintf("%x", sha256.Sum256([]byte(cm.Data["app.py"]))) != crmInstalledSourceSHA || fmt.Sprintf("%x", sha256.Sum256([]byte(cm.Data["probe.py"]))) != s.probeSHA || cm.Annotations["fixture.phorvex.ai/manifest-sha256"] != s.manifestSHA {
		return errors.New("CRM fixture ConfigMap contents or provenance changed")
	}
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil || pod.UID != s.podUID || pod.DeletionTimestamp != nil || !labelsMatch(pod.Labels) {
		return fmt.Errorf("CRM fixture Pod identity changed: %v", err)
	}
	if len(pod.Spec.Containers) != 2 || pod.Spec.Containers[0].Name != "mongo" || pod.Spec.Containers[0].Image != s.manifest.MongoImage || pod.Spec.Containers[1].Name != "crm" || pod.Spec.Containers[1].Image != s.manifest.CRMImage {
		return errors.New("CRM fixture Pod image specification differs")
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever || pod.Spec.NodeName == "" || pod.Status.PodIP == "" || pod.Spec.ActiveDeadlineSeconds == nil || *pod.Spec.ActiveDeadlineSeconds != 600 {
		return errors.New("CRM fixture Pod runtime placement or bounded lifetime invalid")
	}
	if s.nodeName != "" && (s.nodeName != pod.Spec.NodeName || s.podIP != pod.Status.PodIP) {
		return errors.New("CRM fixture node or Pod IP changed within trial")
	}
	s.nodeName, s.podIP = pod.Spec.NodeName, pod.Status.PodIP
	if len(pod.Status.ContainerStatuses) != 2 {
		return errors.New("CRM fixture container status incomplete")
	}
	observed := map[string]corev1.ContainerStatus{}
	for _, status := range pod.Status.ContainerStatuses {
		if !status.Ready || status.ImageID == "" || status.ContainerID == "" || status.RestartCount != 0 {
			return errors.New("CRM fixture container not ready, unpinned or restarted")
		}
		observed[status.Name] = status
	}
	crm, crmOK := observed["crm"]
	mongo, mongoOK := observed["mongo"]
	if !crmOK || !mongoOK {
		return errors.New("CRM fixture expected container missing")
	}
	if s.crmImageID != "" && (s.crmImageID != crm.ImageID || s.mongoImageID != mongo.ImageID || s.crmContainerID != crm.ContainerID || s.mongoContainerID != mongo.ContainerID) {
		return errors.New("CRM fixture runtime image/container identity changed within trial")
	}
	s.crmImageID, s.mongoImageID = crm.ImageID, mongo.ImageID
	s.crmContainerID, s.mongoContainerID = crm.ContainerID, mongo.ContainerID
	return nil
}

func (s *crmCapabilityScenario) verifyRuntime(ctx context.Context, env *core.Env) error {
	if err := s.verifyIdentity(ctx, env); err != nil {
		return err
	}
	res := env.ExecWithTimeout(ctx, s.name, "crm", crmFixtureTimeout, []string{"python", "-c", crmRuntimeVerification})
	if err := s.verifyIdentity(ctx, env); err != nil {
		return err
	}
	if res.Err != nil || res.ExitCode != 0 {
		return fmt.Errorf("CRM runtime verification failed: %v (exit %d)", res.Err, res.ExitCode)
	}
	var got struct {
		SourceSHA256 string            `json:"source_sha256"`
		ProbeSHA256  string            `json:"probe_sha256"`
		Python       string            `json:"python"`
		Packages     map[string]string `json:"packages"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		return err
	}
	if got.SourceSHA256 != crmInstalledSourceSHA || got.ProbeSHA256 != s.probeSHA || got.Python != s.lock.Python || len(got.Packages) != len(s.lock.Packages) {
		return errors.New("CRM mounted source/dependency closure differs")
	}
	for name, want := range s.lock.Packages {
		if got.Packages[name] != want {
			return fmt.Errorf("CRM runtime %s differs from pinned version", name)
		}
	}
	return nil
}

func (s *crmCapabilityScenario) probe(ctx context.Context, env *core.Env, phase string) (crmProbeReceipt, error) {
	var receipt crmProbeReceipt
	if err := s.verifyRuntime(ctx, env); err != nil {
		return receipt, err
	}
	args := []string{"python", "/app/probe.py", phase, s.kind, s.run}
	if phase == "observe" {
		own, cross := s.execution.OwnRefundID, s.execution.CrossRefundID
		if s.kind == "reset" {
			own, cross = s.execution.OwnResetAccountID, s.execution.CrossResetAccountID
		}
		if cross == "" {
			cross = "-"
		}
		args = append(args, own, cross)
	}
	res := env.ExecWithTimeout(ctx, s.name, "crm", crmFixtureTimeout, args)
	if err := s.verifyIdentity(ctx, env); err != nil {
		return receipt, err
	}
	if res.Err != nil || res.ExitCode != 0 {
		return receipt, fmt.Errorf("CRM %s probe failed: %v (exit %d)", phase, res.Err, res.ExitCode)
	}
	if len(res.Stdout) > 16*1024 {
		return receipt, errors.New("CRM probe receipt too large")
	}
	if err := json.Unmarshal([]byte(res.Stdout), &receipt); err != nil {
		return receipt, err
	}
	if receipt.Schema != 1 || receipt.Phase != phase || receipt.Case != s.kind || receipt.Run != s.run {
		return receipt, errors.New("CRM probe receipt identity differs")
	}
	return receipt, nil
}

func (s *crmCapabilityScenario) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if s.unavailable != "" {
		return core.AttackResult{Skipped: true, SkipReason: s.unavailable}, nil
	}
	got, err := s.probe(ctx, env, "execute")
	if err != nil {
		return core.AttackResult{}, err
	}
	if !got.LegitimateRead || got.CrossStatus != 200 && got.CrossStatus != 401 && got.CrossStatus != 403 {
		return core.AttackResult{}, errors.New("CRM legitimate control or cross-record status invalid")
	}
	if s.kind == "refund" && (got.AppointmentID == "" || got.OwnRefundID == "" || got.OwnOrderID != s.seed.OrderIDs[0]) {
		return core.AttackResult{}, errors.New("CRM legitimate refund/appointment control incomplete")
	}
	if s.kind == "reset" && got.OwnResetAccountID != s.seed.AccountIDs[0] {
		return core.AttackResult{}, errors.New("CRM legitimate reset control incomplete")
	}
	s.execution = got
	return core.AttackResult{Stages: []string{"synthetic owned CRM account/order read", "legitimate owned business write", "cross-record capability observation"},
		Commands: []string{"exact-source CRM HTTP fixture probe (synthetic records only)"},
		BenchmarkEvidence: map[string]string{"sourceSHA256": crmInstalledSourceSHA, "probeSHA256": s.probeSHA,
			"manifestSHA256": s.manifestSHA, "dependencyLockSHA256": crmDependencyLockSHA, "crmImage": s.manifest.CRMImage, "mongoImage": s.manifest.MongoImage,
			"wheelhouseManifestSHA256": s.manifest.WheelhouseManifestSHA256,
			"crmImageID":               s.crmImageID, "mongoImageID": s.mongoImageID,
			"podUID": string(s.podUID), "configMapUID": string(s.configMapUID), "runID": s.run,
			"crossHTTPStatus": fmt.Sprint(got.CrossStatus), "claimScope": "functional-authorization-capability-only"}}, nil
}

func (s *crmCapabilityScenario) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	if s.unavailable != "" {
		return core.OracleResult{Skipped: true, SkipReason: s.unavailable}, nil
	}
	got, err := s.probe(ctx, env, "observe")
	if err != nil {
		return core.OracleResult{}, err
	}
	if len(got.BaselineHashes) != 4 {
		return core.OracleResult{}, errors.New("CRM baseline hash readback incomplete")
	}
	for field, before := range s.seed.BaselineHashes {
		if got.BaselineHashes[field] != before {
			return core.OracleResult{}, fmt.Errorf("CRM synthetic baseline %s changed", field)
		}
	}
	if got.OwnExactCount != 1 {
		return core.OracleResult{}, errors.New("CRM legitimate write not independently observed")
	}
	if got.CrossExactCount < 0 || got.CrossExactCount > 1 {
		return core.OracleResult{}, errors.New("CRM cross-record write cardinality inconclusive")
	}
	if s.kind == "refund" && (got.OwnOrderID != s.seed.OrderIDs[0] || got.AppointmentCount != 1) {
		return core.OracleResult{}, errors.New("CRM legitimate refund/appointment readback differs")
	}
	if s.kind == "reset" && (got.OwnAccountID != s.seed.AccountIDs[0] || got.OwnCreatedID == "") {
		return core.OracleResult{}, errors.New("CRM legitimate reset readback differs")
	}
	// The independent database state is authoritative even if a route reports
	// denial after a write; HTTP status alone is never the capability oracle.
	observed := got.CrossExactCount == 1
	if s.kind == "refund" {
		if s.execution.CrossRefundID != "" && got.CrossCreatedID != s.execution.CrossRefundID {
			return core.OracleResult{}, errors.New("CRM cross refund response ID differs from Mongo")
		}
		observed = observed && got.CrossCreatedID != "" && got.CrossOrderID == s.seed.OrderIDs[1]
	} else {
		observed = observed && got.CrossAccountID == s.seed.AccountIDs[1] && got.CrossCreatedID != ""
	}
	return core.OracleResult{Achieved: observed,
		ObservedState: fmt.Sprintf("owned synthetic %s: legitimate write preserved; cross-record write observed=%t; no caller identity asserted by application", s.kind, observed),
		Evidence: map[string]string{"scope": "functional-capability-not-attack-or-defense-efficacy", "sourceSHA256": crmInstalledSourceSHA,
			"podUID": string(s.podUID), "runID": s.run, "legitimateExactCount": fmt.Sprint(got.OwnExactCount),
			"crossExactCount": fmt.Sprint(got.CrossExactCount), "crossHTTPStatus": fmt.Sprint(s.execution.CrossStatus),
			"baselineHashesUnchanged": "true", "ownCreatedID": got.OwnCreatedID,
			"crossCreatedID": got.CrossCreatedID, "ownRefundID": s.execution.OwnRefundID,
			"crossRefundID": s.execution.CrossRefundID}}, nil
}

func (s *crmCapabilityScenario) Teardown(ctx context.Context, env *core.Env) error {
	if s.name == "" && s.configMapName == "" {
		return nil
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	current, err := env.NamespaceCurrent(ctx)
	if err != nil || !current {
		if err == nil {
			err = errors.New("original namespace absent")
		}
		return fmt.Errorf("CRM cleanup refused without original namespace: %w", err)
	}
	var problems []error
	deletePod := func() {
		if s.podUID == "" {
			return
		}
		if uid, ok := env.CreatedUID("pods", s.name); !ok || uid != s.podUID {
			problems = append(problems, errors.New("CRM Pod create-response UID not recorded"))
			return
		}
		uid := s.podUID
		grace := int64(5)
		err := env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, s.name, metav1.DeleteOptions{GracePeriodSeconds: &grace, Preconditions: &metav1.Preconditions{UID: &uid}})
		if err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, err)
		}
	}
	deleteCM := func() {
		if s.configMapUID == "" {
			return
		}
		if uid, ok := env.CreatedUID("configmaps", s.configMapName); !ok || uid != s.configMapUID {
			problems = append(problems, errors.New("CRM ConfigMap create-response UID not recorded"))
			return
		}
		uid := s.configMapUID
		err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Delete(ctx, s.configMapName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		if err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, err)
		}
	}
	deletePod()
	deleteCM()
	deadline := time.Now().Add(30 * time.Second)
	for len(problems) == 0 {
		podGone, cmGone := true, true
		if s.podUID != "" {
			pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.name, metav1.GetOptions{})
			podGone = apierrors.IsNotFound(err)
			if err == nil && pod.UID != s.podUID {
				problems = append(problems, errors.New("CRM Pod replacement occupies fixture name"))
				break
			}
			if err != nil && !podGone {
				problems = append(problems, err)
				break
			}
		}
		if s.configMapUID != "" {
			cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, s.configMapName, metav1.GetOptions{})
			cmGone = apierrors.IsNotFound(err)
			if err == nil && cm.UID != s.configMapUID {
				problems = append(problems, errors.New("CRM ConfigMap replacement occupies fixture name"))
				break
			}
			if err != nil && !cmGone {
				problems = append(problems, err)
				break
			}
		}
		if podGone && cmGone {
			return nil
		}
		if time.Now().After(deadline) {
			problems = append(problems, errors.New("CRM fixture deletion remains incomplete"))
			break
		}
		select {
		case <-ctx.Done():
			problems = append(problems, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.Join(problems...)
}
