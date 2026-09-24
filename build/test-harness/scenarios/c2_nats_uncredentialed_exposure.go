package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
)

func init() { core.RegisterScenario(&c2NATSUncredentialedExposure{}) }

type natsRemoteReceipt struct {
	Kind               string `json:"kind"`
	Status             string `json:"status"`
	Subject            string `json:"subject"`
	Nonce              string `json:"nonce"`
	ServerID           string `json:"serverID"`
	Flushed            bool   `json:"flushed,omitempty"`
	PayloadSHA256      string `json:"payloadSHA256,omitempty"`
	NonceHeaderMatches bool   `json:"nonceHeaderMatches,omitempty"`
	PayloadHashMatches bool   `json:"payloadHashMatches,omitempty"`
}

type natsBaselineArtifact struct {
	Schema               string               `json:"schema"`
	RunID                string               `json:"runId"`
	Nonce                string               `json:"nonce"`
	Namespace            string               `json:"namespace"`
	NamespaceUID         types.UID            `json:"namespaceUID"`
	ObserverPod          string               `json:"observerPod"`
	ObserverPodUID       types.UID            `json:"observerPodUID,omitempty"`
	ObserverConfigMapUID types.UID            `json:"observerConfigMapUID,omitempty"`
	ObserverContainerID  string               `json:"observerContainerID,omitempty"`
	ObserverImageID      string               `json:"observerImageID,omitempty"`
	Route                natsRouteIdentity    `json:"route"`
	Subscription         natsRemoteReceipt    `json:"subscription"`
	Observation          natsRemoteReceipt    `json:"observation"`
	Protocol             natsexposure.Receipt `json:"protocol"`
	ConfigurationFinding string               `json:"configurationFinding"`
	Validity             string               `json:"validity"`
	Cleanup              string               `json:"cleanup"`
	BrainMode            string               `json:"brainMode"`
	SecurityEfficacy     string               `json:"securityEfficacy"`
}

type c2NATSUncredentialedExposure struct {
	route                natsRouteIdentity
	cmName               string
	cmUID                types.UID
	observerConfigSHA256 string
	podName              string
	podUID               types.UID
	podContainerID       string
	evidence             map[string]string
	artifact             natsBaselineArtifact
	executeErr           error
	effectStarted        bool
}

type natsRecoveryAnchor struct {
	Schema            string            `json:"schema"`
	RunID             string            `json:"runId"`
	Nonce             string            `json:"nonce"`
	ClusterUID        types.UID         `json:"clusterUID"`
	Namespace         string            `json:"namespace"`
	NamespaceUID      types.UID         `json:"namespaceUID"`
	ObserverName      string            `json:"observerName"`
	Stream            string            `json:"stream"`
	Route             natsRouteIdentity `json:"route"`
	PID               int               `json:"pid"`
	ProcessStartTicks string            `json:"processStartTicks"`
	FenceIdentity     string            `json:"fenceIdentity"`
}

// NATSNoEffectReceipt is emitted only by a pre-effect exit path. A missing
// receipt is never interpreted as no mutation.
type NATSNoEffectReceipt struct {
	Schema        string    `json:"schema"`
	RunID         string    `json:"runId"`
	Nonce         string    `json:"nonce,omitempty"`
	Namespace     string    `json:"namespace,omitempty"`
	NamespaceUID  types.UID `json:"namespaceUID,omitempty"`
	ClusterUID    types.UID `json:"clusterUID,omitempty"`
	ConfigSHA256  string    `json:"configSHA256,omitempty"`
	Phase         string    `json:"phase"`
	EffectStarted bool      `json:"effectStarted"`
	ObservedAt    string    `json:"observedAt"`
}

func WriteNATSNoEffect(out string, r NATSNoEffectReceipt) error {
	if r.Schema != "nats-baseline-no-effect-v1" || r.RunID == "" || r.EffectStarted || r.Phase == "" {
		return errors.New("NATS no-effect receipt identity invalid")
	}
	r.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 2048 {
		return errors.New("NATS no-effect receipt invalid or oversized")
	}
	return writeNATSBaselineArtifact(filepath.Join(out, "nats-baseline-no-effect.json"), raw)
}

func (s *c2NATSUncredentialedExposure) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name: "c2-nats-uncredentialed-exposure", Category: core.CategoryModernUnsupported, Source: "Owned synthetic NATS no-signal configuration baseline",
		R6ResponseTag: core.R6CannotRespond, BenignControl: true, Realism: core.RealismExecutable,
		Mechanism:          "publish one nonce-owned JetStream message after an independent credential-free Pod subscription barrier and verify both remote receipt and intended consumer ACK",
		OracleDescription:  "a completed configuration measurement requires an exact separate-Pod receipt, legitimate ACK/stored hash, and exact owned cleanup; the exposure finding is reported separately",
		CleanupDescription: "delete only create-response UID-bound observer ConfigMap/Pod and nonce-owned stream; final runner receipt confirms fixture namespace UID preserved and run resources absent",
		ClaimLimits:        "synthetic no-auth configuration finding only; no customer data, permission bypass, SecurityEvent, detector, brain decision, actuator or defense outcome",
		R6Justification:    "this no-signal control has no Phorvex response trigger and is excluded from security efficacy scores",
	}
}

func (s *c2NATSUncredentialedExposure) Setup(ctx context.Context, env *core.Env) error {
	f := env.Config.NATSExposureFixture
	if f == nil {
		return errors.New("NATS baseline fixture not configured")
	}
	s.cmName = "nats-observer-" + f.Nonce
	s.podName = "nats-observer-" + f.Nonce
	s.evidence = map[string]string{}
	s.artifact = natsBaselineArtifact{Schema: "nats-baseline-v1", RunID: f.RunID, Nonce: f.Nonce, Namespace: env.Config.Namespace, NamespaceUID: env.NamespaceUID(), ObserverPod: s.podName, ConfigurationFinding: "UNKNOWN", Validity: "INCONCLUSIVE", Cleanup: "NOT_STARTED", BrainMode: "NO_SIGNAL", SecurityEfficacy: "NOT_EVALUATED"}
	route, err := captureNATSRoute(ctx, env)
	if err != nil {
		return err
	}
	s.route = route
	s.artifact.Route = route
	startTicks, err := natsProcessStartTicks(os.Getpid())
	if err != nil {
		return err
	}
	if env.NATSFenceIdentity == "" {
		return errors.New("exclusive NATS process fence unavailable")
	}
	anchor := natsRecoveryAnchor{Schema: "nats-baseline-anchor-v1", RunID: f.RunID, Nonce: f.Nonce, ClusterUID: route.ClusterUID, Namespace: env.Config.Namespace, NamespaceUID: env.NamespaceUID(), ObserverName: s.podName, Stream: "CAT_" + f.Nonce, Route: route, PID: os.Getpid(), ProcessStartTicks: startTicks, FenceIdentity: env.NATSFenceIdentity}
	raw, err := json.Marshal(anchor)
	if err != nil || len(raw) > 8192 {
		return errors.New("NATS recovery anchor invalid or oversized")
	}
	if err := writeNATSBaselineArtifact(filepath.Join(env.Config.OutDir, "nats-baseline-anchor.json"), raw); err != nil {
		return err
	}
	return nil
}

func natsProcessStartTicks(pid int) (string, error) {
	if pid < 1 {
		return "", errors.New("invalid NATS process PID")
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	i := strings.LastIndex(string(raw), ") ")
	if i < 0 {
		return "", errors.New("NATS process stat malformed")
	}
	fields := strings.Fields(string(raw[i+2:]))
	if len(fields) <= 19 || fields[19] == "" {
		return "", errors.New("NATS process start time unavailable")
	}
	return fields[19], nil
}

func natsBaselinePayload(nonce string) []byte { return []byte("phorvex-owned-nats-exposure:" + nonce) }
func natsSHA(raw []byte) string               { d := sha256.Sum256(raw); return hex.EncodeToString(d[:]) }

type natsExposureFixedDialer struct{ address string }

func (d natsExposureFixedDialer) Dial(network, address string) (net.Conn, error) {
	if address != d.address {
		return nil, errors.New("NATS connection attempted outside exact owned forward")
	}
	return (&net.Dialer{Timeout: 3 * time.Second}).Dial(network, address)
}

func (s *c2NATSUncredentialedExposure) createObserver(ctx context.Context, env *core.Env, subject string, payload []byte) error {
	f := env.Config.NATSExposureFixture
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	allowed := make([]string, 0, len(s.route.Brokers))
	for _, b := range s.route.Brokers {
		allowed = append(allowed, b.ServerID)
	}
	cfg := map[string]any{"brokerURL": "nats://nats.nats.svc.cluster.local:4222", "subject": subject, "nonce": f.Nonce, "allowedServerIDs": allowed, "expectedPayloadSHA256": natsSHA(payload), "connectTimeoutMillis": 3000, "flushTimeoutMillis": 3000, "observeTimeoutMillis": 35000}
	raw, err := json.Marshal(cfg)
	if err != nil || len(raw) > 1024 {
		return errors.New("observer config exceeded reviewed bound")
	}
	immutable := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: s.cmName, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(map[string]string{"fixture.phorvex.ai/owner-nonce": f.Nonce})}, Immutable: &immutable, Data: map[string]string{"observer.json": string(raw)}}
	if err := s.phase(env, "OBSERVER_CONFIG_CREATE_INTENT"); err != nil {
		return err
	}
	s.effectStarted = true
	createdCM, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		return errors.New("owned observer ConfigMap create ambiguous or failed; no retry")
	}
	if createdCM.UID == "" || createdCM.Name != s.cmName {
		return errors.New("observer ConfigMap create response lacks identity")
	}
	s.cmUID = createdCM.UID
	s.artifact.ObserverConfigMapUID = createdCM.UID
	s.observerConfigSHA256 = natsSHA(raw)
	if err := env.RecordCreatedUID("configmaps", s.cmName, s.cmUID); err != nil {
		return err
	}
	if err := s.phase(env, "OBSERVER_CONFIG_CREATED"); err != nil {
		return err
	}
	no := false
	yes := true
	user := int64(65532)
	deadline := int64(50)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: s.podName, Namespace: env.Config.Namespace, Labels: env.OwnedLabels(map[string]string{"fixture.phorvex.ai/owner-nonce": f.Nonce})}, Spec: corev1.PodSpec{
		NodeName: f.NodeName, AutomountServiceAccountToken: &no, RestartPolicy: corev1.RestartPolicyNever, ActiveDeadlineSeconds: &deadline,
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &user, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers: []corev1.Container{{Name: "observer", Image: f.ObserverImage, ImagePullPolicy: corev1.PullIfNotPresent, Command: []string{"/app/nats-owned-observer", "--config", "/config/observer.json"},
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "config", MountPath: "/config", ReadOnly: true}}}},
		Volumes: []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: s.cmName}}}}},
	}}
	if err := s.phase(env, "OBSERVER_POD_CREATE_INTENT"); err != nil {
		return err
	}
	createdPod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return errors.New("owned observer Pod create ambiguous or failed; no retry")
	}
	if createdPod.UID == "" || createdPod.Name != s.podName {
		return errors.New("observer Pod create response lacks identity")
	}
	s.podUID = createdPod.UID
	s.artifact.ObserverPodUID = s.podUID
	if err := env.RecordCreatedUID("pods", s.podName, s.podUID); err != nil {
		return err
	}
	return s.phase(env, "OBSERVER_POD_CREATED")
}

func (s *c2NATSUncredentialedExposure) currentObserver(ctx context.Context, env *core.Env) error {
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID != env.NamespaceUID() {
		return errors.New("owned observer namespace UID changed")
	}
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, s.cmName, metav1.GetOptions{})
	if err != nil || cm.UID != s.cmUID || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || natsSHA([]byte(cm.Data["observer.json"])) != s.observerConfigSHA256 || cm.Labels["fixture.phorvex.ai/owner-nonce"] != env.Config.NATSExposureFixture.Nonce {
		return errors.New("owned immutable observer config identity changed")
	}
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.podName, metav1.GetOptions{})
	if err != nil || pod.UID != s.podUID || pod.DeletionTimestamp != nil || pod.Spec.NodeName != env.Config.NATSExposureFixture.NodeName || pod.Labels["fixture.phorvex.ai/owner-nonce"] != env.Config.NATSExposureFixture.Nonce {
		return errors.New("owned observer Pod identity changed")
	}
	if len(pod.Status.ContainerStatuses) != 1 {
		return errors.New("owned observer container identity unavailable")
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken || len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].ConfigMap == nil || pod.Spec.Volumes[0].ConfigMap.Name != s.cmName {
		return errors.New("owned observer Pod configuration or token isolation differs")
	}
	cs := pod.Status.ContainerStatuses[0]
	if len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Image != env.Config.NATSExposureFixture.ObserverImage || cs.Name != "observer" || !sameImageDigest(cs.ImageID, env.Config.NATSExposureFixture.ObserverImage) || cs.RestartCount != 0 || cs.ContainerID == "" {
		return errors.New("owned observer image/restart/container identity differs")
	}
	container := pod.Spec.Containers[0]
	if len(container.Command) != 3 || container.Command[0] != "/app/nats-owned-observer" || container.Command[1] != "--config" || container.Command[2] != "/config/observer.json" || len(container.Args) != 0 || len(container.VolumeMounts) != 1 || container.VolumeMounts[0].Name != "config" || container.VolumeMounts[0].MountPath != "/config" || !container.VolumeMounts[0].ReadOnly || container.VolumeMounts[0].SubPath != "" || container.VolumeMounts[0].SubPathExpr != "" {
		return errors.New("owned observer process or config mount differs")
	}
	if s.podContainerID != "" && s.podContainerID != cs.ContainerID {
		return errors.New("owned observer container restarted")
	}
	s.podContainerID = cs.ContainerID
	s.artifact.ObserverContainerID = cs.ContainerID
	s.artifact.ObserverImageID = cs.ImageID
	return nil
}

func sameImageDigest(observed, admitted string) bool {
	needle := "@sha256:"
	a, b := strings.LastIndex(observed, needle), strings.LastIndex(admitted, needle)
	return a >= 0 && b >= 0 && len(observed[a+len(needle):]) == 64 && observed[a:] == admitted[b:]
}

func (s *c2NATSUncredentialedExposure) observerLogs(ctx context.Context, env *core.Env) ([]natsRemoteReceipt, error) {
	if err := s.currentObserver(ctx, env); err != nil {
		return nil, err
	}
	stream, err := env.Kube.CoreV1().Pods(env.Config.Namespace).GetLogs(s.podName, &corev1.PodLogOptions{Container: "observer", Timestamps: false}).Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	raw, err := io.ReadAll(io.LimitReader(stream, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("owned observer log exceeded fixed bound")
	}
	if err := s.currentObserver(ctx, env); err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 2 {
		return nil, errors.New("owned observer emitted more than two receipts")
	}
	receipts := make([]natsRemoteReceipt, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var r natsRemoteReceipt
		if json.Unmarshal([]byte(line), &r) != nil {
			return nil, errors.New("observer receipt invalid")
		}
		receipts = append(receipts, r)
	}
	return receipts, nil
}

func (s *c2NATSUncredentialedExposure) waitSubscription(ctx context.Context, env *core.Env, subject string) error {
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		receipts, err := s.observerLogs(ctx, env)
		if err == nil && len(receipts) > 0 {
			r := receipts[0]
			if r.Kind != "subscription" || r.Subject != subject || r.Nonce != env.Config.NATSExposureFixture.Nonce || !r.Flushed {
				return errors.New("remote subscription receipt identity differs")
			}
			if _, ok := brokerForServer(s.route, r.ServerID); !ok {
				return errors.New("remote subscription server ID outside current Service")
			}
			if r.Status != "READY" && r.Status != "SUBSCRIPTION_DENIED" {
				return errors.New("remote subscription status not decisive")
			}
			s.artifact.Subscription = r
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("remote subscription barrier timed out")
		case <-ticker.C:
		}
	}
}

func (s *c2NATSUncredentialedExposure) waitObservation(ctx context.Context, env *core.Env) ([]natsRemoteReceipt, error) {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		receipts, err := s.observerLogs(ctx, env)
		if err == nil && len(receipts) == 2 {
			return receipts, nil
		}
		if err == nil && len(receipts) == 1 && receipts[0] != s.artifact.Subscription {
			return nil, errors.New("observer subscription changed before terminal receipt")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("remote observer terminal receipt timed out")
		case <-ticker.C:
		}
	}
}

func (s *c2NATSUncredentialedExposure) phase(env *core.Env, phase string) error {
	return s.phaseReceipt(env, phase, nil)
}

func (s *c2NATSUncredentialedExposure) phaseReceipt(env *core.Env, phase string, receipt *natsexposure.Receipt) error {
	if env.Config.OutDir == "" {
		return errors.New("run output directory missing")
	}
	path := filepath.Join(env.Config.OutDir, "nats-baseline-phases.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	row, err := json.Marshal(struct {
		Phase           string                `json:"phase"`
		RunID           string                `json:"runId"`
		Nonce           string                `json:"nonce"`
		At              string                `json:"at"`
		ProtocolReceipt *natsexposure.Receipt `json:"protocolReceipt,omitempty"`
	}{phase, env.Config.NATSExposureFixture.RunID, env.Config.NATSExposureFixture.Nonce, time.Now().UTC().Format(time.RFC3339Nano), receipt})
	if err != nil || len(row) > 8192 {
		return errors.New("NATS phase receipt invalid or oversized")
	}
	if _, err = file.Write(append(row, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func (s *c2NATSUncredentialedExposure) Execute(ctx context.Context, env *core.Env) (result core.AttackResult, runErr error) {
	f := env.Config.NATSExposureFixture
	result = core.AttackResult{Stages: []string{"admitted NATS route", "independent observer Pod", "one owned JetStream message"}, BenchmarkEvidence: s.evidence}
	if f == nil {
		return result, errors.New("NATS fixture absent")
	}
	payload := natsBaselinePayload(f.Nonce)
	subject := "cat.exposure." + f.Nonce
	if err := requireNATSRoute(ctx, env, s.route); err != nil {
		return result, err
	}
	if err := s.createObserver(ctx, env, subject, payload); err != nil {
		return result, err
	}
	broker := s.route.Brokers[0]
	current, err := env.Kube.CoreV1().Pods(natsExposureNamespace).Get(ctx, broker.Name, metav1.GetOptions{})
	if err != nil || current.UID != broker.UID {
		return result, errors.New("writer broker Pod replaced before forward")
	}
	port, closeForward, err := forwardNATSPod(ctx, env.Rest, natsExposureNamespace, broker.Name, 4222)
	if err != nil {
		return result, err
	}
	defer func() {
		if err := closeForward(); err != nil {
			s.artifact.Validity = "INCONCLUSIVE"
			s.executeErr = errors.Join(s.executeErr, errors.New("writer broker port-forward stop unconfirmed"))
			runErr = errors.Join(runErr, s.executeErr)
		}
	}()
	current, err = env.Kube.CoreV1().Pods(natsExposureNamespace).Get(ctx, broker.Name, metav1.GetOptions{})
	if err != nil || current.UID != broker.UID {
		return result, errors.New("writer broker Pod replaced across forward")
	}
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	connect := func() (*nats.Conn, error) {
		return nats.Connect(url, nats.Timeout(3*time.Second), nats.NoReconnect(), nats.MaxReconnects(0), nats.RetryOnFailedConnect(false), nats.DontRandomize(), nats.SkipHostLookup(), nats.PermissionErrOnSubscribe(true), nats.SetCustomDialer(natsExposureFixedDialer{address: fmt.Sprintf("127.0.0.1:%d", port)}))
	}
	writer, err := connect()
	if err != nil {
		return result, errors.New("bounded writer connection failed")
	}
	defer writer.Close()
	localReference, err := connect()
	if err != nil {
		return result, errors.New("bounded local protocol reference failed")
	}
	defer localReference.Close()
	if writer.ConnectedServerId() != broker.ServerID || localReference.ConnectedServerId() != broker.ServerID {
		return result, errors.New("writer port-forward broker ID differed")
	}
	pCfg := natsexposure.Config{Nonce: f.Nonce, Stream: "CAT_" + f.Nonce, Subject: subject, Consumer: "CAT_" + f.Nonce + "_C", ExpectedWriterServerID: broker.ServerID, ExpectedAdversaryServerID: broker.ServerID, RequestTimeout: 3 * time.Second, ReceiveTimeout: 3 * time.Second, AckWait: 5 * time.Second, BarrierTimeout: 30 * time.Second}
	recorder := func(_ context.Context, r natsexposure.Receipt) error {
		s.artifact.Protocol = r
		return s.phaseReceipt(env, "PROTOCOL_"+r.Phase, &r)
	}
	barrier := func(barrierCtx context.Context, _ natsexposure.Receipt) error {
		if err := s.waitSubscription(barrierCtx, env, subject); err != nil {
			return err
		}
		if err := requireNATSRoute(barrierCtx, env, s.route); err != nil {
			return err
		}
		return s.currentObserver(barrierCtx, env)
	}
	s.artifact.Protocol, s.executeErr = natsexposure.Run(ctx, pCfg, writer, localReference, payload, recorder, barrier)
	var receipts []natsRemoteReceipt
	var logsErr error
	if s.artifact.Protocol.PublishAttempted {
		receipts, logsErr = s.waitObservation(ctx, env)
	} else {
		receipts, logsErr = s.observerLogs(ctx, env)
	}
	if logsErr == nil && len(receipts) == 2 && receipts[0] == s.artifact.Subscription {
		s.artifact.Observation = receipts[1]
	}
	postRouteErr := requireNATSRoute(ctx, env, s.route)
	if postRouteErr != nil {
		s.artifact.Validity = "INCONCLUSIVE"
	}
	if s.artifact.Subscription.Status == "READY" && s.artifact.Observation.Kind == "observation" && s.artifact.Observation.Status == "EXACT_PAYLOAD_RECEIVED" && s.artifact.Observation.PayloadSHA256 == natsSHA(payload) && s.artifact.Observation.NonceHeaderMatches && s.artifact.Observation.PayloadHashMatches && s.artifact.Observation.Subject == subject && s.artifact.Observation.Nonce == f.Nonce && s.artifact.Observation.ServerID == s.artifact.Subscription.ServerID {
		s.artifact.ConfigurationFinding = "EXPOSED"
	}
	if s.artifact.Subscription.Status == "SUBSCRIPTION_DENIED" && s.artifact.Observation.Status == "PERMISSION_DENIED" {
		s.artifact.ConfigurationFinding = "NOT_EXPOSED_IN_THIS_CONTROL"
	}
	if s.executeErr == nil && logsErr == nil && postRouteErr == nil && s.artifact.Protocol.LegitimateAcked && s.artifact.Protocol.StoredPayloadSHA256 == natsSHA(payload) && s.artifact.Protocol.Cleanup == "CONFIRMED_ABSENT" && s.artifact.ConfigurationFinding != "UNKNOWN" {
		s.artifact.Validity = "MEASUREMENT_COMPLETE"
	}
	if s.executeErr != nil {
		return result, s.executeErr
	}
	if logsErr != nil {
		return result, errors.New("independent remote observer receipt unavailable")
	}
	if postRouteErr != nil {
		return result, errors.New("NATS source/route drifted after publication")
	}
	return result, nil
}

func (s *c2NATSUncredentialedExposure) SuccessOracle(_ context.Context, _ *core.Env) (core.OracleResult, error) {
	return core.OracleResult{Achieved: s.artifact.Validity == "MEASUREMENT_COMPLETE", ObservedState: "NATS synthetic configuration measurement: " + s.artifact.ConfigurationFinding, Evidence: map[string]string{"configurationFinding": s.artifact.ConfigurationFinding, "legitimateAcked": fmt.Sprint(s.artifact.Protocol.LegitimateAcked), "remotePodUID": string(s.podUID)}}, nil
}

func (s *c2NATSUncredentialedExposure) Teardown(ctx context.Context, env *core.Env) error {
	var problems []error
	deleteOne := func(resource, name string, uid types.UID, remove func() error, lookup func() (types.UID, error)) {
		if uid == "" {
			return
		}
		if err := remove(); err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, fmt.Errorf("%s deletion unconfirmed: %w", resource, err))
			return
		}
		deadline := time.NewTimer(20 * time.Second)
		defer deadline.Stop()
		for {
			now, err := lookup()
			if apierrors.IsNotFound(err) {
				if bindErr := env.ForgetCreatedUID(resource, name, uid); bindErr != nil {
					problems = append(problems, bindErr)
				}
				return
			}
			if err != nil {
				problems = append(problems, fmt.Errorf("%s absence unknown: %w", resource, err))
				return
			}
			if now != uid {
				problems = append(problems, fmt.Errorf("%s same-name replacement UID observed", resource))
				return
			}
			select {
			case <-ctx.Done():
				problems = append(problems, fmt.Errorf("%s absence deadline: %w", resource, ctx.Err()))
				return
			case <-deadline.C:
				problems = append(problems, fmt.Errorf("%s deletion not confirmed within 20 seconds", resource))
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	if s.podUID != "" {
		uid := s.podUID
		deleteOne("pods", s.podName, uid, func() error {
			return env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, s.podName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		}, func() (types.UID, error) {
			p, e := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.podName, metav1.GetOptions{})
			if e != nil {
				return "", e
			}
			return p.UID, nil
		})
	}
	if s.cmUID != "" {
		uid := s.cmUID
		deleteOne("configmaps", s.cmName, uid, func() error {
			return env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Delete(ctx, s.cmName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		}, func() (types.UID, error) {
			cm, e := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, s.cmName, metav1.GetOptions{})
			if e != nil {
				return "", e
			}
			return cm.UID, nil
		})
	}
	if len(problems) == 0 && s.artifact.Protocol.Cleanup == "CONFIRMED_ABSENT" {
		s.artifact.Cleanup = "OBSERVER_AND_STREAM_CONFIRMED_ABSENT"
	} else {
		s.artifact.Cleanup = "UNCONFIRMED"
		s.artifact.Validity = "INCONCLUSIVE"
	}
	raw, err := json.Marshal(s.artifact)
	if err == nil && len(raw) <= 64<<10 {
		err = writeNATSBaselineArtifact(filepath.Join(env.Config.OutDir, "nats-baseline.json"), raw)
		if err == nil {
			s.evidence["nats_baseline_artifact_sha256"] = natsSHA(raw)
		}
	} else if err == nil {
		err = errors.New("NATS baseline artifact exceeded bound")
	}
	if !s.effectStarted && len(problems) == 0 {
		if safeErr := env.VerifyNATSFixtureClean(ctx); safeErr == nil {
			noEffect := NATSNoEffectReceipt{Schema: "nats-baseline-no-effect-v1", RunID: env.Config.NATSExposureFixture.RunID, Nonce: env.Config.NATSExposureFixture.Nonce, Namespace: env.Config.Namespace, NamespaceUID: env.NamespaceUID(), ClusterUID: types.UID(env.Config.NATSExposureFixture.ClusterUID), Phase: "SCENARIO_PRE_EFFECT_EXIT"}
			err = errors.Join(err, WriteNATSNoEffect(env.Config.OutDir, noEffect))
		}
	}
	return errors.Join(append(problems, err)...)
}

func writeNATSBaselineArtifact(path string, raw []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
