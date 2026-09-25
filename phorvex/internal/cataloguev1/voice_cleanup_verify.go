package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

var voiceCleanupSID = regexp.MustCompile(`^CA[0-9a-f]{32}$`)

// VoiceCleanupReadDriver intentionally has no delete, eviction, media, or event method.
// The production implementation uses only Snapshot, source hashing, and exact-SID Mongo reads.
type VoiceCleanupReadDriver interface {
	Snapshot(context.Context, VoiceConfig) (VoiceSnapshot, error)
	SourceSHA256(context.Context, VoiceConfig, VoicePod) (string, error)
	ReadTranscriptCount(context.Context, VoiceConfig, VoicePod, []string) (int, error)
	HistoricalPodUIDsAbsent(context.Context, VoiceConfig, string, string) (bool, error)
	DatastoreBinding(context.Context, VoiceConfig, VoiceCleanupHistoricalIdentity, VoicePod) (string, error)
}

func literalVoiceMongoEnv(spec corev1.PodSpec, containerName string) ([]string, error) {
	var containers []corev1.Container
	for _, container := range spec.Containers {
		if container.Name == containerName {
			containers = append(containers, container)
		}
	}
	if len(containers) != 1 {
		return nil, errors.New("Voice Mongo container differs")
	}
	values := make([]string, 0, 3)
	for _, name := range []string{"MONGO_URI", "MONGO_DB", "MONGO_COLLECTION"} {
		found := false
		for _, env := range containers[0].Env {
			if env.Name != name {
				continue
			}
			if found || env.ValueFrom != nil || env.Value == "" {
				return nil, errors.New("Voice Mongo env binding ambiguous")
			}
			found = true
			values = append(values, env.Value)
		}
		if !found {
			return nil, errors.New("Voice Mongo env binding absent")
		}
	}
	return values, nil
}

func (r *kubeVoiceRuntime) DatastoreBinding(ctx context.Context, cfg VoiceConfig, h VoiceCleanupHistoricalIdentity, pod VoicePod) (string, error) {
	list, err := r.kube.AppsV1().ReplicaSets(cfg.Namespace).List(ctx, metav1.ListOptions{Limit: 100})
	if err != nil || list.Continue != "" || len(list.Items) >= 100 {
		return "", errors.New("complete historical Voice ReplicaSet inventory unavailable")
	}
	var historical *appsv1.ReplicaSet
	for i := range list.Items {
		if string(list.Items[i].UID) == h.ReplicaSetUID {
			if historical != nil {
				return "", errors.New("duplicate historical ReplicaSet UID")
			}
			historical = &list.Items[i]
		}
	}
	if historical == nil || !exactController(historical.OwnerReferences, "apps/v1", "Deployment", cfg.DeploymentName, types.UID(h.DeploymentUID)) {
		return "", errors.New("historical Voice ReplicaSet unavailable")
	}
	specSHA, err := voiceCanonicalSHA(historical.Spec)
	if err != nil || specSHA != h.ReplicaSetSpecSHA256 {
		return "", errors.New("historical Voice ReplicaSet spec differs")
	}
	oldValues, err := literalVoiceMongoEnv(historical.Spec.Template.Spec, cfg.ContainerName)
	if err != nil {
		return "", err
	}
	current, err := r.kube.CoreV1().Pods(cfg.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || string(current.UID) != pod.UID || !exactController(current.OwnerReferences, "apps/v1", "ReplicaSet", pod.ReplicaSetName, types.UID(pod.ReplicaSetUID)) {
		return "", errors.New("current Voice Mongo Pod identity differs")
	}
	currentValues, err := literalVoiceMongoEnv(current.Spec, cfg.ContainerName)
	if err != nil || !reflect.DeepEqual(oldValues, currentValues) {
		return "", errors.New("Voice Mongo datastore differs from historical ReplicaSet")
	}
	raw, err := json.Marshal(oldValues)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (r *kubeVoiceRuntime) HistoricalPodUIDsAbsent(ctx context.Context, cfg VoiceConfig, targetUID, replacementUID string) (bool, error) {
	// An old Pod with changed labels is invisible to Snapshot's Deployment selector.
	// Read the whole fixed Voice namespace with a finite cardinality and refuse pagination.
	pods, err := r.kube.CoreV1().Pods(cfg.Namespace).List(ctx, metav1.ListOptions{Limit: 100})
	if err != nil || pods.Continue != "" || len(pods.Items) >= 100 {
		return false, errors.New("complete Voice namespace Pod UID inventory unavailable")
	}
	for _, pod := range pods.Items {
		if string(pod.UID) == targetUID || string(pod.UID) == replacementUID {
			return false, nil
		}
	}
	return true, nil
}

func NewVoiceCleanupReadDriver(runtime Runtime) (VoiceCleanupReadDriver, error) {
	if runtime.RESTConfig == nil || runtime.Kube == nil || !runtime.Voice.Enabled || runtime.Voice.Namespace != "voice" ||
		runtime.Voice.Deployment != "voice-bot" || runtime.Voice.Service != "voice-bot" || runtime.Voice.PDB != "voice-bot" ||
		runtime.Voice.Container != "bot" || runtime.Voice.TranscriptContainer != "bot" || runtime.Voice.ServicePort != 8080 {
		return nil, errors.New("Voice cleanup read runtime differs")
	}
	selector, err := labels.Parse(runtime.Voice.TranscriptPodSelector)
	if err != nil || selector.Empty() {
		return nil, errors.New("Voice transcript read selector differs")
	}
	return &kubeVoiceRuntime{rest: runtime.RESTConfig, kube: runtime.Kube, voice: runtime.Voice}, nil
}

func (r *kubeVoiceRuntime) ReadTranscriptCount(ctx context.Context, cfg VoiceConfig, pod VoicePod, callSIDs []string) (int, error) {
	if len(callSIDs) != 2 {
		return 0, errors.New("Voice cleanup SID count differs")
	}
	args := append([]string{"python3", "-c", transcriptQueryProgram}, callSIDs...)
	output, err := r.exec(ctx, cfg.Namespace, pod.Name, r.voice.TranscriptContainer, args)
	if err != nil {
		return 0, errors.New("Voice transcript read unavailable")
	}
	refs, err := parseTranscriptRefs(output, callSIDs)
	if err != nil {
		return 0, errors.New("Voice transcript projection malformed")
	}
	return len(refs), nil
}

type VoiceCleanupHistoricalIdentity struct {
	NamespaceUID         string `json:"namespaceUID"`
	DeploymentUID        string `json:"deploymentUID"`
	ServiceUID           string `json:"serviceUID"`
	PDBUID               string `json:"pdbUID"`
	ReplicaSetUID        string `json:"replicaSetUID"`
	ReplicaSetSpecSHA256 string `json:"replicaSetSpecSHA256"`
	TargetPodUID         string `json:"targetPodUID"`
	ReplacementPodUID    string `json:"replacementPodUID"`
}

type VoiceCleanupZeroSample struct {
	At    time.Time `json:"at"`
	Count int       `json:"count"`
}
type VoiceCleanupReadProof struct {
	Schema                 string                   `json:"schema"`
	NamespaceUID           string                   `json:"namespaceUID"`
	DeploymentUID          string                   `json:"deploymentUID"`
	ServiceUID             string                   `json:"serviceUID"`
	PDBUID                 string                   `json:"pdbUID"`
	CurrentReplicaSetUID   string                   `json:"currentReplicaSetUID"`
	ReadPodUID             string                   `json:"readPodUID"`
	ReadPodContainerID     string                   `json:"readPodContainerID"`
	ReadPodImageID         string                   `json:"readPodImageID"`
	CurrentSourceSHA256    string                   `json:"currentSourceSHA256"`
	DatastoreBindingSHA256 string                   `json:"datastoreBindingSHA256"`
	CurrentAuthoritySHA256 string                   `json:"currentAuthoritySHA256"`
	SIDHashes              []string                 `json:"sidHashes"`
	Samples                []VoiceCleanupZeroSample `json:"samples"`
	KubernetesWrites       int                      `json:"kubernetesWrites"`
	MongoWrites            int                      `json:"mongoWrites"`
	WorkloadCalls          int                      `json:"workloadCalls"`
}

type voiceCleanupAuthority struct {
	NamespaceUID         string
	DeploymentUID        string
	DeploymentGeneration int64
	DeploymentSpecSHA256 string
	ReplicaSetUID        string
	ReplicaSetGeneration int64
	ReplicaSetSpecSHA256 string
	ServiceUID           string
	ServiceSpecSHA256    string
	PDBUID               string
	PDBSpecSHA256        string
	EndpointUIDs         []string
	Pods                 []VoicePod
}

func cleanupAuthority(snapshot VoiceSnapshot) voiceCleanupAuthority {
	endpoints := append([]string(nil), snapshot.ReadyEndpointUIDs...)
	sort.Strings(endpoints)
	pods := append([]VoicePod(nil), snapshot.Pods...)
	sort.Slice(pods, func(i, j int) bool { return pods[i].UID < pods[j].UID })
	return voiceCleanupAuthority{snapshot.NamespaceUID, snapshot.DeploymentUID, snapshot.DeploymentGeneration, snapshot.DeploymentSpecSHA256,
		snapshot.ReplicaSetUID, snapshot.ReplicaSetGeneration, snapshot.ReplicaSetSpecSHA256, snapshot.ServiceUID, snapshot.ServiceSpecSHA256,
		snapshot.PDBUID, snapshot.PDBSpecSHA256, endpoints, pods}
}
func cleanupReadPod(snapshot VoiceSnapshot, h VoiceCleanupHistoricalIdentity) (VoicePod, error) {
	if snapshot.NamespaceUID != h.NamespaceUID || snapshot.DeploymentUID != h.DeploymentUID || snapshot.ServiceUID != h.ServiceUID || snapshot.PDBUID != h.PDBUID ||
		snapshot.DeploymentReadyReplicas != 3 || snapshot.DeploymentAvailableReplicas != 3 || len(snapshot.Pods) != 3 || len(snapshot.ReadyEndpointUIDs) != 3 {
		return VoicePod{}, errors.New("Voice cleanup current authority differs")
	}
	endpoints := map[string]bool{}
	for _, uid := range snapshot.ReadyEndpointUIDs {
		endpoints[uid] = true
	}
	var selected VoicePod
	for _, p := range snapshot.Pods {
		if p.UID == h.TargetPodUID || p.UID == h.ReplacementPodUID {
			return VoicePod{}, errors.New("original Voice Pod incarnation remains")
		}
		if !p.Ready || !p.Started || p.Terminating || p.UID == "" || p.ContainerID == "" || p.ImageID == "" || !endpoints[p.UID] {
			return VoicePod{}, errors.New("Voice cleanup Pod/endpoint not ready")
		}
		if selected.UID == "" {
			selected = p
		}
	}
	return selected, nil
}

// VerifyVoiceCleanupReadOnly observes only the two journal-derived synthetic SIDs.
// Historical source/image bytes are checked by the caller; current image/source may
// differ but must remain identical throughout this fresh observation.
func VerifyVoiceCleanupReadOnly(ctx context.Context, driver VoiceCleanupReadDriver, cfg VoiceConfig, h VoiceCleanupHistoricalIdentity, sids []string, pause func(context.Context, time.Duration) error) (VoiceCleanupReadProof, error) {
	var proof VoiceCleanupReadProof
	if driver == nil || cfg.Namespace != "voice" || cfg.DeploymentName != "voice-bot" || cfg.ServiceName != "voice-bot" || cfg.PDBName != "voice-bot" || cfg.ContainerName != "bot" ||
		len(sids) != 2 || sids[0] == sids[1] || !voiceCleanupSID.MatchString(sids[0]) || !voiceCleanupSID.MatchString(sids[1]) ||
		h.TargetPodUID == h.ReplacementPodUID || h.TargetPodUID == "" || h.ReplacementPodUID == "" ||
		h.NamespaceUID == "" || h.DeploymentUID == "" || h.ServiceUID == "" || h.PDBUID == "" || h.ReplicaSetUID == "" || !voiceSHA256.MatchString(h.ReplicaSetSpecSHA256) {
		return proof, errors.New("Voice cleanup historical scope differs")
	}
	if pause == nil {
		pause = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	first, err := driver.Snapshot(ctx, cfg)
	if err != nil {
		return proof, err
	}
	pod, err := cleanupReadPod(first, h)
	if err != nil {
		return proof, err
	}
	if absent, e := driver.HistoricalPodUIDsAbsent(ctx, cfg, h.TargetPodUID, h.ReplacementPodUID); e != nil || !absent {
		return proof, errors.New("original Voice Pod UID remains or inventory unavailable")
	}
	datastore, err := driver.DatastoreBinding(ctx, cfg, h, pod)
	if err != nil || !voiceSHA256.MatchString(datastore) {
		return proof, errors.New("historical Voice datastore binding unavailable")
	}
	source, err := driver.SourceSHA256(ctx, cfg, pod)
	if err != nil || !voiceSHA256.MatchString(source) {
		return proof, errors.New("current Voice source unavailable")
	}
	authority := cleanupAuthority(first)
	hashes := []string{}
	for _, sid := range sids {
		sum := sha256.Sum256([]byte(sid))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	sort.Strings(hashes)
	proof = VoiceCleanupReadProof{Schema: "phorvex.voice-cleanup-read.v1", NamespaceUID: h.NamespaceUID, DeploymentUID: h.DeploymentUID, ServiceUID: h.ServiceUID, PDBUID: h.PDBUID,
		CurrentReplicaSetUID: first.ReplicaSetUID, ReadPodUID: pod.UID, ReadPodContainerID: pod.ContainerID, ReadPodImageID: pod.ImageID, CurrentSourceSHA256: source, DatastoreBindingSHA256: datastore, SIDHashes: hashes,
		KubernetesWrites: 0, MongoWrites: 0, WorkloadCalls: 0}
	authoritySum, err := voiceCanonicalSHA(authority)
	if err != nil {
		return VoiceCleanupReadProof{}, err
	}
	proof.CurrentAuthoritySHA256 = authoritySum
	for i := 0; i < 3; i++ {
		before, e := driver.Snapshot(ctx, cfg)
		if e != nil {
			return VoiceCleanupReadProof{}, e
		}
		current, e := cleanupReadPod(before, h)
		if e != nil || !reflect.DeepEqual(cleanupAuthority(before), authority) || current.UID != pod.UID {
			return VoiceCleanupReadProof{}, errors.New("Voice cleanup authority drift before query")
		}
		if absent, e := driver.HistoricalPodUIDsAbsent(ctx, cfg, h.TargetPodUID, h.ReplacementPodUID); e != nil || !absent {
			return VoiceCleanupReadProof{}, errors.New("original Voice Pod UID remains before query")
		}
		if binding, e := driver.DatastoreBinding(ctx, cfg, h, pod); e != nil || binding != datastore {
			return VoiceCleanupReadProof{}, errors.New("Voice datastore binding drift before query")
		}
		count, e := driver.ReadTranscriptCount(ctx, cfg, pod, sids)
		if e != nil {
			return VoiceCleanupReadProof{}, e
		}
		after, e := driver.Snapshot(ctx, cfg)
		if e != nil {
			return VoiceCleanupReadProof{}, e
		}
		current, e = cleanupReadPod(after, h)
		if e != nil || !reflect.DeepEqual(cleanupAuthority(after), authority) || current.UID != pod.UID {
			return VoiceCleanupReadProof{}, errors.New("Voice cleanup authority drift after query")
		}
		if absent, e := driver.HistoricalPodUIDsAbsent(ctx, cfg, h.TargetPodUID, h.ReplacementPodUID); e != nil || !absent {
			return VoiceCleanupReadProof{}, errors.New("original Voice Pod UID remains after query")
		}
		if binding, e := driver.DatastoreBinding(ctx, cfg, h, pod); e != nil || binding != datastore {
			return VoiceCleanupReadProof{}, errors.New("Voice datastore binding drift after query")
		}
		if count != 0 {
			return VoiceCleanupReadProof{}, fmt.Errorf("owned Voice transcript remains at sample %d", i+1)
		}
		proof.Samples = append(proof.Samples, VoiceCleanupZeroSample{At: time.Now().UTC(), Count: count})
		if i < 2 {
			if e = pause(ctx, 2*time.Second); e != nil {
				return VoiceCleanupReadProof{}, e
			}
		}
	}
	afterSource, err := driver.SourceSHA256(ctx, cfg, pod)
	if err != nil || afterSource != source {
		return VoiceCleanupReadProof{}, errors.New("current Voice source drift")
	}
	closing, err := driver.Snapshot(ctx, cfg)
	if err != nil {
		return VoiceCleanupReadProof{}, err
	}
	closingPod, err := cleanupReadPod(closing, h)
	if err != nil || !reflect.DeepEqual(cleanupAuthority(closing), authority) || closingPod.UID != pod.UID {
		return VoiceCleanupReadProof{}, errors.New("Voice cleanup authority drift after source read")
	}
	if absent, e := driver.HistoricalPodUIDsAbsent(ctx, cfg, h.TargetPodUID, h.ReplacementPodUID); e != nil || !absent {
		return VoiceCleanupReadProof{}, errors.New("original Voice Pod UID remains after source read")
	}
	if binding, e := driver.DatastoreBinding(ctx, cfg, h, pod); e != nil || binding != datastore {
		return VoiceCleanupReadProof{}, errors.New("Voice datastore binding drift after source read")
	}
	return proof, nil
}
