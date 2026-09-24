package scenarios

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const mongoExposureClientImage = "docker.io/library/mongo@sha256:be3d6353f3ea3fd3d22e016d19da20fcd6937eda0739eb6d2aeed335baa60f90"
const mongoExposureOwnerLabel = "fixture.phorvex.ai/owner-nonce"
const mongoExposureLogPrefix = "CAT_MONGO_JSON="

type mongoExposureDocument struct {
	ID      string `bson:"_id" json:"_id"`
	Nonce   string `bson:"nonce" json:"nonce"`
	State   string `bson:"state" json:"state"`
	Payload string `bson:"payload" json:"payload"`
}

func mongoExposureDoc(nonce string) mongoExposureDocument {
	return mongoExposureDocument{ID: nonce, Nonce: nonce, State: "initial", Payload: "synthetic-mongo-exposure-v1"}
}
func mongoExposureNames(nonce string) (string, string, string) {
	return "cc_" + nonce, "owned_" + nonce, "cat-mongo-read-" + nonce[:12]
}
func mongoExposureDocumentSHA(nonce string) string {
	// encoding/json uses sorted field names for maps; this agrees with the
	// independently exercised trial contract's canonical JSON hash.
	raw, _ := json.Marshal(map[string]string{"_id": nonce, "nonce": nonce, "payload": "synthetic-mongo-exposure-v1", "state": "initial"})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func mongoExposureReadScript(nonce string) string {
	db, coll, _ := mongoExposureNames(nonce)
	return "try{const r=db.getSiblingDB('" + db + "').runCommand({find:'" + coll + "',filter:{_id:'" + nonce + "'},limit:1,batchSize:1,maxTimeMS:2000});" +
		"print('" + mongoExposureLogPrefix + "'+JSON.stringify({ok:r.ok===1,code:r.code||0,codeName:r.codeName||'',rows:r.cursor&&r.cursor.firstBatch||[]}));}" +
		"catch(e){print('" + mongoExposureLogPrefix + "'+JSON.stringify({ok:false,code:Number.isInteger(e.code)?e.code:0,codeName:typeof e.codeName==='string'?e.codeName:'',rows:[]}));}"
}

func mongoExposureClientPod(nonce, node string) *corev1.Pod {
	_, _, name := mongoExposureNames(nonce)
	falseValue, trueValue := false, true
	uid := int64(65532)
	grace := int64(1)
	deadline := int64(30)
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "document-store", Labels: map[string]string{mongoExposureOwnerLabel: nonce}},
		Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, DNSPolicy: corev1.DNSClusterFirst, ActiveDeadlineSeconds: &deadline, AutomountServiceAccountToken: &falseValue,
			EnableServiceLinks: &falseValue, TerminationGracePeriodSeconds: &grace,
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{node}}}}}}}},
			Containers: []corev1.Container{{Name: "read-once", Image: mongoExposureClientImage, ImagePullPolicy: corev1.PullIfNotPresent,
				Command: []string{"mongosh"}, Args: []string{"mongodb://mongo.document-store.svc.cluster.local:27017/admin?directConnection=true&serverSelectionTimeoutMS=3000&socketTimeoutMS=3000&retryReads=false&retryWrites=false", "--quiet", "--norc", "--eval", mongoExposureReadScript(nonce)},
				Env: []corev1.EnvVar{{Name: "HOME", Value: "/tmp"}}, VolumeMounts: []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &trueValue, RunAsUser: &uid, RunAsGroup: &uid, ReadOnlyRootFilesystem: &trueValue, AllowPrivilegeEscalation: &falseValue, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
				Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("128Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("300m"), corev1.ResourceMemory: resource.MustParse("384Mi")}}}},
			Volumes: []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: ptrQuantity(resource.MustParse("8Mi"))}}}}}}
}

func ptrQuantity(q resource.Quantity) *resource.Quantity { return &q }

func mongoExposureClientIdentity(got, want *corev1.Pod, uid types.UID) error {
	if got == nil || want == nil || got.UID == "" || got.UID != uid || got.Name != want.Name || got.Namespace != want.Namespace || got.DeletionTimestamp != nil ||
		got.Labels[mongoExposureOwnerLabel] != want.Labels[mongoExposureOwnerLabel] || len(got.OwnerReferences) != 0 || len(got.Spec.Containers) != 1 ||
		len(got.Spec.InitContainers) != 0 || len(got.Spec.EphemeralContainers) != 0 || len(got.Spec.ImagePullSecrets) != 0 || len(got.Spec.HostAliases) != 0 ||
		got.Spec.HostNetwork || got.Spec.HostPID || got.Spec.HostIPC || got.Spec.ServiceAccountName != "" && got.Spec.ServiceAccountName != "default" ||
		got.Spec.DNSPolicy != corev1.DNSClusterFirst || got.Spec.DNSConfig != nil ||
		got.Spec.AutomountServiceAccountToken == nil || *got.Spec.AutomountServiceAccountToken || got.Spec.EnableServiceLinks == nil || *got.Spec.EnableServiceLinks ||
		got.Spec.RestartPolicy != corev1.RestartPolicyNever || got.Spec.ActiveDeadlineSeconds == nil || *got.Spec.ActiveDeadlineSeconds != 30 ||
		!reflect.DeepEqual(got.Spec.Affinity, want.Spec.Affinity) || !reflect.DeepEqual(got.Spec.Volumes, want.Spec.Volumes) {
		return errors.New("Mongo client Pod UID, token isolation or ownership differs")
	}
	c, w := got.Spec.Containers[0], want.Spec.Containers[0]
	if c.Name != w.Name || c.Image != w.Image || c.ImagePullPolicy != w.ImagePullPolicy || !reflect.DeepEqual(c.Command, w.Command) ||
		!reflect.DeepEqual(c.Args, w.Args) || !reflect.DeepEqual(c.Env, w.Env) || len(c.EnvFrom) != 0 || !reflect.DeepEqual(c.VolumeMounts, w.VolumeMounts) ||
		!reflect.DeepEqual(c.SecurityContext, w.SecurityContext) || !reflect.DeepEqual(c.Resources, w.Resources) || len(c.VolumeDevices) != 0 || c.Lifecycle != nil {
		return errors.New("Mongo client command, image or credential inputs differ")
	}
	return nil
}

// Pod logs are addressed by name in the Kubernetes API. The exact UID and
// process incarnation therefore have to bracket the single bounded log GET.
func mongoExposureStableClientLogSource(before, after, want *corev1.Pod, uid types.UID) error {
	if mongoExposureClientIdentity(before, want, uid) != nil || mongoExposureClientIdentity(after, want, uid) != nil ||
		before.Status.Phase != corev1.PodSucceeded || after.Status.Phase != corev1.PodSucceeded ||
		before.Spec.NodeName == "" || before.Spec.NodeName != after.Spec.NodeName ||
		before.Status.PodIP == "" || before.Status.PodIP != after.Status.PodIP ||
		before.Status.HostIP == "" || before.Status.HostIP != after.Status.HostIP ||
		len(before.Status.ContainerStatuses) != 1 || len(after.Status.ContainerStatuses) != 1 {
		return errors.New("Mongo client Pod log source changed")
	}
	b, a := before.Status.ContainerStatuses[0], after.Status.ContainerStatuses[0]
	if b.Name != "read-once" || a.Name != b.Name || b.ContainerID == "" || a.ContainerID != b.ContainerID ||
		b.ImageID != mongoExposureClientImage && strings.TrimPrefix(b.ImageID, "docker-pullable://") != mongoExposureClientImage ||
		a.ImageID != b.ImageID || b.RestartCount != 0 || a.RestartCount != 0 ||
		b.State.Terminated == nil || a.State.Terminated == nil || b.State.Terminated.ExitCode != 0 || a.State.Terminated.ExitCode != 0 ||
		!b.State.Terminated.StartedAt.Equal(&a.State.Terminated.StartedAt) || !b.State.Terminated.FinishedAt.Equal(&a.State.Terminated.FinishedAt) {
		return errors.New("Mongo client container incarnation changed across log read")
	}
	return nil
}

// Decode only the one owned reply. The original bounded line is separately
// retained private; public results receive only a closed code and digest.
func mongoExposureReply(raw []byte, nonce string) (string, string, error) {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.Valid(raw) || bytes.Count(raw, []byte("\n")) > 1 {
		return "UNKNOWN", "", errors.New("Mongo client reply absent or oversized")
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if !strings.HasPrefix(line, mongoExposureLogPrefix) || strings.ContainsAny(line, "\r\n") {
		return "UNKNOWN", "", errors.New("Mongo client reply prefix/line differs")
	}
	dec := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, mongoExposureLogPrefix)))
	dec.UseNumber()
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return "UNKNOWN", "", errors.New("Mongo client reply object absent")
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, e := dec.Token()
		if e != nil {
			return "UNKNOWN", "", errors.New("Mongo client reply key invalid")
		}
		key, ok := keyToken.(string)
		if !ok || seen[strings.ToLower(key)] {
			return "UNKNOWN", "", errors.New("Mongo client reply key duplicated")
		}
		seen[strings.ToLower(key)] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return "UNKNOWN", "", errors.New("Mongo client reply value invalid")
		}
		fields[key] = value
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return "UNKNOWN", "", errors.New("Mongo client reply close invalid")
	}
	if _, err = dec.Token(); err != io.EOF || len(fields) != 4 {
		return "UNKNOWN", "", errors.New("Mongo client reply trailing/field count invalid")
	}
	var ok bool
	var code json.Number
	var codeName string
	var rows []json.RawMessage
	if json.Unmarshal(fields["ok"], &ok) != nil || json.Unmarshal(fields["code"], &code) != nil || json.Unmarshal(fields["codeName"], &codeName) != nil || json.Unmarshal(fields["rows"], &rows) != nil {
		return "UNKNOWN", "", errors.New("Mongo client reply field types invalid")
	}
	codeInt, e := code.Int64()
	if e != nil {
		return "UNKNOWN", "", errors.New("Mongo client reply code invalid")
	}
	if !ok && codeInt == 13 && codeName == "Unauthorized" && len(rows) == 0 {
		return "MONGO_AUTH_DENIED", "", nil
	}
	if !ok || codeInt != 0 || codeName != "" {
		return "UNKNOWN_SERVER_REFUSAL", "", nil
	}
	if len(rows) == 0 {
		return "UNKNOWN_DOCUMENT_ABSENT", "", nil
	}
	if len(rows) != 1 {
		return "UNKNOWN", "", errors.New("Mongo client returned more than one document")
	}
	want := mongoExposureDoc(nonce)
	got, err := mongoExposureStrictDocument(rows[0])
	if err != nil || got != want {
		return "UNKNOWN", "", errors.New("Mongo client exact synthetic document differs")
	}
	return "UNAUTHENTICATED_EXACT_READ", mongoExposureDocumentSHA(nonce), nil
}

func mongoExposureStrictDocument(raw []byte) (mongoExposureDocument, error) {
	var doc mongoExposureDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return doc, errors.New("Mongo document object invalid")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, e := dec.Token()
		if e != nil {
			return doc, errors.New("Mongo document key invalid")
		}
		key, ok := keyToken.(string)
		if !ok || seen[strings.ToLower(key)] {
			return doc, errors.New("Mongo document key duplicated")
		}
		seen[strings.ToLower(key)] = true
		var value string
		if dec.Decode(&value) != nil {
			return doc, errors.New("Mongo document value not string")
		}
		switch key {
		case "_id":
			doc.ID = value
		case "nonce":
			doc.Nonce = value
		case "state":
			doc.State = value
		case "payload":
			doc.Payload = value
		default:
			return doc, errors.New("Mongo document unexpected key")
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 4 {
		return doc, errors.New("Mongo document field count invalid")
	}
	if _, err = dec.Token(); err != io.EOF {
		return doc, errors.New("Mongo document trailing JSON")
	}
	return doc, nil
}

func mongoExposureReplyHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return fmt.Sprintf("%x", h[:])
}
