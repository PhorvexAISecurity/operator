package actuator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/statefulrotation"
)

// --- class A: replicated member rebuilt on fresh claims from its peers ---------------------

type replicaRebuildClass struct{}

func (replicaRebuildClass) action() model.Action { return model.ActionStatefulReplicaRebuild }

// prepare marks every claim of the member for deletion (UID-bound). Kubernetes' pvc-protection
// finalizer keeps each claim attached until the member's Pod is gone, so the running member is
// undisturbed until its Eviction; the StatefulSet then recreates the ordinal and its claims from
// the volumeClaimTemplates, and the application re-seeds the fresh member from its peers.
// Admission already proved quorum headroom, a non-leader target and PDB admission (dry run).
func (replicaRebuildClass) prepare(ctx context.Context, ec EnactCtx, op *statefulOperation) (string, error) {
	for _, claim := range op.obs.Claims {
		uid := types.UID(claim.UID)
		pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: op.req.Namespace, Name: claim.Name}}
		if err := ec.Client.Delete(ctx, pvc, client.Preconditions{UID: &uid}); err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
				return "claim " + claim.Name + " changed before deletion", nil
			}
			if apierrors.IsForbidden(err) {
				return "claim deletion permission denied", nil
			}
			return "", fmt.Errorf("delete claim %s: %w", claim.Name, err)
		}
		op.prepared = true
		op.touch("PersistentVolumeClaim", claim.Name)
	}
	op.notes = append(op.notes, fmt.Sprintf("%d claim(s) released for peer resync", len(op.obs.Claims)))
	return "", nil
}

// confirm requires every template claim of the ordinal to be recreated (new UID) and Bound.
// Readiness of the member is the application's own resync signal; catch-up past the readiness
// probe is the owner-declared resync bound, not observed here.
func (replicaRebuildClass) confirm(ctx context.Context, ec EnactCtx, op *statefulOperation, _ *corev1.Pod) (string, bool) {
	for _, claim := range op.obs.Claims {
		fresh := &corev1.PersistentVolumeClaim{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: op.req.Namespace, Name: claim.Name}, fresh); err != nil {
			return "claim " + claim.Name + " not yet recreated", false
		}
		if string(fresh.UID) == claim.UID || !fresh.DeletionTimestamp.IsZero() {
			return "claim " + claim.Name + " still the released volume", false
		}
		if fresh.Status.Phase != corev1.ClaimBound {
			return "claim " + claim.Name + " recreated but not Bound", false
		}
	}
	return "member rebuilt on fresh claims", true
}

// --- class B: single writer restarted behind a ready CSI snapshot ---------------------------

// statefulSnapshotTimeout bounds the wait for every pre-rotation snapshot to be readyToUse.
// Measured on EKS (ebs.csi.aws.com, 1Gi gp2 volumes, 2026-10-29): created within 1s, ready
// after ~60-70s. A slower snapshot stops the dispatch as partial with the member retained; a
// retried dispatch reuses the same snapshot and proceeds once it is ready.
const statefulSnapshotTimeout = 120 * time.Second

type snapshotRotateClass struct{}

func (snapshotRotateClass) action() model.Action { return model.ActionStatefulSnapshotRotate }

// prepare creates one VolumeSnapshot per claim (deterministic name: a retried dispatch reuses
// it) and waits, bounded, for every snapshot to report readyToUse. The member is evicted only
// behind a complete, ready rollback point; snapshots are retained as the restore source.
func (snapshotRotateClass) prepare(ctx context.Context, ec EnactCtx, op *statefulOperation) (string, error) {
	var names []string
	for _, claim := range op.obs.Claims {
		name := statefulSnapshotName(string(op.pod.UID), claim.UID)
		snap := &unstructured.Unstructured{}
		snap.SetGroupVersionKind(statefulrotation.VolumeSnapshotGVK)
		snap.SetNamespace(op.req.Namespace)
		snap.SetName(name)
		snap.SetLabels(map[string]string{labelStatefulRotation: string(model.ActionStatefulSnapshotRotate), labelStatefulTargetUID: string(op.pod.UID)})
		_ = unstructured.SetNestedField(snap.Object, op.obs.Contract.SnapshotClass, "spec", "volumeSnapshotClassName")
		_ = unstructured.SetNestedField(snap.Object, claim.Name, "spec", "source", "persistentVolumeClaimName")
		switch err := ec.Client.Create(ctx, snap); {
		case err == nil:
			op.prepared = true
		case apierrors.IsAlreadyExists(err):
			if why := ownedSnapshot(ctx, ec, op, name, claim.Name); why != "" {
				return why, nil
			}
		case apierrors.IsForbidden(err):
			return "snapshot creation permission denied", nil
		case apierrors.IsNotFound(err):
			return "volume snapshot API unavailable", nil
		default:
			return "", fmt.Errorf("create snapshot of %s: %w", claim.Name, err)
		}
		op.touch("VolumeSnapshot", name)
		names = append(names, objRef("VolumeSnapshot", op.req.Namespace, name))
	}
	op.rollbackRef = strings.Join(names, ",")
	timeout := statefulSnapshotTimeout
	if ec.StatefulSnapshotTimeout > 0 {
		timeout = ec.StatefulSnapshotTimeout
	}
	interval := statefulConfirmInterval
	if ec.StatefulConfirmInterval > 0 {
		interval = ec.StatefulConfirmInterval
	}
	deadline := time.Now().Add(timeout)
	for _, claim := range op.obs.Claims {
		name := statefulSnapshotName(string(op.pod.UID), claim.UID)
		for {
			ready, failure, readErr := snapshotReady(ctx, ec, op.req.Namespace, name)
			if failure != "" {
				return "snapshot " + name + " failed: " + failure, nil
			}
			if ready {
				break
			}
			if !time.Now().Before(deadline) {
				why := "snapshot " + name + " not ready within " + timeout.String()
				if readErr != nil {
					why += " (last read error: " + readErr.Error() + ")"
				}
				return why, nil
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(interval):
			}
		}
	}
	op.notes = append(op.notes, fmt.Sprintf("%d ready snapshot(s) retained as rollback point", len(op.obs.Claims)))
	return "", nil
}

// confirm requires the replacement to have reattached the exact same claims.
func (snapshotRotateClass) confirm(ctx context.Context, ec EnactCtx, op *statefulOperation, _ *corev1.Pod) (string, bool) {
	for _, claim := range op.obs.Claims {
		current := &corev1.PersistentVolumeClaim{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: op.req.Namespace, Name: claim.Name}, current); err != nil ||
			string(current.UID) != claim.UID || current.Status.Phase != corev1.ClaimBound {
			return "claim " + claim.Name + " not reattached", false
		}
	}
	return "same claims reattached", true
}

const (
	labelStatefulRotation  = "phorvex.ai/stateful-rotation"
	labelStatefulTargetUID = "phorvex.ai/stateful-target-uid"
)

// statefulSnapshotName is deterministic per (Pod UID, claim UID) so a retry reuses the
// snapshot instead of multiplying them.
func statefulSnapshotName(podUID, claimUID string) string {
	sum := sha256.Sum256([]byte(podUID + "/" + claimUID))
	return "phorvex-pre-rotate-" + hex.EncodeToString(sum[:8])
}

// ownedSnapshot accepts an existing snapshot only if this exact operation created it.
func ownedSnapshot(ctx context.Context, ec EnactCtx, op *statefulOperation, name, claim string) string {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(statefulrotation.VolumeSnapshotGVK)
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: op.req.Namespace, Name: name}, existing); err != nil {
		return "existing snapshot " + name + " unreadable"
	}
	source, _, _ := unstructured.NestedString(existing.Object, "spec", "source", "persistentVolumeClaimName")
	if existing.GetLabels()[labelStatefulTargetUID] != string(op.pod.UID) || source != claim {
		return "snapshot name " + name + " is held by another object"
	}
	return ""
}

// snapshotReady reads one snapshot's readiness. A read error is returned separately so the
// caller keeps polling through a transient failure but can name it if the wait expires.
func snapshotReady(ctx context.Context, ec EnactCtx, namespace, name string) (bool, string, error) {
	snap := &unstructured.Unstructured{}
	snap.SetGroupVersionKind(statefulrotation.VolumeSnapshotGVK)
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, snap); err != nil {
		return false, "", err
	}
	if message, found, _ := unstructured.NestedString(snap.Object, "status", "error", "message"); found && message != "" {
		return false, message, nil
	}
	ready, _, _ := unstructured.NestedBool(snap.Object, "status", "readyToUse")
	return ready, "", nil
}

// --- class C: volume-less state handed over through an application checkpoint --------------

type checkpointHandoffClass struct{}

func (checkpointHandoffClass) action() model.Action { return model.ActionStatefulCheckpointHandoff }

// statefulCheckpoint is the application's checkpoint acknowledgement.
type statefulCheckpoint struct {
	ID     string `json:"checkpointId"`
	SHA256 string `json:"sha256"`
}

var checkpointIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (c statefulCheckpoint) valid() bool {
	return checkpointIDPattern.MatchString(c.ID) && sha256Pattern.MatchString(c.SHA256)
}

// prepare asks the application to commit its state to its declared durable store. Nothing in
// the cluster changes, so a failed checkpoint is a clean refusal and the member keeps running.
func (checkpointHandoffClass) prepare(ctx context.Context, ec EnactCtx, op *statefulOperation) (string, error) {
	c := op.obs.Contract
	ack, why := checkpointCall(ctx, ec, op.pod, http.MethodPost, c.CheckpointPort, c.CheckpointPath)
	if why != "" {
		return "checkpoint " + why, nil
	}
	op.checkpoint = ack
	op.notes = append(op.notes, "checkpoint "+ack.ID+" committed ("+ack.SHA256[:12]+")")
	return "", nil
}

// confirm requires the replacement to report that it restored the exact checkpoint digest.
func (checkpointHandoffClass) confirm(ctx context.Context, ec EnactCtx, op *statefulOperation, replacement *corev1.Pod) (string, bool) {
	c := op.obs.Contract
	restored, why := checkpointCall(ctx, ec, replacement, http.MethodGet, c.CheckpointPort, c.RestorePath)
	if why != "" {
		return "restore status " + why, false
	}
	if restored != op.checkpoint {
		return "replacement restored a different checkpoint", false
	}
	return "checkpoint " + restored.ID + " restored", true
}

// checkpointCall performs one bounded request to the exact Pod IP. The response is treated
// as untrusted data: only a well-formed (id, sha256) pair is accepted.
func checkpointCall(ctx context.Context, ec EnactCtx, pod *corev1.Pod, method string, port int, path string) (statefulCheckpoint, string) {
	if net.ParseIP(pod.Status.PodIP) == nil {
		return statefulCheckpoint{}, "target Pod IP unavailable"
	}
	transport := ec.StatefulCheckpointTransport
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true}
	}
	hc := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	}}
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewReader([]byte(`{"podUID":"` + string(pod.UID) + `"}`))
	}
	url := "http://" + net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(port)) + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return statefulCheckpoint{}, "request invalid"
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return statefulCheckpoint{}, "endpoint unreachable"
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || resp.StatusCode != http.StatusOK {
		return statefulCheckpoint{}, fmt.Sprintf("endpoint returned %d", resp.StatusCode)
	}
	var ack statefulCheckpoint
	if json.Unmarshal(raw, &ack) != nil || !ack.valid() {
		return statefulCheckpoint{}, "response malformed"
	}
	return ack, ""
}
