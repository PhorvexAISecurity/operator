package scenarios

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
)

// TestCheckpointLocalSixSlotsRunFullLifecycleAndDurableServer is the six-slot
// discriminator from the signed lifecycle decision. Each arm/trial executes the
// real scenario Setup and Teardown, then the real generic closer. Separately,
// the exact embedded checkpoint server writes and reloads each distinct slot's
// durable bytes so checksum, acknowledged high-water and post-boot progress are
// exercised rather than inferred from object construction.
func TestCheckpointLocalSixSlotsRunFullLifecycleAndDurableServer(t *testing.T) {
	env, client, slotZero := checkpointLocalSetupEnv(t)
	ctx := context.Background()
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: env.Config.Namespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// The single-slot helper includes a pre-existing controller fixture for its
	// setup tests. This test creates the exact controller chain independently for
	// every slot.
	_ = client.CoreV1().Pods(env.Config.Namespace).Delete(ctx, "target-pod", metav1.DeleteOptions{})
	_ = client.AppsV1().ReplicaSets(env.Config.Namespace).Delete(ctx, "checkpoint-rs", metav1.DeleteOptions{})

	arms := []struct {
		defender string
		trial    int
	}{{"d-nomtd", 0}, {"d-nomtd", 1}, {"d-nomtd", 2}, {"d-r6blindtimer", 0}, {"d-r6blindtimer", 1}, {"d-r6blindtimer", 2}}
	holderUID := types.UID(env.Config.BenignCheckpointLocalHolderUID)
	for slot, arm := range arms {
		if slot == 0 {
			continue
		}
		pv := slotZero.DeepCopy()
		pv.Name = fmt.Sprintf("checkpoint-local-%d", slot)
		pv.UID = types.UID(fmt.Sprintf("pv-local-uid-%d", slot))
		pv.Labels = checkpointLocalSelector(arm.defender, arm.trial, slot)
		pv.Annotations["fixture.phorvex.ai/slot"] = fmt.Sprint(slot)
		path := checkpointLocalPath(holderUID, slot)
		pv.Annotations["fixture.phorvex.ai/local-path-sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(path)))
		pv.Spec.Local.Path = path
		pv.Spec.ClaimRef = nil
		pv.Status.Phase = corev1.VolumeAvailable
		if _, err := client.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	client.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateAction)
		slot, err := checkpointLocalAssignment(env.DefenderName, env.Trial)
		if err != nil {
			return true, nil, err
		}
		switch obj := create.GetObject().(type) {
		case *corev1.PersistentVolumeClaim:
			pending := obj.DeepCopy()
			pending.UID = types.UID(fmt.Sprintf("pvc-uid-%d", slot))
			pending.Status.Phase = corev1.ClaimPending
			bound := pending.DeepCopy()
			bound.Status.Phase = corev1.ClaimBound
			if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("persistentvolumeclaims"), bound, env.Config.Namespace); err != nil {
				return true, nil, err
			}
			pvName := fmt.Sprintf("checkpoint-local-%d", slot)
			current, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("persistentvolumes"), "", pvName)
			if err != nil {
				return true, nil, err
			}
			pv := current.(*corev1.PersistentVolume).DeepCopy()
			pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: env.Config.Namespace, Name: checkpointPVC, UID: pending.UID}
			pv.Status.Phase = corev1.VolumeBound
			if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("persistentvolumes"), pv, ""); err != nil {
				return true, nil, err
			}
			return true, pending, nil
		case *appsv1.Deployment:
			obj.UID = types.UID(fmt.Sprintf("deployment-uid-%d", slot))
		case *corev1.Service:
			obj.UID = types.UID(fmt.Sprintf("service-uid-%d", slot))
		case *corev1.Pod:
			if obj.Name == checkpointProducer {
				obj.UID = types.UID(fmt.Sprintf("producer-uid-%d", slot))
				obj.Status.Phase = corev1.PodRunning
				obj.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
				obj.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "producer", Ready: true}}
			}
		}
		return false, nil, nil
	})

	seenPaths := map[string]bool{}
	stateRoot := t.TempDir()
	for slot, arm := range arms {
		t.Run(fmt.Sprintf("slot-%d-%s-trial-%d", slot, arm.defender, arm.trial), func(t *testing.T) {
			env.DefenderName, env.Trial = arm.defender, arm.trial
			depUID := types.UID(fmt.Sprintf("deployment-uid-%d", slot))
			rsUID := types.UID(fmt.Sprintf("replicaset-uid-%d", slot))
			targetUID := types.UID(fmt.Sprintf("target-uid-%d", slot))
			controller := true
			rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("checkpoint-rs-%d", slot), Namespace: env.Config.Namespace, UID: rsUID, Labels: env.OwnedLabels(nil), OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: checkpointApp, UID: depUID, Controller: &controller}}}}
			if _, err := client.AppsV1().ReplicaSets(env.Config.Namespace).Create(ctx, rs, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			target := sessionFixturePod(checkpointApp, checkpointApp, targetUID, false, true)
			target.Name = fmt.Sprintf("checkpoint-target-%d", slot)
			target.Namespace = env.Config.Namespace
			target.Labels = env.OwnedLabels(map[string]string{"app": checkpointApp})
			target.Spec.NodeName = "reviewed-node"
			bindCheckpointFixturePod(target)
			target.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}
			createSessionFixturePod(t, env, target)

			scenario := &c2CheckpointContinuity{}
			setupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := scenario.Setup(setupCtx, env)
			cancel()
			if err != nil {
				t.Fatalf("Setup: %v", err)
			}
			wantPath := checkpointLocalPath(holderUID, slot)
			if scenario.localSlot != slot || scenario.localPath != wantPath || scenario.localHolderUID != holderUID {
				t.Fatalf("slot binding=%+v want slot=%d path=%s holder=%s", scenario, slot, wantPath, holderUID)
			}
			if seenPaths[scenario.localPath] {
				t.Fatalf("local path reused: %s", scenario.localPath)
			}
			seenPaths[scenario.localPath] = true

			stateDir := filepath.Join(stateRoot, fmt.Sprintf("slot-%d", slot))
			if err := os.Mkdir(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			original := startCheckpointServer(t, stateDir, port, string(scenario.targetUID), string(scenario.pvcUID), "")
			originalStopped := false
			t.Cleanup(func() {
				if !originalStopped {
					stopCheckpointServer(t, original)
				}
			})
			first := waitCheckpointHTTP(t, port, func(body checkpointBody) bool { return body.Sequence >= 1 })
			ack := waitCheckpointHTTP(t, port, func(body checkpointBody) bool { return body.Sequence > first.Sequence })
			if err := validateCheckpointIdentity(ack, scenario.targetUID, scenario.pvcUID); err != nil {
				t.Fatalf("original acknowledgement: %v", err)
			}
			stopCheckpointServer(t, original)
			originalStopped = true

			replacementUID := types.UID(fmt.Sprintf("replacement-uid-%d", slot))
			replacement := startCheckpointServer(t, stateDir, port, string(replacementUID), string(scenario.pvcUID), "")
			replacementStopped := false
			t.Cleanup(func() {
				if !replacementStopped {
					stopCheckpointServer(t, replacement)
				}
			})
			reloaded := waitCheckpointHTTP(t, port, func(body checkpointBody) bool { return body.Sequence > body.BootSequence })
			if err := validateCheckpointIdentity(reloaded, replacementUID, scenario.pvcUID); err != nil {
				t.Fatalf("replacement acknowledgement: %v", err)
			}
			if err := validateCheckpointReplacement(reloaded, ack, ack.Incarnation, true); err != nil {
				t.Fatalf("replacement high-water: %v", err)
			}
			stopCheckpointServer(t, replacement)
			replacementStopped = true

			if err := scenario.Teardown(ctx, env); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			// Leave one actual generic-owned Service for the real per-trial
			// closer, so this is not an empty cleanup call.
			residue := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("closer-residue-%d", slot), Namespace: env.Config.Namespace, Labels: env.OwnedLabels(nil)}}
			if _, err := client.CoreV1().Services(env.Config.Namespace).Create(ctx, residue, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 5*time.Second)
			err = env.CleanupOwned(cleanupCtx, false)
			cleanupCancel()
			if err != nil {
				t.Fatalf("CleanupOwned(false): %v", err)
			}
			if _, err := client.CoreV1().Services(env.Config.Namespace).Get(ctx, residue.Name, metav1.GetOptions{}); err == nil {
				t.Fatal("per-trial closer left generic-owned residue")
			}
			holder, err := client.CoreV1().Pods(env.Config.Namespace).Get(ctx, checkpointLocalHolder, metav1.GetOptions{})
			if err != nil || holder.UID != holderUID {
				t.Fatalf("external holder continuity lost: holder=%v err=%v", holder, err)
			}
			if _, err := client.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{}); err != nil {
				t.Fatalf("namespace continuity lost: %v", err)
			}
		})
	}
	if len(seenPaths) != 6 {
		t.Fatalf("distinct local paths=%d want 6", len(seenPaths))
	}
}
