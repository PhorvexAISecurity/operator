package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (w *newstackRuntime) evidence(name string, value any) error {
	if name == "" || strings.Contains(name, "/") {
		return errors.New("evidence name invalid")
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(raw) > 1<<20 {
		return errors.New("evidence exceeds bound")
	}
	dir := filepath.Join(w.server.cfg.StateDir, "newstack", w.run.RunID)
	file, err := os.CreateTemp(dir, "evidence-*.tmp")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
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
	if err = os.Rename(path, filepath.Join(dir, name)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func newstackCleanupRefAllowed(ref newstackObject, run *newstackRun, item newstackCase) bool {
	name := newstackResourceName(item, run)
	if ref.Namespace == "" {
		return ref.Kind == "SecurityEvent" && ref.APIVersion == "amtd.r6security.com/v1beta1" && ref.Name == "newstack-event-"+strings.TrimPrefix(run.RunID, "ns-")
	}
	if ref.Namespace != newstackNamespace {
		return false
	}
	switch ref.Kind {
	case "Deployment":
		return ref.APIVersion == "apps/v1" && ref.Name == name
	case "Service":
		return ref.APIVersion == "v1" && ref.Name == name
	case "PodDisruptionBudget":
		return ref.APIVersion == "policy/v1" && ref.Name == name
	case "PhorvexPolicy":
		return ref.APIVersion == "phorvex.ai/v1alpha1" && ref.Name == name+"-defense"
	case "ConfigMap":
		return ref.APIVersion == "v1" && (ref.Name == name+"-fixture" || (item.Fixture == "crm-refund" && ref.Name == "crm-refund-guard"))
	}
	return false
}

func (w *newstackRuntime) cleanup(ctx context.Context) error {
	item, ok := newstackCaseByID(w.run.CaseID)
	if !ok || !newstackIDPattern.MatchString(w.run.RunID) || w.run.Namespace != newstackNamespace || len(w.run.Objects) > 8 {
		return errors.New("retained cleanup identity invalid")
	}
	lock := &corev1.ConfigMap{}
	if err := w.kube.Get(ctx, client.ObjectKey{Namespace: newstackNamespace, Name: newstackLaneName}, lock); err != nil || !newstackOwned(lock, w.run) || string(lock.UID) != w.run.LockUID || lock.Data["runId"] != w.run.RunID || lock.Data["caseId"] != item.ID {
		return errors.New("shared lane UID or run ownership changed")
	}
	w.run.CleanupComplete = false
	w.run.PostflightClean = false
	if err := w.savePhase("cleanup"); err != nil {
		return errors.New("cleanup intent persistence unavailable")
	}
	for _, ref := range w.run.Objects {
		if !newstackCleanupRefAllowed(ref, w.run, item) {
			return errors.New("cleanup object lies outside exact fixture plan")
		}
	}
	// Remove signal and selecting policy before their disposable target. Deleting
	// the Deployment lets Kubernetes garbage collection remove its children;
	// this runner has no Pod delete or eviction permission.
	for _, kind := range []string{"SecurityEvent", "PhorvexPolicy", "Deployment", "PodDisruptionBudget", "Service", "ConfigMap"} {
		for i := range w.run.Objects {
			if w.run.Objects[i].Kind != kind {
				continue
			}
			if err := w.cleanupObject(ctx, &w.run.Objects[i]); err != nil {
				return err
			}
		}
	}
	if err := newstackWait(ctx, time.Second, func() (bool, error) { return w.postflight(ctx, item) }); err != nil {
		return errors.New("postflight still sees fixture resources or cannot verify their absence")
	}
	w.run.CleanupComplete = false
	w.run.PostflightClean = true
	if err := w.savePhase("postflight-clean"); err != nil {
		return errors.New("postflight persistence unavailable")
	}
	// Retain the shared lane on every uncertain deletion/persistence failure. An
	// exact later cleanup can reconcile it; an unrelated run can never steal it.
	latest := &corev1.ConfigMap{}
	if err := w.kube.Get(ctx, client.ObjectKey{Namespace: newstackNamespace, Name: newstackLaneName}, latest); err != nil || !newstackOwned(latest, w.run) || string(latest.UID) != w.run.LockUID {
		return errors.New("shared lane changed before release")
	}
	uid, rv := latest.UID, latest.ResourceVersion
	if err := w.kube.Delete(ctx, latest, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
		return errors.New("shared lane release unavailable")
	}
	if err := newstackWait(ctx, 200*time.Millisecond, func() (bool, error) {
		current := &corev1.ConfigMap{}
		err := w.kube.Get(ctx, client.ObjectKey{Namespace: newstackNamespace, Name: newstackLaneName}, current)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	}); err != nil {
		return errors.New("shared lane release not confirmed")
	}
	w.run.CleanupComplete = true
	return w.savePhase("cleanup-complete")
}

func (w *newstackRuntime) cleanupObject(ctx context.Context, ref *newstackObject) error {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
	key := client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
	err := w.kube.Get(ctx, key, object)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return errors.New("cleanup exact object read unavailable")
	}
	if !newstackOwned(object, w.run) || (ref.UID != "" && string(object.GetUID()) != ref.UID) || object.GetUID() == "" {
		return fmt.Errorf("cleanup refuses changed ownership or UID of %s %s", ref.Kind, ref.Name)
	}
	// A lost CREATE acknowledgement is reconciled only against the pre-written
	// exact name and nonce; persist its discovered UID before the guarded delete.
	if ref.UID == "" {
		ref.UID = string(object.GetUID())
		if err = w.server.newstackSave(w.run); err != nil {
			return errors.New("reconciled cleanup UID persistence unavailable")
		}
	}
	uid, rv := object.GetUID(), object.GetResourceVersion()
	foreground := metav1.DeletePropagationForeground
	if object.GetDeletionTimestamp() == nil {
		if err = w.kube.Delete(ctx, object, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &foreground}); err != nil && !apierrors.IsNotFound(err) {
			return errors.New("cleanup UID-guarded delete unavailable")
		}
	}
	return newstackWait(ctx, 500*time.Millisecond, func() (bool, error) {
		current := &unstructured.Unstructured{}
		current.SetGroupVersionKind(object.GroupVersionKind())
		err := w.kube.Get(ctx, key, current)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, errors.New("cleanup disappearance read unavailable")
		}
		if string(current.GetUID()) != ref.UID {
			return false, errors.New("cleanup name replaced by another UID")
		}
		return false, nil
	})
}

func (w *newstackRuntime) postflight(ctx context.Context, item newstackCase) (bool, error) {
	for _, ref := range w.run.Objects {
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
		err := w.kube.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, object)
		if err == nil {
			return false, nil
		}
		if !apierrors.IsNotFound(err) {
			return false, err
		}
	}
	var pods corev1.PodList
	if err := w.kube.List(ctx, &pods, client.InNamespace(newstackNamespace), client.MatchingLabels{newstackRunLabel: w.run.RunID}); err != nil {
		return false, err
	}
	if len(pods.Items) > 0 {
		return false, nil
	}
	var replicas appsv1.ReplicaSetList
	if err := w.kube.List(ctx, &replicas, client.InNamespace(newstackNamespace), client.MatchingLabels{newstackRunLabel: w.run.RunID}); err != nil {
		return false, err
	}
	if len(replicas.Items) > 0 {
		return false, nil
	}
	var slices discoveryv1.EndpointSliceList
	if err := w.kube.List(ctx, &slices, client.InNamespace(newstackNamespace), client.MatchingLabels{discoveryv1.LabelServiceName: newstackResourceName(item, w.run)}); err != nil {
		return false, err
	}
	if len(slices.Items) > 0 {
		return false, nil
	}
	return true, nil
}

// An empty lane is not evidence of cleanup if labelled fixture objects remain.
// This query never removes orphaned or unrecorded objects.
func (w *newstackRuntime) orphans(ctx context.Context, item newstackCase) (bool, error) {
	for _, gvk := range []schema.GroupVersionKind{
		{Group: "", Version: "v1", Kind: "ConfigMapList"}, {Group: "", Version: "v1", Kind: "ServiceList"}, {Group: "", Version: "v1", Kind: "PodList"},
		{Group: "apps", Version: "v1", Kind: "DeploymentList"}, {Group: "apps", Version: "v1", Kind: "ReplicaSetList"},
		{Group: "policy", Version: "v1", Kind: "PodDisruptionBudgetList"}, {Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicyList"},
		{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEventList"},
	} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk)
		options := []client.ListOption{client.MatchingLabels{newstackFixtureLabel: item.Fixture}}
		if gvk.Kind != "SecurityEventList" {
			options = append(options, client.InNamespace(newstackNamespace))
		}
		if err := w.kube.List(ctx, list, options...); err != nil {
			return false, err
		}
		if len(list.Items) > 0 {
			return false, nil
		}
	}
	return true, nil
}
