package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/phorvex/phorvex/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const warmPoolMaxMembers = 128

// warmPoolIntent is a point-in-time snapshot persisted before any serving mutation.
// Member UIDs never authorize a mutation of a replacement Pod.
type warmPoolIntent struct {
	RSName              string   `json:"rsName"`
	RSUID               string   `json:"rsUID"`
	RSGeneration        int64    `json:"rsGeneration"`
	Desired             int32    `json:"desired"`
	RSTemplateHash      string   `json:"rsTemplateHash"`
	RSSelectorHash      string   `json:"rsSelectorHash"`
	ParentName          string   `json:"parentName,omitempty"`
	ParentUID           string   `json:"parentUID,omitempty"`
	ServiceName         string   `json:"serviceName"`
	ServiceUID          string   `json:"serviceUID"`
	ServiceSelectorHash string   `json:"serviceSelectorHash"`
	Members             []string `json:"members"`
}

func hashWarmObject(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

func controllingRS(p *corev1.Pod) (*metav1.OwnerReference, error) {
	if p == nil || len(p.OwnerReferences) != 1 {
		return nil, fmt.Errorf("warm pool pod requires exactly one owner reference")
	}
	o := metav1.GetControllerOf(p)
	if o == nil || o.APIVersion != "apps/v1" || o.Kind != "ReplicaSet" || o.UID == "" || o.Name == "" {
		return nil, fmt.Errorf("warm pool pod lacks controlling apps/v1 ReplicaSet")
	}
	return o, nil
}

func warmPoolSelector(rs *appsv1.ReplicaSet, groupKey, groupValue string) (labels.Selector, error) {
	if rs.Spec.Selector == nil || rs.Spec.Selector.MatchLabels == nil {
		return nil, fmt.Errorf("warm pool ReplicaSet selector unavailable")
	}
	for _, key := range []string{labelRole, labelModelLoaded} {
		if _, ok := rs.Spec.Selector.MatchLabels[key]; ok {
			return nil, fmt.Errorf("warm pool selector uses mutable label %s", key)
		}
	}
	for _, e := range rs.Spec.Selector.MatchExpressions {
		if e.Key == labelRole || e.Key == labelModelLoaded {
			return nil, fmt.Errorf("warm pool selector uses mutable label %s", e.Key)
		}
	}
	sel, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector)
	if err != nil || sel.Empty() {
		return nil, fmt.Errorf("warm pool selector invalid: %v", err)
	}
	if !sel.Matches(labels.Set(rs.Spec.Template.Labels)) || rs.Spec.Template.Labels[groupKey] != groupValue || rs.Spec.Template.Labels[labelRole] != roleShadow || rs.Spec.Template.Labels[labelModelLoaded] != "false" || len(rs.Spec.Template.Spec.EphemeralContainers) != 0 {
		return nil, fmt.Errorf("warm pool template is not a clean shadow in group")
	}
	return sel, nil
}

func warmPoolService(ctx context.Context, reader client.Reader, ns, groupKey, groupValue string, old, next *corev1.Pod) (*corev1.Service, error) {
	name := old.Annotations[annoRouteService]
	if name == "" || next.Annotations[annoRouteService] != name {
		return nil, fmt.Errorf("warm pool requires one declared route Service")
	}
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, svc); err != nil {
		return nil, err
	}
	if svc.UID == "" || svc.DeletionTimestamp != nil || svc.Spec.Selector[groupKey] != groupValue || svc.Spec.Selector[labelRole] != roleLeader || len(svc.Spec.Selector) == 0 {
		return nil, fmt.Errorf("warm pool serving Service selector invalid")
	}
	for _, p := range []*corev1.Pod{old, next} {
		if err := warmPoolRouteMember(svc, p); err != nil {
			return nil, err
		}
	}
	return svc, nil
}

func warmPoolRouteMember(svc *corev1.Service, p *corev1.Pod) error {
	if svc == nil || p == nil || p.Annotations[annoRouteService] != svc.Name {
		return fmt.Errorf("warm pool route declaration unavailable")
	}
	selector := labels.SelectorFromSet(svc.Spec.Selector)
	for _, role := range []string{roleLeader, roleShadow, roleRetiring} {
		projected := make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			projected[k] = v
		}
		projected[labelRole] = role
		matches := selector.Matches(labels.Set(projected))
		if matches != (role == roleLeader) {
			return fmt.Errorf("warm pool route does not isolate current Pod role projections")
		}
	}
	return nil
}

func warmPoolListMembers(ctx context.Context, reader client.Reader, ns string, sel labels.Selector) (corev1.PodList, error) {
	var list corev1.PodList
	err := reader.List(ctx, &list, client.InNamespace(ns), client.MatchingLabelsSelector{Selector: sel}, client.Limit(warmPoolMaxMembers+1))
	if err != nil {
		return list, err
	}
	if list.Continue != "" || len(list.Items) > warmPoolMaxMembers {
		return list, fmt.Errorf("warm pool membership result incomplete/overflow")
	}
	return list, nil
}

func warmPoolCapture(ctx context.Context, reader client.Reader, old, next *corev1.Pod, groupKey, groupValue string) (warmPoolIntent, error) {
	var out warmPoolIntent
	if reader == nil || old == nil || next == nil || old.Namespace != next.Namespace || old.UID == "" || next.UID == "" {
		return out, fmt.Errorf("warm pool authoritative pair unavailable")
	}
	oldOwner, err := controllingRS(old)
	if err != nil {
		return out, err
	}
	newOwner, err := controllingRS(next)
	if err != nil {
		return out, err
	}
	if oldOwner.UID != newOwner.UID || oldOwner.Name != newOwner.Name {
		return out, fmt.Errorf("warm pool pair has different controllers")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: oldOwner.Name}, rs); err != nil {
		return out, err
	}
	if rs.UID != oldOwner.UID || rs.DeletionTimestamp != nil || rs.Spec.Replicas == nil || *rs.Spec.Replicas < 2 || *rs.Spec.Replicas > warmPoolMaxMembers || rs.Status.ObservedGeneration != rs.Generation {
		return out, fmt.Errorf("warm pool controller identity/state unavailable")
	}
	sel, err := warmPoolSelector(rs, groupKey, groupValue)
	if err != nil {
		return out, err
	}
	for _, p := range []*corev1.Pod{old, next} {
		if p.DeletionTimestamp != nil || !sel.Matches(labels.Set(p.Labels)) || p.Labels[groupKey] != groupValue || p.ResourceVersion == "" {
			return out, fmt.Errorf("warm pool pair outside stable selector")
		}
	}
	parent := metav1.GetControllerOf(rs)
	if parent != nil {
		if len(rs.OwnerReferences) != 1 || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" || parent.UID == "" {
			return out, fmt.Errorf("warm pool parent unsupported")
		}
		d := &appsv1.Deployment{}
		if err := reader.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: parent.Name}, d); err != nil {
			return out, err
		}
		if d.UID != parent.UID || d.DeletionTimestamp != nil {
			return out, fmt.Errorf("warm pool parent changed")
		}
		out.ParentName, out.ParentUID = d.Name, string(d.UID)
	} else if len(rs.OwnerReferences) != 0 {
		return out, fmt.Errorf("warm pool parent references unsupported")
	}
	svc, err := warmPoolService(ctx, reader, old.Namespace, groupKey, groupValue, old, next)
	if err != nil {
		return out, err
	}
	if rs.Spec.Template.Annotations[annoRouteService] != svc.Name {
		return out, fmt.Errorf("warm pool template lacks route declaration")
	}
	templateLabels := make(map[string]string, len(rs.Spec.Template.Labels))
	for k, v := range rs.Spec.Template.Labels {
		templateLabels[k] = v
	}
	templateLabels[labelRole] = roleLeader
	if !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(templateLabels)) {
		return out, fmt.Errorf("warm pool route does not match template-derived leader")
	}
	pods, err := warmPoolListMembers(ctx, reader, old.Namespace, sel)
	if err != nil {
		return out, err
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		o, err := controllingRS(p)
		if err != nil || o.UID != rs.UID || o.Name != rs.Name || p.DeletionTimestamp != nil || p.Labels[groupKey] != groupValue || p.Annotations[annoRouteService] != svc.Name {
			return out, fmt.Errorf("warm pool selector contains foreign/terminating member")
		}
		out.Members = append(out.Members, string(p.UID))
		if len(out.Members) > warmPoolMaxMembers {
			return out, fmt.Errorf("warm pool member bound exceeded")
		}
	}
	if len(out.Members) != int(*rs.Spec.Replicas) {
		return out, fmt.Errorf("warm pool member count differs from desired")
	}
	foundOld, foundNext := false, false
	for _, uid := range out.Members {
		if uid == string(old.UID) {
			foundOld = true
		}
		if uid == string(next.UID) {
			foundNext = true
		}
	}
	if !foundOld || !foundNext {
		return out, fmt.Errorf("warm pool selected pair absent from complete inventory")
	}
	sort.Strings(out.Members)
	out.RSName, out.RSUID, out.RSGeneration, out.Desired = rs.Name, string(rs.UID), rs.Generation, *rs.Spec.Replicas
	out.RSTemplateHash, out.RSSelectorHash = hashWarmObject(rs.Spec.Template), hashWarmObject(rs.Spec.Selector)
	out.ServiceName, out.ServiceUID, out.ServiceSelectorHash = svc.Name, string(svc.UID), hashWarmObject(svc.Spec.Selector)
	return out, nil
}

func warmPoolRecheck(ctx context.Context, reader client.Reader, r operationReceipt, old, next *corev1.Pod) error {
	if (r.Version != 2 && r.Version != warmSecureReceiptVersion) || r.Pool == nil {
		return fmt.Errorf("warm pool receipt intent unavailable")
	}
	if reader == nil {
		return fmt.Errorf("warm pool authoritative reader unavailable")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.Pool.RSName}, rs); err != nil {
		return err
	}
	if string(rs.UID) != r.Pool.RSUID || rs.DeletionTimestamp != nil || rs.Generation != r.Pool.RSGeneration || rs.Status.ObservedGeneration != rs.Generation || rs.Spec.Replicas == nil || *rs.Spec.Replicas != r.Pool.Desired || hashWarmObject(rs.Spec.Template) != r.Pool.RSTemplateHash || hashWarmObject(rs.Spec.Selector) != r.Pool.RSSelectorHash {
		return fmt.Errorf("warm pool ReplicaSet intent drift")
	}
	sel, err := warmPoolSelector(rs, r.GroupKey, r.GroupValue)
	if err != nil {
		return err
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.PolicyName}, pol); err != nil {
		return err
	}
	if string(pol.UID) != r.PolicyUID || pol.DeletionTimestamp != nil {
		return fmt.Errorf("warm pool policy identity drift")
	}
	policySel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || !policySel.Matches(labels.Set(rs.Spec.Template.Labels)) {
		return fmt.Errorf("warm pool template outside policy selector")
	}
	parent := metav1.GetControllerOf(rs)
	if r.Pool.ParentUID == "" {
		if parent != nil || len(rs.OwnerReferences) != 0 {
			return fmt.Errorf("warm pool parent drift")
		}
	} else {
		if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" || parent.Name != r.Pool.ParentName || string(parent.UID) != r.Pool.ParentUID || len(rs.OwnerReferences) != 1 {
			return fmt.Errorf("warm pool parent drift")
		}
		d := &appsv1.Deployment{}
		if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: parent.Name}, d); err != nil {
			return err
		}
		if d.UID != parent.UID || d.DeletionTimestamp != nil {
			return fmt.Errorf("warm pool Deployment drift")
		}
	}
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.Pool.ServiceName}, svc); err != nil {
		return err
	}
	if string(svc.UID) != r.Pool.ServiceUID || svc.DeletionTimestamp != nil || hashWarmObject(svc.Spec.Selector) != r.Pool.ServiceSelectorHash || svc.Spec.Selector[r.GroupKey] != r.GroupValue || svc.Spec.Selector[labelRole] != roleLeader {
		return fmt.Errorf("warm pool serving route drift")
	}
	for _, p := range []*corev1.Pod{old, next} {
		if p == nil {
			continue
		}
		o, err := controllingRS(p)
		if err != nil || string(o.UID) != r.Pool.RSUID || o.Name != r.Pool.RSName || p.DeletionTimestamp != nil || !sel.Matches(labels.Set(p.Labels)) || p.Labels[r.GroupKey] != r.GroupValue {
			return fmt.Errorf("warm pool recorded Pod ownership/scope drift")
		}
		if p.Annotations[annoRouteService] != r.Pool.ServiceName {
			return fmt.Errorf("warm pool route declaration drift")
		}
		if err := warmPoolRouteMember(svc, p); err != nil {
			return err
		}
	}
	// Before retiring the recorded old UID, neither an unrelated scale event nor
	// an ownerless/foreign member may change the complete baseline pool. After
	// deletion, observation uses a separate stage-aware new-member check.
	if old != nil {
		members, err := warmPoolListMembers(ctx, reader, r.PolicyNamespace, sel)
		if err != nil {
			return err
		}
		if len(members.Items) != int(r.Pool.Desired) {
			return fmt.Errorf("warm pool pre-retirement membership count drift")
		}
		expected := make(map[string]bool, len(r.Pool.Members))
		for _, uid := range r.Pool.Members {
			expected[uid] = true
		}
		seen := make(map[string]bool, len(members.Items))
		for i := range members.Items {
			p := &members.Items[i]
			o, err := controllingRS(p)
			if err != nil || string(o.UID) != r.Pool.RSUID || o.Name != r.Pool.RSName || p.DeletionTimestamp != nil || p.Labels[r.GroupKey] != r.GroupValue || !expected[string(p.UID)] || seen[string(p.UID)] {
				return fmt.Errorf("warm pool pre-retirement member identity drift")
			}
			if err := warmPoolRouteMember(svc, p); err != nil {
				return err
			}
			seen[string(p.UID)] = true
		}
		if len(seen) != len(expected) {
			return fmt.Errorf("warm pool pre-retirement member UID set incomplete")
		}
	}
	return nil
}

// warmPoolObserve records only the identity of a controller-created member. It
// never grants update or delete authority over that member.
func warmPoolObserve(ctx context.Context, reader client.Reader, r operationReceipt) (*corev1.Pod, error) {
	if err := warmPoolRecheck(ctx, reader, r, nil, nil); err != nil {
		return nil, err
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.Pool.RSName}, rs); err != nil {
		return nil, err
	}
	sel, err := warmPoolSelector(rs, r.GroupKey, r.GroupValue)
	if err != nil {
		return nil, err
	}
	list, err := warmPoolListMembers(ctx, reader, r.PolicyNamespace, sel)
	if err != nil {
		return nil, err
	}
	baseline := make(map[string]bool, len(r.Pool.Members))
	for _, uid := range r.Pool.Members {
		baseline[uid] = true
	}
	var candidate *corev1.Pod
	count := 0
	oldPresent, survivorPresent := false, false
	for i := range list.Items {
		p := &list.Items[i]
		if string(p.UID) == r.OldUID {
			oldPresent = true
		}
		if !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		o, err := controllingRS(p)
		if err != nil || string(o.UID) != r.Pool.RSUID || o.Name != r.Pool.RSName || p.DeletionTimestamp != nil {
			return nil, fmt.Errorf("warm pool membership ambiguous")
		}
		count++
		if string(p.UID) == r.NewUID {
			survivorPresent = true
		}
		if count > warmPoolMaxMembers {
			return nil, fmt.Errorf("warm pool observation overflow")
		}
		if baseline[string(p.UID)] {
			continue
		}
		if candidate != nil {
			return nil, fmt.Errorf("warm pool multiple new members")
		}
		candidate = p.DeepCopy()
	}
	if oldPresent || !survivorPresent || count != int(r.Pool.Desired) || candidate == nil {
		return nil, fmt.Errorf("warm pool replenishment pending: count %d desired %d", count, r.Pool.Desired)
	}
	// The full selector list cannot reveal an old Pod whose labels were changed
	// outside the selector. Keep the retired name/UID check separate and explicit.
	oldByName := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.OldName}, oldByName); err == nil {
		return nil, fmt.Errorf("warm pool retired name still occupied (UID %s)", oldByName.UID)
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}
	if candidate.Labels[r.GroupKey] != r.GroupValue || candidate.Labels[labelRole] != roleShadow || len(candidate.Spec.EphemeralContainers) != 0 || candidate.Annotations[annoRouteService] != r.Pool.ServiceName {
		return nil, fmt.Errorf("warm pool new member not clean shadow")
	}
	for k, v := range rs.Spec.Template.Labels {
		if k == labelRole || k == labelModelLoaded {
			continue
		}
		actual, present := candidate.Labels[k]
		if !present || actual != v {
			return nil, fmt.Errorf("warm pool new member template label drift")
		}
	}
	for k, v := range rs.Spec.Template.Annotations {
		actual, present := candidate.Annotations[k]
		if !present || actual != v {
			return nil, fmt.Errorf("warm pool new member serving annotation drift")
		}
	}
	if err := warmPoolStableSpec(rs.Spec.Template.Spec, candidate.Spec); err != nil {
		return nil, err
	}
	return candidate, nil
}

func warmPoolSATokenVolume(v corev1.Volume) bool {
	if !strings.HasPrefix(v.Name, "kube-api-access-") || v.Projected == nil {
		return false
	}
	for _, source := range v.Projected.Sources {
		if source.ServiceAccountToken != nil {
			return true
		}
	}
	return false
}

func warmPoolStableVolumeSource(want, got corev1.VolumeSource) bool {
	// API admission fills the ordinary file-mode default for these sources.
	normalize := func(v corev1.VolumeSource) corev1.VolumeSource {
		mode := int32(0644)
		if v.Secret != nil && v.Secret.DefaultMode == nil {
			v.Secret = v.Secret.DeepCopy()
			v.Secret.DefaultMode = &mode
		}
		if v.ConfigMap != nil && v.ConfigMap.DefaultMode == nil {
			v.ConfigMap = v.ConfigMap.DeepCopy()
			v.ConfigMap.DefaultMode = &mode
		}
		if v.Projected != nil && v.Projected.DefaultMode == nil {
			v.Projected = v.Projected.DeepCopy()
			v.Projected.DefaultMode = &mode
		}
		return v
	}
	return reflect.DeepEqual(normalize(want), normalize(got))
}

func warmPoolResourcesMatch(want, got corev1.ResourceRequirements) bool {
	for resource, quantity := range want.Requests {
		actual, ok := got.Requests[resource]
		if !ok || quantity.Cmp(actual) != 0 {
			return false
		}
	}
	for resource, quantity := range want.Limits {
		actual, ok := got.Limits[resource]
		if !ok || quantity.Cmp(actual) != 0 {
			return false
		}
	}
	return reflect.DeepEqual(want.Claims, got.Claims)
}

func warmPoolMountsMatch(want, got []corev1.VolumeMount, autoToken string) bool {
	if len(got) < len(want) {
		return false
	}
	used := make([]bool, len(got))
	for _, mount := range want {
		found := false
		for i := range got {
			if !used[i] && reflect.DeepEqual(mount, got[i]) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for i := range got {
		if used[i] {
			continue
		}
		if autoToken == "" || got[i].Name != autoToken || got[i].MountPath != "/var/run/secrets/kubernetes.io/serviceaccount" || !got[i].ReadOnly {
			return false
		}
	}
	return true
}

func warmPoolContainerMatch(want, got corev1.Container, autoToken string) bool {
	if want.Name != got.Name || want.Image != got.Image || !reflect.DeepEqual(want.Command, got.Command) || !reflect.DeepEqual(want.Args, got.Args) || !reflect.DeepEqual(want.Env, got.Env) || !reflect.DeepEqual(want.EnvFrom, got.EnvFrom) || want.WorkingDir != got.WorkingDir || !warmPoolResourcesMatch(want.Resources, got.Resources) || !warmPoolMountsMatch(want.VolumeMounts, got.VolumeMounts, autoToken) || !reflect.DeepEqual(want.VolumeDevices, got.VolumeDevices) {
		return false
	}
	if len(want.Ports) != len(got.Ports) {
		return false
	}
	for i := range want.Ports {
		w, g := want.Ports[i], got.Ports[i]
		if w.Protocol == "" {
			w.Protocol = corev1.ProtocolTCP
		}
		if g.Protocol == "" {
			g.Protocol = corev1.ProtocolTCP
		}
		if !reflect.DeepEqual(w, g) {
			return false
		}
	}
	if want.ImagePullPolicy != "" && want.ImagePullPolicy != got.ImagePullPolicy {
		return false
	}
	if want.SecurityContext != nil && !reflect.DeepEqual(want.SecurityContext, got.SecurityContext) {
		return false
	}
	if want.Lifecycle != nil && !reflect.DeepEqual(want.Lifecycle, got.Lifecycle) {
		return false
	}
	return true
}

// Compare explicit serving fields to the pinned ReplicaSet template. Scheduler
// assignment, image-pull defaulting, resource defaults and the admission-added
// service-account projection are not treated as template drift.
func warmPoolStableSpec(want, got corev1.PodSpec) error {
	wantSA := want.ServiceAccountName
	saMatches := got.ServiceAccountName == wantSA || (wantSA == "" && got.ServiceAccountName == "default")
	if !saMatches || len(got.Containers) != len(want.Containers) || len(got.InitContainers) != len(want.InitContainers) {
		return fmt.Errorf("warm pool new member container/service-account drift")
	}
	if want.AutomountServiceAccountToken != nil && (got.AutomountServiceAccountToken == nil || *want.AutomountServiceAccountToken != *got.AutomountServiceAccountToken) {
		return fmt.Errorf("warm pool service-account automount drift")
	}
	gotVolumes := make(map[string]corev1.Volume, len(got.Volumes))
	for _, v := range got.Volumes {
		if _, exists := gotVolumes[v.Name]; exists {
			return fmt.Errorf("warm pool duplicate volume")
		}
		gotVolumes[v.Name] = v
	}
	wantNames := make(map[string]bool, len(want.Volumes))
	for _, v := range want.Volumes {
		wantNames[v.Name] = true
		actual, ok := gotVolumes[v.Name]
		if !ok || !warmPoolStableVolumeSource(v.VolumeSource, actual.VolumeSource) {
			return fmt.Errorf("warm pool new member volume source drift")
		}
	}
	autoToken := ""
	for _, v := range got.Volumes {
		if wantNames[v.Name] {
			continue
		}
		if autoToken != "" || !warmPoolSATokenVolume(v) {
			return fmt.Errorf("warm pool unexpected admitted volume")
		}
		autoToken = v.Name
	}
	for i := range want.Containers {
		if !warmPoolContainerMatch(want.Containers[i], got.Containers[i], autoToken) {
			return fmt.Errorf("warm pool new member serving container drift")
		}
	}
	for i := range want.InitContainers {
		if !warmPoolContainerMatch(want.InitContainers[i], got.InitContainers[i], autoToken) {
			return fmt.Errorf("warm pool new member init container drift")
		}
	}
	for k, v := range want.NodeSelector {
		if got.NodeSelector[k] != v {
			return fmt.Errorf("warm pool node selector drift")
		}
	}
	if want.Affinity != nil && !reflect.DeepEqual(want.Affinity, got.Affinity) {
		return fmt.Errorf("warm pool affinity drift")
	}
	return nil
}
