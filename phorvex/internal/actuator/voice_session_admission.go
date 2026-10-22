package actuator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type voiceAdmissionScope struct {
	pod        *corev1.Pod
	deployment *appsv1.Deployment
	source     voiceadmissionpolicy.SourceEvidence
	policy     *v1alpha1.PhorvexPolicy
	cm         *corev1.ConfigMap
	rule       voiceadmissionpolicy.Rule
	token      []byte
	pods       []corev1.Pod
}

func voiceAdmissionReady(p *corev1.Pod) bool {
	if p == nil || p.DeletionTimestamp != nil || !voiceadmissionpolicy.UsesWrapper(p) {
		return false
	}
	if _, e := netip.ParseAddr(p.Status.PodIP); e != nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func voiceAdmissionScopeAt(ctx context.Context, reader client.Reader, target Target) (voiceAdmissionScope, error) {
	var s voiceAdmissionScope
	if reader == nil || target.Namespace != voiceadmissionpolicy.Namespace || target.Pod == "" || !voiceadmissionpolicy.ValidUID(target.UID) || target.PolicyName == "" || !voiceadmissionpolicy.ValidUID(target.PolicyUID) {
		return s, errors.New("Voice admission target authority incomplete")
	}
	pod := &corev1.Pod{}
	if e := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: target.Pod}, pod); e != nil {
		return s, e
	}
	if string(pod.UID) != target.UID || !voiceAdmissionReady(pod) || pod.Annotations[voiceadmissionpolicy.EventCreatorAnnotation] != eventtrust.Injector() {
		return s, errors.New("Voice admission target readiness/creator changed")
	}
	dep, e := voiceRefundOwner(ctx, reader, pod)
	if e != nil {
		return s, e
	}
	source, e := voiceadmissionpolicy.VerifySource(ctx, reader, pod, dep)
	if e != nil {
		return s, e
	}
	pol, e := receiptAuthority(ctx, reader, operationReceipt{PolicyNamespace: target.Namespace, PolicyName: target.PolicyName, PolicyUID: target.PolicyUID, TargetName: target.Pod, TargetUID: target.UID, TargetLabels: pod.Labels}, model.ActionVoiceSessionAdmissionEnforce)
	if e != nil {
		return s, e
	}
	sel, e := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if e != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) {
		return s, errors.New("Voice admission selecting policy scope changed")
	}
	cm := &corev1.ConfigMap{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voiceadmissionpolicy.ConfigMapName}, cm); e != nil {
		return s, e
	}
	if !voiceadmissionpolicy.OwnedConfigMap(cm, dep) || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return s, errors.New("Voice admission current rule object invalid")
	}
	rule, e := voiceadmissionpolicy.Parse(cm.Data[voiceadmissionpolicy.RuleKey])
	if e != nil || rule.DeploymentUID != string(dep.UID) || rule.SecurityPolicyUID != string(pol.UID) || rule.WrapperCMUID != source.ConfigMapUID || rule.AdmissionSourceSHA256 != source.SourceSHA256 || rule.LegacyBundleSHA256 != source.LegacyBundleSHA256 || rule.AuthProfileSHA256 != source.AuthProfileSHA256 {
		return s, errors.New("Voice admission current rule/source authority changed")
	}
	secret := &corev1.Secret{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: "voice-memory-state-token"}, secret); e != nil {
		return s, e
	}
	token := secret.Data["token"]
	if secret.DeletionTimestamp != nil || len(token) < 32 || len(token) > 256 {
		return s, errors.New("Voice admission private readback token invalid")
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return s, errors.New("Voice admission private readback token invalid")
		}
	}
	svc := &corev1.Service{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: "voice-bot"}, svc); e != nil {
		return s, e
	}
	if svc.DeletionTimestamp != nil || svc.UID == "" || len(svc.Spec.Selector) == 0 {
		return s, errors.New("Voice admission serving Service authority incomplete")
	}
	portOK := false
	for _, port := range svc.Spec.Ports {
		if port.Port == 8080 && port.Protocol == corev1.ProtocolTCP && port.TargetPort.IntVal == 8080 {
			portOK = true
		}
	}
	if !portOK {
		return s, errors.New("Voice admission serving Service port authority differs")
	}
	depSel, e := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if e != nil || depSel.Empty() {
		return s, errors.New("Voice admission Deployment selector invalid")
	}
	svcSel := labels.SelectorFromSet(svc.Spec.Selector)
	list := &corev1.PodList{}
	if e = reader.List(ctx, list, client.InNamespace(target.Namespace), client.Limit(129)); e != nil {
		return s, e
	}
	if list.Continue != "" || len(list.Items) > 128 {
		return s, errors.New("Voice admission Pod inventory exceeds bound")
	}
	peers := map[string]corev1.Pod{}
	found := false
	for _, p := range list.Items {
		selected := svcSel.Matches(labels.Set(p.Labels)) || depSel.Matches(labels.Set(p.Labels))
		if !selected {
			continue
		}
		owner, oe := voiceRefundOwner(ctx, reader, &p)
		if oe != nil || owner.UID != dep.UID || !voiceAdmissionReady(&p) || !svcSel.Matches(labels.Set(p.Labels)) || !depSel.Matches(labels.Set(p.Labels)) || !sel.Matches(labels.Set(p.Labels)) || p.Annotations[voiceadmissionpolicy.EventCreatorAnnotation] != eventtrust.Injector() {
			return s, errors.New("Voice admission serving owner/readiness set incomplete")
		}
		peerSource, se := voiceadmissionpolicy.VerifySource(ctx, reader, &p, dep)
		if se != nil || peerSource != source {
			return s, errors.New("Voice admission serving source identity differs")
		}
		peers[string(p.UID)] = p
		found = found || p.UID == pod.UID
		s.pods = append(s.pods, p)
	}
	if !found || len(peers) == 0 {
		return s, errors.New("Voice admission observed target absent from serving set")
	}
	endpoints := &discoveryv1.EndpointSliceList{}
	if e = reader.List(ctx, endpoints, client.InNamespace(target.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}, client.Limit(129)); e != nil {
		return s, e
	}
	if endpoints.Continue != "" || len(endpoints.Items) == 0 || len(endpoints.Items) > 128 {
		return s, errors.New("Voice admission serving endpoint inventory incomplete")
	}
	serving := map[string]bool{}
	count := 0
	for _, slice := range endpoints.Items {
		owned := false
		for _, owner := range slice.OwnerReferences {
			if owner.Kind == "Service" && owner.APIVersion == "v1" && owner.Name == svc.Name && owner.UID == svc.UID {
				owned = true
			}
		}
		if slice.DeletionTimestamp != nil || !owned {
			return s, errors.New("Voice admission serving EndpointSlice owner differs")
		}
		portOK := false
		for _, port := range slice.Ports {
			if port.Port != nil && *port.Port == 8080 && port.Protocol != nil && *port.Protocol == corev1.ProtocolTCP {
				portOK = true
			}
		}
		if !portOK {
			return s, errors.New("Voice admission EndpointSlice port authority differs")
		}
		for _, ep := range slice.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready && (ep.Conditions.Serving == nil || !*ep.Conditions.Serving) {
				continue
			}
			count++
			if count > 128 || ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.Namespace != target.Namespace {
				return s, errors.New("Voice admission endpoint target authority invalid")
			}
			p, ok := peers[string(ep.TargetRef.UID)]
			if !ok || p.Name != ep.TargetRef.Name || len(ep.Addresses) != 1 || ep.Addresses[0] != p.Status.PodIP {
				return s, errors.New("Voice admission serving endpoint/source identity differs")
			}
			serving[string(p.UID)] = true
		}
	}
	if len(serving) != len(peers) {
		return s, errors.New("Voice admission all Ready source Pods must be current serving endpoints")
	}
	s.pod, s.deployment, s.source, s.policy, s.cm, s.rule, s.token = pod, dep, source, pol, cm, rule, append([]byte(nil), token...)
	return s, nil
}

func voiceAdmissionGet(ctx context.Context, pod corev1.Pod, token []byte, path string, transport http.RoundTripper) ([]byte, error) {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	}
	hc := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	url := "http://" + net.JoinHostPort(pod.Status.PodIP, "8080") + path
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, e := hc.Do(req)
	if e != nil {
		return nil, fmt.Errorf("Voice admission authenticated Pod readback unavailable: %w", e)
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, voiceadmissionpolicy.MaxBytes+1))
	if e != nil || len(body) > voiceadmissionpolicy.MaxBytes || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		return nil, errors.New("Voice admission private readback unready")
	}
	return body, nil
}

func voiceAdmissionReadback(ctx context.Context, s voiceAdmissionScope, settled bool, transport http.RoundTripper) ([]voiceadmissionpolicy.State, error) {
	states := []voiceadmissionpolicy.State{}
	for _, p := range s.pods {
		body, e := voiceAdmissionGet(ctx, p, s.token, voiceadmissionpolicy.StatePath, transport)
		if e != nil {
			return nil, e
		}
		state, e := voiceadmissionpolicy.ParseState(body)
		now := time.Now().UnixMilli()
		if e != nil || state.PodUID != string(p.UID) || state.DeploymentUID != s.rule.DeploymentUID || state.PolicyCMUID != string(s.cm.UID) || state.PolicyResourceVersion != s.cm.ResourceVersion || state.RuleSHA256 != s.rule.SHA256() || state.Revision != s.rule.Revision || state.Mode != s.rule.Mode || state.OperationID != s.rule.OperationID || state.AdmissionSourceSHA256 != s.rule.AdmissionSourceSHA256 || state.LegacyBundleSHA256 != s.rule.LegacyBundleSHA256 || state.AuthProfileSHA256 != s.rule.AuthProfileSHA256 || state.ObservedAtUnixMs > now+1000 || now-state.ObservedAtUnixMs > 10000 || state.TransitionPending || state.Settled != settled {
			return nil, errors.New("Voice admission rule or settled serving barrier unconfirmed")
		}
		states = append(states, state)
	}
	return states, nil
}

func voiceAdmissionObserveLive(ctx context.Context, s voiceAdmissionScope, transport http.RoundTripper) error {
	states, err := voiceAdmissionReadback(ctx, s, false, transport)
	if err != nil {
		return err
	}
	for _, state := range states {
		if state.PodUID == string(s.pod.UID) && state.ActiveUnsigned > 0 {
			return nil
		}
	}
	return errors.New("Voice admission selected target has no actual active unsigned delegate")
}

func voiceAdmissionEvidence(ctx context.Context, s voiceAdmissionScope, a voiceadmissionpolicy.EventAssertion, transport http.RoundTripper) error {
	body, e := voiceAdmissionGet(ctx, *s.pod, s.token, "/v1/voice-session-admission/evidence?sessionID="+a.SessionID, transport)
	if e != nil {
		return e
	}
	proof, e := voiceadmissionpolicy.ParseEvidence(body)
	if e != nil {
		return e
	}
	return voiceadmissionpolicy.ValidateEvidence(proof, a)
}

// The immutable exposure establishes loss; this fresh lifecycle establishes that
// enforcement actually stopped the selected local delegate.
func voiceAdmissionSession(ctx context.Context, s voiceAdmissionScope, r voiceadmissionpolicy.Receipt, closed bool, transport http.RoundTripper) error {
	body, err := voiceAdmissionGet(ctx, *s.pod, s.token, "/v1/voice-session-admission/session?sessionID="+r.SessionID, transport)
	if err != nil {
		return err
	}
	session, err := voiceadmissionpolicy.ParseSession(body)
	now := time.Now().UnixMilli()
	if err != nil || session.SessionID != r.SessionID || session.RunSHA256 != r.RunSHA256 || session.PodUID != r.TargetPodUID || session.DeploymentUID != r.DeploymentUID || session.AdmissionSourceSHA256 != r.Prior.AdmissionSourceSHA256 || session.LegacyBundleSHA256 != r.Prior.LegacyBundleSHA256 || session.AuthProfileSHA256 != r.Prior.AuthProfileSHA256 || session.AdmissionRuleSHA256 != r.Prior.SHA256() || session.AdmissionRevision != 0 || session.Authenticated || session.ObservedAtUnixMs > now+1000 || now-session.ObservedAtUnixMs > 10000 || !voiceadmissionpolicy.ValidSHA(session.CallSIDHash) || session.ReceivedAudioFrames <= 0 || session.SentAudioFrames <= 0 || session.SentAudioBytes <= 0 {
		return errors.New("Voice admission selected session lifecycle authority unconfirmed")
	}
	if closed {
		if session.Stage != "closed" || !session.DisconnectDelivered || !session.DelegateCompleted || session.DisconnectedAtUnixMs <= 0 {
			return errors.New("Voice admission selected local delegate teardown unconfirmed")
		}
	} else if session.Stage != "pipeline-observed" || session.DisconnectDelivered || session.DelegateCompleted || session.DisconnectedAtUnixMs != 0 {
		return errors.New("Voice admission selected unsigned session is no longer active")
	}
	return nil
}

func voiceAdmissionJournalGet(ctx context.Context, reader client.Reader, ns string) (*corev1.ConfigMap, voiceadmissionpolicy.Journal, error) {
	cm := &corev1.ConfigMap{}
	if reader == nil || ns == "" {
		return nil, voiceadmissionpolicy.Journal{}, errors.New("Voice admission protected journal unavailable")
	}
	if e := reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: voiceadmissionpolicy.JournalName}, cm); e != nil {
		return nil, voiceadmissionpolicy.Journal{}, e
	}
	if cm.DeletionTimestamp != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.Labels[voiceadmissionpolicy.JournalLabel] != "v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return nil, voiceadmissionpolicy.Journal{}, errors.New("Voice admission protected journal shape invalid")
	}
	j, e := voiceadmissionpolicy.ParseJournal(cm.Data["receipts.json"])
	return cm, j, e
}
func voiceAdmissionJournalMatchesRule(j voiceadmissionpolicy.Journal, rule voiceadmissionpolicy.Rule) bool {
	if !rule.Valid() {
		return false
	}
	if len(j.Receipts) == 0 {
		return rule.Revision == 0
	}
	r := j.Receipts[0]
	return (r.Phase == "prepared" && rule.SHA256() == r.Prior.SHA256()) || rule.SHA256() == r.Desired.SHA256()
}
func voiceAdmissionCapability(ctx context.Context, reader client.Reader, journalNS string, target Target, transport http.RoundTripper) (bool, string) {
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, e := voiceAdmissionScopeAt(probe, reader, target)
	if e != nil {
		return false, "voice-admission-scope-unavailable: " + e.Error()
	}
	if s.rule.Revision != 0 {
		return false, "voice-admission-already-enforced"
	}
	_, j, e := voiceAdmissionJournalGet(probe, reader, journalNS)
	if e != nil || !voiceAdmissionJournalMatchesRule(j, s.rule) {
		return false, "voice-admission-prior-history-unverified"
	}
	if len(j.Receipts) != 0 {
		return false, "voice-admission-operation-pending"
	}
	if _, e = voiceAdmissionReadback(probe, s, false, transport); e != nil {
		return false, "voice-admission-runtime-unverified: " + e.Error()
	}
	return true, ""
}
func PendingVoiceAdmissionOperation(ctx context.Context, reader client.Reader, journalNS, namespace, podName, podUID string) (bool, error) {
	if namespace != voiceadmissionpolicy.Namespace || podUID == "" {
		return false, nil
	}
	// An uninstalled legacy Voice target must not acquire a new journal/RBAC
	// prerequisite. Installed wrapper targets remain fenced on unknown history.
	live := &corev1.Pod{}
	if reader == nil || podName == "" {
		return true, errors.New("Voice admission target identity unavailable")
	}
	if e := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: podName}, live); e != nil {
		return true, e
	}
	if string(live.UID) != podUID {
		return true, errors.New("Voice admission target lifetime changed")
	}
	if !voiceadmissionpolicy.HasWrapperAuthority(live) && live.Annotations[voiceadmissionpolicy.PolicyConfigMapAnnotation] == "" {
		return false, nil
	}
	_, j, e := voiceAdmissionJournalGet(ctx, reader, journalNS)
	if apierrors.IsNotFound(e) {
		cm := &corev1.ConfigMap{}
		pe := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: voiceadmissionpolicy.ConfigMapName}, cm)
		if apierrors.IsNotFound(pe) {
			return false, nil
		}
		if pe != nil {
			return true, pe
		}
		return true, errors.New("Voice admission installed policy has no protected journal")
	}
	if e != nil {
		return true, e
	}
	if len(j.Receipts) == 0 || j.Receipts[0].Phase != "prepared" {
		return false, nil
	}
	r := j.Receipts[0]
	if r.TargetPodUID == podUID {
		return true, nil
	}
	pod := &corev1.Pod{}
	if podName == "" {
		return true, errors.New("Voice admission pending target ownership unavailable")
	}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: podName}, pod); e != nil {
		return true, e
	}
	if string(pod.UID) != podUID {
		return true, errors.New("Voice admission pending Pod lifetime changed")
	}
	dep, e := voiceRefundOwner(ctx, reader, pod)
	if e != nil {
		return true, e
	}
	return string(dep.UID) == r.DeploymentUID, nil
}

type voiceAdmissionHandler struct{}

func (voiceAdmissionHandler) Name() string { return string(model.ActionVoiceSessionAdmissionEnforce) }
func init()                                { HandlerRegistry.Register(voiceAdmissionHandler{}) }

func voiceAdmissionEvent(ctx context.Context, ec EnactCtx, req Request, o *model.VoiceAdmissionObservation, s voiceAdmissionScope) error {
	event := &amtdv1beta1.SecurityEvent{}
	if e := ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); e != nil {
		return e
	}
	if string(event.UID) != o.EventUID || event.DeletionTimestamp != nil || event.Annotations["phorvex.ai/creator-identity"] != eventtrust.Injector() || o.CreatorIdentity != eventtrust.Injector() || event.Annotations[model.ConsoleTargetPodUIDAnnotation] != req.TargetUID || event.Spec.Rule.Type != model.AttackVectorVoiceAdmission || event.Spec.Rule.Source != "redteam" || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod || event.CreationTimestamp.IsZero() || time.Since(event.CreationTimestamp.Time) < 0 || time.Since(event.CreationTimestamp.Time) >= time.Minute {
		return errors.New("Voice admission SecurityEvent identity or freshness changed")
	}
	a, e := voiceadmissionpolicy.ParseEvent(event.Annotations[voiceadmissionpolicy.EventAnnotation])
	if e != nil || !bytes.Equal(voiceadmissionpolicy.CanonicalBytes(a), voiceadmissionpolicy.CanonicalBytes(o.Assertion)) || a.PodUID != req.TargetUID || a.DeploymentUID != string(s.deployment.UID) || a.SecurityPolicyUID != req.PolicyUID || a.SecurityPolicyGeneration != req.PolicyGeneration || a.PolicyCMUID != string(s.cm.UID) || a.PolicyResourceVersion != s.cm.ResourceVersion || a.RuleSHA256 != s.rule.SHA256() || a.ObservedAtUnixMs > time.Now().UnixMilli() || a.ObservedAtUnixMs > event.CreationTimestamp.UnixMilli()+1000 || event.CreationTimestamp.UnixMilli()-a.ObservedAtUnixMs > 60000 {
		return errors.New("Voice admission observed assertion changed")
	}
	return voiceAdmissionEvidence(ctx, s, a, ec.VoiceAdmissionTransport)
}

func voiceAdmissionResume(ctx context.Context, ec EnactCtx, jcm *corev1.ConfigMap, j voiceadmissionpolicy.Journal, r voiceadmissionpolicy.Receipt) (HandlerResult, error) {
	target := Target{Namespace: voiceadmissionpolicy.Namespace, Pod: r.TargetName, UID: r.TargetPodUID, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID}
	s, e := voiceAdmissionScopeAt(ctx, ec.Reader, target)
	if e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}
	if string(s.deployment.UID) != r.DeploymentUID || string(s.cm.UID) != r.ConfigMapUID || s.policy.Generation != r.PolicyGeneration || s.source.ConfigMapUID != r.SourceConfigMapUID || s.source.SourceSHA256 != r.Prior.AdmissionSourceSHA256 {
		return HandlerResult{MutationKind: "partial"}, errors.New("Voice admission recovery authority changed")
	}
	if s.rule.SHA256() == r.Prior.SHA256() {
		if r.Phase != "prepared" {
			return HandlerResult{MutationKind: "partial"}, errors.New("Voice admission terminal history was reset")
		}
		if e = voiceAdmissionObserveLive(ctx, s, ec.VoiceAdmissionTransport); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
		if e = voiceAdmissionSession(ctx, s, r, false, ec.VoiceAdmissionTransport); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
		copy := s.cm.DeepCopy()
		copy.Data[voiceadmissionpolicy.RuleKey] = string(r.Desired.Bytes())
		if e = ec.Client.Update(ctx, copy); e != nil {
			return HandlerResult{MutationKind: "partial", Note: "Voice admission CAS acknowledgment unresolved; original journal retained"}, e
		}
	} else if s.rule.SHA256() != r.Desired.SHA256() {
		return HandlerResult{MutationKind: "partial"}, errors.New("Voice admission protected rule superseded")
	}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		current, se := voiceAdmissionScopeAt(deadline, ec.Reader, target)
		var states []voiceadmissionpolicy.State
		if se == nil {
			if current.rule.SHA256() != r.Desired.SHA256() {
				se = errors.New("Voice admission desired rule not current")
			} else {
				states, se = voiceAdmissionReadback(deadline, current, true, ec.VoiceAdmissionTransport)
				if se == nil && r.Phase == "prepared" {
					se = voiceAdmissionSession(deadline, current, r, true, ec.VoiceAdmissionTransport)
				}
			}
		}
		if se == nil {
			// Inventory is re-resolved after network acknowledgments; a changed set
			// cannot inherit an old Pod's barrier acknowledgment.
			again, ae := voiceAdmissionScopeAt(deadline, ec.Reader, target)
			if ae != nil || again.cm.ResourceVersion != current.cm.ResourceVersion || !voiceAdmissionSamePods(again.pods, current.pods) {
				se = errors.New("Voice admission serving inventory changed during barrier")
			} else {
				if r.Phase == "prepared" {
					copy := jcm.DeepCopy()
					j.Receipts[0].Phase = "terminal-full"
					j.Receipts[0].PodReceipts = states
					copy.Data["receipts.json"] = string(j.Bytes())
					if _, e = voiceadmissionpolicy.ParseJournal(copy.Data["receipts.json"]); e != nil {
						return HandlerResult{MutationKind: "partial"}, e
					}
					if e = ec.Client.Update(ctx, copy); e != nil {
						return HandlerResult{MutationKind: "partial", Note: "Voice admission effect observed; terminal journal acknowledgment unresolved"}, e
					}
				}
				note := "Voice admission authenticated all-serving-Pod barrier settled; selected unsigned local delegate completed; signed audio and fresh unsigned replay require Console proof"
				if r.Phase == "terminal-full" {
					note = "Voice admission already enforced; protected terminal history proves prior selected local teardown and current all-serving-Pod barrier remains settled"
				}
				return HandlerResult{ObjectsTouched: []string{voiceadmissionpolicy.Namespace + "/" + voiceadmissionpolicy.ConfigMapName}, MutationKind: "forward-only", Emitted: true, Note: note}, nil
			}
		}
		select {
		case <-deadline.Done():
			return HandlerResult{MutationKind: "partial", Note: "Voice admission enforcement or local teardown barrier unresolved"}, fmt.Errorf("Voice admission barrier timed out: %w", se)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func voiceAdmissionContainerIdentity(p corev1.Pod) string {
	for _, status := range p.Status.ContainerStatuses {
		if status.Name == "bot" && status.State.Running != nil {
			return fmt.Sprintf("%s\x00%s\x00%d\x00%d", status.ContainerID, status.ImageID, status.RestartCount, status.State.Running.StartedAt.UnixNano())
		}
	}
	return ""
}

func voiceAdmissionSamePods(a, b []corev1.Pod) bool {
	if len(a) != len(b) {
		return false
	}
	ids := map[string]string{}
	for _, p := range a {
		ids[string(p.UID)] = p.ResourceVersion + "\x00" + p.Status.PodIP + "\x00" + voiceAdmissionContainerIdentity(p)
	}
	for _, p := range b {
		if ids[string(p.UID)] != p.ResourceVersion+"\x00"+p.Status.PodIP+"\x00"+voiceAdmissionContainerIdentity(p) {
			return false
		}
	}
	return true
}

func (voiceAdmissionHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	o := req.VoiceAdmissionObservation
	if !ec.VoiceAdmissionEnabled || req.Action != model.ActionVoiceSessionAdmissionEnforce || ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || o == nil || !o.Assertion.Valid() || req.Namespace != voiceadmissionpolicy.Namespace || o.TargetPodUID != req.TargetUID || o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration || o.CreatorIdentity != eventtrust.Injector() {
		return HandlerResult{}, errors.New("Voice admission selection authority incomplete")
	}
	opID, e := voiceadmissionpolicy.OperationID(o.DeploymentUID, o.ConfigMapUID, req.PolicyUID, req.PolicyGeneration, o.EventUID, req.TickID, req.OperationID, o.RuleSHA256)
	if e != nil {
		return HandlerResult{}, e
	}
	target := Target{Namespace: req.Namespace, Pod: req.Pod, UID: req.TargetUID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID}
	s, e := voiceAdmissionScopeAt(ctx, ec.Reader, target)
	if e != nil {
		return HandlerResult{}, e
	}
	jcm, j, e := voiceAdmissionJournalGet(ctx, ec.Reader, ec.JournalNamespace)
	if e != nil || !voiceAdmissionJournalMatchesRule(j, s.rule) {
		return HandlerResult{}, errors.New("Voice admission prior protected history unavailable or changed")
	}
	if len(j.Receipts) > 0 {
		r := j.Receipts[0]
		if r.OperationID != opID || r.EventUID != o.EventUID || r.TargetPodUID != req.TargetUID || r.ConfigMapUID != o.ConfigMapUID || r.SessionID != o.SessionID || r.ReceiptSHA256 != o.Assertion.ReceiptSHA256 || r.ProviderEvidenceSHA256 != o.Assertion.ProviderEvidenceSHA256 {
			return HandlerResult{}, errors.New("Voice admission journal occupied by another selection")
		}
		return voiceAdmissionResume(ctx, ec, jcm, j, r)
	}
	if s.rule.Revision != 0 || string(s.deployment.UID) != o.DeploymentUID || string(s.cm.UID) != o.ConfigMapUID || s.cm.ResourceVersion != o.ConfigMapResourceVersion || s.rule.SHA256() != o.RuleSHA256 || s.source.SourceSHA256 != o.SourceSHA256 || s.policy.Generation != o.PolicyGeneration {
		return HandlerResult{}, errors.New("Voice admission selection rule/source lifetime changed")
	}
	if e = voiceAdmissionEvent(ctx, ec, req, o, s); e != nil {
		return HandlerResult{}, e
	}
	if e = voiceAdmissionObserveLive(ctx, s, ec.VoiceAdmissionTransport); e != nil {
		return HandlerResult{}, e
	}
	desired, e := voiceadmissionpolicy.Enforce(s.rule, opID)
	if e != nil {
		return HandlerResult{}, e
	}
	r := voiceadmissionpolicy.Receipt{Version: 1, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, DeploymentUID: o.DeploymentUID, TargetName: req.Pod, TargetPodUID: req.TargetUID, EventName: o.EventName, EventUID: o.EventUID, CreatorIdentity: o.CreatorIdentity, TickID: req.TickID, SelectionDecisionID: req.OperationID, ConfigMapUID: o.ConfigMapUID, SourceConfigMapUID: s.source.ConfigMapUID, SessionID: o.SessionID, RunSHA256: o.Assertion.RunSHA256, ReceiptSHA256: o.Assertion.ReceiptSHA256, ProviderEvidenceSHA256: o.Assertion.ProviderEvidenceSHA256, Prior: s.rule, Desired: desired, OperationID: opID, PodReceipts: []voiceadmissionpolicy.State{}}
	if e = voiceAdmissionSession(ctx, s, r, false, ec.VoiceAdmissionTransport); e != nil {
		return HandlerResult{}, e
	}
	j.Receipts = append(j.Receipts, r)
	if _, e = voiceadmissionpolicy.ParseJournal(string(j.Bytes())); e != nil {
		return HandlerResult{}, e
	}
	copy := jcm.DeepCopy()
	copy.Data["receipts.json"] = string(j.Bytes())
	if e = ec.Client.Update(ctx, copy); e != nil {
		return HandlerResult{MutationKind: "partial", Note: "Voice admission journal reservation acknowledgment unresolved; policy not written"}, e
	}
	return voiceAdmissionResume(ctx, ec, copy, j, r)
}

func recoverVoiceAdmissionOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	cm, j, e := voiceAdmissionJournalGet(ctx, ec.Reader, ec.JournalNamespace)
	if apierrors.IsNotFound(e) {
		return nil, nil
	}
	if e != nil {
		return []RecoveryEvent{{Receipt: voiceadmissionpolicy.JournalName, Kind: string(model.ActionVoiceSessionAdmissionEnforce), Outcome: "refused", Err: e}}, nil
	}
	if len(j.Receipts) == 0 || j.Receipts[0].Phase != "prepared" {
		return nil, nil
	}
	r := j.Receipts[0]
	ev := RecoveryEvent{Receipt: voiceadmissionpolicy.JournalName, Kind: string(model.ActionVoiceSessionAdmissionEnforce), Phase: r.Phase, Tenant: voiceadmissionpolicy.Namespace, PolicyNamespace: voiceadmissionpolicy.Namespace, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.TargetName, TargetUID: r.TargetPodUID, Outcome: "refused"}
	if !ec.VoiceAdmissionEnabled || (allow != nil && !allow(model.ActionVoiceSessionAdmissionEnforce)) {
		ev.Err = errors.New("Voice admission recovery routed away from native")
	} else {
		_, ev.Err = voiceAdmissionResume(ctx, ec, cm, j, r)
	}
	if ev.Err == nil {
		ev.Outcome = "confirmed"
		ev.Effect = "Voice admission all-serving-Pod local teardown barrier confirmed"
	} else {
		ev.Outcome = "partial"
	}
	return []RecoveryEvent{ev}, nil
}
