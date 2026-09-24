package scenarios

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// This file owns only exact fixture teardown. The protected Phorvex capacity
// ledger is not a fixture object: removing its reservation requires the
// operator's separate, quiesced administrative reconciliation protocol.
const natsResponseCleanupJournalLimit = 64 << 10

type natsResponseCleanupPhase struct {
	Schema       string    `json:"schema"`
	RunID        string    `json:"runId"`
	Nonce        string    `json:"nonce"`
	NamespaceUID types.UID `json:"namespaceUID"`
	Phase        string    `json:"phase"`
	Resource     string    `json:"resource"`
	Name         string    `json:"name"`
	UID          types.UID `json:"uid,omitempty"`
	At           string    `json:"at"`
}

type natsResponseCreateState struct {
	intent  bool
	created types.UID
}

func natsResponseCleanupPhases(out, runID, nonce string, nsUID types.UID) (map[string]natsResponseCreateState, error) {
	path := filepath.Join(out, "nats-response-phases.jsonl")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > natsResponseCleanupJournalLimit {
		return nil, errors.New("response phase journal is not bounded regular data")
	}
	raw, err := io.ReadAll(io.LimitReader(f, natsResponseCleanupJournalLimit+1))
	if err != nil || int64(len(raw)) != info.Size() || raw[len(raw)-1] != '\n' {
		return nil, errors.New("response phase journal read is incomplete")
	}
	states := make(map[string]natsResponseCreateState, 5)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		var row natsResponseCleanupPhase
		if json.Unmarshal(scanner.Bytes(), &row) != nil || row.Schema != natsResponseSchema || row.RunID != runID ||
			row.Nonce != nonce || row.NamespaceUID != nsUID || row.Name == "" || row.Phase == "" || row.Resource == "" {
			return nil, errors.New("response phase journal identity differs")
		}
		if _, err := time.Parse(time.RFC3339Nano, row.At); err != nil {
			return nil, errors.New("response phase journal timestamp invalid")
		}
		if row.Name != natsResponseName(nonce) || !natsResponseCreatedResource(row.Resource) {
			continue // role patch and other known bounded phases carry no create authority
		}
		state := states[row.Resource]
		switch row.Phase {
		case "CREATE_INTENT":
			if state.intent || row.UID != "" {
				return nil, errors.New("response create intent repeated or already bound")
			}
			state.intent = true
		case "CREATED":
			if !state.intent || state.created != "" || row.UID == "" {
				return nil, errors.New("response create receipt lacks one preceding intent")
			}
			state.created = row.UID
		default:
			continue
		}
		states[row.Resource] = state
	}
	if scanner.Err() != nil {
		return nil, errors.New("response phase journal record exceeds bound")
	}
	return states, nil
}

func natsResponseCreatedResource(resource string) bool {
	switch resource {
	case "configmaps", "services", "poddisruptionbudgets", "phorvexpolicies", "deployments":
		return true
	}
	return false
}

func natsResponseCreateAuthority(states map[string]natsResponseCreateState, resource string, uid types.UID) error {
	state := states[resource]
	if state.intent && state.created == "" {
		return fmt.Errorf("%s create response was ambiguous", resource)
	}
	if uid != state.created {
		return fmt.Errorf("%s create UID and durable receipt differ", resource)
	}
	return nil
}

type natsResponseCleanupWhy struct {
	Schema         string                `json:"schema"`
	RunID          string                `json:"runId"`
	NamespaceUID   types.UID             `json:"namespaceUID"`
	ClientPodUID   types.UID             `json:"clientPodUID"`
	PolicyUID      types.UID             `json:"policyUID"`
	EventName      string                `json:"eventName"`
	EventUID       types.UID             `json:"eventUID"`
	SelectedAction string                `json:"selectedAction"`
	ObjectEffect   *natsResponseEffectID `json:"objectEffect,omitempty"`
}

type natsResponseEffectID struct {
	GeneratedEventName       string    `json:"generatedEventName"`
	GeneratedEventUID        types.UID `json:"generatedEventUID"`
	OperationID              string    `json:"operationID"`
	AMTDName                 string    `json:"amtdName"`
	AMTDUID                  types.UID `json:"amtdUID"`
	PhoenixNetworkPolicyName string    `json:"phoenixNetworkPolicyName"`
	PhoenixNetworkPolicyUID  types.UID `json:"phoenixNetworkPolicyUID"`
	SourcePodUID             types.UID `json:"sourcePodUID"`
	PeerPodUID               types.UID `json:"peerPodUID"`
}

func natsResponseCleanupEffect(out string, env *core.Env, fixture natsResponseFixture, d *natsResponseSignalDecision) (*natsResponseEffectID, error) {
	if d == nil {
		return nil, nil
	}
	if d.RunID != env.Config.NATSExposureFixture.RunID || d.Nonce != env.Config.NATSExposureFixture.Nonce ||
		d.NamespaceUID != fixture.NamespaceUID || d.ClientPodUID != fixture.Client.UID || d.PeerPodUID != fixture.Peer.UID ||
		d.PolicyUID != fixture.PolicyUID || d.EventUID == "" || d.EventName == "" || d.DecisionEvidenceSHA256 == "" {
		return nil, errors.New("response decision cleanup authority differs")
	}
	raw, err := natsResponseCleanupReadPrivate(out, "nats-response-decision-evidence.json", 32<<10)
	if err != nil || natsSHA(raw) != d.DecisionEvidenceSHA256 {
		return nil, errors.New("response decision evidence digest differs")
	}
	var why natsResponseCleanupWhy
	if natsResponseCleanupNoDuplicates(raw) != nil || json.Unmarshal(raw, &why) != nil || why.Schema != "nats-client-response-decision-evidence-v1" ||
		why.RunID != d.RunID || why.NamespaceUID != fixture.NamespaceUID || why.ClientPodUID != fixture.Client.UID ||
		why.PolicyUID != fixture.PolicyUID || why.EventName != d.EventName || why.EventUID != d.EventUID ||
		why.SelectedAction != d.SelectedAction {
		return nil, errors.New("response decision evidence identity differs")
	}
	if d.SelectedAction != "quarantine" {
		if why.ObjectEffect != nil {
			return nil, errors.New("response no-op carries quarantine object effect")
		}
		return nil, nil
	}
	e := why.ObjectEffect
	if e == nil || e.GeneratedEventName == "" || e.GeneratedEventUID == "" || e.AMTDUID == "" || e.PhoenixNetworkPolicyUID == "" ||
		e.AMTDName != "phorvex-"+env.Config.Namespace+"-"+d.Nonce ||
		e.PhoenixNetworkPolicyName != amtdv1beta1.QuarantineNetworkPolicyName(env.Config.Namespace, fixture.Client.Name) ||
		e.SourcePodUID != fixture.Client.UID || e.PeerPodUID != fixture.Peer.UID || len(e.OperationID) != 40 {
		return nil, errors.New("response Phoenix child authority differs")
	}
	return e, nil
}

func natsResponseCleanupReadPrivate(out, name string, limit int64) ([]byte, error) {
	path := filepath.Join(out, name)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("response evidence is not bounded regular data")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errors.New("response evidence has another link")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) != before.Size() {
		return nil, errors.New("response evidence read incomplete")
	}
	afterFD, err := f.Stat()
	if err != nil || !os.SameFile(before, afterFD) || before.Size() != afterFD.Size() || !before.ModTime().Equal(afterFD.ModTime()) {
		return nil, errors.New("response evidence changed during read")
	}
	afterPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, afterPath) || !afterPath.Mode().IsRegular() {
		return nil, errors.New("response evidence path changed")
	}
	return raw, nil
}

func natsResponseCleanupNoDuplicates(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("response evidence nesting exceeded")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyTok, err := d.Token()
				key, ok := keyTok.(string)
				if err != nil || !ok || seen[key] {
					return errors.New("response evidence JSON key ambiguous")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("response evidence object incomplete")
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("response evidence array incomplete")
			}
		default:
			return errors.New("response evidence delimiter invalid")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("response evidence trailing data")
	}
	return nil
}

// natsResponseExactDelete verifies fresh identity, dispatches one UID+RV
// preconditioned delete, then proves exact-name absence. A replacement or
// ambiguous delete is never silently adopted or retried.
func natsResponseExactDelete(ctx context.Context, kind, name string, uid types.UID,
	get func(context.Context) (types.UID, string, error), remove func(context.Context, types.UID, string) error) error {
	if uid == "" || name == "" {
		return fmt.Errorf("%s cleanup lacks create-response identity", kind)
	}
	current, rv, err := get(ctx)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || current != uid || rv == "" {
		return fmt.Errorf("%s cleanup current identity differs or unavailable", kind)
	}
	if err := remove(ctx, uid, rv); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("%s UID-preconditioned delete unconfirmed: %w", kind, err)
	}
	for {
		current, _, err = get(ctx)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil || current != uid {
			return fmt.Errorf("%s absence or replacement unknown", kind)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s absence deadline: %w", kind, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func natsResponseDeleteOptions(uid types.UID, rv string) metav1.DeleteOptions {
	return metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
}

func natsResponseControllerOwner(refs []metav1.OwnerReference, kind, name string, uid types.UID) bool {
	return len(refs) == 1 && refs[0].APIVersion != "" && refs[0].Kind == kind && refs[0].Name == name &&
		refs[0].UID == uid && refs[0].Controller != nil && *refs[0].Controller
}

func natsResponseOwnedLabels(labels map[string]string, nonce string) bool {
	return labels[natsResponseOwnerLabel] == nonce && labels[core.OwnedLabelKey] == core.OwnedLabelValue &&
		labels[core.ScenarioLabelKey] == natsResponseScenario && labels[core.TrialLabelKey] == "0"
}

// Phoenix moves the source Pod's non-selector labels into annotations when it
// reparents that exact incarnation to the AMTD. The peer and any replacement
// remain ReplicaSet children and must retain the complete fixture labels.
func natsResponseCleanupPodOwned(pod *corev1.Pod, f natsResponseFixture, rsName string, e *natsResponseEffectID, nonce string) bool {
	if pod.UID == "" || pod.Labels[natsResponseOwnerLabel] != nonce {
		return false
	}
	if pod.Name == f.Client.Name && pod.UID == f.Client.UID && e != nil {
		return pod.Labels[natsResponseRoleLabel] == "source" &&
			pod.Labels["amtd.r6security.com/network-policy"] == e.PhoenixNetworkPolicyName &&
			pod.Annotations[core.OwnedLabelKey] == core.OwnedLabelValue &&
			pod.Annotations[core.ScenarioLabelKey] == natsResponseScenario &&
			pod.Annotations[core.TrialLabelKey] == "0" &&
			pod.Annotations[natsResponseComponentLabel] == "consumer" &&
			natsResponseControllerOwner(pod.OwnerReferences, "AdaptiveMovingTargetDefense", e.AMTDName, e.AMTDUID) &&
			pod.OwnerReferences[0].APIVersion == "amtd.r6security.com/v1beta1"
	}
	return natsResponseOwnedLabels(pod.Labels, nonce) &&
		natsResponseControllerOwner(pod.OwnerReferences, "ReplicaSet", rsName, f.ReplicaSetUID) &&
		pod.OwnerReferences[0].APIVersion == "apps/v1"
}

func natsResponseCleanupPhoenixIdentity(ctx context.Context, env *core.Env, f natsResponseFixture, e *natsResponseEffectID) error {
	if e == nil {
		return nil
	}
	ns, nonce := env.Config.Namespace, env.Config.NATSExposureFixture.Nonce
	var event amtdv1beta1.SecurityEvent
	if err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Name: e.GeneratedEventName}, &event); err != nil {
		return fmt.Errorf("generated Phoenix event identity unavailable: %w", err)
	}
	if event.UID != e.GeneratedEventUID || event.DeletionTimestamp != nil ||
		event.Labels["app.kubernetes.io/managed-by"] != "phorvex" || event.Labels["phorvex.ai/tenant"] != nonce ||
		event.Labels["phorvex.ai/action"] != "quarantine" ||
		event.Annotations["phorvex.ai/quarantine-target-uid"] != string(f.Client.UID) ||
		event.Annotations["phorvex.ai/quarantine-namespace-uid"] != string(f.NamespaceUID) ||
		event.Annotations["phorvex.ai/quarantine-operation"] != e.OperationID ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != ns+"/"+f.Client.Name ||
		event.Spec.Rule.Type != "phorvex.quarantine" || event.Spec.Rule.Source != "PhorvexController" ||
		event.Spec.Rule.ThreatLevel != "high" {
		return errors.New("generated Phoenix event differs from exact response effect")
	}
	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	if err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: e.AMTDName}, &amtd); err != nil {
		return fmt.Errorf("owned AMTD identity unavailable: %w", err)
	}
	if amtd.UID != e.AMTDUID || amtd.DeletionTimestamp != nil ||
		amtd.Labels["app.kubernetes.io/managed-by"] != "phorvex" || amtd.Labels["phorvex.ai/tenant"] != nonce ||
		amtd.Annotations["phorvex.ai/policy-uid"] != string(f.PolicyUID) {
		return errors.New("owned AMTD identity changed")
	}
	np, err := env.Kube.NetworkingV1().NetworkPolicies(ns).Get(ctx, e.PhoenixNetworkPolicyName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Phoenix deny policy identity unavailable: %w", err)
	}
	if np.UID != e.PhoenixNetworkPolicyUID || np.DeletionTimestamp != nil ||
		!natsResponseControllerOwner(np.OwnerReferences, "AdaptiveMovingTargetDefense", e.AMTDName, e.AMTDUID) ||
		np.OwnerReferences[0].APIVersion != "amtd.r6security.com/v1beta1" ||
		len(np.Spec.PodSelector.MatchLabels) != 1 || np.Spec.PodSelector.MatchLabels["amtd.r6security.com/network-policy"] != e.PhoenixNetworkPolicyName ||
		len(np.Spec.PodSelector.MatchExpressions) != 0 || len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 || !natsResponseBothNPTypes(np.Spec.PolicyTypes) {
		return errors.New("Phoenix deny policy owner or shape changed")
	}
	pod, err := env.Kube.CoreV1().Pods(ns).Get(ctx, f.Client.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("quarantined source identity unavailable: %w", err)
	}
	if pod.UID != f.Client.UID || pod.Labels["amtd.r6security.com/network-policy"] != e.PhoenixNetworkPolicyName ||
		!natsResponseControllerOwner(pod.OwnerReferences, "AdaptiveMovingTargetDefense", e.AMTDName, e.AMTDUID) ||
		pod.OwnerReferences[0].APIVersion != "amtd.r6security.com/v1beta1" {
		return errors.New("quarantined source ownership changed")
	}
	return nil
}

func natsResponseBothNPTypes(types []networkingv1.PolicyType) bool {
	return len(types) == 2 &&
		(types[0] == networkingv1.PolicyTypeIngress && types[1] == networkingv1.PolicyTypeEgress ||
			types[0] == networkingv1.PolicyTypeEgress && types[1] == networkingv1.PolicyTypeIngress)
}

type natsResponseStandingAMTD struct {
	Name string
	UID  types.UID
}

func natsResponseCaptureStandingAMTD(ctx context.Context, env *core.Env, f natsResponseFixture) (natsResponseStandingAMTD, error) {
	var identity natsResponseStandingAMTD
	ns, nonce := env.Config.Namespace, env.Config.NATSExposureFixture.Nonce
	identity.Name = "phorvex-" + ns + "-" + nonce
	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	if err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: identity.Name}, &amtd); err != nil {
		return identity, fmt.Errorf("response standing AMTD unavailable: %w", err)
	}
	if amtd.UID == "" || amtd.DeletionTimestamp != nil ||
		amtd.Labels["app.kubernetes.io/managed-by"] != "phorvex" || amtd.Labels["phorvex.ai/tenant"] != nonce ||
		amtd.Annotations["phorvex.ai/identity-version"] != "v1" ||
		amtd.Annotations["phorvex.ai/namespace-raw"] != ns || amtd.Annotations["phorvex.ai/tenant-raw"] != nonce ||
		amtd.Annotations["phorvex.ai/policy-name"] != f.Name ||
		amtd.Annotations["phorvex.ai/policy-uid"] != string(f.PolicyUID) ||
		amtd.Annotations["phorvex.ai/policy-generation"] != fmt.Sprint(f.PolicyGen) ||
		!reflect.DeepEqual(amtd.Spec.PodSelector, map[string]string{natsResponseOwnerLabel: nonce, natsResponseRoleLabel: "source"}) ||
		amtd.Spec.MatcherMode != amtdv1beta1.MatcherModeExact || len(amtd.Spec.Strategy) != 2 ||
		!reflect.DeepEqual(amtd.Spec.Strategy[0].Rule, amtdv1beta1.Rule{Type: "phorvex.rotate", ThreatLevel: "high", Source: "PhorvexController"}) ||
		!reflect.DeepEqual(amtd.Spec.Strategy[0].Action, amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}}) ||
		!reflect.DeepEqual(amtd.Spec.Strategy[1].Rule, amtdv1beta1.Rule{Type: "phorvex.quarantine", ThreatLevel: "high", Source: "PhorvexController"}) ||
		!reflect.DeepEqual(amtd.Spec.Strategy[1].Action, amtdv1beta1.AMTDAction{Quarantine: &amtdv1beta1.QuarantineAction{}}) {
		return identity, errors.New("response standing AMTD source authority differs")
	}
	identity.UID = amtd.UID
	return identity, nil
}

type natsResponseCleanupChildren struct {
	RSName string
	Pods   []natsResponsePodIdentity
}

func natsResponseCleanupOne(ctx context.Context, env *core.Env, resource, name string, uid types.UID,
	get func(context.Context) (types.UID, string, error), remove func(context.Context, types.UID, string) error) error {
	err := natsResponseExactDelete(ctx, resource, name, uid, get, func(ctx context.Context, uid types.UID, rv string) error {
		if err := natsResponsePhase(env, "DELETE_INTENT", resource, name, uid); err != nil {
			return err
		}
		return remove(ctx, uid, rv)
	})
	if err != nil {
		return err
	}
	if err := natsResponsePhase(env, "DELETE_ABSENT", resource, name, uid); err != nil {
		return err
	}
	if natsResponseCreatedResource(resource) {
		return env.ForgetCreatedUID(resource, name, uid)
	}
	return nil
}

func natsResponseCleanupStreams(out string, f natsResponseFixture, receipts [2]natsexposure.Receipt, runID, nonce string) bool {
	subjects := natsResponseSubjects(nonce)
	for i, phase := range [2]string{"M0", "M1"} {
		r := receipts[i]
		name := "CAT_" + nonce + "_" + phase
		if r.Stream != name || r.Subject != subjects[i] || r.Consumer != name+"_C" || r.Nonce != nonce ||
			r.Cleanup != "CONFIRMED_ABSENT" || r.StreamCreatedUTC == "" {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, r.StreamCreatedUTC); err != nil {
			return false
		}
	}
	return natsResponseCleanupProtocolJournal(out, f, receipts, runID, nonce)
}

type natsResponseProtocolRow struct {
	Schema       string               `json:"schema"`
	RunID        string               `json:"runId"`
	NamespaceUID types.UID            `json:"namespaceUID"`
	Phase        string               `json:"phase"`
	Receipt      natsexposure.Receipt `json:"receipt"`
	At           string               `json:"at"`
}

func natsResponseCleanupProtocolJournal(out string, f natsResponseFixture, receipts [2]natsexposure.Receipt, runID, nonce string) bool {
	path := filepath.Join(out, "nats-response-protocol.jsonl")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128<<10 {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(file, 128<<10+1))
	if err != nil || int64(len(raw)) != info.Size() || raw[len(raw)-1] != '\n' {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 4096)
	last := [2]*natsexposure.Receipt{}
	for scanner.Scan() {
		var row natsResponseProtocolRow
		if json.Unmarshal(scanner.Bytes(), &row) != nil || row.Schema != natsResponseSchema || row.RunID != runID || row.NamespaceUID != f.NamespaceUID ||
			row.Receipt.Nonce != nonce || row.Receipt.Stream == "" || (row.Phase != "M0" && row.Phase != "M1") {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, row.At); err != nil {
			return false
		}
		index := 0
		if row.Phase == "M1" {
			index = 1
		}
		copy := row.Receipt
		last[index] = &copy
	}
	return scanner.Err() == nil && last[0] != nil && last[1] != nil &&
		reflect.DeepEqual(*last[0], receipts[0]) && reflect.DeepEqual(*last[1], receipts[1])
}

// A terminal decision is the only proof that an accepted signal is no longer
// driving the Phoenix target. When no signal request was even published, the
// early-exit path can retire acknowledged fixture UIDs; an ambiguous CREATE
// remains debt and never authorizes same-name adoption.
func natsResponseNoSignalRequest(out string) bool {
	_, err := os.Lstat(filepath.Join(out, "nats-response-signal-request.json"))
	return errors.Is(err, os.ErrNotExist)
}

func natsResponseCleanupEarly(ctx context.Context, env *core.Env, f natsResponseFixture) error {
	ns, nonce, name := env.Config.Namespace, env.Config.NATSExposureFixture.Nonce, f.Name
	var problems []error
	deleteKnown := func(resource string, uid types.UID, get func(context.Context) (types.UID, string, error),
		remove func(context.Context, types.UID, string) error) {
		if uid == "" {
			return
		}
		if err := natsResponseCleanupOne(ctx, env, resource, name, uid, get, remove); err != nil {
			problems = append(problems, err)
		}
	}
	deleteKnown("deployments", f.DeploymentUID,
		func(ctx context.Context) (types.UID, string, error) {
			obj, err := env.Kube.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(obj.Labels, nonce) {
				return "", "", errors.New("early Deployment owner changed")
			}
			return obj.UID, obj.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.AppsV1().Deployments(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		})
	deleteKnown("phorvexpolicies", f.PolicyUID,
		func(ctx context.Context) (types.UID, string, error) {
			obj := &unstructured.Unstructured{}
			obj.SetGroupVersionKind(natsResponsePolicyGVK)
			err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: name}, obj)
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(obj.GetLabels(), nonce) {
				return "", "", errors.New("early policy owner changed")
			}
			return obj.GetUID(), obj.GetResourceVersion(), nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			obj := &unstructured.Unstructured{}
			obj.SetGroupVersionKind(natsResponsePolicyGVK)
			obj.SetNamespace(ns)
			obj.SetName(name)
			return env.Ctrl.Delete(ctx, obj, &ctrlclient.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
		})
	deleteKnown("services", f.ServiceUID,
		func(ctx context.Context) (types.UID, string, error) {
			obj, err := env.Kube.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(obj.Labels, nonce) {
				return "", "", errors.New("early Service owner changed")
			}
			return obj.UID, obj.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.CoreV1().Services(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		})
	deleteKnown("poddisruptionbudgets", f.PDBUID,
		func(ctx context.Context) (types.UID, string, error) {
			obj, err := env.Kube.PolicyV1().PodDisruptionBudgets(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(obj.Labels, nonce) {
				return "", "", errors.New("early PDB owner changed")
			}
			return obj.UID, obj.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.PolicyV1().PodDisruptionBudgets(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		})
	deleteKnown("configmaps", f.ConfigMapUID,
		func(ctx context.Context) (types.UID, string, error) {
			obj, err := env.Kube.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(obj.Labels, nonce) {
				return "", "", errors.New("early ConfigMap owner changed")
			}
			return obj.UID, obj.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.CoreV1().ConfigMaps(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		})
	return errors.Join(problems...)
}

// natsResponseCleanup runs with the caller's detached, finite cleanup context.
// It never adopts an unacknowledged CREATE, retries a mutation, deletes a
// shared NATS object, or edits the protected quarantine capacity ledger.
func natsResponseCleanup(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	decision *natsResponseSignalDecision, protocols [2]natsexposure.Receipt) (natsResponseCleanupChecks, error) {
	var checks natsResponseCleanupChecks
	if env == nil || env.Config.NATSExposureFixture == nil || env.Kube == nil || env.Ctrl == nil ||
		env.Config.Namespace != natsResponseFixtureNamespace || fixture.NamespaceUID == "" ||
		fixture.NamespaceUID != env.NamespaceUID() || fixture.Name != natsResponseName(env.Config.NATSExposureFixture.Nonce) {
		return checks, errors.New("NATS response cleanup authority incomplete")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return checks, err
	}
	ns, nonce, name := env.Config.Namespace, env.Config.NATSExposureFixture.Nonce, fixture.Name
	namespace, err := env.Kube.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil || namespace.UID != fixture.NamespaceUID || namespace.DeletionTimestamp != nil ||
		namespace.Labels["phorvex.ai/nats-exposure-fixture"] != "true" {
		return checks, errors.New("NATS response cleanup namespace identity changed")
	}
	checks.NamespacePreserved = true
	if decision == nil {
		if !natsResponseNoSignalRequest(env.Config.OutDir) {
			return checks, errors.New("response signal may be active without a terminal decision; cleanup withheld")
		}
		earlyErr := natsResponseCleanupEarly(ctx, env, fixture)
		return checks, errors.Join(errors.New("response fixture never reached an exact terminal decision; cleanup and capacity remain unconfirmed"), earlyErr)
	}
	states, journalErr := natsResponseCleanupPhases(env.Config.OutDir, env.Config.NATSExposureFixture.RunID, nonce, fixture.NamespaceUID)
	if journalErr != nil {
		return checks, fmt.Errorf("NATS response cleanup phase journal unavailable: %w", journalErr)
	}
	for resource, uid := range map[string]types.UID{"configmaps": fixture.ConfigMapUID, "services": fixture.ServiceUID,
		"poddisruptionbudgets": fixture.PDBUID, "phorvexpolicies": fixture.PolicyUID, "deployments": fixture.DeploymentUID} {
		if err := natsResponseCreateAuthority(states, resource, uid); err != nil {
			return checks, err // an ambiguous CREATE has no safe deletion authority
		}
	}
	if fixture.ConfigMapUID == "" || fixture.ServiceUID == "" || fixture.PDBUID == "" || fixture.PolicyUID == "" ||
		fixture.DeploymentUID == "" || fixture.ReplicaSetUID == "" || fixture.Client.UID == "" || fixture.Peer.UID == "" {
		return checks, errors.New("NATS response cleanup fixture create identities incomplete")
	}
	effect, err := natsResponseCleanupEffect(env.Config.OutDir, env, fixture, decision)
	if err != nil {
		return checks, err
	}
	if decision.EventCleanupStatus != "CONFIRMED_ABSENT" || decision.SelectedAction != "noop" && decision.SelectedAction != "quarantine" {
		return checks, errors.New("NATS response injected event or decision not terminal")
	}
	children, err := captureNATSResponseChildren(ctx, env, fixture, effect)
	if err != nil {
		return checks, err
	}
	if err := natsResponseCleanupPhoenixIdentity(ctx, env, fixture, effect); err != nil {
		return checks, err // capture generated event, AMTD and NP before any policy deletion
	}
	standing, err := natsResponseCaptureStandingAMTD(ctx, env, fixture)
	if err != nil || effect != nil && effect.AMTDUID != standing.UID {
		return checks, errors.New("response standing AMTD UID or source authority unconfirmed")
	}
	checks.StreamsAbsent = natsResponseCleanupStreams(env.Config.OutDir, fixture, protocols, env.Config.NATSExposureFixture.RunID, nonce)
	if !checks.StreamsAbsent {
		return checks, errors.New("NATS response exact stream cleanup receipts incomplete")
	}
	var problems []error
	appendProblem := func(err error) {
		if err != nil {
			problems = append(problems, err)
		}
	}

	// Stop any pending Phoenix reconciliation before tearing down its target.
	if effect != nil {
		e := effect
		appendProblem(natsResponseCleanupOne(ctx, env, "securityevents", e.GeneratedEventName, e.GeneratedEventUID,
			func(ctx context.Context) (types.UID, string, error) {
				var event amtdv1beta1.SecurityEvent
				err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Name: e.GeneratedEventName}, &event)
				if err != nil {
					return "", "", err
				}
				if event.Annotations["phorvex.ai/quarantine-target-uid"] != string(fixture.Client.UID) ||
					event.Annotations["phorvex.ai/quarantine-operation"] != e.OperationID {
					return "", "", errors.New("generated event envelope changed")
				}
				return event.UID, event.ResourceVersion, nil
			},
			func(ctx context.Context, uid types.UID, rv string) error {
				obj := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: e.GeneratedEventName}}
				return env.Ctrl.Delete(ctx, obj, &ctrlclient.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
			}))
		if len(problems) > 0 {
			return checks, errors.Join(problems...)
		}
	}
	var injected amtdv1beta1.SecurityEvent
	err = env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Name: decision.EventName}, &injected)
	checks.SecurityEventAbsent = apierrors.IsNotFound(err)
	if !checks.SecurityEventAbsent {
		return checks, errors.New("NATS response injected SecurityEvent absence unconfirmed")
	}
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(natsResponsePolicyGVK)
	policy.SetNamespace(ns)
	policy.SetName(name)
	appendProblem(natsResponseCleanupOne(ctx, env, "phorvexpolicies", name, fixture.PolicyUID,
		func(ctx context.Context) (types.UID, string, error) {
			current := policy.DeepCopy()
			err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: name}, current)
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(current.GetLabels(), nonce) || current.GetGeneration() != fixture.PolicyGen {
				return "", "", errors.New("response policy authority changed")
			}
			return current.GetUID(), current.GetResourceVersion(), nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Ctrl.Delete(ctx, policy, &ctrlclient.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
		}))
	checks.PolicyAbsent = len(problems) == 0
	if !checks.PolicyAbsent {
		return checks, errors.Join(problems...)
	}

	appendProblem(natsResponseCleanupOne(ctx, env, "deployments", name, fixture.DeploymentUID,
		func(ctx context.Context) (types.UID, string, error) {
			dep, err := env.Kube.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(dep.Labels, nonce) {
				return "", "", errors.New("response Deployment labels changed")
			}
			return dep.UID, dep.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.AppsV1().Deployments(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		}))
	checks.DeploymentAbsent = len(problems) == 0
	if !checks.DeploymentAbsent {
		return checks, errors.Join(problems...)
	}

	appendProblem(natsResponseCleanupOne(ctx, env, "replicasets", children.RSName, fixture.ReplicaSetUID,
		func(ctx context.Context) (types.UID, string, error) {
			rs, err := env.Kube.AppsV1().ReplicaSets(ns).Get(ctx, children.RSName, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseControllerOwner(rs.OwnerReferences, "Deployment", name, fixture.DeploymentUID) ||
				!natsResponseOwnedLabels(rs.Labels, nonce) {
				return "", "", errors.New("response ReplicaSet authority changed")
			}
			return rs.UID, rs.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.AppsV1().ReplicaSets(ns).Delete(ctx, children.RSName, natsResponseDeleteOptions(uid, rv))
		}))
	checks.ReplicaSetAbsent = len(problems) == 0
	if !checks.ReplicaSetAbsent {
		return checks, errors.Join(problems...)
	}

	for _, child := range children.Pods {
		child := child
		appendProblem(natsResponseCleanupOne(ctx, env, "pods", child.Name, child.UID,
			func(ctx context.Context) (types.UID, string, error) {
				pod, err := env.Kube.CoreV1().Pods(ns).Get(ctx, child.Name, metav1.GetOptions{})
				if err != nil {
					return "", "", err
				}
				if !natsResponseCleanupPodOwned(pod, fixture, children.RSName, effect, nonce) {
					return "", "", errors.New("response Pod ownership changed")
				}
				return pod.UID, pod.ResourceVersion, nil
			},
			func(ctx context.Context, uid types.UID, rv string) error {
				return env.Kube.CoreV1().Pods(ns).Delete(ctx, child.Name, natsResponseDeleteOptions(uid, rv))
			}))
	}
	checks.OriginalPodsAbsent = len(problems) == 0
	if !checks.OriginalPodsAbsent {
		return checks, errors.Join(problems...)
	}
	if effect != nil {
		e := effect
		appendProblem(natsResponseCleanupOne(ctx, env, "networkpolicies", e.PhoenixNetworkPolicyName, e.PhoenixNetworkPolicyUID,
			func(ctx context.Context) (types.UID, string, error) {
				np, err := env.Kube.NetworkingV1().NetworkPolicies(ns).Get(ctx, e.PhoenixNetworkPolicyName, metav1.GetOptions{})
				if err != nil {
					return "", "", err
				}
				if !natsResponseControllerOwner(np.OwnerReferences, "AdaptiveMovingTargetDefense", e.AMTDName, e.AMTDUID) {
					return "", "", errors.New("Phoenix NP owner changed")
				}
				return np.UID, np.ResourceVersion, nil
			},
			func(ctx context.Context, uid types.UID, rv string) error {
				return env.Kube.NetworkingV1().NetworkPolicies(ns).Delete(ctx, e.PhoenixNetworkPolicyName, natsResponseDeleteOptions(uid, rv))
			}))
	}
	appendProblem(natsResponseCleanupOne(ctx, env, "adaptivemovingtargetdefenses", standing.Name, standing.UID,
		func(ctx context.Context) (types.UID, string, error) {
			var amtd amtdv1beta1.AdaptiveMovingTargetDefense
			err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: standing.Name}, &amtd)
			if err != nil {
				return "", "", err
			}
			if amtd.Annotations["phorvex.ai/policy-uid"] != string(fixture.PolicyUID) {
				return "", "", errors.New("AMTD policy owner changed")
			}
			return amtd.UID, amtd.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			obj := &amtdv1beta1.AdaptiveMovingTargetDefense{ObjectMeta: metav1.ObjectMeta{Name: standing.Name, Namespace: ns}}
			return env.Ctrl.Delete(ctx, obj, &ctrlclient.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
		}))
	checks.PhoenixChildrenAbsent = len(problems) == 0
	if !checks.PhoenixChildrenAbsent {
		return checks, errors.Join(problems...)
	}
	appendProblem(natsResponseCleanupOne(ctx, env, "services", name, fixture.ServiceUID,
		func(ctx context.Context) (types.UID, string, error) {
			svc, err := env.Kube.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(svc.Labels, nonce) {
				return "", "", errors.New("response Service labels changed")
			}
			return svc.UID, svc.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.CoreV1().Services(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		}))
	checks.ServiceAbsent = len(problems) == 0
	appendProblem(natsResponseCleanupOne(ctx, env, "poddisruptionbudgets", name, fixture.PDBUID,
		func(ctx context.Context) (types.UID, string, error) {
			pdb, err := env.Kube.PolicyV1().PodDisruptionBudgets(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(pdb.Labels, nonce) {
				return "", "", errors.New("response PDB labels changed")
			}
			return pdb.UID, pdb.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.PolicyV1().PodDisruptionBudgets(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		}))
	checks.PDBAbsent = len(problems) == 0
	appendProblem(natsResponseCleanupOne(ctx, env, "configmaps", name, fixture.ConfigMapUID,
		func(ctx context.Context) (types.UID, string, error) {
			cm, err := env.Kube.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", "", err
			}
			if !natsResponseOwnedLabels(cm.Labels, nonce) {
				return "", "", errors.New("response ConfigMap labels changed")
			}
			return cm.UID, cm.ResourceVersion, nil
		},
		func(ctx context.Context, uid types.UID, rv string) error {
			return env.Kube.CoreV1().ConfigMaps(ns).Delete(ctx, name, natsResponseDeleteOptions(uid, rv))
		}))
	checks.ConfigMapAbsent = len(problems) == 0
	if len(problems) != 0 {
		return checks, errors.Join(problems...)
	}
	if err := natsResponseCleanupFinalInventory(ctx, env, fixture, decision, effect, standing); err != nil {
		checks.OriginalPodsAbsent = false
		checks.ReplicaSetAbsent = false
		checks.SecurityEventAbsent = false
		checks.PhoenixChildrenAbsent = false
		return checks, err
	}
	return checks, nil
}

// This terminal read catches a controller-created replacement or a delayed
// Phoenix child after the exact-name deletions. Absence here is about fixture
// objects only; it is not a protected capacity-ledger release.
func natsResponseCleanupFinalInventory(ctx context.Context, env *core.Env, f natsResponseFixture,
	d *natsResponseSignalDecision, effect *natsResponseEffectID, standing natsResponseStandingAMTD) error {
	ns, nonce := env.Config.Namespace, env.Config.NATSExposureFixture.Nonce
	selector := natsResponseOwnerLabel + "=" + nonce
	pods, err := env.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 20})
	if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil || len(pods.Items) != 0 {
		return errors.New("response nonce-labelled Pod residue or incomplete inventory")
	}
	sets, err := env.Kube.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 10})
	if err != nil || sets.Continue != "" || sets.RemainingItemCount != nil || len(sets.Items) != 0 {
		return errors.New("response nonce-labelled ReplicaSet residue or incomplete inventory")
	}
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + f.Name, Limit: 10})
	if err != nil || slices.Continue != "" || slices.RemainingItemCount != nil || len(slices.Items) != 0 {
		return errors.New("response Service EndpointSlice residue or incomplete inventory")
	}
	var injected amtdv1beta1.SecurityEvent
	err = env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Name: d.EventName}, &injected)
	if !apierrors.IsNotFound(err) {
		return errors.New("response injected event terminal absence unknown")
	}
	if effect != nil {
		var generated amtdv1beta1.SecurityEvent
		err = env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Name: effect.GeneratedEventName}, &generated)
		if !apierrors.IsNotFound(err) {
			return errors.New("response generated event terminal absence unknown")
		}
		np, err := env.Kube.NetworkingV1().NetworkPolicies(ns).Get(ctx, effect.PhoenixNetworkPolicyName, metav1.GetOptions{})
		if err == nil && np.UID != effect.PhoenixNetworkPolicyUID {
			return errors.New("response Phoenix NP name replaced")
		}
		if !apierrors.IsNotFound(err) {
			return errors.New("response Phoenix NP terminal absence unknown")
		}
	}
	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	err = env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: standing.Name}, &amtd)
	if err == nil && amtd.UID != standing.UID {
		return errors.New("response AMTD name replaced")
	}
	if !apierrors.IsNotFound(err) {
		return errors.New("response AMTD terminal absence unknown")
	}
	return nil
}

// All nonce-labelled children are included. A replacement Pod is deletable
// only through the exact original RS controller chain; the original source may
// instead be controlled by the verified AMTD after Phoenix adoption.
func captureNATSResponseChildren(ctx context.Context, env *core.Env, f natsResponseFixture, e *natsResponseEffectID) (natsResponseCleanupChildren, error) {
	var out natsResponseCleanupChildren
	ns, nonce := env.Config.Namespace, env.Config.NATSExposureFixture.Nonce
	selector := natsResponseOwnerLabel + "=" + nonce
	sets, err := env.Kube.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 10})
	if err != nil || sets.Continue != "" || sets.RemainingItemCount != nil || len(sets.Items) != 1 {
		return out, errors.New("response ReplicaSet child inventory incomplete")
	}
	rs := &sets.Items[0]
	if rs.UID != f.ReplicaSetUID || !natsResponseOwnedLabels(rs.Labels, nonce) ||
		!natsResponseControllerOwner(rs.OwnerReferences, "Deployment", f.Name, f.DeploymentUID) || rs.OwnerReferences[0].APIVersion != "apps/v1" {
		return out, errors.New("response ReplicaSet owner changed")
	}
	out.RSName = rs.Name
	pods, err := env.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 20})
	if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil || len(pods.Items) < 2 {
		return out, errors.New("response Pod child inventory incomplete")
	}
	seenClient, seenPeer := false, false
	for i := range pods.Items {
		pod := &pods.Items[i]
		switch {
		case pod.Name == f.Client.Name && pod.UID == f.Client.UID:
			seenClient = true
		case pod.Name == f.Peer.Name && pod.UID == f.Peer.UID:
			seenPeer = true
		}
		if !natsResponseCleanupPodOwned(pod, f, rs.Name, e, nonce) {
			return natsResponseCleanupChildren{}, errors.New("response labelled Pod ownership differs")
		}
		out.Pods = append(out.Pods, natsResponsePodIdentity{Name: pod.Name, UID: pod.UID})
	}
	if !seenClient || !seenPeer {
		return natsResponseCleanupChildren{}, errors.New("response original Pod absent from owned child inventory")
	}
	return out, nil
}
