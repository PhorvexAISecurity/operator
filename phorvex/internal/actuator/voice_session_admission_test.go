package actuator

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

type admissionRoundTripper func(*http.Request) (*http.Response, error)

func (f admissionRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func admissionReadbackFixture() (voiceAdmissionScope, voiceadmissionpolicy.State, voiceadmissionpolicy.SessionReceipt, voiceadmissionpolicy.Receipt) {
	uid := "11111111-1111-4111-8111-111111111111"
	sha := strings.Repeat("a", 64)
	rule := voiceadmissionpolicy.Rule{Version: 1, DeploymentUID: uid, SecurityPolicyUID: uid, WrapperCMUID: uid, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, Mode: voiceadmissionpolicy.ModeObserve}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: types.UID(uid)}, Status: corev1.PodStatus{PodIP: "192.0.2.1"}}
	s := voiceAdmissionScope{pod: &pod, cm: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), ResourceVersion: "1"}}, rule: rule, token: []byte(strings.Repeat("x", 32)), pods: []corev1.Pod{pod}}
	state := voiceadmissionpolicy.State{Version: 1, PodUID: uid, DeploymentUID: uid, PolicyCMUID: uid, PolicyResourceVersion: "1", RuleSHA256: rule.SHA256(), Mode: voiceadmissionpolicy.ModeObserve, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, ObservedAtUnixMs: time.Now().UnixMilli()}
	session := voiceadmissionpolicy.SessionReceipt{Version: 1, SessionID: uid, RunSHA256: sha, CallSIDHash: sha, PodUID: uid, DeploymentUID: uid, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, AdmissionRuleSHA256: rule.SHA256(), ConnectedAtUnixMs: time.Now().UnixMilli() - 1000, ObservedAtUnixMs: time.Now().UnixMilli(), Stage: "pipeline-observed", ReceivedAudioFrames: 2, SentAudioFrames: 3, SentAudioBytes: 960}
	r := voiceadmissionpolicy.Receipt{SessionID: uid, RunSHA256: sha, TargetPodUID: uid, DeploymentUID: uid, Prior: rule}
	return s, state, session, r
}

func admissionJSONTransport(t *testing.T, s voiceAdmissionScope, body []byte, path string) http.RoundTripper {
	t.Helper()
	return admissionRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Host != "192.0.2.1:8080" || r.URL.RequestURI() != path || r.Header.Get("Authorization") != "Bearer "+string(s.token) {
			t.Error("readback escaped its fixed Pod/token/path authority")
			return nil, errors.New("authority")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
}

func TestAdmissionSelectedSessionRequiresLiveDelegateThenActualTeardown(t *testing.T) {
	s, _, session, r := admissionReadbackFixture()
	path := "/v1/voice-session-admission/session?sessionID=" + r.SessionID
	check := func(session voiceadmissionpolicy.SessionReceipt, closed bool) error {
		return voiceAdmissionSession(context.Background(), s, r, closed, admissionJSONTransport(t, s, voiceadmissionpolicy.CanonicalBytes(session), path))
	}
	if err := check(session, false); err != nil {
		t.Fatal(err)
	}
	natural := session
	natural.Stage = "closed"
	natural.DelegateCompleted = true
	natural.DisconnectedAtUnixMs = time.Now().UnixMilli()
	natural.ObservedAtUnixMs = natural.DisconnectedAtUnixMs
	if check(natural, false) == nil || check(natural, true) == nil {
		t.Fatal("natural close was claimed as enforced active cancellation")
	}
	stopped := natural
	stopped.DisconnectDelivered = true
	if err := check(stopped, true); err != nil {
		t.Fatal(err)
	}
	stopped.PodUID = "22222222-2222-4222-8222-222222222222"
	if check(stopped, true) == nil {
		t.Fatal("old/new Pod lifecycle identities mixed")
	}
	stale := session
	stale.ObservedAtUnixMs = time.Now().UnixMilli() - 11000
	stale.ConnectedAtUnixMs = stale.ObservedAtUnixMs - 1000
	if check(stale, false) == nil {
		t.Fatal("stale selected session accepted as active")
	}
}

func TestAdmissionAllServingReadbackRequiresExactCurrentPolicy(t *testing.T) {
	s, state, _, _ := admissionReadbackFixture()
	read := func(state voiceadmissionpolicy.State) error {
		_, err := voiceAdmissionReadback(context.Background(), s, false, admissionJSONTransport(t, s, voiceadmissionpolicy.CanonicalBytes(state), voiceadmissionpolicy.StatePath))
		return err
	}
	if err := read(state); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*voiceadmissionpolicy.State){func(s *voiceadmissionpolicy.State) { s.PolicyResourceVersion = "old" }, func(s *voiceadmissionpolicy.State) { s.RuleSHA256 = strings.Repeat("b", 64) }, func(s *voiceadmissionpolicy.State) { s.TransitionPending = true }, func(s *voiceadmissionpolicy.State) { s.ObservedAtUnixMs = time.Now().UnixMilli() - 11000 }} {
		bad := state
		change(&bad)
		if read(bad) == nil {
			t.Fatal("incomplete source/policy acknowledgment accepted")
		}
	}
	peer := s.pods[0].DeepCopy()
	peer.UID = types.UID("22222222-2222-4222-8222-222222222222")
	s.pods = append(s.pods, *peer)
	if read(state) == nil {
		t.Fatal("target acknowledgment inherited by second serving Pod")
	}
}

func TestAdmissionReadbackRejectsRedirectOrMalformedResponse(t *testing.T) {
	s, _, _, _ := admissionReadbackFixture()
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusServiceUnavailable} {
		transport := admissionRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})
		if _, err := voiceAdmissionGet(context.Background(), *s.pod, s.token, voiceadmissionpolicy.StatePath, transport); err == nil {
			t.Fatal("unready response accepted")
		}
	}
	transport := admissionRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", voiceadmissionpolicy.MaxBytes+1)))}, nil
	})
	if _, err := voiceAdmissionGet(context.Background(), *s.pod, s.token, voiceadmissionpolicy.StatePath, transport); err == nil {
		t.Fatal("unbounded response accepted")
	}
}

func TestAdmissionPreCASRequiresActualActiveUnsignedDelegate(t *testing.T) {
	s, state, _, _ := admissionReadbackFixture()
	transport := func(state voiceadmissionpolicy.State) http.RoundTripper {
		return admissionJSONTransport(t, s, voiceadmissionpolicy.CanonicalBytes(state), voiceadmissionpolicy.StatePath)
	}
	if voiceAdmissionObserveLive(context.Background(), s, transport(state)) == nil {
		t.Fatal("retained exposure without actual active delegate authorized CAS")
	}
	state.ActiveUnsigned = 1
	if err := voiceAdmissionObserveLive(context.Background(), s, transport(state)); err != nil {
		t.Fatal(err)
	}
	// A real attack need not include the Console's additional pending control.
	if state.PendingUnsigned != 0 {
		t.Fatal("fixture must exercise no test-created pending client")
	}
}

func TestAdmissionBarrierCannotInheritRestartedContainerReceipt(t *testing.T) {
	s, _, _, _ := admissionReadbackFixture()
	p := s.pods[0]
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "bot", ContainerID: "containerd://original", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}
	changed := p.DeepCopy()
	changed.Status.ContainerStatuses[0].ContainerID = "containerd://replacement"
	changed.Status.ContainerStatuses[0].RestartCount = 1
	if voiceAdmissionSamePods([]corev1.Pod{p}, []corev1.Pod{*changed}) {
		t.Fatal("container restart inherited old acknowledgment")
	}
}
