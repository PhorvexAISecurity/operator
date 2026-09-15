/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * The paired handler profile MUST match the VAP allow-set exactly, or Phorvex's own
 * injection is denied by its own admission policy. These L0-L2 tests assert the emitted
 * ephemeral container carries: the pinned busybox DIGEST (not the mutable tag); the exact
 * hardened securityContext; and the fixed sleep 300 debugger command,
 * command:["sh","-c"] args:["echo phorvex-custom-action; sleep 1"] for custom-inject.
 */

package actuator

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

// The frozen contract values the VAP enforces (kept literal here so a drift in the handler
// away from the allow-set fails this test rather than silently shipping a denied request).
const (
	wantImageDigest = "busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"
)

// assertHardenedProfile checks the fields common to BOTH actions against the VAP allow-set.
func assertHardenedProfile(t *testing.T, ec corev1.EphemeralContainer) {
	t.Helper()
	if ec.Image != wantImageDigest {
		t.Errorf("image = %q, want pinned digest %q", ec.Image, wantImageDigest)
	}
	if ec.TTY || ec.Stdin {
		t.Errorf("tty/stdin must be unset, got tty=%v stdin=%v target=%q", ec.TTY, ec.Stdin, ec.TargetContainerName)
	}
	if len(ec.Env) != 0 || len(ec.EnvFrom) != 0 || len(ec.VolumeMounts) != 0 || len(ec.VolumeDevices) != 0 {
		t.Errorf("env/envFrom/volumeMounts/volumeDevices must be empty")
	}
	sc := ec.SecurityContext
	if sc == nil {
		t.Fatal("securityContext must be set")
	}
	if sc.Privileged == nil || *sc.Privileged {
		t.Error("privileged must be false")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("allowPrivilegeEscalation must be false")
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("runAsNonRoot must be true")
	}
	if sc.RunAsUser == nil || *sc.RunAsUser != 65534 {
		t.Error("runAsUser must be 65534")
	}
	if sc.RunAsGroup == nil || *sc.RunAsGroup != 65534 {
		t.Error("runAsGroup must be 65534")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("readOnlyRootFilesystem must be true")
	}
	if sc.Capabilities == nil || !reflect.DeepEqual(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(sc.Capabilities.Add) != 0 {
		t.Errorf("capabilities must drop=[ALL] add=none, got %+v", sc.Capabilities)
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("seccompProfile.type must be RuntimeDefault")
	}
}

func TestDebuggerEmitsBoundedCommand(t *testing.T) {
	ec := debuggerEphemeralSpec()
	if ec.Name != "phorvex-debugger" {
		t.Fatalf("name = %q, want phorvex-debugger", ec.Name)
	}
	assertHardenedProfile(t, ec)
	// The fixed BusyBox applet runs for five minutes without a shell or user script.
	if !reflect.DeepEqual(ec.Command, []string{"sleep", "300"}) {
		t.Errorf("debugger command = %v, want [sleep 300]", ec.Command)
	}
	if len(ec.Args) != 0 {
		t.Errorf("debugger args must be empty, got %v", ec.Args)
	}
}

func TestCustomInjectEmitsSplitCommandArgs(t *testing.T) {
	ec := customInjectEphemeralSpec()
	if ec.Name != "phorvex-custom" {
		t.Fatalf("name = %q, want phorvex-custom", ec.Name)
	}
	assertHardenedProfile(t, ec)
	if ec.TargetContainerName != "" {
		t.Errorf("custom target must be absent, got %q", ec.TargetContainerName)
	}
	if !reflect.DeepEqual(ec.Command, []string{"sh", "-c"}) {
		t.Errorf("custom-inject command = %v, want [sh -c]", ec.Command)
	}
	if !reflect.DeepEqual(ec.Args, []string{"echo phorvex-custom-action; sleep 1"}) {
		t.Errorf("custom-inject args = %v, want [echo phorvex-custom-action; sleep 1]", ec.Args)
	}
}

// The handler actually enacts the spec through the ephemeralcontainers subresource and
// reports an irreversible emit (the injection path itself, end to end).
func TestCodeExecHandlersEnactIrreversibly(t *testing.T) {
	for _, tc := range []struct {
		h      ActionHandler
		action model.Action
	}{
		{debuggerHandler{}, model.ActionDebugger},
		{customInjectHandler{}, model.ActionCustomInject},
	} {
		pod := aiPod("ns", "victim", map[string]string{"app": "web"})
		c := fakeC(pod)
		res, err := tc.h.Enact(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "victim", TargetUID: string(pod.UID), Action: tc.action})
		if err != nil {
			t.Fatalf("%s enact: %v", tc.action, err)
		}
		if !res.Emitted || res.MutationKind != "irreversible" {
			t.Fatalf("%s result = %+v, want emitted irreversible", tc.action, res)
		}
	}
}

func TestDebuggerExistingLifecycleIsObserved(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state corev1.ContainerState
		want  string
	}{
		{"running", corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Minute))}}, "observed running"},
		{"expired-running", corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-6 * time.Minute))}}, "past five-minute expiry"},
		{"unknown-start", corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}, "availability unobservable"},
		{"waiting", corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}, "observed waiting"},
		{"terminated", corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}, "fresh Pod"},
		{"missing", corev1.ContainerState{}, "status missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := aiPod("ns", "victim", nil)
			spec := debuggerEphemeralSpec()
			spec.TargetContainerName = "vllm"
			pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{spec}
			if tc.name != "missing" {
				pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: spec.Name, State: tc.state}}
			}
			c := fakeC(pod)
			res, err := debuggerHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "victim", TargetUID: string(pod.UID)})
			if err != nil || res.Emitted || !strings.Contains(res.Note, tc.want) {
				t.Fatalf("result=%+v err=%v, want unsubmitted %q", res, err, tc.want)
			}
		})
	}
}

func TestDebuggerRequiresAuthoritativeReader(t *testing.T) {
	pod := aiPod("ns", "victim", nil)
	c := fakeC(pod)
	if _, err := (debuggerHandler{}).Enact(context.Background(), EnactCtx{Client: c}, Request{Namespace: "ns", Pod: "victim", TargetUID: string(pod.UID)}); err == nil {
		t.Fatal("missing authoritative reader must refuse")
	}
	got := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), got); err != nil || len(got.Spec.EphemeralContainers) != 0 {
		t.Fatalf("missing reader caused mutation: %v %+v", err, got.Spec.EphemeralContainers)
	}
}

func TestDebuggerAPIDefaultNormalizationRejectsUnexpectedValues(t *testing.T) {
	desired := debuggerEphemeralSpec()
	desired.TargetContainerName = "vllm"
	readback := *desired.DeepCopy()
	readback.ImagePullPolicy = corev1.PullIfNotPresent
	readback.TerminationMessagePath = corev1.TerminationMessagePathDefault
	readback.TerminationMessagePolicy = corev1.TerminationMessageReadFile
	if !sameEphemeralSpec(readback, desired) {
		t.Fatal("legitimate API defaults must preserve idempotency")
	}
	readback.ImagePullPolicy = corev1.PullAlways
	if sameEphemeralSpec(readback, desired) {
		t.Fatal("unexpected pull policy must be rejected")
	}
}

func TestDebuggerRejectsStaleAndMismatchedSession(t *testing.T) {
	pod := aiPod("ns", "victim", nil)
	c := fakeC(pod)
	if _, err := (debuggerHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "victim", TargetUID: "stale"}); err == nil {
		t.Fatal("stale target UID must block injection")
	}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{debuggerEphemeralSpec()}
	c = fakeC(pod)
	if _, err := (debuggerHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "victim", TargetUID: string(pod.UID)}); err == nil {
		t.Fatal("same-name unbounded/mismatched old session must not be accepted")
	}
}
