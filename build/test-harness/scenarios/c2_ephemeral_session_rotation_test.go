package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

const sessionTestServiceURL = "http://c2-session-target:8080"

func TestEphemeralSessionMetadataIsExplicitBenignControl(t *testing.T) {
	md := (&c2EphemeralSessionRotation{}).Metadata()
	if !md.BenignControl || md.EffectiveRealism() != core.RealismExecutable {
		t.Fatalf("classification=%+v", md)
	}
	if len(md.AttackTechniqueIDs) != 0 || len(md.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("benign control claims techniques: declared=%v exercised=%v", md.AttackTechniqueIDs, md.ExercisedTechniqueIDs)
	}
	for _, want := range []string{sessionPythonImage, "serverSourceSHA256=" + sessionServerSourceSHA256(), "fixed 20-second observation window", "at-most 15-second measurement convergence interval", "zero ATT&CK", "does not establish credential revocation"} {
		if !strings.Contains(md.Mechanism+" "+md.ClaimLimits, want) {
			t.Errorf("metadata omits %q: %+v", want, md)
		}
	}
}

func TestEphemeralSessionActualHTTPBatchPreservesAndLosesProcessStateAcrossRestart(t *testing.T) {
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	original := startSessionServer(t, port, "original")
	waitSessionServer(t, base)
	sid := "session-actual-batch"
	established := runActualSessionBatch(t, base, []sessionBatchOperation{{Method: "POST", ID: sid, When: "always"}, {Method: "GET", ID: sid, When: "always"}})
	if established.ServedUID != "original" || len(established.Responses) != 2 || established.Responses[0].Reply.HTTPStatus != 201 || established.Responses[1].Reply.HTTPStatus != 200 || !established.Responses[1].Reply.Body.Present {
		t.Fatalf("actual establishment batch=%+v", established)
	}
	stopSessionServer(t, original)
	replacement := startSessionServer(t, port, "replacement")
	t.Cleanup(func() { stopSessionServer(t, replacement) })
	waitSessionServer(t, base)
	newID := sid + "-new"
	observed := runActualSessionBatch(t, base, []sessionBatchOperation{{Method: "GET", ID: sid, When: "always"}, {Method: "POST", ID: newID, When: "old-absent"}, {Method: "GET", ID: newID, When: "old-absent"}})
	if observed.ServedUID != "replacement" || len(observed.Responses) != 3 || observed.Responses[0].Reply.HTTPStatus != 404 || observed.Responses[0].Reply.Body.Present || observed.Responses[1].Reply.HTTPStatus != 201 || !observed.Responses[1].Reply.Body.Created || observed.Responses[2].Reply.HTTPStatus != 200 || !observed.Responses[2].Reply.Body.Present {
		t.Fatalf("actual replacement batch=%+v", observed)
	}
	if observed.Ended.Sub(observed.Started) > sessionBatchHTTPBudget {
		t.Fatalf("actual batch exceeded internal bound: %s", observed.Ended.Sub(observed.Started))
	}
}

func TestEphemeralSessionBatchParserRejectsIdentityAndEnvelopeAmbiguity(t *testing.T) {
	ops := []sessionBatchOperation{{Method: "GET", ID: "session-old", When: "always"}, {Method: "POST", ID: "session-new", When: "old-absent"}, {Method: "GET", ID: "session-new", When: "old-absent"}}
	valid := sessionBatchExecReply(ops, func(i int, operation sessionBatchOperation) (sessionReply, string, string) {
		if i == 0 {
			return sessionReplyValue("GET", 404, "replacement", operation.ID, false, false), "", ""
		}
		if operation.Method == "POST" {
			return sessionReplyValue("POST", 201, "replacement", operation.ID, true, true), "", ""
		}
		return sessionReplyValue("GET", 200, "replacement", operation.ID, true, false), "", ""
	}).Stdout
	if _, err := parseSessionBatchReply([]byte(valid), ops, sessionBatchHTTPBudget, sessionTestServiceURL); err != nil {
		t.Fatalf("valid strict batch rejected: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(valid), &envelope); err != nil {
		t.Fatal(err)
	}
	changed := cloneJSONMap(t, envelope)
	changed["responses"].([]any)[1].(map[string]any)["bodyBase64"] = base64.StdEncoding.EncodeToString([]byte(`{"podUID":"other","id":"session-new","present":true,"created":true}`))
	body := []byte(`{"podUID":"other","id":"session-new","present":true,"created":true}`)
	changed["responses"].([]any)[1].(map[string]any)["bodyBytes"] = len(body)
	changed["responses"].([]any)[1].(map[string]any)["bodySHA256"] = fmt.Sprintf("%x", sha256.Sum256(body))
	changedRaw, _ := json.Marshal(changed)
	if _, err := parseSessionBatchReply(changedRaw, ops, sessionBatchHTTPBudget, sessionTestServiceURL); err == nil || !strings.Contains(err.Error(), "changed serving Pod UID") {
		t.Fatalf("within-batch UID change accepted: %v", err)
	}
	wrongDestination := cloneJSONMap(t, envelope)
	wrongDestination["responses"].([]any)[0].(map[string]any)["destination"] = "http://foreign/session?id=session-old"
	wrongDestinationRaw, _ := json.Marshal(wrongDestination)
	if _, err := parseSessionBatchReply(wrongDestinationRaw, ops, sessionBatchHTTPBudget, sessionTestServiceURL); err == nil || !strings.Contains(err.Error(), "identity/required fields differ") {
		t.Fatalf("wrong request destination accepted: %v", err)
	}
	outOfOrder := cloneJSONMap(t, envelope)
	outOfOrder["responses"].([]any)[1].(map[string]any)["startedAtUTC"] = outOfOrder["startedAtUTC"]
	outOfOrderRaw, _ := json.Marshal(outOfOrder)
	if _, err := parseSessionBatchReply(outOfOrderRaw, ops, sessionBatchHTTPBudget, sessionTestServiceURL); err == nil || !strings.Contains(err.Error(), "timestamp order") {
		t.Fatalf("overlapping response timestamps accepted: %v", err)
	}
	overBudget := cloneJSONMap(t, envelope)
	started, err := time.Parse(time.RFC3339Nano, overBudget["startedAtUTC"].(string))
	if err != nil {
		t.Fatal(err)
	}
	overBudget["endedAtUTC"] = started.Add(sessionBatchHTTPBudget + time.Second).Format(time.RFC3339Nano)
	overBudgetRaw, _ := json.Marshal(overBudget)
	if _, err := parseSessionBatchReply(overBudgetRaw, ops, sessionBatchHTTPBudget, sessionTestServiceURL); err == nil || !strings.Contains(err.Error(), "timestamp/bound") {
		t.Fatalf("over-budget batch timestamps accepted: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "duplicate", raw: strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1)},
		{name: "unknown", raw: strings.Replace(valid, `"version":1`, `"unexpected":1,"version":1`, 1)},
		{name: "null timestamp", raw: strings.Replace(valid, `"startedAtUTC":"`, `"startedAtUTC":null,"ignored":"`, 1)},
		{name: "trailing", raw: valid + `{}`},
		{name: "partial", raw: valid[:len(valid)/2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSessionBatchReply([]byte(tc.raw), ops, sessionBatchHTTPBudget, sessionTestServiceURL); err == nil {
				t.Fatalf("ambiguous batch accepted: %s", tc.raw)
			}
		})
	}
}

func TestEphemeralSessionActualBatchClientEnforcesWallBudgetAndRetainsFailureBytes(t *testing.T) {
	ops := []sessionBatchOperation{{Method: "GET", ID: "session-budget", When: "always"}}
	t.Run("delayed header", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"podUID":"slow","id":"session-budget","present":true}`))
		}))
		defer server.Close()
		started := time.Now()
		raw := runActualSessionClientRaw(t, server.URL, ops, 100*time.Millisecond)
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("delayed header exceeded producer wall bound: %s", elapsed)
		}
		assertActualBatchFailureReceipt(t, raw, server.URL, 100*time.Millisecond, false)
	})
	t.Run("drip body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			flusher, _ := w.(http.Flusher)
			for _, b := range []byte(`{"podUID":"drip","id":"session-budget","present":true}`) {
				_, _ = w.Write([]byte{b})
				if flusher != nil {
					flusher.Flush()
				}
				time.Sleep(50 * time.Millisecond)
			}
		}))
		defer server.Close()
		started := time.Now()
		raw := runActualSessionClientRaw(t, server.URL, ops, 200*time.Millisecond)
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("drip body exceeded producer wall bound: %s", elapsed)
		}
		assertActualBatchFailureReceipt(t, raw, server.URL, 200*time.Millisecond, true)
	})
	t.Run("oversized body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 1025)))
		}))
		defer server.Close()
		raw := runActualSessionClientRaw(t, server.URL, ops, time.Second)
		var envelope struct {
			Responses []struct {
				BodyBytes     int    `json:"bodyBytes"`
				BodyBase64    string `json:"bodyBase64"`
				ProtocolError string `json:"protocolError"`
			} `json:"responses"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Responses) != 1 || envelope.Responses[0].BodyBytes != 1025 || len(envelope.Responses[0].BodyBase64) == 0 || envelope.Responses[0].ProtocolError != "response-too-large" {
			t.Fatalf("oversized raw evidence missing: envelope=%+v err=%v raw=%s", envelope, err, raw)
		}
		if _, err := parseSessionBatchReply(raw, ops, time.Second, server.URL); err == nil || !strings.Contains(err.Error(), "protocol failed") {
			t.Fatalf("oversized response was accepted: %v", err)
		}
	})
}

func TestEphemeralSessionActualBatchDoesNotCreateAfterMalformedAbsence(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.Query().Get("id"))
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"podUID":"replacement","id":"session-old","present":false,"unknown":true}`))
	}))
	defer server.Close()
	ops := []sessionBatchOperation{{Method: "GET", ID: "session-old", When: "always"}, {Method: "POST", ID: "session-new", When: "old-absent"}, {Method: "GET", ID: "session-new", When: "old-absent"}}
	raw := runActualSessionClientRaw(t, server.URL, ops, time.Second)
	if strings.Join(requests, ",") != "GET session-old" {
		t.Fatalf("malformed absence caused state mutation: requests=%v raw=%s", requests, raw)
	}
	if _, err := parseSessionBatchReply(raw, ops, time.Second, server.URL); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("malformed absence was accepted: %v raw=%s", err, raw)
	}
}

func TestEphemeralSessionSetupBuildsPinnedControllerOwnedCPUFixture(t *testing.T) {
	env := fixtureObservationEnv()
	env.Config.BenignSessionNodeSelector = map[string]string{"kubernetes.io/hostname": "ip-172-27-12-233.us-east-2.compute.internal"}
	env.ScenarioName = "c2-ephemeral-session-rotation"
	env.Trial = 2
	createSessionFixturePod(t, env, sessionFixturePod("controller-fixture-pod", sessionApp, "fixture", false, true))
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment).UID = "deployment-owned"
		return false, nil, nil
	})
	client.PrependReactor("create", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*corev1.Service).UID = "service-owned"
		return false, nil, nil
	})
	client.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pod := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		if pod.Name == sessionProducer {
			pod.UID = "producer-owned"
			pod.Status.Phase = corev1.PodRunning
			pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		}
		return false, nil, nil
	})
	scenario := &c2EphemeralSessionRotation{}
	if err := scenario.Setup(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if scenario.deploymentUID != "deployment-owned" || scenario.serviceUID != "service-owned" || scenario.producerUID != "producer-owned" {
		t.Fatalf("successful Create UIDs not retained: %+v", scenario)
	}
	dep, err := env.Kube.AppsV1().Deployments("sandbox").Get(context.Background(), sessionDeployment, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	template := dep.Spec.Template
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || template.Labels["app"] != sessionApp || template.Labels["r6th.io/rotation-target"] != "true" {
		t.Fatalf("deployment ownership/rotation shape=%+v", dep.Spec)
	}
	if template.Spec.AutomountServiceAccountToken == nil || *template.Spec.AutomountServiceAccountToken || len(template.Spec.Containers) != 1 {
		t.Fatalf("deployment token/container shape=%+v", template.Spec)
	}
	if got := template.Spec.NodeSelector["kubernetes.io/hostname"]; got != "ip-172-27-12-233.us-east-2.compute.internal" {
		t.Fatalf("deployment selector=%v", template.Spec.NodeSelector)
	}
	container := template.Spec.Containers[0]
	if container.Image != sessionPythonImage || !strings.Contains(strings.Join(container.Command, " "), sessionServerSource) {
		t.Fatalf("fixture image/source drift: image=%q command=%v", container.Image, container.Command)
	}
	for name := range container.Resources.Requests {
		if strings.Contains(string(name), "gpu") {
			t.Fatalf("fixture requested GPU resource %q", name)
		}
	}
	if container.Resources.Requests.Cpu().IsZero() || container.Resources.Requests.Memory().IsZero() || container.Resources.Limits.Cpu().IsZero() || container.Resources.Limits.Memory().IsZero() {
		t.Fatalf("fixture CPU/memory quota missing: %+v", container.Resources)
	}
	svc, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Spec.Selector["app"] != sessionApp || len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != sessionPort {
		t.Fatalf("stable Service shape=%+v", svc.Spec)
	}
	producer, err := env.Kube.CoreV1().Pods("sandbox").Get(context.Background(), sessionProducer, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if producer.Labels["r6th.io/rotation-target"] != "" || producer.Spec.AutomountServiceAccountToken == nil || *producer.Spec.AutomountServiceAccountToken || producer.Spec.Containers[0].Image != sessionPythonImage {
		t.Fatalf("producer isolation/pin drift: labels=%v spec=%+v", producer.Labels, producer.Spec)
	}
	if got := producer.Spec.NodeSelector["kubernetes.io/hostname"]; got != "ip-172-27-12-233.us-east-2.compute.internal" {
		t.Fatalf("producer selector=%v", producer.Spec.NodeSelector)
	}
	// Each object receives its own copy. Mutating config or one created object
	// cannot silently retarget the other fixture Pod.
	env.Config.BenignSessionNodeSelector["kubernetes.io/hostname"] = "changed-config"
	template.Spec.NodeSelector["kubernetes.io/hostname"] = "changed-deployment"
	if producer.Spec.NodeSelector["kubernetes.io/hostname"] != "ip-172-27-12-233.us-east-2.compute.internal" {
		t.Fatalf("producer selector aliased deployment/config: %v", producer.Spec.NodeSelector)
	}
}

func TestEphemeralSessionSetupDefaultLeavesBothPodsUnscheduled(t *testing.T) {
	env := fixtureObservationEnv()
	createSessionFixturePod(t, env, sessionFixturePod("controller-fixture-pod", sessionApp, "fixture", false, true))
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment).UID = "deployment-owned"
		return false, nil, nil
	})
	client.PrependReactor("create", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*corev1.Service).UID = "service-owned"
		return false, nil, nil
	})
	client.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pod := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		if pod.Name == sessionProducer {
			pod.UID = "producer-owned"
			pod.Status.Phase = corev1.PodRunning
			pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		}
		return false, nil, nil
	})
	if err := (&c2EphemeralSessionRotation{}).Setup(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	dep, err := env.Kube.AppsV1().Deployments("sandbox").Get(context.Background(), sessionDeployment, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	producer, err := env.Kube.CoreV1().Pods("sandbox").Get(context.Background(), sessionProducer, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dep.Spec.Template.Spec.NodeSelector != nil || producer.Spec.NodeSelector != nil {
		t.Fatalf("default scheduling changed: deployment=%v producer=%v", dep.Spec.Template.Spec.NodeSelector, producer.Spec.NodeSelector)
	}
}

func TestEphemeralSessionSetupCollisionPreservesForeignResource(t *testing.T) {
	env := fixtureObservationEnv()
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: sessionService, Namespace: "sandbox", UID: "foreign-service"}}
	if _, err := env.Kube.CoreV1().Services("sandbox").Create(context.Background(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("create", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		action.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment).UID = "deployment-owned"
		return false, nil, nil
	})
	s := &c2EphemeralSessionRotation{deploymentUID: "stale-deployment", serviceUID: "stale-service", producerUID: "stale-producer"}
	if err := s.Setup(context.Background(), env); err == nil {
		t.Fatal("fixed-name Service collision was accepted")
	}
	if s.deploymentUID != "deployment-owned" || s.serviceUID != "" || s.producerUID != "" {
		t.Fatalf("setup did not reset/bind cleanup UIDs: %+v", s)
	}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	got, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
	if err != nil || got.UID != "foreign-service" {
		t.Fatalf("foreign colliding Service was deleted or replaced: service=%+v err=%v", got, err)
	}
}

func TestEphemeralSessionTeardownUsesUIDPrecondition(t *testing.T) {
	env := fixtureObservationEnv()
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: sessionService, Namespace: "sandbox", UID: "replacement-foreign"}}
	if _, err := env.Kube.CoreV1().Services("sandbox").Create(context.Background(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	client := env.Kube.(*k8sfake.Clientset)
	client.PrependReactor("delete", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		opts := action.(k8stesting.DeleteAction).GetDeleteOptions()
		if opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != "original-owned" {
			t.Fatalf("delete did not carry exact owned UID: %+v", opts)
		}
		return true, nil, errors.New("UID precondition rejected replacement")
	})
	s := &c2EphemeralSessionRotation{serviceUID: "original-owned"}
	if err := s.Teardown(context.Background(), env); err == nil {
		t.Fatal("replacement UID conflict was hidden")
	}
	got, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
	if err != nil || got.UID != "replacement-foreign" {
		t.Fatalf("replacement Service was deleted: service=%+v err=%v", got, err)
	}
}

func TestEphemeralSessionExecuteUsesActualServiceReplyAndClearsState(t *testing.T) {
	env := sessionRequestEnv(t)
	env.Config.BenignSessionNodeSelector = map[string]string{"kubernetes.io/hostname": "ip-172-27-12-233.us-east-2.compute.internal"}
	env.Rand = rand.New(rand.NewSource(19))
	env.Trial = 4
	producer, err := env.Kube.CoreV1().Pods("sandbox").Get(context.Background(), sessionProducer, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	producer.Labels[core.TrialLabelKey] = "4"
	if _, err := env.Kube.CoreV1().Pods("sandbox").Update(context.Background(), producer, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deployment, err := env.Kube.AppsV1().Deployments("sandbox").Get(context.Background(), sessionDeployment, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deployment.Labels[core.TrialLabelKey] = "4"
	if _, err := env.Kube.AppsV1().Deployments("sandbox").Update(context.Background(), deployment, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	service, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	service.Labels[core.TrialLabelKey] = "4"
	if _, err := env.Kube.CoreV1().Services("sandbox").Update(context.Background(), service, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	var calls int
	var events []string
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, pod, _ string, command []string) core.ExecResult {
		calls++
		if pod != sessionProducer {
			t.Fatalf("unexpected producer request: pod=%s command=%v", pod, command)
		}
		operations := sessionOperationsFromCommand(t, command)
		for _, operation := range operations {
			events = append(events, operation.Method)
		}
		return sessionSuccessfulBatch(t, command, "original", true)
	})
	oldWait := benignSessionObservationWait
	windowStart := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	benignSessionObservationWait = func(_ context.Context, interval time.Duration) (time.Time, time.Time, error) {
		if interval != benignSessionObservationWindow {
			t.Fatalf("observation interval=%s want=%s", interval, benignSessionObservationWindow)
		}
		events = append(events, "WAIT")
		return windowStart, windowStart.Add(interval), nil
	}
	t.Cleanup(func() {
		benignSessionObservationWait = oldWait
		core.SetExecer(nil)
	})

	s := &c2EphemeralSessionRotation{originalName: "stale", originalUID: "stale", sessionID: "stale", producerUID: "producer-owned", deploymentUID: "deployment-owned", serviceUID: "service-owned"}
	result, err := s.Execute(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || s.originalName != "original-pod" || s.originalUID != "original" || !strings.HasPrefix(s.sessionID, "session-4-") {
		t.Fatalf("state/calls not grounded: calls=%d scenario=%+v result=%+v", calls, s, result)
	}
	if strings.Join(events, ",") != "POST,GET,WAIT" {
		t.Fatalf("session establishment/window ordering=%v", events)
	}
	if result.Notes["transport"] != "ordinary HTTP via ClusterIP Service" || result.Notes["sessionID"] != s.sessionID || result.Notes["fixtureImage"] != sessionPythonImage || result.Notes["serverSourceSHA256"] != sessionServerSourceSHA256() {
		t.Fatalf("provenance=%v", result.Notes)
	}
	if result.Notes["benignSessionNodeSelector"] != `{"kubernetes.io/hostname":"ip-172-27-12-233.us-east-2.compute.internal"}` {
		t.Fatalf("placement provenance=%v", result.Notes)
	}
	if result.Notes["observationWindowSeconds"] != "20" || result.Notes["observationWindowStartedAtUTC"] != windowStart.Format(time.RFC3339Nano) || result.Notes["observationWindowEndedAtUTC"] != windowStart.Add(20*time.Second).Format(time.RFC3339Nano) || result.Notes["observationWindowElapsedSeconds"] != "20.000" {
		t.Fatalf("observation timing notes=%v", result.Notes)
	}
}

func TestEphemeralSessionObservationWindowIsContextCancellableAfterEstablishment(t *testing.T) {
	env := sessionRequestEnv(t)
	env.Rand = rand.New(rand.NewSource(29))
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	ctx, cancel := context.WithCancel(context.Background())
	var events []string
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
		operations := sessionOperationsFromCommand(t, command)
		for _, operation := range operations {
			events = append(events, operation.Method)
		}
		return sessionSuccessfulBatch(t, command, "original", true)
	})
	oldWait := benignSessionObservationWait
	benignSessionObservationWait = func(waitCtx context.Context, interval time.Duration) (time.Time, time.Time, error) {
		events = append(events, "WAIT")
		cancel()
		return waitBenignSessionObservation(waitCtx, interval)
	}
	t.Cleanup(func() {
		cancel()
		benignSessionObservationWait = oldWait
		core.SetExecer(nil)
	})
	started := time.Now()
	_, err := (&c2EphemeralSessionRotation{producerUID: "producer-owned", deploymentUID: "deployment-owned", serviceUID: "service-owned"}).Execute(ctx, env)
	if err == nil || !strings.Contains(err.Error(), "observation window did not complete: context canceled") {
		t.Fatalf("cancelled post-establishment window result=%v", err)
	}
	if strings.Join(events, ",") != "POST,GET,WAIT" || time.Since(started) >= time.Second {
		t.Fatalf("window cancellation was not prompt or ordered: events=%v elapsed=%s", events, time.Since(started))
	}
}

func TestEphemeralSessionExecutePreservesProducerFailure(t *testing.T) {
	env := sessionRequestEnv(t)
	env.Rand = rand.New(rand.NewSource(23))
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		return core.ExecResult{Err: errors.New("fixture producer failed"), ExitCode: -1}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := &c2EphemeralSessionRotation{originalName: "stale", originalUID: "stale", sessionID: "stale", producerUID: "producer-owned"}
	if _, err := s.Execute(context.Background(), env); err == nil {
		t.Fatal("producer failure was accepted")
	}
	if s.originalName != "" || s.originalUID != "" || s.sessionID != "" {
		t.Fatalf("failed producer retained stale/success state: %+v", s)
	}
}

func TestEphemeralSessionOracleNoDefenseRetainsSameUIDAndID(t *testing.T) {
	env := sessionRequestEnv(t)
	createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
		return sessionSuccessfulBatch(t, command, "original", true)
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedSessionScenario()
	got, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Achieved || got.Evidence["originalUIDAbsent"] != "false" || got.Evidence["oldSessionPresent"] != "true" {
		t.Fatalf("same-identity persistence not observed: %+v", got)
	}
}

func TestEphemeralSessionOracleCreditsOnlyConfirmedReplacementLoss(t *testing.T) {
	env := sessionRequestEnv(t)
	createSessionFixturePod(t, env, sessionFixturePod("replacement-pod", sessionApp, "replacement", false, true))
	var call int
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
		call++
		return sessionSuccessfulBatch(t, command, "replacement", false)
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedSessionScenario()
	got, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Achieved || call != 1 || got.Evidence["originalUIDAbsent"] != "true" || got.Evidence["newSessionRetrieved"] != "true" {
		t.Fatalf("replacement loss not fully confirmed: calls=%d result=%+v", call, got)
	}
}

func TestEphemeralSessionMeasurementRetainsOutageBeforeConvergence(t *testing.T) {
	env := sessionRequestEnv(t)
	createSessionFixturePod(t, env, sessionFixturePod("replacement-pod", sessionApp, "replacement", false, true))
	var calls int
	core.SetExecer(func(ctx context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
		calls++
		if calls == 1 {
			return core.ExecResult{ExitCode: -1, Err: errors.New("temporary endpoint outage")}
		}
		return sessionSuccessfulBatch(t, command, "replacement", false)
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedSessionScenario()
	got, err := s.SuccessOracle(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Achieved || calls != 2 || got.Evidence["measurementAttempts"] != "2" || got.Evidence["measurementFailures"] != "1" || got.Evidence["measurementWindowElapsedSeconds"] == "" {
		t.Fatalf("outage/convergence evidence lost: calls=%d result=%+v", calls, got)
	}
}

func TestEphemeralSessionCorroboratesExactServedWorkloadChain(t *testing.T) {
	newFixture := func(t *testing.T) (*core.Env, *c2EphemeralSessionRotation, *corev1.Pod) {
		env := sessionRequestEnv(t)
		pod := sessionFixturePod("replacement-pod", sessionApp, "replacement", false, true)
		createSessionFixturePod(t, env, pod)
		return env, observedSessionScenario(), pod
	}
	t.Run("positive", func(t *testing.T) {
		env, scenario, pod := newFixture(t)
		if got, err := scenario.corroborateSessionWorkload(context.Background(), env, pod.UID, false); err != nil || got.UID != pod.UID {
			t.Fatalf("exact workload rejected: pod=%v err=%v", got, err)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *core.Env, *corev1.Pod)
	}{
		{name: "wrong image", mutate: func(t *testing.T, env *core.Env, pod *corev1.Pod) {
			pod.Spec.Containers[0].Image = "foreign.invalid/session@sha256:deadbeef"
			if _, err := env.Kube.CoreV1().Pods("sandbox").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong parent UID", mutate: func(t *testing.T, env *core.Env, pod *corev1.Pod) {
			pod.OwnerReferences[0].UID = "foreign-rs"
			if _, err := env.Kube.CoreV1().Pods("sandbox").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "replacement service UID", mutate: func(t *testing.T, env *core.Env, _ *corev1.Pod) {
			svc, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), sessionService, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			svc.UID = "foreign-service"
			if _, err := env.Kube.CoreV1().Services("sandbox").Update(context.Background(), svc, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "foreign endpoint target", mutate: func(t *testing.T, env *core.Env, _ *corev1.Pod) {
			slice, err := env.Kube.DiscoveryV1().EndpointSlices("sandbox").Get(context.Background(), "session-slice", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			slice.Endpoints[0].TargetRef.UID = "foreign-pod"
			if _, err := env.Kube.DiscoveryV1().EndpointSlices("sandbox").Update(context.Background(), slice, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, scenario, pod := newFixture(t)
			tc.mutate(t, env, pod)
			if _, err := scenario.corroborateSessionWorkload(context.Background(), env, pod.UID, false); err == nil {
				t.Fatal("foreign workload chain accepted")
			}
		})
	}
}

func TestEphemeralSessionIdentityReceiptPersistsThroughRealTrialLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out", "raw", "session-identity.log")
	logger, err := core.NewTrialLogger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := sessionRequestEnv(t)
	env.Log = logger
	pod := sessionFixturePod("replacement-pod", sessionApp, "replacement", false, true)
	createSessionFixturePod(t, env, pod)
	if _, err := observedSessionScenario().corroborateSessionWorkload(context.Background(), env, pod.UID, false); err != nil {
		t.Fatal(err)
	}
	closer, ok := logger.(interface{ Close() error })
	if !ok {
		t.Fatal("real trial logger has no close seam")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "c2-ephemeral-session-rotation identity-receipt="
	at := strings.Index(string(raw), marker)
	if at < 0 {
		t.Fatalf("identity receipt absent from raw log:\n%s", raw)
	}
	line := strings.Split(string(raw)[at+len(marker):], "\n")[0]
	var receipt sessionIdentityReceipt
	if err := json.Unmarshal([]byte(line), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ServedPodUID != "replacement" || receipt.PodUID != "replacement" || receipt.ReplicaSetUID != "session-rs-owned" || receipt.DeploymentUID != "deployment-owned" || receipt.ServiceUID != "service-owned" || strings.Join(receipt.ReadyEndpointUIDs, ",") != "replacement" || receipt.Error != "" {
		t.Fatalf("persisted identity receipt incomplete: %+v", receipt)
	}
	if len(receipt.PodObject) == 0 || len(receipt.ReplicaSetObject) == 0 || len(receipt.DeploymentObject) == 0 || len(receipt.ServiceObject) == 0 || len(receipt.EndpointSliceObjects) != 1 {
		t.Fatalf("persisted raw identity objects incomplete: %+v", receipt)
	}
	var recordedPod corev1.Pod
	if err := json.Unmarshal(receipt.PodObject, &recordedPod); err != nil || recordedPod.UID != "replacement" {
		t.Fatalf("persisted Pod object is not independently usable: uid=%s err=%v raw=%s", recordedPod.UID, err, receipt.PodObject)
	}
}

func TestEphemeralSessionBatchDeadlineAndProducerDriftRemainUnavailable(t *testing.T) {
	t.Run("deadline too short for producer", func(t *testing.T) {
		env := sessionRequestEnv(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := performSessionBatch(ctx, env, []sessionBatchOperation{{Method: "GET", ID: "session-old", When: "always"}}, "producer-owned"); err == nil || !strings.Contains(err.Error(), "caller deadline") {
			t.Fatalf("deadline was credited: %v", err)
		}
	})
	t.Run("producer budget is shorter than caller", func(t *testing.T) {
		env := sessionRequestEnv(t)
		var observed time.Duration
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
			seconds, err := strconv.ParseFloat(command[len(command)-1], 64)
			if err != nil {
				t.Fatal(err)
			}
			observed = time.Duration(seconds * float64(time.Second))
			return sessionSuccessfulBatch(t, command, "original", true)
		})
		defer core.SetExecer(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := performSessionBatch(ctx, env, []sessionBatchOperation{{Method: "GET", ID: "session-old", When: "always"}}, "producer-owned"); err != nil {
			t.Fatal(err)
		}
		if observed <= 0 || observed+50*time.Millisecond >= 2*time.Second {
			t.Fatalf("producer budget is not bounded below caller deadline: %s", observed)
		}
	})
	t.Run("cancelled before exec", func(t *testing.T) {
		env := sessionRequestEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := performSessionBatch(ctx, env, []sessionBatchOperation{{Method: "GET", ID: "session-old", When: "always"}}, "producer-owned"); err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Fatalf("cancellation was credited: %v", err)
		}
	})
	t.Run("producer changes after exec", func(t *testing.T) {
		env := sessionRequestEnv(t)
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
			pod, err := env.Kube.CoreV1().Pods("sandbox").Get(context.Background(), sessionProducer, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pod.UID = "replacement-producer"
			if _, err := env.Kube.CoreV1().Pods("sandbox").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			return sessionSuccessfulBatch(t, command, "original", true)
		})
		defer core.SetExecer(nil)
		if _, err := performSessionBatch(context.Background(), env, []sessionBatchOperation{{Method: "GET", ID: "session-old", When: "always"}}, "producer-owned"); err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("producer drift was credited: %v", err)
		}
	})
}

func TestEphemeralSessionOracleRejectsOverlapAndObservationFailures(t *testing.T) {
	oldLimit := sessionMeasurementLimit
	// Leave enough room for the production rule that keeps the producer's
	// absolute wall budget at least 100ms inside the caller deadline.
	sessionMeasurementLimit = 150 * time.Millisecond
	t.Cleanup(func() { sessionMeasurementLimit = oldLimit })
	newScenario := func() *c2EphemeralSessionRotation {
		return observedSessionScenario()
	}

	t.Run("overlap with original label removed", func(t *testing.T) {
		env := sessionRequestEnv(t)
		createSessionFixturePod(t, env, sessionFixturePod("replacement-pod", sessionApp, "replacement", false, true))
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", "detached", "original", false, true))
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
			return sessionSuccessfulBatch(t, command, "replacement", false)
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "original UID survives") {
			t.Fatalf("overlap was credited as mitigation: %v", err)
		}
	})

	t.Run("original terminating", func(t *testing.T) {
		env := sessionRequestEnv(t)
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", true, true))
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
			return sessionSuccessfulBatch(t, command, "original", true)
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "absent, terminating, or not Ready") {
			t.Fatalf("terminating original was scored: %v", err)
		}
	})

	t.Run("replacement unavailable", func(t *testing.T) {
		if _, err := newScenario().SuccessOracle(context.Background(), fixtureObservationEnv()); err == nil {
			t.Fatal("absence without replacement was scored")
		}
	})

	t.Run("malformed reply", func(t *testing.T) {
		env := sessionRequestEnv(t)
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
		core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
			return core.ExecResult{Stdout: "{", ExitCode: 0}
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("malformed reply was scored: %v", err)
		}
	})

	t.Run("server error", func(t *testing.T) {
		env := sessionRequestEnv(t)
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _ string, _ string, command []string) core.ExecResult {
			operations := sessionOperationsFromCommand(t, command)
			return sessionBatchExecReply(operations, func(_ int, operation sessionBatchOperation) (sessionReply, string, string) {
				return sessionReplyValue(operation.Method, 503, "original", operation.ID, false, false), "", ""
			})
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "unusable status 503") {
			t.Fatalf("server error was scored: %v", err)
		}
	})

	t.Run("transport timeout", func(t *testing.T) {
		env := sessionRequestEnv(t)
		createSessionFixturePod(t, env, sessionFixturePod("original-pod", sessionApp, "original", false, true))
		core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
			return core.ExecResult{Err: context.DeadlineExceeded, ExitCode: -1}
		})
		defer core.SetExecer(nil)
		if _, err := newScenario().SuccessOracle(context.Background(), env); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
			t.Fatalf("transport timeout was scored: %v", err)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := newScenario().SuccessOracle(ctx, fixtureObservationEnv()); err == nil {
			t.Fatal("cancelled observation was scored")
		}
	})

	t.Run("required presence field integrity", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{name: "omitted", raw: `{"podUID":"original","id":"session-old"}`},
			{name: "null", raw: `{"podUID":"original","id":"session-old","present":null}`},
			{name: "duplicate", raw: `{"podUID":"original","id":"session-old","present":false,"present":true}`},
			{name: "case variant", raw: `{"podUID":"original","id":"session-old","Present":false}`},
			{name: "trailing object", raw: `{"podUID":"original","id":"session-old","present":false} {}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := sessionRequestEnv(t)
				core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, command []string) core.ExecResult {
					return sessionBatchRawBody(sessionOperationsFromCommand(t, command), 404, tc.raw)
				})
				defer core.SetExecer(nil)
				if _, err := performSessionRequest(context.Background(), env, "GET", "session-old", "producer-owned"); err == nil {
					t.Fatalf("%s presence reply was accepted", tc.name)
				}
			})
		}
	})

	t.Run("POST requires explicit created field", func(t *testing.T) {
		env := sessionRequestEnv(t)
		core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, command []string) core.ExecResult {
			return sessionBatchRawBody(sessionOperationsFromCommand(t, command), 201, `{"podUID":"original","id":"session-old","present":true}`)
		})
		defer core.SetExecer(nil)
		if _, err := performSessionRequest(context.Background(), env, "POST", "session-old", "producer-owned"); err == nil {
			t.Fatal("POST without explicit created field was accepted")
		}
	})

	t.Run("redirect following disabled", func(t *testing.T) {
		if !strings.Contains(sessionClientSource, "HTTPRedirectHandler") || !strings.Contains(sessionClientSource, "return None") {
			t.Fatalf("client source can follow redirects:\n%s", sessionClientSource)
		}
	})
}

func TestEphemeralSessionHTTPReceiptPersistsThroughRealTrialLogger(t *testing.T) {
	for _, tc := range []struct {
		name          string
		result        core.ExecResult
		wantError     bool
		wantTruncated bool
	}{
		{name: "success", result: sessionExecReply("GET", 200, "original", "session-old", true, false)},
		{name: "malformed", result: core.ExecResult{Stdout: "malformed-envelope", ExitCode: 0}, wantError: true},
		{name: "transport", result: core.ExecResult{Stderr: "bounded transport detail", ExitCode: -1, Err: context.DeadlineExceeded}, wantError: true},
		{name: "oversized", result: core.ExecResult{Stdout: strings.Repeat("x", sessionReceiptStdoutLimit+1), ExitCode: 0}, wantError: true, wantTruncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out", "raw", "session.log")
			logger, err := core.NewTrialLogger(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			env := sessionRequestEnv(t)
			env.Log = logger
			core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
				return tc.result
			})
			t.Cleanup(func() { core.SetExecer(nil) })
			_, requestErr := performSessionRequest(context.Background(), env, "GET", "session-old", "producer-owned")
			if (requestErr != nil) != tc.wantError {
				t.Fatalf("request error=%v wantError=%v", requestErr, tc.wantError)
			}
			closer, ok := logger.(interface{ Close() error })
			if !ok {
				t.Fatal("real trial logger has no close seam")
			}
			if err := closer.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			receipt := persistedSessionReceipt(t, string(raw))
			if receipt.ProducerName != sessionProducer || receipt.ExpectedProducerUID != "producer-owned" || receipt.ObservedProducerUID != "producer-owned" {
				t.Fatalf("producer identity missing from persisted receipt: %+v", receipt)
			}
			wantStdout := tc.result.Stdout
			if tc.wantTruncated {
				wantStdout = wantStdout[:sessionReceiptStdoutLimit]
			}
			if receipt.Stdout != wantStdout || receipt.StdoutBytes != len(tc.result.Stdout) || receipt.StdoutTruncated != tc.wantTruncated {
				t.Fatalf("actual HTTP envelope not retained exactly: receipt=%+v result=%+v", receipt, tc.result)
			}
			wantDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.result.Stdout)))
			if receipt.StdoutSHA256 != wantDigest {
				t.Fatalf("stdout digest=%s want=%s", receipt.StdoutSHA256, wantDigest)
			}
			if tc.result.Err != nil && !strings.Contains(receipt.ExecError, tc.result.Err.Error()) {
				t.Fatalf("transport failure missing from persisted receipt: %+v", receipt)
			}
		})
	}
}

func TestEphemeralSessionHTTPReceiptRejectsReplacedProducerBeforeExec(t *testing.T) {
	env := sessionRequestEnv(t)
	called := false
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		called = true
		return core.ExecResult{}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	if _, err := performSessionRequest(context.Background(), env, "GET", "session-old", "different-producer-uid"); err == nil || !strings.Contains(err.Error(), "producer UID/readiness mismatch") {
		t.Fatalf("replaced producer error=%v", err)
	}
	if called {
		t.Fatal("request ran through a producer whose UID did not match the setup identity")
	}
}

func persistedSessionReceipt(t *testing.T, rawLog string) sessionHTTPReceipt {
	t.Helper()
	const marker = "c2-ephemeral-session-rotation http-receipt="
	for _, line := range strings.Split(rawLog, "\n") {
		if at := strings.Index(line, marker); at >= 0 {
			var receipt sessionHTTPReceipt
			if err := json.Unmarshal([]byte(line[at+len(marker):]), &receipt); err != nil {
				t.Fatalf("persisted receipt malformed: %v\n%s", err, line)
			}
			return receipt
		}
	}
	t.Fatalf("raw log omitted HTTP receipt:\n%s", rawLog)
	return sessionHTTPReceipt{}
}

func observedSessionScenario() *c2EphemeralSessionRotation {
	started := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	return &c2EphemeralSessionRotation{
		originalName:   "original-pod",
		originalUID:    "original",
		sessionID:      "session-old",
		deploymentUID:  "deployment-owned",
		serviceUID:     "service-owned",
		replicaSetName: "session-rs",
		replicaSetUID:  "session-rs-owned",
		windowStarted:  started,
		windowEnded:    started.Add(benignSessionObservationWindow),
		producerUID:    "producer-owned",
	}
}

func sessionRequestEnv(t *testing.T) *core.Env {
	t.Helper()
	env := fixtureObservationEnv()
	env.ScenarioName = "c2-ephemeral-session-rotation"
	controller := true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: sessionDeployment, Namespace: "sandbox", UID: "deployment-owned", Labels: env.OwnedLabels(map[string]string{"app": sessionApp})}}
	if _, err := env.Kube.AppsV1().Deployments("sandbox").Create(context.Background(), dep, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "session-rs", Namespace: "sandbox", UID: "session-rs-owned", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: sessionDeployment, UID: dep.UID, Controller: &controller}}}}
	if _, err := env.Kube.AppsV1().ReplicaSets("sandbox").Create(context.Background(), rs, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: sessionService, Namespace: "sandbox", UID: "service-owned", Labels: env.OwnedLabels(map[string]string{"app": sessionApp})}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": sessionApp}, Ports: []corev1.ServicePort{{Name: "http", Port: sessionPort, TargetPort: intstr.FromString("http")}}}}
	if _, err := env.Kube.CoreV1().Services("sandbox").Create(context.Background(), svc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	producer := sessionFixturePod(sessionProducer, sessionProducer, "producer-owned", false, true)
	producer.Labels = env.OwnedLabels(map[string]string{"app": sessionProducer})
	producer.Spec.Containers[0].Name = "producer"
	producer.Spec.Containers[0].Image = sessionPythonImage
	producer.Spec.Containers[0].Command = []string{"python3", "-c", "import time; time.sleep(3600)"}
	createSessionFixturePod(t, env, producer)
	return env
}

func sessionFixturePod(name, app string, uid types.UID, terminating, ready bool) *corev1.Pod {
	controller := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sandbox", UID: uid, Labels: map[string]string{"app": app}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "session"}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: map[bool]corev1.ConditionStatus{true: corev1.ConditionTrue, false: corev1.ConditionFalse}[ready]}},
		},
	}
	if app == sessionApp {
		pod.Labels = map[string]string{core.OwnedLabelKey: core.OwnedLabelValue, core.ScenarioLabelKey: "c2-ephemeral-session-rotation", core.TrialLabelKey: "0", "app": sessionApp, defenders.RotationTargetLabel: "true"}
		pod.Annotations = map[string]string{"r6th.io/session-source-sha256": sessionServerSourceSHA256()}
		pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "session-rs", UID: "session-rs-owned", Controller: &controller}}
		pod.Spec.Containers = []corev1.Container{{Name: "session", Image: sessionPythonImage, Command: []string{"python3", "-B", "-c", sessionServerSource}}}
	}
	if terminating {
		now := metav1.Now()
		pod.DeletionTimestamp = &now
	}
	return pod
}

func createSessionFixturePod(t *testing.T, env *core.Env, pod *corev1.Pod) {
	t.Helper()
	if pod.Labels["app"] == sessionApp {
		pod.Labels[core.TrialLabelKey] = fmt.Sprintf("%d", env.Trial)
	}
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if pod.Labels["app"] == sessionApp {
		if _, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(context.Background(), sessionService, metav1.GetOptions{}); err == nil {
			setSessionFixtureEndpoint(t, env, pod)
		}
	}
}

func setSessionFixtureEndpoint(t *testing.T, env *core.Env, pod *corev1.Pod) {
	t.Helper()
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range slices.Items {
		if err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).Delete(context.Background(), slices.Items[i].Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ready, controller := true, true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "session-slice", Namespace: env.Config.Namespace, Labels: map[string]string{discoveryv1.LabelServiceName: sessionService}, OwnerReferences: []metav1.OwnerReference{{Kind: "Service", Name: sessionService, UID: "service-owned", Controller: &controller}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: env.Config.Namespace, Name: pod.Name, UID: pod.UID}}}}
	if _, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).Create(context.Background(), slice, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func sessionExecReply(method string, status int, uid, id string, present, created bool) core.ExecResult {
	op := sessionBatchOperation{Method: method, ID: id, When: "always"}
	return sessionBatchExecReply([]sessionBatchOperation{op}, func(int, sessionBatchOperation) (sessionReply, string, string) {
		return sessionReplyValue(method, status, uid, id, present, created), "", ""
	})
}

func sessionOperationsFromCommand(t *testing.T, command []string) []sessionBatchOperation {
	t.Helper()
	if len(command) < 3 {
		t.Fatalf("short session batch command: %v", command)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(command[len(command)-2])
	if err != nil {
		t.Fatalf("decode batch operations: %v", err)
	}
	var operations []sessionBatchOperation
	if err := json.Unmarshal(raw, &operations); err != nil {
		t.Fatalf("parse batch operations: %v", err)
	}
	return operations
}

func sessionReplyValue(method string, status int, uid, id string, present, created bool) sessionReply {
	reply := sessionReply{HTTPStatus: status}
	reply.Body.PodUID, reply.Body.ID, reply.Body.Present, reply.Body.Created = uid, id, present, created
	return reply
}

func sessionBatchExecReply(operations []sessionBatchOperation, response func(int, sessionBatchOperation) (sessionReply, string, string)) core.ExecResult {
	start := time.Date(2026, 9, 20, 21, 0, 0, 0, time.UTC)
	rows := make([]map[string]any, 0, len(operations))
	for i, operation := range operations {
		reply, skipped, transport := response(i, operation)
		row := map[string]any{"method": operation.Method, "id": operation.ID, "destination": sessionTestServiceURL + "/session?id=" + operation.ID, "startedAtUTC": start.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano), "endedAtUTC": start.Add(time.Duration(i+1) * time.Millisecond).Format(time.RFC3339Nano)}
		if skipped != "" {
			row["skipped"] = skipped
		} else if transport != "" {
			row["transportError"] = transport
		} else {
			body := map[string]any{"podUID": reply.Body.PodUID, "id": reply.Body.ID, "present": reply.Body.Present}
			if operation.Method == "POST" {
				body["created"] = reply.Body.Created
			}
			raw, _ := json.Marshal(body)
			row["httpStatus"] = reply.HTTPStatus
			row["bodyBase64"] = base64.StdEncoding.EncodeToString(raw)
			row["bodyBytes"] = len(raw)
			row["bodySHA256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
		}
		rows = append(rows, row)
	}
	raw, _ := json.Marshal(map[string]any{"version": 1, "startedAtUTC": start.Format(time.RFC3339Nano), "endedAtUTC": start.Add(time.Duration(len(operations)+1) * time.Millisecond).Format(time.RFC3339Nano), "responses": rows})
	return core.ExecResult{Stdout: string(raw), ExitCode: 0}
}

func sessionBatchRawBody(operations []sessionBatchOperation, status int, body string) core.ExecResult {
	start := time.Date(2026, 9, 20, 21, 0, 0, 0, time.UTC)
	rawBody := []byte(body)
	rows := make([]map[string]any, len(operations))
	for i, operation := range operations {
		rows[i] = map[string]any{
			"method": operation.Method, "id": operation.ID,
			"destination":  sessionTestServiceURL + "/session?id=" + operation.ID,
			"startedAtUTC": start.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
			"endedAtUTC":   start.Add(time.Duration(i+1) * time.Millisecond).Format(time.RFC3339Nano),
			"httpStatus":   status, "bodyBase64": base64.StdEncoding.EncodeToString(rawBody),
			"bodyBytes": len(rawBody), "bodySHA256": fmt.Sprintf("%x", sha256.Sum256(rawBody)),
		}
	}
	raw, _ := json.Marshal(map[string]any{"version": 1, "startedAtUTC": start.Format(time.RFC3339Nano), "endedAtUTC": start.Add(time.Duration(len(operations)+1) * time.Millisecond).Format(time.RFC3339Nano), "responses": rows})
	return core.ExecResult{Stdout: string(raw), ExitCode: 0}
}

func sessionSuccessfulBatch(t *testing.T, command []string, uid string, oldPresent bool) core.ExecResult {
	t.Helper()
	operations := sessionOperationsFromCommand(t, command)
	oldAbsent := false
	return sessionBatchExecReply(operations, func(i int, operation sessionBatchOperation) (sessionReply, string, string) {
		if operation.When == "old-absent" && !oldAbsent {
			return sessionReply{}, "old-session-not-explicitly-absent", ""
		}
		status, present, created := 200, true, false
		if i == 0 && operation.Method == "GET" && !oldPresent {
			status, present, oldAbsent = 404, false, true
		} else if operation.Method == "POST" {
			status, created = 201, true
		}
		return sessionReplyValue(operation.Method, status, uid, operation.ID, present, created), "", ""
	})
}

func startSessionServer(t *testing.T, port int, uid string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("python3", "-B", "-c", sessionServerSource)
	cmd.Env = append(os.Environ(), "PORT="+fmt.Sprintf("%d", port), "POD_UID="+uid)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func stopSessionServer(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func waitSessionServer(t *testing.T, base string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(base + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("session server did not become ready")
}

func runActualSessionBatch(t *testing.T, base string, operations []sessionBatchOperation) sessionBatchResult {
	t.Helper()
	raw, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionBatchExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-B", "-c", sessionClientSource, base, base64.StdEncoding.EncodeToString(raw), strconv.FormatFloat(sessionBatchHTTPBudget.Seconds(), 'f', 3, 64))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual batch client failed: %v\n%s", err, out)
	}
	result, err := parseSessionBatchReply(out, operations, sessionBatchHTTPBudget, base)
	if err != nil {
		t.Fatalf("actual batch parse failed: %v\n%s", err, out)
	}
	return result
}

func runActualSessionClientRaw(t *testing.T, base string, operations []sessionBatchOperation, budget time.Duration) []byte {
	t.Helper()
	raw, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-B", "-c", sessionClientSource, base, base64.StdEncoding.EncodeToString(raw), strconv.FormatFloat(budget.Seconds(), 'f', 3, 64))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual bounded client failed: %v\n%s", err, out)
	}
	return out
}

func assertActualBatchFailureReceipt(t *testing.T, raw []byte, base string, budget time.Duration, requirePartialBody bool) {
	t.Helper()
	var envelope struct {
		Responses []struct {
			HTTPStatus     *int   `json:"httpStatus"`
			BodyBase64     string `json:"bodyBase64"`
			BodyBytes      int    `json:"bodyBytes"`
			BodySHA256     string `json:"bodySHA256"`
			TransportError string `json:"transportError"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Responses) != 1 || envelope.Responses[0].TransportError == "" {
		t.Fatalf("transport receipt missing: envelope=%+v err=%v raw=%s", envelope, err, raw)
	}
	row := envelope.Responses[0]
	if requirePartialBody {
		body, err := base64.StdEncoding.Strict().DecodeString(row.BodyBase64)
		if err != nil || len(body) == 0 || len(body) != row.BodyBytes || fmt.Sprintf("%x", sha256.Sum256(body)) != row.BodySHA256 || row.HTTPStatus == nil {
			t.Fatalf("partial body evidence missing: row=%+v err=%v", row, err)
		}
	}
	ops := []sessionBatchOperation{{Method: "GET", ID: "session-budget", When: "always"}}
	if _, err := parseSessionBatchReply(raw, ops, budget, base); err == nil || !strings.Contains(err.Error(), "transport failed") {
		t.Fatalf("transport failure was accepted: %v", err)
	}
}

func cloneJSONMap(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
