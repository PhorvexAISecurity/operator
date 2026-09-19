package actuator

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m067Backend struct {
	mu       sync.Mutex
	posts    int
	requests []string
	mode     string
	server   *httptest.Server
}

func (b *m067Backend) handler(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	b.requests = append(b.requests, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
	if r.Method == http.MethodPost {
		b.posts++
	}
	b.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer m067-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "models") {
			_, _ = w.Write([]byte(`{"data":[{"id":"model"}]}`))
			if b.mode == "definitely-unsent" {
				_ = b.server.Listener.Close()
			}
			return
		}
		_, _ = w.Write([]byte(`{}`))
		return
	}
	switch b.mode {
	case "202":
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	case "malformed-200":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"aborted":`))
	case "empty-200":
		w.WriteHeader(http.StatusOK)
	case "404":
		http.Error(w, "missing", http.StatusNotFound)
	case "501":
		http.Error(w, "unsupported", http.StatusNotImplemented)
	case "accepted-lost-response":
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		_ = rw.Flush()
		_ = conn.Close()
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"aborted":2}`))
	}
}

func (b *m067Backend) counts() (int, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.posts, append([]string(nil), b.requests...)
}

func m067NonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		var ip net.IP
		switch parsed := address.(type) {
		case *net.IPNet:
			ip = parsed.IP
		case *net.IPAddr:
			ip = parsed.IP
		}
		if ip4 := ip.To4(); ip4 != nil && ip4.IsGlobalUnicast() && !ip4.IsLoopback() {
			return ip4.String()
		}
	}
	t.Fatal("isolated EndpointSlice fixture requires a non-loopback local IPv4 address")
	return ""
}

type m067APIFixture struct {
	client  client.WithWatch
	native  *NativeActuator
	old     *corev1.Pod
	next    *corev1.Pod
	third   *corev1.Pod
	policy  *v1alpha1.PhorvexPolicy
	service *corev1.Service
	backend *m067Backend
	opns    string
}

func m067NewAPIFixture(t *testing.T, ctx context.Context, c client.WithWatch, suffix, mode string) *m067APIFixture {
	return m067NewAPIAvailabilityFixture(t, ctx, c, suffix, mode, 2, 1)
}

func m067NewAPIAvailabilityFixture(t *testing.T, ctx context.Context, c client.WithWatch, suffix, mode string, replicas int32, floor int) *m067APIFixture {
	t.Helper()
	nsName, opns := "m067-"+suffix, "m067-op-"+suffix
	for _, name := range []string{nsName, opns} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	backend := &m067Backend{mode: mode}
	server := httptest.NewUnstartedServer(http.HandlerFunc(backend.handler))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(m067NonLoopbackIPv4(t), "0"))
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.StartTLS()
	backend.server = server
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cert := server.Certificate()
	serverName := host
	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) > 0 {
		serverName = cert.IPAddresses[0].String()
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: nsName, Name: "serving"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": suffix, labelSwapGroup: "g", labelRole: roleLeader}, Ports: []corev1.ServicePort{{Port: int32(port)}}}}
	if err := c.Create(ctx, service); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: nsName, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Tenant: suffix, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": suffix}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Second}, ProactiveFloor: metav1.Duration{Duration: time.Minute}}, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: floor}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: opns, Name: "serving-admin"}, Data: map[string][]byte{"bearer": []byte("m067-token"), "ca.crt": ca}}
	if err := c.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: nsName, Name: "pool"}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": suffix, labelSwapGroup: "g"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": suffix, labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "false"}, Annotations: map[string]string{annoRouteService: service.Name, "phorvex.ai/model-id": "model", annoServingPort: portText}}, Spec: corev1.PodSpec{NodeName: "m067-node", ServiceAccountName: "model-sa", TerminationGracePeriodSeconds: &zero, Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}}}}}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	var pods corev1.PodList
	m066Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &pods, client.InNamespace(nsName)); err != nil {
			return false, err
		}
		current := &appsv1.ReplicaSet{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(rs), current); err != nil {
			return false, err
		}
		return len(pods.Items) == int(replicas) && current.Status.ObservedGeneration == current.Generation && current.Status.Replicas == replicas, nil
	})
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	old, next := pods.Items[0].DeepCopy(), pods.Items[1].DeepCopy()
	old.Labels[labelRole] = roleLeader
	next.Labels[labelModelLoaded] = "true"
	fixturePods := []*corev1.Pod{old, next}
	var third *corev1.Pod
	for i := 2; i < len(pods.Items); i++ {
		member := pods.Items[i].DeepCopy()
		member.Labels[labelRole] = roleLeader
		fixturePods = append(fixturePods, member)
		if third == nil {
			third = member
		}
	}
	for _, pod := range fixturePods {
		if err := c.Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.PodIP = host
		pod.Status.PodIPs = []corev1.PodIP{{IP: host}}
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		// envtest has no kubelet. These explicitly seeded statuses let the real
		// EndpointSlice controller exercise UID membership, but do not claim
		// kubelet readiness or cluster Pod-network traffic.
		if err := c.Status().Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(service), service); err != nil {
		t.Fatal(err)
	}
	m066Poll(t, 20*time.Second, func() (bool, error) {
		members, err := routeEndpointMembers(ctx, c, service)
		if err != nil || len(members) != len(fixturePods)-1 {
			return false, nil
		}
		for _, pod := range fixturePods {
			if pod.Name == next.Name {
				continue
			}
			if !slices.Contains(members, string(pod.UID)) {
				return false, nil
			}
		}
		return true, nil
	})
	binding := ServingSecurityBinding{Namespace: nsName, PolicyName: policy.Name, PolicyUID: string(policy.UID), ServiceAccount: "model-sa", ProfileID: "m067", SecretName: secret.Name, BearerKey: "bearer", CAKey: "ca.crt", ServerName: serverName}
	native := NewNativeActuator(c)
	native.Reader, native.JournalNamespace = c, opns
	native.RouteObservationTimeout, native.RouteObservationInterval = 20*time.Second, 100*time.Millisecond
	native.SetServingSecurity(writeServingSecurityConfig(t, ServingSecuritySecureRequired, opns, []ServingSecurityBinding{binding}))
	return &m067APIFixture{client: c, native: native, old: old, next: next, third: third, policy: policy, service: service, backend: backend, opns: opns}
}

func (f *m067APIFixture) request() Request {
	return Request{Tenant: f.policy.Spec.Tenant, Namespace: f.old.Namespace, Pod: f.old.Name, TargetUID: string(f.old.UID), PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), Action: model.ActionWarmSwap}
}

func (f *m067APIFixture) receipt(t *testing.T, ctx context.Context) (*corev1.ConfigMap, operationReceipt) {
	t.Helper()
	var list corev1.ConfigMapList
	if err := f.client.List(ctx, &list, client.InNamespace(f.opns), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(list.Items) != 1 {
		t.Fatalf("protected receipt count=%d err=%v", len(list.Items), err)
	}
	var receipt operationReceipt
	if err := json.Unmarshal([]byte(list.Items[0].Data["receipt"]), &receipt); err != nil {
		t.Fatal(err)
	}
	return list.Items[0].DeepCopy(), receipt
}

func TestM067ActualAPIControllersAndAuthenticatedDrainOutcomes(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" || os.Getenv("KUBE_CONTROLLER_MANAGER") == "" {
		t.Skip("requires pinned envtest and kube-controller-manager")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if out, err := exec.Command(kcm, "--version").Output(); err != nil || !strings.Contains(string(out), "v1.34.0") {
		t.Fatalf("kube-controller-manager must be v1.34.0: %q %v", out, err)
	}
	local := false
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, UseExistingCluster: &local}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kubeconfig := m066Kubeconfig(t, cfg)
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+kubeconfig, "--controllers=replicaset,endpointslice", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = []string{"KUBECONFIG=" + kubeconfig}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KUBECONFIG=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	var kcmLog m066BoundedLog
	cmd.Stdout, cmd.Stderr = &kcmLog, &kcmLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("bounded kube-controller-manager log:\n%s", kcmLog.String())
		}
		cancel()
		_ = cmd.Wait()
	})
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		var pods corev1.PodList
		var slices discoveryv1.EndpointSliceList
		_ = c.List(context.Background(), &pods)
		_ = c.List(context.Background(), &slices)
		podState := make([]string, 0, len(pods.Items))
		for i := range pods.Items {
			pod := &pods.Items[i]
			if !strings.HasPrefix(pod.Namespace, "m067-") {
				continue
			}
			podState = append(podState, fmt.Sprintf("%s/%s uid=%s role=%s IPs=%v deleting=%t", pod.Namespace, pod.Name, pod.UID, pod.Labels[labelRole], pod.Status.PodIPs, pod.DeletionTimestamp != nil))
		}
		sliceState := make([]string, 0, len(slices.Items))
		for i := range slices.Items {
			slice := &slices.Items[i]
			if !strings.HasPrefix(slice.Namespace, "m067-") {
				continue
			}
			for j := range slice.Endpoints {
				endpoint := &slice.Endpoints[j]
				target := ""
				if endpoint.TargetRef != nil {
					target = endpoint.TargetRef.Namespace + "/" + endpoint.TargetRef.Name + " uid=" + string(endpoint.TargetRef.UID)
				}
				sliceState = append(sliceState, fmt.Sprintf("%s/%s addresses=%v target=%s", slice.Namespace, slice.Name, endpoint.Addresses, target))
			}
		}
		t.Logf("M067 failure-state Pods=%v EndpointSlices=%v", podState, sliceState)
	})
	if err := c.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "m067-node"}}); err != nil {
		t.Fatal(err)
	}
	t.Run("three-member-ready-floor-retains-then-recovers", func(t *testing.T) {
		fixture := m067NewAPIAvailabilityFixture(t, ctx, c, "floor", "confirmed", 3, 2)
		dropped := false
		guard := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || dropped || !strings.Contains(cm.Data["receipt"], `"phase":"promoted"`) {
				return inner.Update(ctx, obj, opts...)
			}
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			dropped = true
			return m067SetPodReady(ctx, inner, fixture.third, false)
		}})
		fixture.native.Client, fixture.native.Reader = guard, guard
		result, enactErr := fixture.native.Actuate(ctx, fixture.request())
		if enactErr == nil || result.MutationKind != "swap" || !dropped {
			t.Fatalf("actual API availability boundary not exercised: result=%+v err=%v dropped=%t", result, enactErr, dropped)
		}
		if posts, requests := fixture.backend.counts(); posts != 0 {
			t.Fatalf("actual API unavailable prospective set reached POST: posts=%d requests=%v", posts, requests)
		}
		_, receipt := fixture.receipt(t, ctx)
		if receipt.Phase != "promoted" || receipt.AdmittedFloor != 2 {
			t.Fatalf("actual API availability refusal lost admitted state: %+v", receipt)
		}
		oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.old), oldCurrent); err != nil || oldCurrent.UID != fixture.old.UID || oldCurrent.Labels[labelRole] != roleLeader {
			t.Fatalf("actual API availability refusal changed old route: %v %+v", err, oldCurrent)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.next), nextCurrent); err != nil || nextCurrent.UID != fixture.next.UID || nextCurrent.Labels[labelRole] != roleLeader {
			t.Fatalf("actual API availability refusal rolled back promoted capacity: %v %+v", err, nextCurrent)
		}
		if err := m067SetPodReady(ctx, c, fixture.third, true); err != nil {
			t.Fatal(err)
		}
		consumer := NewNativeActuator(c)
		consumer.Reader, consumer.JournalNamespace = c, fixture.opns
		consumer.RouteObservationTimeout, consumer.RouteObservationInterval = 20*time.Second, 100*time.Millisecond
		consumer.SetServingSecurity(fixture.native.servingSecurity)
		events, recoverErr := consumer.RecoverOperations(ctx, false)
		if recoverErr != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Effect, "old leader retired") {
			t.Fatalf("actual API restored readiness did not resume through confirmed retirement: events=%+v err=%v", events, recoverErr)
		}
		if posts, requests := fixture.backend.counts(); posts != 1 {
			t.Fatalf("actual API availability recovery POSTs=%d requests=%v", posts, requests)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.old), &corev1.Pod{}); !apierrors.IsNotFound(err) {
			t.Fatalf("actual API availability recovery did not delete exact old UID: %v", err)
		}
	})
	t.Run("authority-drift-after-acknowledged-dispatch-claim", func(t *testing.T) {
		fixture := m067NewAPIFixture(t, ctx, c, "authority", "confirmed")
		claimed := false
		guard := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || claimed || !strings.Contains(cm.Data["receipt"], `"phase":"drain-dispatching"`) {
				return inner.Update(ctx, obj, opts...)
			}
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			claimed = true
			policy := &v1alpha1.PhorvexPolicy{}
			if err := inner.Get(ctx, client.ObjectKeyFromObject(fixture.policy), policy); err != nil {
				return err
			}
			policy.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRotate)}
			return inner.Update(ctx, policy)
		}})
		fixture.native.Client, fixture.native.Reader = guard, guard
		result, enactErr := fixture.native.Actuate(ctx, fixture.request())
		if enactErr == nil || result.MutationKind != "swap" || !claimed {
			t.Fatalf("actual API post-claim authority seam not exercised: result=%+v err=%v claimed=%t", result, enactErr, claimed)
		}
		if posts, requests := fixture.backend.counts(); posts != 0 {
			t.Fatalf("authority drift after acknowledged claim reached POST: posts=%d requests=%v", posts, requests)
		}
		_, receipt := fixture.receipt(t, ctx)
		if receipt.Phase != "drain-dispatching" || receipt.DrainAttempts != 1 {
			t.Fatalf("authority drift did not retain dispatch claim: %+v", receipt)
		}
		oldCurrent, nextCurrent := &corev1.Pod{}, &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.old), oldCurrent); err != nil || oldCurrent.Labels[labelRole] != roleRetiring {
			t.Fatalf("authority drift deleted or compensated old UID: %v %+v", err, oldCurrent)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.next), nextCurrent); err != nil || nextCurrent.Labels[labelRole] != roleLeader {
			t.Fatalf("authority drift compensated promoted UID: %v %+v", err, nextCurrent)
		}
	})
	t.Run("two-consumers-one-cas-winner-one-post", func(t *testing.T) {
		fixture := m067NewAPIFixture(t, ctx, c, "cas", "confirmed")
		retiringPersisted := false
		prepare := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || retiringPersisted || !strings.Contains(cm.Data["receipt"], `"phase":"retiring"`) {
				return inner.Update(ctx, obj, opts...)
			}
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			retiringPersisted = true
			return fmt.Errorf("retiring acknowledgement intentionally lost")
		}})
		fixture.native.Client, fixture.native.Reader = prepare, prepare
		if _, err := fixture.native.Actuate(ctx, fixture.request()); err == nil || !retiringPersisted {
			t.Fatalf("durable retiring fixture not prepared: err=%v persisted=%t", err, retiringPersisted)
		}
		if posts, requests := fixture.backend.counts(); posts != 0 {
			t.Fatalf("pre-CAS fixture sent drain: posts=%d requests=%v", posts, requests)
		}

		runCtx, cancelRun := context.WithTimeout(ctx, 20*time.Second)
		defer cancelRun()
		var barrierMu sync.Mutex
		arrivals, winners := 0, 0
		bothArrived := make(chan struct{})
		barrier := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || !strings.Contains(cm.Data["receipt"], `"phase":"drain-dispatching"`) {
				return inner.Update(ctx, obj, opts...)
			}
			barrierMu.Lock()
			arrivals++
			if arrivals == 2 {
				close(bothArrived)
			}
			barrierMu.Unlock()
			select {
			case <-bothArrived:
			case <-ctx.Done():
				return ctx.Err()
			}
			err := inner.Update(ctx, obj, opts...)
			if err == nil {
				barrierMu.Lock()
				winners++
				barrierMu.Unlock()
			}
			return err
		}})
		makeConsumer := func() *NativeActuator {
			n := NewNativeActuator(barrier)
			n.Reader, n.JournalNamespace = barrier, fixture.opns
			n.RouteObservationTimeout, n.RouteObservationInterval = 20*time.Second, 100*time.Millisecond
			n.SetServingSecurity(fixture.native.servingSecurity)
			return n
		}
		consumers := []*NativeActuator{makeConsumer(), makeConsumer()}
		results := make([][]RecoveryEvent, len(consumers))
		errs := make([]error, len(consumers))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range consumers {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				<-start
				results[index], errs[index] = consumers[index].RecoverOperations(runCtx, false)
			}(i)
		}
		close(start)
		wg.Wait()
		barrierMu.Lock()
		gotArrivals, gotWinners := arrivals, winners
		barrierMu.Unlock()
		if gotArrivals != 2 || gotWinners != 1 {
			t.Fatalf("actual API dispatch CAS arrivals=%d winners=%d results=%+v errs=%v", gotArrivals, gotWinners, results, errs)
		}
		if posts, requests := fixture.backend.counts(); posts != 1 {
			t.Fatalf("competing consumers emitted posts=%d requests=%v results=%+v errs=%v", posts, requests, results, errs)
		}
		for i := range results {
			if errs[i] != nil || len(results[i]) != 1 {
				t.Fatalf("consumer %d recovery events=%+v err=%v", i, results[i], errs[i])
			}
			if strings.Contains(results[i][0].Effect, "restored") {
				t.Fatalf("CAS loser compensated routing: consumer=%d event=%+v", i, results[i][0])
			}
		}
		next := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.next), next); err != nil || next.Labels[labelRole] != roleLeader {
			t.Fatalf("competing consumer changed promoted route: %v %+v", err, next)
		}
		old := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.old), old); err == nil && old.Labels[labelRole] != roleRetiring {
			t.Fatalf("CAS loser changed retained old route: %+v", old)
		}
		check := NewNativeActuator(c)
		check.Reader, check.JournalNamespace = c, fixture.opns
		check.SetServingSecurity(fixture.native.servingSecurity)
		_, _ = check.RecoverOperations(ctx, false)
		if posts, requests := fixture.backend.counts(); posts != 1 {
			t.Fatalf("post-race recovery replayed drain: posts=%d requests=%v", posts, requests)
		}
	})
	for i, mode := range []string{"202", "malformed-200", "empty-200", "404", "501", "accepted-lost-response"} {
		t.Run(mode, func(t *testing.T) {
			fixture := m067NewAPIFixture(t, ctx, c, fmt.Sprintf("u%d", i), mode)
			result, enactErr := fixture.native.Actuate(ctx, fixture.request())
			if enactErr == nil || result.Emitted {
				t.Fatalf("possibly-sent drain was reported complete: result=%+v err=%v", result, enactErr)
			}
			posts, requests := fixture.backend.counts()
			if posts != 1 {
				t.Fatalf("drain POST count=%d requests=%v", posts, requests)
			}
			_, receipt := fixture.receipt(t, ctx)
			if receipt.Version != warmDrainReceiptVersion || receipt.Phase != "drain-dispatching" || receipt.DrainAttempts != 1 {
				t.Fatalf("possibly-sent receipt lost exact state: %+v", receipt)
			}
			old, next := &corev1.Pod{}, &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.old), old); err != nil || old.UID != fixture.old.UID || old.Labels[labelRole] != roleRetiring {
				t.Fatalf("old UID was deleted/restored without confirmation: %v %+v", err, old)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.next), next); err != nil || next.UID != fixture.next.UID || next.Labels[labelRole] != roleLeader {
				t.Fatalf("promoted survivor changed: %v %+v", err, next)
			}
			events, recoverErr := fixture.native.RecoverOperations(ctx, false)
			if recoverErr != nil || len(events) != 1 || events[0].Err == nil || !strings.Contains(events[0].Err.Error(), "without replay") {
				t.Fatalf("possibly-sent recovery was not retained: events=%+v err=%v", events, recoverErr)
			}
			if after, _ := fixture.backend.counts(); after != posts {
				t.Fatalf("recovery replayed possibly-sent drain: before=%d after=%d", posts, after)
			}
		})
	}
	t.Run("typed-actual-transport-definitely-unsent", func(t *testing.T) {
		fixture := m067NewAPIFixture(t, ctx, c, "unsent", "definitely-unsent")
		sampleCtx, stopSamples := context.WithCancel(ctx)
		sampleDone := make(chan []int, 1)
		go func() {
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			samples := make([]int, 0, 64)
			for {
				select {
				case <-sampleCtx.Done():
					sampleDone <- samples
					return
				case <-ticker.C:
					members, err := routeEndpointMembers(ctx, c, fixture.service)
					if err != nil {
						samples = append(samples, -1)
					} else {
						samples = append(samples, len(members))
					}
				}
			}
		}()
		result, enactErr := fixture.native.Actuate(ctx, fixture.request())
		stopSamples()
		samples := <-sampleDone
		if enactErr == nil || result.Emitted || !strings.Contains(enactErr.Error(), "routing restored") {
			t.Fatalf("definitely-unsent drain did not report compensated partial: result=%+v err=%v", result, enactErr)
		}
		posts, requests := fixture.backend.counts()
		if posts != 0 {
			t.Fatalf("closed-listener transport reached a drain handler: posts=%d requests=%v", posts, requests)
		}
		sawBridge := false
		for _, count := range samples {
			if count <= 0 {
				t.Fatalf("actual EndpointSlice observation saw an empty/unreadable route: samples=%v", samples)
			}
			sawBridge = sawBridge || count == 2
		}
		if !sawBridge {
			t.Fatalf("actual EndpointSlice controller never exposed the protected old+new bridge: samples=%v", samples)
		}
		old, next := &corev1.Pod{}, &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.old), old); err != nil || old.UID != fixture.old.UID || old.Labels[labelRole] != roleLeader {
			t.Fatalf("old-first restoration did not retain exact old UID: %v %+v", err, old)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.next), next); err != nil || next.UID != fixture.next.UID || next.Labels[labelRole] != roleShadow {
			t.Fatalf("new member did not return to shadow: %v %+v", err, next)
		}
		members, err := routeEndpointMembers(ctx, c, fixture.service)
		if err != nil || len(members) != 1 || members[0] != string(old.UID) {
			t.Fatalf("actual EndpointSlice controller did not restore old-only route: members=%v err=%v", members, err)
		}
		var journals corev1.ConfigMapList
		if err := c.List(ctx, &journals, client.InNamespace(fixture.opns), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(journals.Items) != 0 {
			t.Fatalf("completed definitely-unsent restoration retained receipt: count=%d err=%v", len(journals.Items), err)
		}
	})
	t.Run("promoted-not-ready-restores-old-through-controller", func(t *testing.T) {
		fixture := m067NewAPIAvailabilityFixture(t, ctx, c, "next-not-ready", "definitely-unsent", 3, 2)
		dropped := false
		guard := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || dropped || !strings.Contains(cm.Data["receipt"], `"phase":"drain-unsent"`) {
				return inner.Update(ctx, obj, opts...)
			}
			if err := inner.Update(ctx, cm, opts...); err != nil {
				return err
			}
			dropped = true
			return m067SetPodReady(ctx, inner, fixture.next, false)
		}})
		fixture.native.Client, fixture.native.Reader = guard, guard
		result, enactErr := fixture.native.Actuate(ctx, fixture.request())
		if enactErr == nil || result.Emitted || !dropped || !strings.Contains(enactErr.Error(), "routing restored") {
			t.Fatalf("actual API next-readiness compensation not completed: result=%+v err=%v dropped=%t", result, enactErr, dropped)
		}
		if posts, requests := fixture.backend.counts(); posts != 0 {
			t.Fatalf("definitely-unsent actual transport reached backend POST: posts=%d requests=%v", posts, requests)
		}
		oldCurrent, nextCurrent, thirdCurrent := &corev1.Pod{}, &corev1.Pod{}, &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.old), oldCurrent); err != nil || oldCurrent.UID != fixture.old.UID || oldCurrent.Labels[labelRole] != roleLeader || !podReady(oldCurrent) {
			t.Fatalf("actual controller path did not restore healthy old UID: %v %+v", err, oldCurrent)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.next), nextCurrent); err != nil || nextCurrent.UID != fixture.next.UID || nextCurrent.Labels[labelRole] != roleShadow || podReady(nextCurrent) {
			t.Fatalf("actual controller path did not retain inactive exact shadow: %v %+v", err, nextCurrent)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(fixture.third), thirdCurrent); err != nil || thirdCurrent.UID != fixture.third.UID || thirdCurrent.Labels[labelRole] != roleLeader || !podReady(thirdCurrent) {
			t.Fatalf("actual controller path changed third serving member: %v %+v", err, thirdCurrent)
		}
		members, err := routeEndpointMembers(ctx, c, fixture.service)
		if err != nil || len(members) != 2 || !slices.Contains(members, string(fixture.old.UID)) || !slices.Contains(members, string(fixture.third.UID)) || slices.Contains(members, string(fixture.next.UID)) {
			t.Fatalf("actual EndpointSlice active membership did not match exact Ready leaders: members=%v err=%v", members, err)
		}
		var journals corev1.ConfigMapList
		if err := c.List(ctx, &journals, client.InNamespace(fixture.opns), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(journals.Items) != 0 {
			t.Fatalf("completed actual API next-readiness compensation retained receipt: count=%d err=%v", len(journals.Items), err)
		}
	})
	t.Run("secure-profile-drift-retains-compensation", func(t *testing.T) {
		fixture := m067NewAPIFixture(t, ctx, c, "profile", "definitely-unsent")
		lost := false
		guard := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || lost || !strings.Contains(cm.Data["receipt"], `"phase":"restore-old-claimed"`) {
				return inner.Update(ctx, obj, opts...)
			}
			lost = true
			if err := inner.Update(ctx, obj, opts...); err != nil {
				return err
			}
			return fmt.Errorf("persisted restoration claim acknowledgement lost")
		}})
		fixture.native.Client = guard
		result, enactErr := fixture.native.Actuate(ctx, fixture.request())
		if enactErr == nil || result.Emitted || !lost {
			t.Fatalf("secure restoration claim loss not exercised: result=%+v err=%v lost=%t", result, enactErr, lost)
		}
		bindingKey := servingBindingKey(fixture.old.Namespace, fixture.policy.Name, string(fixture.policy.UID), "model-sa")
		binding := fixture.native.servingSecurity.byKey[bindingKey]
		binding.ProfileID = "foreign-profile"
		fixture.native.servingSecurity.byKey[bindingKey] = binding
		events, recoverErr := fixture.native.RecoverOperations(ctx, false)
		if recoverErr != nil || len(events) != 1 || events[0].Err == nil {
			t.Fatalf("secure profile drift did not retain compensation: events=%+v err=%v", events, recoverErr)
		}
		if posts, requests := fixture.backend.counts(); posts != 0 {
			t.Fatalf("secure profile drift triggered a drain POST: posts=%d requests=%v", posts, requests)
		}
		_, receipt := fixture.receipt(t, ctx)
		if receipt.Phase != "restore-old-claimed" {
			t.Fatalf("secure profile drift changed retained phase: %+v", receipt)
		}
	})
}
