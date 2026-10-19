package sensorclient_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	amtd "github.com/r6security/phoenix/api/v1beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorclient"
	"github.com/phorvex/phorvex/internal/sensorpb"
	"github.com/phorvex/phorvex/internal/sensorsvc"
	"github.com/phorvex/phorvex/internal/wire"
)

var testConfig = sensorapi.Config{TrustedDetectors: []string{"vllm/detector"}}

func TestWireTypesRoundTripStructurally(t *testing.T) {
	if problems := wire.Problems(sensorapi.ObserveRequest{}, sensorapi.Observation{}, map[string]model.Telemetry{}, model.SourceHealth{}); len(problems) > 0 {
		t.Fatalf("types crossing the sensor wire would not survive CBOR:\n  %s", strings.Join(problems, "\n  "))
	}
}

// serve runs sensor behind a gRPC server on an in-memory listener.
func serve(t *testing.T, sensor sensorapi.Sensor, source string) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.MaxSendMsgSize(wire.MaxMessageBytes))
	sensorpb.RegisterSensorServiceServer(srv, sensorsvc.NewServer(sensor, testConfig.SHA256(), source))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///sensor",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(wire.MaxMessageBytes)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func connect(t *testing.T, sensor sensorapi.Sensor, source string) *sensorclient.Client {
	t.Helper()
	client, err := sensorclient.New(context.Background(), serve(t, sensor, source), sensorclient.Options{Config: testConfig})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type fakeSource struct{ err error }

func (fakeSource) Name() string { return "fake-prometheus" }
func (f fakeSource) PodMetrics(_ context.Context, _ string, names []string) (map[string]model.Telemetry, error) {
	out := map[string]model.Telemetry{}
	for i, name := range names {
		out[name] = model.Telemetry{ReqRate: model.PresentSignal(float64(i)+0.5, "fake"), P99Ms: model.Signal{State: model.Absent}}
	}
	return out, f.err
}
func (f fakeSource) LastHealth() model.SourceHealth {
	if f.err != nil {
		return model.SourceHealth{Source: "fake-prometheus", Total: 2, Failed: 1}
	}
	return model.SourceHealth{Source: "fake-prometheus", Total: 2}
}

// cluster is a fixture cluster: two namespaces, a dry-run brake, a Service, a
// policy, and Pods across the web and db tiers.
func cluster(t *testing.T) *sensorsvc.Local {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	started := metav1.NewTime(time.Date(2026, 10, 18, 8, 0, 0, 0, time.UTC))
	pod := func(ns, name, app string, ready bool) *corev1.Pod {
		status := corev1.ConditionFalse
		if ready {
			status = corev1.ConditionTrue
		}
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name), Labels: map[string]string{"app": app}},
			Spec: corev1.PodSpec{NodeName: "node-1", ServiceAccountName: "sa-" + app, Containers: []corev1.Container{{Name: "c", Image: "img@sha256:" + strings.Repeat("a", 64)}},
				Volumes: []corev1.Volume{{Name: "creds", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "creds"}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, StartTime: &started,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}},
		}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "vllm", Labels: map[string]string{"tier": "serving"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "batch", Annotations: map[string]string{"phorvex.ai/dry-run": "true"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{"node.kubernetes.io/instance-type": "g5"}},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: "web", UID: "svc-uid"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}}},
		&v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: "defense"},
			Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}},
		pod("vllm", "web-1", "web", true), pod("vllm", "web-2", "web", false), pod("vllm", "db", "db", true), pod("batch", "job", "job", true),
	).Build()
	return &sensorsvc.Local{Client: c, Metrics: fakeSource{}}
}

// TestRemoteSensorMatchesInProcess observes the same cluster in process and
// through the sensor service and requires the identical observation and telemetry.
func TestRemoteSensorMatchesInProcess(t *testing.T) {
	local := cluster(t)
	client := connect(t, local, local.TelemetrySource())
	req := sensorapi.ObserveRequest{Now: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC), ResolveOwners: true,
		Scopes: []sensorapi.Scope{{Namespace: "vllm", Selector: "app=web"}, {Namespace: "batch"}}}
	ctx := context.Background()
	want, err := local.Observe(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Observe(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Pods) != 4 || len(want.Context) != 3 || len(want.NamespaceDryRun) == 0 || len(want.Services) != 1 || len(want.Physics) == 0 {
		t.Fatalf("fixture observation is too thin to prove parity: pods %d context %d", len(want.Pods), len(want.Context))
	}
	wantRaw, err := wire.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	gotRaw, err := wire.Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantRaw, gotRaw) {
		t.Fatalf("remote observation encodes differently from the in-process one in %v", differingFields(t, want, got))
	}
	if diffs := differences(reflect.ValueOf(want).Elem(), reflect.ValueOf(got).Elem(), "observation"); len(diffs) > 0 {
		t.Fatalf("remote observation differs from the in-process one:\n  %s", strings.Join(diffs, "\n  "))
	}

	treq := sensorapi.TelemetryRequest{Namespace: "vllm", Pods: []string{"web-1", "web-2"}}
	if l, r := local.Telemetry(ctx, treq), client.Telemetry(ctx, treq); !reflect.DeepEqual(l, r) || !r.Configured || len(r.Telemetry) != 2 {
		t.Fatalf("telemetry differs:\nlocal:  %+v\nremote: %+v", l, r)
	}
	partial := &sensorsvc.Local{Metrics: fakeSource{err: errors.New("reqRate: 500")}}
	partialClient := connect(t, partial, partial.TelemetrySource())
	if l, r := partial.Telemetry(ctx, treq), partialClient.Telemetry(ctx, treq); !reflect.DeepEqual(l, r) || r.Error != "reqRate: 500" {
		t.Fatalf("partial telemetry differs:\nlocal:  %+v\nremote: %+v", l, r)
	}
	none := &sensorsvc.Local{}
	if r := connect(t, none, none.TelemetrySource()).Telemetry(ctx, treq); r.Configured {
		t.Fatal("no telemetry source, yet the remote read reports one")
	}
}

// differingFields names the observation fields whose encodings differ.
func differingFields(t *testing.T, a, b *sensorapi.Observation) []string {
	t.Helper()
	var out []string
	va, vb := reflect.ValueOf(a).Elem(), reflect.ValueOf(b).Elem()
	for i := 0; i < va.NumField(); i++ {
		ra, err := wire.Encode(va.Field(i).Interface())
		if err != nil {
			t.Fatal(err)
		}
		rb, err := wire.Encode(vb.Field(i).Interface())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ra, rb) {
			out = append(out, va.Type().Field(i).Name)
		}
	}
	return out
}

var timeType = reflect.TypeOf(time.Time{})

// differences compares two values field by field. Unlike reflect.DeepEqual it
// tells nil from empty collections apart in its report, and it compares times by
// instant and UTC offset: the wire keeps both, not the *time.Location pointer.
func differences(a, b reflect.Value, path string) []string {
	if a.Kind() != b.Kind() {
		return []string{path + ": kind differs"}
	}
	var out []string
	switch a.Kind() {
	case reflect.Pointer, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			if a.IsNil() != b.IsNil() {
				out = append(out, path+": nil differs")
			}
			return out
		}
		return differences(a.Elem(), b.Elem(), path)
	case reflect.Slice:
		if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
			return []string{fmt.Sprintf("%s: nil %v/%v, len %d/%d", path, a.IsNil(), b.IsNil(), a.Len(), b.Len())}
		}
		for i := 0; i < a.Len(); i++ {
			out = append(out, differences(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
	case reflect.Map:
		if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
			return []string{fmt.Sprintf("%s: nil %v/%v, len %d/%d", path, a.IsNil(), b.IsNil(), a.Len(), b.Len())}
		}
		for _, k := range a.MapKeys() {
			if !b.MapIndex(k).IsValid() {
				out = append(out, fmt.Sprintf("%s[%v]: missing", path, k))
				continue
			}
			out = append(out, differences(a.MapIndex(k), b.MapIndex(k), fmt.Sprintf("%s[%v]", path, k))...)
		}
	case reflect.Struct:
		if a.Type() == timeType {
			ta, tb := a.Interface().(time.Time), b.Interface().(time.Time)
			_, oa := ta.Zone()
			_, ob := tb.Zone()
			if !ta.Equal(tb) || oa != ob {
				out = append(out, fmt.Sprintf("%s: %v vs %v", path, ta, tb))
			}
			return out
		}
		for i := 0; i < a.NumField(); i++ {
			if a.Type().Field(i).IsExported() {
				out = append(out, differences(a.Field(i), b.Field(i), path+"."+a.Type().Field(i).Name)...)
			}
		}
	case reflect.Float32, reflect.Float64:
		if fa, fb := a.Float(), b.Float(); fa != fb && !(math.IsNaN(fa) && math.IsNaN(fb)) {
			out = append(out, fmt.Sprintf("%s: %v vs %v", path, fa, fb))
		}
	default:
		if !reflect.DeepEqual(a.Interface(), b.Interface()) {
			out = append(out, fmt.Sprintf("%s: %v vs %v", path, a.Interface(), b.Interface()))
		}
	}
	return out
}

type failingSensor struct{ sensorapi.Sensor }

func (failingSensor) Observe(context.Context, sensorapi.ObserveRequest) (*sensorapi.Observation, error) {
	return nil, errors.New("pods list: forbidden")
}

func TestUnavailableObservationIsAnError(t *testing.T) {
	client := connect(t, failingSensor{}, "")
	obs, err := client.Observe(context.Background(), sensorapi.ObserveRequest{Now: time.Now()})
	if err == nil || obs != nil || !strings.Contains(err.Error(), "pods list: forbidden") {
		t.Fatalf("a failed observation must be an error: %v, %v", obs, err)
	}
}

func TestUnreachableTelemetryReadsAsSourceOutage(t *testing.T) {
	local := &sensorsvc.Local{Metrics: fakeSource{}}
	conn := serve(t, local, local.TelemetrySource())
	client, err := sensorclient.New(context.Background(), conn, sensorclient.Options{Config: testConfig})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	read := client.Telemetry(context.Background(), sensorapi.TelemetryRequest{Namespace: "vllm"})
	if !read.Configured || !read.Health.Unreachable() || read.Health.Source != "fake-prometheus" || read.Error == "" || read.Telemetry != nil {
		t.Fatalf("unanswered telemetry = %+v, want an unreachable source", read)
	}
}

func TestHelloRefusesAnotherContractOrConfiguration(t *testing.T) {
	conn := serve(t, &sensorsvc.Local{}, "")
	other := testConfig
	other.EndpointLeaseApprovedSource = strings.Repeat("b", 64)
	if _, err := sensorclient.New(context.Background(), conn, sensorclient.Options{Config: other}); status.Code(errors.Unwrap(err)) != codes.FailedPrecondition {
		t.Fatalf("other configuration: %v", err)
	}
	reordered := sensorapi.Config{TrustedDetectors: []string{"b", "a"}}
	sorted := sensorapi.Config{TrustedDetectors: []string{"a", "b"}}
	if reordered.SHA256() != sorted.SHA256() {
		t.Fatal("trusted identities must compare as a set")
	}
	_, err := sensorpb.NewSensorServiceClient(conn).Hello(context.Background(),
		&sensorpb.HelloRequest{ContractVersion: sensorapi.ContractVersion + 1, ConfigSha256: testConfig.SHA256()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("another contract version: %v", err)
	}
}
