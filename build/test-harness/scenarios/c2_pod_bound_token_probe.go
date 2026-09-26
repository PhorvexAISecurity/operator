package scenarios

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type podTokenHandle struct {
	token             string
	captureID         string
	podUID            types.UID
	serviceAccountUID types.UID
	expiry            time.Time
}

func podTokenCaptureID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func podTokenJWTClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 16<<10 {
		return nil, errors.New("projected Pod token shape invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) > 8<<10 {
		return nil, errors.New("projected Pod token payload invalid")
	}
	var claims map[string]any
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	if d.Decode(&claims) != nil || len(claims) == 0 {
		return nil, errors.New("projected Pod token claims invalid")
	}
	return claims, nil
}
func podTokenClaimUID(claims map[string]any, kind string) (string, error) {
	k, ok := claims["kubernetes.io"].(map[string]any)
	if !ok {
		return "", errors.New("projected token Kubernetes claims absent")
	}
	obj, ok := k[kind].(map[string]any)
	if !ok {
		return "", errors.New("projected token bound object absent")
	}
	uid, ok := obj["uid"].(string)
	if !ok || uid == "" {
		return "", errors.New("projected token bound UID absent")
	}
	return uid, nil
}
func podTokenCapture(ctx context.Context, env *core.Env, p corev1.Pod, saUID types.UID) (podTokenHandle, error) {
	var h podTokenHandle
	if err := podTokenCurrentPod(ctx, env, p); err != nil {
		return h, err
	}
	exec := env.ExecWithTimeout(ctx, p.Name, "responder", 5*time.Second, []string{"cat", "/var/run/pod-token/token"})
	// Never return/log stdout or stderr: both may contain credential material.
	if exec.Err != nil || exec.ExitCode != 0 {
		return h, errors.New("projected Pod token read failed")
	}
	token := strings.TrimSpace(exec.Stdout)
	claims, err := podTokenJWTClaims(token)
	if err != nil {
		return h, err
	}
	podUID, err := podTokenClaimUID(claims, "pod")
	if err != nil || podUID != string(p.UID) {
		return h, errors.New("projected token Pod UID differs")
	}
	accountUID, err := podTokenClaimUID(claims, "serviceaccount")
	if err != nil || accountUID != string(saUID) {
		return h, errors.New("projected token ServiceAccount UID differs")
	}
	exp, ok := claims["exp"].(json.Number)
	if !ok {
		return h, errors.New("projected token expiry absent")
	}
	unix, e := exp.Int64()
	if e != nil {
		return h, errors.New("projected token expiry invalid")
	}
	expiry := time.Unix(unix, 0).UTC()
	if time.Until(expiry) < 3*time.Minute || time.Until(expiry) > 20*time.Minute {
		return h, errors.New("projected token expiry outside replay window")
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 {
		return h, errors.New("projected default-audience token claim differs")
	}
	if text, ok := aud[0].(string); !ok || text == "" {
		return h, errors.New("projected default audience absent")
	}
	captureID, err := podTokenCaptureID()
	if err != nil {
		return h, err
	}
	return podTokenHandle{token: token, captureID: captureID, podUID: p.UID, serviceAccountUID: saUID, expiry: expiry}, nil
}
func podTokenAPIClient(restConfig *rest.Config) (*http.Client, string, error) {
	if restConfig == nil || restConfig.Host == "" {
		return nil, "", errors.New("Pod token API transport unavailable")
	}
	cfg := rest.CopyConfig(restConfig)
	cfg.BearerToken = ""
	cfg.BearerTokenFile = ""
	cfg.Username = ""
	cfg.Password = ""
	cfg.ExecProvider = nil
	cfg.AuthProvider = nil
	transport, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, "", err
	}
	return &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, strings.TrimRight(cfg.Host, "/"), nil
}
func podTokenReplayAPI(ctx context.Context, env *core.Env, h podTokenHandle, peerName string) (int, time.Time, error) {
	status, _, end, err := podTokenReplayAPIWindow(ctx, env, h, peerName)
	return status, end, err
}

// The start and completed response time are both needed for a before-expiry
// credential observation. A socket return time before body drain is insufficient.
func podTokenReplayAPIWindow(ctx context.Context, env *core.Env, h podTokenHandle, peerName string) (int, time.Time, time.Time, error) {
	if h.token == "" || h.captureID == "" || h.podUID == "" {
		return 0, time.Time{}, time.Time{}, errors.New("Pod token capture handle absent")
	}
	client, host, err := podTokenAPIClient(env.Rest)
	if err != nil {
		return 0, time.Time{}, time.Time{}, err
	}
	url := host + "/api/v1/namespaces/" + env.Config.Namespace + "/pods/" + peerName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, time.Time{}, time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	start := time.Now().UTC()
	resp, err := client.Do(req)
	if err != nil {
		return 0, start, time.Now().UTC(), errors.New("Pod token API replay transport failed")
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 2048)); err != nil {
		return 0, start, time.Now().UTC(), errors.New("Pod token API replay body incomplete")
	}
	return resp.StatusCode, start, time.Now().UTC(), nil
}
func podTokenHTTPClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type podTokenReadyReply struct {
	PodUID string `json:"podUID"`
	Nonce  string `json:"nonce"`
}

func podTokenReadyHTTP(ctx context.Context, client *http.Client, url, nonce string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", errors.New("Pod token ready transport failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
	if err != nil || len(raw) > 1024 {
		return 0, "", errors.New("Pod token ready reply unavailable or oversized")
	}
	if resp.StatusCode != 200 {
		return resp.StatusCode, "", nil
	}
	var body podTokenReadyReply
	if json.Unmarshal(raw, &body) != nil || body.PodUID == "" || body.Nonce != nonce {
		return resp.StatusCode, "", errors.New("Pod token ready identity differs")
	}
	return resp.StatusCode, body.PodUID, nil
}
func podTokenDirectReady(ctx context.Context, p corev1.Pod, nonce string) (int, error) {
	if p.Status.PodIP == "" {
		return 0, errors.New("Pod token direct Pod IP absent")
	}
	status, uid, err := podTokenReadyHTTP(ctx, podTokenHTTPClient(), fmt.Sprintf("http://%s:%d/ready", p.Status.PodIP, podTokenPort), nonce)
	if err != nil || uid != string(p.UID) {
		return status, errors.New("Pod token direct ready UID differs")
	}
	return status, nil
}
func podTokenServiceReady(ctx context.Context, env *core.Env, f podTokenFixture) (int, types.UID, types.UID, error) {
	svc, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, f.name, metav1.GetOptions{})
	if err != nil || svc.UID != f.serviceUID || svc.Spec.ClusterIP == "" {
		return 0, "", "", errors.New("Pod token Service identity changed")
	}
	status, rawUID, err := podTokenReadyHTTP(ctx, podTokenHTTPClient(), fmt.Sprintf("http://%s.%s.svc.cluster.local:%d/ready", f.name, env.Config.Namespace, podTokenPort), env.Config.PodBoundTokenFixture.Nonce)
	if err != nil {
		return status, "", "", err
	}
	member := types.UID(rawUID)
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + f.name, Limit: 20})
	if err != nil || slices.Continue != "" {
		return status, member, "", errors.New("Pod token Service EndpointSlice inventory incomplete")
	}
	for _, s := range slices.Items {
		for _, e := range s.Endpoints {
			if e.TargetRef != nil && e.TargetRef.Kind == "Pod" && e.TargetRef.UID == member && e.Conditions.Ready != nil && *e.Conditions.Ready {
				podName := e.TargetRef.Name
				pod, pe := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, podName, metav1.GetOptions{})
				if pe != nil || pod.UID != member || !podTokenReady(*pod) ||
					pod.Labels[podTokenOwnerLabel] != env.Config.PodBoundTokenFixture.Nonce ||
					len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].Kind != "ReplicaSet" ||
					pod.OwnerReferences[0].UID == "" {
					return status, member, s.UID, errors.New("Pod token routed member not current controller-owned Ready Pod")
				}
				rs, re := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
				if re != nil || rs.UID != pod.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 ||
					rs.OwnerReferences[0].Kind != "Deployment" || rs.OwnerReferences[0].UID != f.deploymentUID {
					return status, member, s.UID, errors.New("Pod token routed member Deployment ownership differs")
				}
				return status, member, s.UID, nil
			}
		}
	}
	return status, member, "", errors.New("Pod token routed member not Ready EndpointSlice member")
}

type podTokenPromResult struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []any             `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

func podTokenPromQuery(ctx context.Context, base, expression, namespace, pod, nonce, podUID string, evaluation time.Time, sourceLabels bool) (float64, []byte, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return 0, nil, errors.New("Pod token Prometheus URL invalid")
	}
	// Prometheus serializes vector evaluation timestamps to milliseconds. Send
	// that same instant and compare its decoded value exactly, so a legitimate
	// millisecond response is accepted without admitting a different instant.
	evaluation = evaluation.UTC().Truncate(time.Millisecond)
	evaluationText := strconv.FormatFloat(float64(evaluation.UnixMilli())/1000, 'f', 3, 64)
	parsed.Path = "/api/v1/query"
	parsed.RawQuery = url.Values{"query": {expression}, "time": {evaluationText}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	client := podTokenHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, errors.New("Pod token Prometheus query unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(raw) > 8192 || resp.StatusCode != 200 {
		return 0, nil, errors.New("Pod token Prometheus response incomplete")
	}
	var p podTokenPromResult
	if json.Unmarshal(raw, &p) != nil || p.Status != "success" || p.Data.ResultType != "vector" {
		return 0, raw, errors.New("Pod token Prometheus vector response invalid")
	}
	if len(p.Data.Result) == 0 {
		return 0, raw, errors.New("Pod token Prometheus source series absent")
	}
	if len(p.Data.Result) != 1 {
		return 0, raw, errors.New("Pod token Prometheus source series ambiguous")
	}
	row := p.Data.Result[0]
	if row.Metric["pod"] != pod || len(row.Value) != 2 ||
		(sourceLabels && (row.Metric["namespace"] != namespace || row.Metric["nonce"] != nonce)) {
		return 0, raw, errors.New("Pod token Prometheus Pod series differs")
	}
	if podUID != "" && row.Metric["pod_uid"] != podUID {
		return 0, raw, errors.New("Pod token Prometheus source UID differs")
	}
	if label := row.Metric["nonce"]; label != "" && label != nonce {
		return 0, raw, errors.New("Pod token Prometheus nonce differs")
	}
	value, ok := row.Value[1].(string)
	if !ok {
		return 0, raw, errors.New("Pod token Prometheus value shape differs")
	}
	returnedAt, ok := row.Value[0].(float64)
	expectedAt, _ := strconv.ParseFloat(evaluationText, 64)
	if !ok || returnedAt != expectedAt {
		return 0, raw, errors.New("Pod token Prometheus evaluation time differs")
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, raw, errors.New("Pod token Prometheus value invalid")
	}
	return number, raw, nil
}
func podTokenMetricSample(ctx context.Context, env *core.Env, f podTokenFixture) (time.Time, float64, string, error) {
	nonce := env.Config.PodBoundTokenFixture.Nonce
	pod := f.source.Name
	ns := env.Config.Namespace
	uid := string(f.source.UID)
	if uid == "" {
		return time.Time{}, 0, "", errors.New("Pod token metric source Pod UID absent")
	}
	selector := `http_requests_total{namespace="` + ns + `",pod="` + pod + `",nonce="` + nonce + `",pod_uid="` + uid + `"}`
	evaluation := time.Now().UTC().Truncate(time.Millisecond)
	timestampRaw, partA, err := podTokenPromQuery(ctx, env.Config.PodBoundTokenFixture.PrometheusURL, "timestamp("+selector+")", ns, pod, nonce, uid, evaluation, true)
	if err != nil {
		return time.Time{}, 0, "", fmt.Errorf("Pod token source scrape timestamp: %w", err)
	}
	counter, partB, err := podTokenPromQuery(ctx, env.Config.PodBoundTokenFixture.PrometheusURL, selector, ns, pod, nonce, uid, evaluation, true)
	if err != nil {
		return time.Time{}, 0, "", fmt.Errorf("Pod token source counter: %w", err)
	}
	// A scrape can be ingested between separate instant queries even when both
	// queries use the same evaluation time. Bracket the counter with the source
	// series' actual sample timestamp, and refuse a mixed-scrape pair.
	confirmedTimestamp, partC, err := podTokenPromQuery(ctx, env.Config.PodBoundTokenFixture.PrometheusURL, "timestamp("+selector+")", ns, pod, nonce, uid, evaluation, true)
	if err != nil {
		return time.Time{}, 0, "", fmt.Errorf("Pod token source confirming timestamp: %w", err)
	}
	if confirmedTimestamp != timestampRaw {
		return time.Time{}, 0, "", errors.New("Pod token counter and scrape timestamp differ")
	}
	rate, partD, err := podTokenPromQuery(ctx, env.Config.PodBoundTokenFixture.PrometheusURL, `sum by (pod,pod_uid) (rate(`+selector+`[1m]))`, ns, pod, nonce, uid, evaluation, false)
	if err != nil {
		return time.Time{}, 0, "", fmt.Errorf("Pod token source request rate: %w", err)
	}
	if rate <= 0 {
		return time.Time{}, 0, "", errors.New("Pod token real request rate absent")
	}
	at := time.Unix(0, int64(timestampRaw*float64(time.Second))).UTC()
	if time.Since(at) > 75*time.Second || at.After(time.Now().Add(5*time.Second)) {
		return at, counter, "", errors.New("Pod token actual scrape sample stale")
	}
	digest := podTokenHash(bytes.Join([][]byte{partA, partB, partC, partD}, []byte{'\n'}))
	return at, counter, digest, nil
}

// CPU discovery of a new PodMonitor can take much longer than its 30-second
// scrape interval. The CPU bound still leaves time for the 900-second case's
// replay, decision, observation and cleanup, while requiring two distinct
// positive-rate source samples. The caller's run context remains authoritative.
const podTokenMetricWarmBudget = 270 * time.Second

func podTokenWarmMetric(ctx context.Context, env *core.Env, f podTokenFixture) (podTokenTelemetry, error) {
	budget := 125 * time.Second // Preserve optional telemetry timing for Voice.
	if env.Config.Namespace == "phorvex-catalogue-cpu" {
		budget = podTokenMetricWarmBudget
	}
	return podTokenWarmMetricWith(ctx, env, f, budget, 5*time.Second, podTokenMetricSample, podTokenDirectReady)
}

func podTokenWarmMetricWith(ctx context.Context, env *core.Env, f podTokenFixture, budget, interval time.Duration,
	sample func(context.Context, *core.Env, podTokenFixture) (time.Time, float64, string, error),
	ready func(context.Context, corev1.Pod, string) (int, error)) (podTokenTelemetry, error) {
	result := podTokenTelemetry{ProducerStatus: "MISSING_REQUEST_RATE", SourcePodName: f.source.Name, PodMonitorUID: string(f.monitorUID)}
	warmCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var firstAt time.Time
	var firstValue float64
	var firstHash string
	var lastErr error
	stop := func() (podTokenTelemetry, error) {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if lastErr == nil {
			lastErr = errors.New("Pod token source samples unavailable")
		}
		return result, fmt.Errorf("Pod token metric warm-up deadline: %w; last metric failure: %v", warmCtx.Err(), lastErr)
	}
	for {
		if warmCtx.Err() != nil {
			return stop()
		}
		if _, err := ready(warmCtx, f.source, env.Config.PodBoundTokenFixture.Nonce); err != nil {
			lastErr = errors.New("Pod token direct source readiness unavailable")
		}
		if warmCtx.Err() != nil {
			return stop()
		}
		at, value, hash, err := sample(warmCtx, env, f)
		if warmCtx.Err() != nil {
			return stop()
		}
		if err == nil && at.After(firstAt) {
			if firstAt.IsZero() {
				firstAt, firstValue, firstHash = at, value, hash
				result.FirstAt = at.Format(time.RFC3339Nano)
				result.FirstValue = value
			} else if value > firstValue && at.Sub(firstAt) >= 15*time.Second {
				result.SecondAt = at.Format(time.RFC3339Nano)
				result.SecondValue = value
				result.QuerySHA256 = podTokenHash([]byte(firstHash + hash))
				result.ProducerStatus = "MEASURED_FRESH"
				return result, nil
			} else {
				lastErr = errors.New("Pod token source scrape not yet increasing after distinct interval")
			}
		} else if err != nil && !at.IsZero() {
			result.ProducerStatus = "STALE_REQUEST_RATE"
			lastErr = err
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("Pod token source scrape timestamp not advancing")
		}
		select {
		case <-warmCtx.Done():
			return stop()
		case <-tick.C:
		}
	}
}
