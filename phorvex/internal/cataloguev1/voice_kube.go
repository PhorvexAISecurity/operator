package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	transportspdy "k8s.io/client-go/transport/spdy"
)

type kubeVoiceRuntime struct {
	rest          *rest.Config
	kube          kubernetes.Interface
	voice         VoiceRuntime
	execOverride  func(context.Context, string, string, string, []string) (string, error)
	pauseOverride func(context.Context, time.Duration) error
}

func newKubeVoiceRuntime(runtime Runtime) (VoiceDriver, error) {
	if runtime.RESTConfig == nil || runtime.Kube == nil {
		return nil, errors.New("Voice Kubernetes runtime is unavailable")
	}
	return &kubeVoiceRuntime{rest: rest.CopyConfig(runtime.RESTConfig), kube: runtime.Kube, voice: runtime.Voice}, nil
}

func voiceCanonicalSHA(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (r *kubeVoiceRuntime) Snapshot(ctx context.Context, cfg VoiceConfig) (VoiceSnapshot, error) {
	ns, err := r.kube.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil {
		return VoiceSnapshot{}, fmt.Errorf("read Voice namespace: %w", err)
	}
	deployment, err := r.kube.AppsV1().Deployments(cfg.Namespace).Get(ctx, cfg.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return VoiceSnapshot{}, fmt.Errorf("read Voice Deployment: %w", err)
	}
	selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil || selector.Empty() {
		return VoiceSnapshot{}, errors.New("Voice Deployment selector is invalid")
	}
	selectorText := selector.String()
	podList, err := r.kube.CoreV1().Pods(cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selectorText})
	if err != nil {
		return VoiceSnapshot{}, fmt.Errorf("list Voice Pods: %w", err)
	}
	rsList, err := r.kube.AppsV1().ReplicaSets(cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selectorText})
	if err != nil {
		return VoiceSnapshot{}, fmt.Errorf("list Voice ReplicaSets: %w", err)
	}
	service, err := r.kube.CoreV1().Services(cfg.Namespace).Get(ctx, cfg.ServiceName, metav1.GetOptions{})
	if err != nil {
		return VoiceSnapshot{}, fmt.Errorf("read Voice Service: %w", err)
	}
	pdb, err := r.kube.PolicyV1().PodDisruptionBudgets(cfg.Namespace).Get(ctx, cfg.PDBName, metav1.GetOptions{})
	if err != nil {
		return VoiceSnapshot{}, fmt.Errorf("read Voice PDB: %w", err)
	}
	slices, err := r.kube.DiscoveryV1().EndpointSlices(cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + cfg.ServiceName})
	if err != nil {
		return VoiceSnapshot{}, fmt.Errorf("list Voice EndpointSlices: %w", err)
	}
	if len(podList.Items) != int(cfg.ExpectedReplicas) {
		// During replacement the selector can briefly return the terminating old
		// Pod plus its Pending successor. Preserve those known states for the
		// availability sampler; validateVoiceReady remains exact at effect/final
		// boundaries.
		if len(podList.Items) < int(cfg.MinimumReady) || len(podList.Items) > int(cfg.ExpectedReplicas)+1 {
			return VoiceSnapshot{}, fmt.Errorf("Voice selector returned %d Pods", len(podList.Items))
		}
	}
	pods := make([]VoicePod, 0, len(podList.Items))
	rsUIDs := map[types.UID]bool{}
	for i := range podList.Items {
		pod, podErr := projectVoicePod(&podList.Items[i], cfg)
		if podErr != nil {
			return VoiceSnapshot{}, podErr
		}
		pods = append(pods, pod)
		rsUIDs[types.UID(pod.ReplicaSetUID)] = true
	}
	if len(rsUIDs) != 1 {
		return VoiceSnapshot{}, errors.New("Voice Pods are not owned by one ReplicaSet")
	}
	var active *appsv1.ReplicaSet
	for i := range rsList.Items {
		rs := &rsList.Items[i]
		if !rsUIDs[rs.UID] {
			continue
		}
		if !exactController(rs.OwnerReferences, "apps/v1", "Deployment", deployment.Name, deployment.UID) || active != nil {
			return VoiceSnapshot{}, errors.New("Voice ReplicaSet ownership is ambiguous")
		}
		active = rs
	}
	if active == nil {
		return VoiceSnapshot{}, errors.New("Voice active ReplicaSet is absent")
	}
	if !mapsEqual(service.Spec.Selector, deployment.Spec.Selector.MatchLabels) {
		return VoiceSnapshot{}, errors.New("Voice Service selector differs from Deployment")
	}
	pdbSelector, selectorErr := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if selectorErr != nil || pdbSelector.String() != selectorText {
		return VoiceSnapshot{}, errors.New("Voice PDB selector differs from Deployment")
	}
	readyEndpoints := map[string]bool{}
	for i := range slices.Items {
		slice := &slices.Items[i]
		if !exactController(slice.OwnerReferences, "v1", "Service", service.Name, service.UID) {
			return VoiceSnapshot{}, errors.New("Voice EndpointSlice Service ownership differs")
		}
		portMatched := false
		for _, port := range slice.Ports {
			if port.Port != nil && *port.Port == cfg.Port {
				portMatched = true
			}
		}
		if !portMatched {
			return VoiceSnapshot{}, errors.New("Voice EndpointSlice port differs")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != cfg.Namespace || endpoint.TargetRef.UID == "" {
				return VoiceSnapshot{}, errors.New("Voice EndpointSlice target identity is incomplete")
			}
			ready := endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready
			serving := endpoint.Conditions.Serving == nil || *endpoint.Conditions.Serving
			terminating := endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating
			if ready && serving && !terminating {
				readyEndpoints[string(endpoint.TargetRef.UID)] = true
			}
		}
	}
	endpointUIDs := make([]string, 0, len(readyEndpoints))
	for uid := range readyEndpoints {
		endpointUIDs = append(endpointUIDs, uid)
	}
	sort.Strings(endpointUIDs)
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
	depSpec, _ := voiceCanonicalSHA(deployment.Spec)
	rsSpec, _ := voiceCanonicalSHA(active.Spec)
	serviceSpec, _ := voiceCanonicalSHA(service.Spec)
	pdbSpec, _ := voiceCanonicalSHA(pdb.Spec)
	return VoiceSnapshot{
		At: time.Now().UTC(), NamespaceUID: string(ns.UID), DeploymentUID: string(deployment.UID),
		DeploymentGeneration: deployment.Generation, DeploymentSpecSHA256: depSpec,
		ReplicaSetUID: string(active.UID), ReplicaSetGeneration: active.Generation, ReplicaSetSpecSHA256: rsSpec,
		ServiceUID: string(service.UID), ServiceSpecSHA256: serviceSpec, PDBUID: string(pdb.UID),
		PDBGeneration: pdb.Generation, PDBSpecSHA256: pdbSpec, PDBDisruptionsAllowed: pdb.Status.DisruptionsAllowed,
		PDBObservedGeneration: pdb.Status.ObservedGeneration, PDBCurrentHealthy: pdb.Status.CurrentHealthy,
		PDBDesiredHealthy: pdb.Status.DesiredHealthy, PDBExpectedPods: pdb.Status.ExpectedPods,
		DeploymentObservedGeneration: deployment.Status.ObservedGeneration, DeploymentReplicas: deployment.Status.Replicas,
		DeploymentUpdatedReplicas: deployment.Status.UpdatedReplicas, DeploymentReadyReplicas: deployment.Status.ReadyReplicas,
		DeploymentAvailableReplicas: deployment.Status.AvailableReplicas, ReplicaSetReplicas: active.Status.Replicas,
		ReplicaSetReadyReplicas: active.Status.ReadyReplicas, ReplicaSetAvailableReplicas: active.Status.AvailableReplicas,
		ReadyEndpointUIDs: endpointUIDs, Pods: pods,
	}, nil
}

func projectVoicePod(pod *corev1.Pod, cfg VoiceConfig) (VoicePod, error) {
	owners := make([]metav1.OwnerReference, 0, 1)
	for _, owner := range pod.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			owners = append(owners, owner)
		}
	}
	if len(owners) != 1 || owners[0].APIVersion != "apps/v1" || owners[0].Kind != "ReplicaSet" || owners[0].UID == "" {
		return VoicePod{}, errors.New("Voice Pod controller identity differs")
	}
	var statuses []corev1.ContainerStatus
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == cfg.ContainerName {
			statuses = append(statuses, status)
		}
	}
	if len(statuses) > 1 {
		return VoicePod{}, errors.New("Voice Pod has duplicate container status")
	}
	status := corev1.ContainerStatus{}
	if len(statuses) == 1 {
		status = statuses[0]
	}
	ready := false
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	started := status.Started != nil && *status.Started
	return VoicePod{Name: pod.Name, UID: string(pod.UID), ResourceVersion: pod.ResourceVersion,
		ReplicaSetName: owners[0].Name, ReplicaSetUID: string(owners[0].UID), Ready: ready && status.Ready,
		Started: started, Terminating: pod.DeletionTimestamp != nil, RestartCount: status.RestartCount,
		ImageID: status.ImageID, ContainerID: status.ContainerID}, nil
}

func exactController(refs []metav1.OwnerReference, apiVersion, kind, name string, uid types.UID) bool {
	var controllers []metav1.OwnerReference
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller {
			controllers = append(controllers, ref)
		}
	}
	return len(controllers) == 1 && controllers[0].APIVersion == apiVersion && controllers[0].Kind == kind && controllers[0].Name == name && controllers[0].UID == uid
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func (r *kubeVoiceRuntime) SourceSHA256(ctx context.Context, cfg VoiceConfig, pod VoicePod) (string, error) {
	out, err := r.exec(ctx, cfg.Namespace, pod.Name, cfg.ContainerName, []string{"sha256sum", cfg.BotSourcePath})
	if err != nil {
		return "", err
	}
	parts := strings.Fields(out)
	if len(parts) != 2 || parts[1] != cfg.BotSourcePath || !voiceSHA256.MatchString(parts[0]) {
		return "", errors.New("Voice source hash response is malformed")
	}
	return parts[0], nil
}

func (r *kubeVoiceRuntime) CanEvict(ctx context.Context, cfg VoiceConfig) error {
	review, err := r.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: cfg.Namespace, Verb: "create", Group: "", Resource: "pods", Subresource: "eviction"}}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	if !review.Status.Allowed {
		return fmt.Errorf("pods/eviction create denied: %s", review.Status.Reason)
	}
	return nil
}

func (r *kubeVoiceRuntime) exec(ctx context.Context, namespace, pod, container string, command []string) (string, error) {
	if r.execOverride != nil {
		return r.execOverride(ctx, namespace, pod, container, command)
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req := r.kube.CoreV1().RESTClient().Post().Resource("pods").Name(pod).Namespace(namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: container, Command: command, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(r.rest, http.MethodPost, req.URL())
	if err != nil {
		return "", err
	}
	var stdout, stderr limitedVoiceBuffer
	stdout.limit, stderr.limit = 1<<20, 64<<10
	if err = executor.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
		return stdout.String(), fmt.Errorf("Voice pod exec: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

type limitedVoiceBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedVoiceBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		_, _ = b.buf.Write(p[:min(len(p), remaining)])
	}
	return len(p), nil
}
func (b *limitedVoiceBuffer) String() string { return b.buf.String() }

type voiceForward struct {
	local uint16
	stop  chan struct{}
	done  chan error
	once  sync.Once
}

func (r *kubeVoiceRuntime) openForward(ctx context.Context, cfg VoiceConfig, pod VoicePod) (*voiceForward, error) {
	current, err := r.kube.CoreV1().Pods(cfg.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("re-read Voice port-forward target: %w", err)
	}
	projected, err := projectVoicePod(current, cfg)
	if err != nil || projected.UID != pod.UID || projected.ReplicaSetUID != pod.ReplicaSetUID || projected.ImageID != pod.ImageID || projected.ContainerID != pod.ContainerID || !projected.Ready || !projected.Started || projected.Terminating {
		return nil, errors.New("Voice port-forward target identity changed")
	}
	transport, upgrader, err := transportspdy.RoundTripperFor(r.rest)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(r.rest.Host)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawQuery, u.Fragment = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", cfg.Namespace, pod.Name), "", ""
	dialer := transportspdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, u)
	stop, ready, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var out, errOut limitedVoiceBuffer
	out.limit, errOut.limit = 64<<10, 64<<10
	forwarder, err := portforward.New(dialer, []string{"0:" + strconv.Itoa(int(cfg.Port))}, stop, ready, &out, &errOut)
	if err != nil {
		return nil, err
	}
	go func() { done <- forwarder.ForwardPorts() }()
	select {
	case <-ctx.Done():
		close(stop)
		return nil, ctx.Err()
	case forwardErr := <-done:
		close(stop)
		return nil, fmt.Errorf("Voice port-forward stopped before ready: %v: %s", forwardErr, errOut.String())
	case <-ready:
	}
	ports, err := forwarder.GetPorts()
	if err != nil || len(ports) != 1 || ports[0].Remote != uint16(cfg.Port) || ports[0].Local == 0 {
		close(stop)
		return nil, errors.New("Voice forwarded port identity differs")
	}
	return &voiceForward{local: ports[0].Local, stop: stop, done: done}, nil
}

func (f *voiceForward) close() bool {
	f.once.Do(func() { close(f.stop) })
	select {
	case <-f.done:
	case <-time.After(10 * time.Second):
		return false
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.local)))
	conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return false
	}
	return true
}

type voiceInbound struct {
	audio []byte
	err   error
	close int
}

func sendVoiceInbound(done <-chan struct{}, output chan<- voiceInbound, value voiceInbound) bool {
	select {
	case output <- value:
		return true
	case <-done:
		return false
	}
}

func (r *kubeVoiceRuntime) RunMedia(ctx context.Context, cfg VoiceConfig, pod VoicePod, initial VoiceSession, speech []byte, interrupt func(context.Context) (VoiceEviction, error)) (session VoiceSession) {
	session = initial
	started := time.Now()
	forward, err := r.openForward(ctx, cfg, pod)
	if err != nil {
		session.Error = err.Error()
		return session
	}
	defer func() { session.ForwardClosed = forward.close() }()
	wsURL := fmt.Sprintf("ws://127.0.0.1:%d/ws", forward.local)
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second, ReadBufferSize: 64 << 10, WriteBufferSize: 64 << 10}
	conn, response, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		session.Error = "Voice WebSocket upgrade: " + err.Error()
		return session
	}
	defer conn.Close()
	readerDone := make(chan struct{})
	defer close(readerDone)
	pong := make(chan struct{}, 1)
	conn.SetPongHandler(func(string) error {
		select {
		case pong <- struct{}{}:
		default:
		}
		return nil
	})
	conn.SetReadLimit(64 << 10)
	if err = conn.WriteControl(websocket.PingMessage, []byte("owned-v1-functional-control"), time.Now().Add(3*time.Second)); err != nil {
		session.Error = err.Error()
		return session
	}
	inbound := make(chan voiceInbound, 64)
	go readVoiceWebSocket(conn, session.StreamSID, inbound, readerDone)
	connected := map[string]any{"event": "connected", "protocol": "Call", "version": "1.0.0"}
	start := map[string]any{"event": "start", "sequenceNumber": "1", "streamSid": session.StreamSID, "start": map[string]any{"streamSid": session.StreamSID, "callSid": session.CallSID, "accountSid": session.AccountSID, "tracks": []string{"inbound"}, "customParameters": map[string]string{}, "mediaFormat": map[string]any{"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1}}}
	if err = conn.WriteJSON(connected); err != nil {
		session.Error = err.Error()
		return session
	}
	if err = conn.WriteJSON(start); err != nil {
		session.Error = err.Error()
		return session
	}
	session.StartSent = true
	select {
	case <-pong:
		session.IdlePingPong = true
	case <-time.After(3 * time.Second):
		session.Error = "Voice WebSocket pong deadline exceeded"
		return session
	case <-ctx.Done():
		session.Error = ctx.Err().Error()
		return session
	}
	input := make([]byte, 0, 80000+len(speech))
	input = append(input, bytes.Repeat([]byte{0xff}, 16000)...)
	input = append(input, speech...)
	input = append(input, bytes.Repeat([]byte{0xff}, 64000)...)
	hash := sha256.New()
	deadline := time.NewTimer(map[bool]time.Duration{true: 90 * time.Second, false: 60 * time.Second}[interrupt != nil])
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	offset, events, interrupted := 0, 0, false
	for session.MediaFramesSent < voiceExpectedFramesMax {
		select {
		case <-ctx.Done():
			session.Error = ctx.Err().Error()
			return session
		case <-deadline.C:
			session.Error = "Voice media deadline exceeded"
			return session
		case message := <-inbound:
			if message.err != nil {
				session.CloseCode = message.close
				if interrupt != nil && session.Eviction != nil && session.Eviction.Disposition == EvictionAccepted {
					session.ReceivedAudioSHA256 = hex.EncodeToString(hash.Sum(nil))
					session.Error = ""
					return session
				}
				session.Error = message.err.Error()
				return session
			}
			events++
			if events > voiceExpectedMessagesMax {
				session.Error = "Voice inbound message bound exceeded"
				return session
			}
			if len(message.audio) > 0 {
				session.MediaFramesReceived++
				session.MediaBytesReceived += len(message.audio)
				if session.MediaBytesReceived > voiceExpectedMediaByteMax {
					session.Error = "Voice returned media byte bound exceeded"
					return session
				}
				_, _ = hash.Write(message.audio)
				if session.FirstAudioSeconds == 0 {
					session.FirstAudioSeconds = time.Since(started).Seconds()
				}
			}
		case <-ticker.C:
			if session.FirstAudioSeconds > 0 && interrupt != nil && !interrupted {
				if err = conn.WriteControl(websocket.PingMessage, []byte("owned-v1-immediate-pre-eviction"), time.Now().Add(3*time.Second)); err != nil {
					session.Error = "Voice immediate pre-eviction ping: " + err.Error()
					return session
				}
				select {
				case <-pong:
					session.ImmediatePreEvictionPingPong = true
				case <-time.After(3 * time.Second):
					session.Error = "Voice immediate pre-eviction pong deadline exceeded"
					return session
				}
				receipt, dispatchErr := interrupt(ctx)
				session.Eviction, interrupted = &receipt, true
				if dispatchErr != nil {
					session.ReceivedAudioSHA256 = hex.EncodeToString(hash.Sum(nil))
					session.Error = dispatchErr.Error()
					return session
				}
				if receipt.Disposition != EvictionAccepted {
					session.ReceivedAudioSHA256 = hex.EncodeToString(hash.Sum(nil))
					session.CloseWasTestInitiated = true
					_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1000, "eviction not accepted"), time.Now().Add(3*time.Second))
					return session
				}
			}
			frame := make([]byte, 160)
			for i := range frame {
				frame[i] = 0xff
			}
			if offset < len(input) {
				copy(frame, input[offset:min(offset+160, len(input))])
				offset += 160
			} else if interrupt == nil && session.MediaFramesReceived > 0 {
				stop := map[string]any{"event": "stop", "sequenceNumber": strconv.Itoa(session.MediaFramesSent + 2), "streamSid": session.StreamSID, "stop": map[string]string{"accountSid": session.AccountSID, "callSid": session.CallSID}}
				if err = conn.WriteJSON(stop); err != nil {
					session.Error = err.Error()
					return session
				}
				session.StopSent, session.CloseWasTestInitiated = true, true
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1000, "owned functional control complete"), time.Now().Add(3*time.Second))
				peerDeadline := time.NewTimer(5 * time.Second)
				defer peerDeadline.Stop()
				for {
					select {
					case peer := <-inbound:
						if peer.err != nil {
							session.CloseCode = peer.close
							if peer.close != 1000 {
								session.Error = "Voice peer did not acknowledge normal close"
							}
							session.ReceivedAudioSHA256 = hex.EncodeToString(hash.Sum(nil))
							return session
						}
					case <-peerDeadline.C:
						session.Error = "Voice peer close acknowledgement deadline exceeded"
						return session
					case <-ctx.Done():
						session.Error = ctx.Err().Error()
						return session
					}
				}
			}
			number := session.MediaFramesSent + 1
			message := map[string]any{"event": "media", "sequenceNumber": strconv.Itoa(number + 1), "streamSid": session.StreamSID, "media": map[string]string{"track": "inbound", "chunk": strconv.Itoa(number), "timestamp": strconv.Itoa((number - 1) * 20), "payload": base64.StdEncoding.EncodeToString(frame)}}
			if err = conn.WriteJSON(message); err != nil {
				session.Error = err.Error()
				return session
			}
			session.MediaFramesSent = number
		}
	}
	session.Error = "Voice media frame bound exceeded"
	return session
}

func readVoiceWebSocket(conn *websocket.Conn, streamSID string, output chan<- voiceInbound, done <-chan struct{}) {
	for {
		kind, raw, err := conn.ReadMessage()
		if err != nil {
			closeCode := 0
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) {
				closeCode = closeErr.Code
			}
			sendVoiceInbound(done, output, voiceInbound{err: err, close: closeCode})
			return
		}
		if kind != websocket.TextMessage || len(raw) > 64<<10 {
			sendVoiceInbound(done, output, voiceInbound{err: errors.New("Voice inbound WebSocket message is invalid")})
			return
		}
		var message struct {
			Event     string `json:"event"`
			StreamSID string `json:"streamSid"`
			Media     struct {
				Payload string `json:"payload"`
			} `json:"media"`
		}
		if err = json.Unmarshal(raw, &message); err != nil {
			sendVoiceInbound(done, output, voiceInbound{err: err})
			return
		}
		if message.Event != "media" {
			if !sendVoiceInbound(done, output, voiceInbound{}) {
				return
			}
			continue
		}
		if message.StreamSID != streamSID {
			sendVoiceInbound(done, output, voiceInbound{err: errors.New("Voice returned media stream identity differs")})
			return
		}
		audio, decodeErr := base64.StdEncoding.Strict().DecodeString(message.Media.Payload)
		if decodeErr != nil || len(audio) == 0 || len(audio) > 64<<10 {
			sendVoiceInbound(done, output, voiceInbound{err: errors.New("Voice returned media payload is invalid")})
			return
		}
		if !sendVoiceInbound(done, output, voiceInbound{audio: audio}) {
			return
		}
	}
}

func (r *kubeVoiceRuntime) Evict(ctx context.Context, cfg VoiceConfig, pod VoicePod) VoiceEviction {
	uid, resourceVersion := types.UID(pod.UID), pod.ResourceVersion
	eviction := &policyv1.Eviction{TypeMeta: metav1.TypeMeta{APIVersion: "policy/v1", Kind: "Eviction"}, ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: cfg.Namespace}, DeleteOptions: &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &resourceVersion}}}
	receipt := VoiceEviction{Dispatched: true, Disposition: EvictionUnknown}
	err := r.kube.PolicyV1().Evictions(cfg.Namespace).Evict(ctx, eviction)
	if err == nil {
		receipt.Disposition, receipt.StatusCode = EvictionAccepted, http.StatusCreated
		return receipt
	}
	receipt.Reason = err.Error()
	if apierrors.IsTooManyRequests(err) || apierrors.IsForbidden(err) || apierrors.IsInvalid(err) || apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		receipt.Disposition = EvictionRefused
		if statusErr, ok := err.(apierrors.APIStatus); ok {
			receipt.StatusCode = int(statusErr.Status().Code)
		}
	}
	return receipt
}

const transcriptQueryProgram = `import hashlib,json,os,sys
from bson import json_util
from pymongo import MongoClient
c=MongoClient(os.environ["MONGO_URI"],serverSelectionTimeoutMS=3000,connectTimeoutMS=3000,socketTimeoutMS=3000,retryWrites=False)
col=c[os.environ.get("MONGO_DB","voice")][os.environ.get("MONGO_COLLECTION","transcripts")]
out=[]
for sid in sys.argv[1:]:
 for d in col.find({"call_sid":sid}).max_time_ms(3000).limit(5):
  oid=str(d["_id"]);d["_id"]=oid
  raw=json_util.dumps(d,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
  out.append({"callSid":sid,"objectID":oid,"contentSHA256":hashlib.sha256(raw).hexdigest()})
print("OWNED_TRANSCRIPTS="+json.dumps(out,sort_keys=True,separators=(",",":")))`

const transcriptDeleteProgram = `import hashlib,json,os,sys
from bson import ObjectId,json_util
from pymongo import MongoClient
sid,oid,want=sys.argv[1:4]
c=MongoClient(os.environ["MONGO_URI"],serverSelectionTimeoutMS=3000,connectTimeoutMS=3000,socketTimeoutMS=3000,retryWrites=False)
col=c[os.environ.get("MONGO_DB","voice")][os.environ.get("MONGO_COLLECTION","transcripts")]
d=col.find_one({"_id":ObjectId(oid),"call_sid":sid})
if d is None: print("OWNED_DELETE="+json.dumps({"deletedCount":0,"alreadyAbsent":True,"remaining":col.count_documents({"call_sid":sid})},sort_keys=True));sys.exit(0)
original=dict(d);d["_id"]=str(d["_id"]);got=hashlib.sha256(json_util.dumps(d,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
if got!=want: print("OWNED_DELETE="+json.dumps({"error":"content-hash-drift"},sort_keys=True));sys.exit(42)
r=col.delete_one(original)
print("OWNED_DELETE="+json.dumps({"deletedCount":r.deleted_count,"alreadyAbsent":False,"remaining":col.count_documents({"call_sid":sid})},sort_keys=True))`

func (r *kubeVoiceRuntime) CleanupTranscripts(ctx context.Context, cfg VoiceConfig, pod VoicePod, callSIDs []string, onIntent func(TranscriptRef) error, onResult func(TranscriptRef) error) VoiceCleanup {
	cleanup := VoiceCleanup{Status: "FAIL", ForwardsClosed: true, UnsafeToRetry: true}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if len(callSIDs) == 0 || len(callSIDs) > 2 {
		cleanup.Error = "Voice transcript cleanup session set is outside bounds"
		return cleanup
	}
	selector, err := labels.Parse(r.voice.TranscriptPodSelector)
	if err != nil || selector.Empty() {
		cleanup.Error = "Voice transcript cleanup selector is invalid"
		return cleanup
	}
	current, err := r.kube.CoreV1().Pods(cfg.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || string(current.UID) != pod.UID || !selector.Matches(labels.Set(current.Labels)) {
		cleanup.Error = "Voice transcript cleanup Pod identity differs"
		return cleanup
	}
	query := []string{"python3", "-c", transcriptQueryProgram}
	query = append(query, callSIDs...)
	readRefs := func() ([]TranscriptRef, error) {
		out, readErr := r.exec(ctx, cfg.Namespace, pod.Name, r.voice.TranscriptContainer, query)
		if readErr != nil {
			return nil, readErr
		}
		return parseTranscriptRefs(out, callSIDs)
	}
	// Both sessions can persist after their WebSocket closes. Complete the finite
	// settling window even when the first session's document arrives early.
	var refs []TranscriptRef
	observed := map[string]bool{}
	for observation := 0; observation < 10; observation++ {
		if err = ctx.Err(); err != nil {
			cleanup.Error = err.Error()
			return cleanup
		}
		refs, err = readRefs()
		if err != nil {
			cleanup.Error = err.Error()
			return cleanup
		}
		for _, ref := range refs {
			observed[ref.CallSID+"\x00"+ref.ObjectID] = true
		}
		if observation < 9 {
			if err = r.pauseVoiceCleanup(ctx, time.Second); err != nil {
				cleanup.Error = err.Error()
				return cleanup
			}
		}
	}
	const maxOwnedDocuments = 4
	cleanup.DocumentsFound = len(observed)
	cleanup.DocumentsRemaining = len(refs)
	deleted := map[string]bool{}
	zeroSamples := 0
	// A new owned document discovered during zero checks receives its own
	// persisted intent and fresh content-hash CAS. Never repeat an acknowledged
	// deletion, and stop after a fixed observation/document ceiling.
	for observation := 0; observation < 20; observation++ {
		if err = ctx.Err(); err != nil {
			cleanup.Error = err.Error()
			return cleanup
		}
		if len(observed) > maxOwnedDocuments {
			cleanup.Error = "Voice transcript count exceeds bound"
			return cleanup
		}
		for _, ref := range refs {
			if err = ctx.Err(); err != nil {
				cleanup.Error = err.Error()
				return cleanup
			}
			key := ref.CallSID + "\x00" + ref.ObjectID
			if deleted[key] {
				cleanup.Error = "acknowledged Voice transcript reappeared"
				return cleanup
			}
			if err = onIntent(ref); err != nil {
				cleanup.Error = "persist transcript delete intent: " + err.Error()
				return cleanup
			}
			deleteOut, deleteErr := r.exec(ctx, cfg.Namespace, pod.Name, r.voice.TranscriptContainer, []string{"python3", "-c", transcriptDeleteProgram, ref.CallSID, ref.ObjectID, ref.ContentSHA256})
			if deleteErr != nil {
				cleanup.Error = "exact Voice transcript deletion outcome is unknown"
				return cleanup
			}
			deletedCount, alreadyAbsent, receiptErr := parseTranscriptDelete(deleteOut)
			if receiptErr != nil || deletedCount != 1 && !alreadyAbsent {
				cleanup.Error = "exact Voice transcript deletion was not acknowledged"
				return cleanup
			}
			if err = onResult(ref); err != nil {
				cleanup.Error = "persist transcript delete result: " + err.Error()
				return cleanup
			}
			deleted[key] = true
		}
		refs, err = readRefs()
		if err != nil {
			cleanup.Error = err.Error()
			return cleanup
		}
		cleanup.DocumentsRemaining = len(refs)
		for _, ref := range refs {
			observed[ref.CallSID+"\x00"+ref.ObjectID] = true
		}
		if len(observed) > maxOwnedDocuments {
			cleanup.Error = "Voice transcript count exceeds bound"
			return cleanup
		}
		cleanup.DocumentsFound = len(observed)
		if len(refs) == 0 {
			zeroSamples++
			if zeroSamples == 3 {
				cleanup.Status, cleanup.UnsafeToRetry = "PASS", false
				return cleanup
			}
			if err = r.pauseVoiceCleanup(ctx, 2*time.Second); err != nil {
				cleanup.Error = err.Error()
				return cleanup
			}
		} else {
			zeroSamples = 0
		}
	}
	cleanup.Error = "Voice transcript verification exceeded observation bound"
	return cleanup
}

func (r *kubeVoiceRuntime) pauseVoiceCleanup(ctx context.Context, duration time.Duration) error {
	if r.pauseOverride != nil {
		return r.pauseOverride(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseTranscriptRefs(output string, callSIDs []string) ([]TranscriptRef, error) {
	allowed := map[string]bool{}
	for _, sid := range callSIDs {
		allowed[sid] = true
	}
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "OWNED_TRANSCRIPTS=") {
			lines = append(lines, strings.TrimPrefix(line, "OWNED_TRANSCRIPTS="))
		}
	}
	if len(lines) != 1 {
		return nil, errors.New("Voice transcript response is malformed")
	}
	var refs []TranscriptRef
	if err := json.Unmarshal([]byte(lines[0]), &refs); err != nil {
		return nil, err
	}
	if len(refs) > 4 {
		return nil, errors.New("Voice transcript count exceeds bound")
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		key := ref.CallSID + "\x00" + ref.ObjectID
		if !allowed[ref.CallSID] || !regexp.MustCompile(`^[0-9a-f]{24}$`).MatchString(ref.ObjectID) || !voiceSHA256.MatchString(ref.ContentSHA256) || seen[key] {
			return nil, errors.New("Voice transcript identity differs")
		}
		seen[key] = true
	}
	return refs, nil
}

func parseTranscriptDelete(output string) (deleted int, alreadyAbsent bool, err error) {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "OWNED_DELETE=") {
			lines = append(lines, strings.TrimPrefix(line, "OWNED_DELETE="))
		}
	}
	if len(lines) != 1 {
		return 0, false, errors.New("Voice transcript delete response is malformed")
	}
	var receipt struct {
		DeletedCount  int    `json:"deletedCount"`
		AlreadyAbsent bool   `json:"alreadyAbsent"`
		Remaining     int    `json:"remaining"`
		Error         string `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &receipt); err != nil {
		return 0, false, err
	}
	if receipt.Error != "" || receipt.Remaining < 0 || receipt.Remaining > 4 || receipt.DeletedCount < 0 || receipt.DeletedCount > 1 || receipt.AlreadyAbsent && receipt.DeletedCount != 0 {
		return 0, false, errors.New("Voice transcript delete receipt differs")
	}
	return receipt.DeletedCount, receipt.AlreadyAbsent, nil
}
