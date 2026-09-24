// Package scenarios contains the self-registering Scenario plugins. Each scenario
// is ONE file with a func init(){ core.RegisterScenario(...) }. Adding a future
// attack is one new file + one register call, ZERO core changes.
//
// Every scenario defines its attack-success ORACLE as a concrete OBSERVABLE
// state and measures disruption strictly against it. ALL behavior is confined to
// the sandbox namespace; category-3 scenarios use the in-cluster MOCK endpoints
// from internal/mocks and never touch real cloud/registry/credentials.
package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

// ---- credential-replay boundary (c1-credtheft-rbac) ----
//
// The credential-theft scenario replays the ACTUAL bytes it exfiltrated from the
// pod against the SAME guarded API. These helpers build a replay client that
// carries ONLY the captured bearer (no fallback identity), classify the API's
// response into the arms the oracle must treat differently, and describe the
// captured credential's binding/expiry WITHOUT ever logging or emitting the
// credential itself.

// replayReqTimeout bounds a single replay API call so a hung or slow endpoint
// cannot stall a trial. It is per-call and independent of the observation window.
const replayReqTimeout = 20 * time.Second

// tokenServiceAccountPath is the in-pod path of the projected ServiceAccount
// token the attack exfiltrates.
const tokenServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// replayClass classifies the outcome of replaying a captured bearer against the
// guarded API. It distinguishes an authenticated success and an authenticated
// refusal (401/403 — a real API decision) from every transport/protocol fault
// (which makes the measurement invalid rather than a defensive win).
type replayClass int

const (
	replayAuthorized   replayClass = iota // 2xx with a decodable PodList
	replayUnauthorized                    // 401
	replayForbidden                       // 403
	replayOtherHTTP                       // other API status (5xx, 429, ...)
	replayMalformed                       // 2xx whose body is not a valid PodList
	replayTimeout                         // deadline exceeded
	replayCancelled                       // context cancelled
	replayTransport                       // dial/TLS/connection error
	replayRefused                         // refused to build a clean replay client
)

// authorized reports an authenticated success (a usable credential).
func (c replayClass) authorized() bool { return c == replayAuthorized }

// denied reports an authenticated-but-refused outcome (401/403): a genuine API
// decision, which is a measured failure, NOT an invalid measurement.
func (c replayClass) denied() bool { return c == replayUnauthorized || c == replayForbidden }

// String is a short, safe label for evidence (never a token or a response body).
func (c replayClass) String() string {
	switch c {
	case replayAuthorized:
		return "authorized"
	case replayUnauthorized:
		return "unauthorized-401"
	case replayForbidden:
		return "forbidden-403"
	case replayOtherHTTP:
		return "other-http-error"
	case replayMalformed:
		return "malformed-2xx"
	case replayTimeout:
		return "timeout"
	case replayCancelled:
		return "cancelled"
	case replayTransport:
		return "transport-error"
	case replayRefused:
		return "replay-refused"
	default:
		return "unknown"
	}
}

// replayOutcome is the sanitized result of one replay. It NEVER carries the token
// or a response body; detail is a short, safe reason.
type replayOutcome struct {
	class    replayClass
	podCount int
	detail   string
}

// sanitizedReplayConfig builds a fresh rest.Config carrying ONLY the captured
// bearer plus the NON-AUTH connectivity/trust settings needed to reach the SAME
// endpoint with the SAME verified server trust: host, TLS server verification
// (CA/ServerName/ALPN) and any Proxy/Dial connectivity hooks. Every caller
// identity is simply OMITTED, never invoked: a fresh config carries no bearer
// file, client cert/key, basic auth, auth/exec provider or impersonation, so an
// auth/exec plugin is never executed and a failure to authenticate can never be
// masked by the harness's own admin caller. Two things are hard REFUSALS rather
// than silent proceed: an opaque custom Transport/WrapTransport (which could
// inject a non-captured identity we cannot strip), and insecure TLS (skip-verify),
// because a real credential must only ever reach a server whose identity was
// verified.
func sanitizedReplayConfig(base *rest.Config, token string) (*rest.Config, error) {
	if base == nil {
		return nil, errors.New("no live rest config (non-live env)")
	}
	if base.Transport != nil || base.WrapTransport != nil {
		return nil, errors.New("base client uses an opaque custom transport that may inject a non-captured identity")
	}
	if base.TLSClientConfig.Insecure {
		return nil, errors.New("insecure TLS (skip-verify) is refused for credential replay; the server's identity must be verified")
	}
	// Require an EXPLICIT https:// endpoint before any transport is built: a
	// cleartext (http), scheme-relative/implicit, or userinfo-bearing host would
	// send the captured bearer without a verified TLS peer. Insecure=false only
	// governs verification once TLS is in use; it does not reject a cleartext host.
	u, err := url.Parse(base.Host)
	if err != nil {
		return nil, errors.New("replay endpoint is not a parseable URL")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("replay endpoint must be an explicit https:// URL, not %q; cleartext/implicit transport is refused", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("replay endpoint must not carry userinfo credentials")
	}
	if u.Host == "" {
		return nil, errors.New("replay endpoint has no host")
	}
	cfg := &rest.Config{
		Host:      base.Host,
		APIPath:   base.APIPath,
		UserAgent: base.UserAgent,
		QPS:       base.QPS,
		Burst:     base.Burst,
		Timeout:   replayReqTimeout,
		TLSClientConfig: rest.TLSClientConfig{
			// Insecure is left false: server trust is always verified.
			ServerName: base.TLSClientConfig.ServerName,
			CAFile:     base.TLSClientConfig.CAFile,
			CAData:     base.TLSClientConfig.CAData,
			NextProtos: base.TLSClientConfig.NextProtos,
		},
		// Preserve NON-AUTH connectivity so the replay reaches the same endpoint
		// the operator does (a proxy or custom dialer is connectivity, not identity).
		Proxy:       base.Proxy,
		Dial:        base.Dial,
		BearerToken: token,
	}
	return cfg, nil
}

// replayCapturedCredential replays the captured bearer against the sandbox
// list-pods operation with a freshly built client that follows NO redirects (so
// the credential is never forwarded to another host). It records the operation
// for provenance but never the token or a response body, and returns a sanitized,
// classified outcome.
func replayCapturedCredential(ctx context.Context, env *core.Env, token string) replayOutcome {
	cfg, err := sanitizedReplayConfig(env.Rest, token)
	if err != nil {
		return replayOutcome{class: replayRefused, detail: err.Error()}
	}
	httpClient, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return replayOutcome{class: replayTransport, detail: "could not build replay HTTP client"}
	}
	// Refuse to follow redirects: a 3xx to another host must never carry the
	// captured credential onward.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cs, err := kubernetes.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return replayOutcome{class: replayTransport, detail: "could not build replay client"}
	}
	reqCtx, cancel := context.WithTimeout(ctx, replayReqTimeout)
	defer cancel()
	env.Log.Command(fmt.Sprintf("kubectl --token=<captured> get pods -n %s  # replay the exfiltrated credential", env.Config.Namespace))
	var code int
	raw, err := cs.CoreV1().RESTClient().Get().
		Namespace(env.Config.Namespace).Resource("pods").
		Do(reqCtx).StatusCode(&code).Raw()
	if err != nil {
		return classifyReplayError(ctx, reqCtx, err, code)
	}
	return classifyReplayBody(code, raw)
}

// classifyReplayBody accepts a replay ONLY when the API answered the exact
// list-pods protocol: HTTP 200 with a body that is structurally a v1 PodList
// (kind "PodList", apiVersion "v1", an "items" array present — empty is valid —
// AND every member decodes as an actual Pod object). Any other 2xx status, or a
// body that is empty, null, a bare object, a success Status, a different
// collection kind, or a PodList whose items are not Pod objects (e.g. numbers or
// strings), is a MALFORMED response, not evidence of credential usability: a
// proxy/frontend generic 200 must never be read as attacker capability. This is a
// protocol-shape check, not an attempt to authenticate the (trusted) server's
// claims.
func classifyReplayBody(code int, raw []byte) replayOutcome {
	if code != 200 {
		return replayOutcome{class: replayMalformed, detail: fmt.Sprintf("non-200 success status %d", code)}
	}
	var probe struct {
		Kind       string           `json:"kind"`
		APIVersion string           `json:"apiVersion"`
		Items      *json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return replayOutcome{class: replayMalformed, detail: "200 body did not decode as JSON"}
	}
	if probe.Kind != "PodList" || probe.APIVersion != "v1" {
		return replayOutcome{class: replayMalformed,
			detail: fmt.Sprintf("200 body is not a v1 PodList (kind=%q apiVersion=%q)", probe.Kind, probe.APIVersion)}
	}
	if probe.Items == nil {
		return replayOutcome{class: replayMalformed, detail: "200 PodList body has no items list"}
	}
	// Go's typed JSON decoder accepts null as the zero value of a Pod. Inspect
	// each raw member first so every list entry is actually a JSON object; this
	// rejects null without attempting full Kubernetes schema validation.
	var members []json.RawMessage
	if err := json.Unmarshal(*probe.Items, &members); err != nil {
		return replayOutcome{class: replayMalformed, detail: "200 v1 PodList had malformed item member(s)"}
	}
	for _, rawMember := range members {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawMember, &object); err != nil || object == nil {
			return replayOutcome{class: replayMalformed, detail: "200 v1 PodList had non-object item member(s)"}
		}
	}
	// Decode the actual PodList structure so items whose members are not Pod
	// objects (numbers, strings, null, or wrong shape) are rejected rather than
	// counted.
	var pods corev1.PodList
	if err := json.Unmarshal(raw, &pods); err != nil {
		return replayOutcome{class: replayMalformed, detail: "200 v1 PodList had malformed item member(s)"}
	}
	n := len(pods.Items)
	return replayOutcome{class: replayAuthorized, podCount: n, detail: fmt.Sprintf("HTTP 200, listed %d pods", n)}
}

// classifyReplayError maps a failed replay into its sanitized class. It never
// includes the server's message or body in the detail, only the class of fault.
func classifyReplayError(parent, reqCtx context.Context, err error, code int) replayOutcome {
	switch {
	case parent.Err() == context.Canceled, errors.Is(err, context.Canceled):
		return replayOutcome{class: replayCancelled, detail: "replay cancelled"}
	case errors.Is(err, context.DeadlineExceeded), reqCtx.Err() == context.DeadlineExceeded:
		return replayOutcome{class: replayTimeout, detail: "replay timed out"}
	case apierrors.IsUnauthorized(err):
		return replayOutcome{class: replayUnauthorized, detail: "API returned 401 Unauthorized"}
	case apierrors.IsForbidden(err):
		return replayOutcome{class: replayForbidden, detail: "API returned 403 Forbidden"}
	}
	if code >= 400 {
		return replayOutcome{class: replayOtherHTTP, detail: fmt.Sprintf("API returned HTTP %d", code)}
	}
	return replayOutcome{class: replayTransport, detail: "transport/TLS error reaching the API"}
}

// capturedCredMeta is the best-effort, NON-AUTHORITATIVE metadata decoded from a
// captured credential. Decoding a JWT's unverified claims is not cryptographic
// proof of anything; it is used ONLY to describe binding for the report and to
// guard against crediting a defender for a token's own natural expiry. An opaque
// or malformed credential yields decoded=false and binding "unknown".
type capturedCredMeta struct {
	decoded   bool
	binding   string // "pod-bound" | "unbound" | "unknown"
	boundName string
	expUnix   int64 // 0 = no/unknown expiry
}

// parseCapturedCredMeta decodes a projected ServiceAccount JWT's claims WITHOUT
// verifying its signature. A three-segment JWT with a kubernetes.io pod claim is
// reported pod-bound; a JWT without one is unbound; anything that is not a decodable
// JWT (opaque or malformed) stays "unknown". The result is descriptive only and is
// never treated as authority for attack success.
func parseCapturedCredMeta(token string) capturedCredMeta {
	meta := capturedCredMeta{binding: "unknown"}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return meta // opaque, not a JWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return meta // malformed base64url payload
	}
	var claims struct {
		Exp        int64 `json:"exp"`
		Kubernetes struct {
			Pod *struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"pod"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return meta // malformed claims
	}
	meta.decoded = true
	meta.expUnix = claims.Exp
	if claims.Kubernetes.Pod != nil && claims.Kubernetes.Pod.Name != "" {
		meta.binding = "pod-bound"
		meta.boundName = claims.Kubernetes.Pod.Name
	} else {
		meta.binding = "unbound"
	}
	return meta
}

// credObservationSleep is the observation-window wait seam. Production waits the
// real, context-cancellable interval; tests replace it so they exercise the real
// request order without sleeping. It returns a non-nil error only when the context
// ends first (cancellation), which the oracle treats as an invalid measurement.
var credObservationSleep = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// rbacRollbackTimeout bounds exact-absence verification after partial setup.
var rbacRollbackTimeout = 10 * time.Second

type createdRBACObject struct {
	kind string
	name string
	uid  types.UID
	del  func(context.Context, metav1.DeleteOptions) error
	get  func(context.Context) (metav1.Object, error)
}

// ensureSAWithRBAC creates one fresh ServiceAccount, Role and RoleBinding. It
// never adopts a same-name object. If a later create fails, every earlier object
// is rolled back by its create-response UID; ambiguous creates are never replayed.
func ensureSAWithRBAC(ctx context.Context, env *core.Env, saName string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	var created []createdRBACObject
	rollback := func(cause error) error {
		var errs []error
		errs = append(errs, cause)
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rbacRollbackTimeout)
		defer cancel()
		for i := len(created) - 1; i >= 0; i-- {
			obj := created[i]
			current, err := env.NamespaceCurrent(cleanupCtx)
			if err != nil || !current {
				if err == nil {
					err = fmt.Errorf("original namespace is absent")
				}
				errs = append(errs, fmt.Errorf("refusing rollback delete of %s %s UID %s without exact namespace identity: %w", obj.kind, obj.name, obj.uid, err))
				continue
			}
			uid := obj.uid
			if err := obj.del(cleanupCtx, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("rollback %s %s UID %s: %w", obj.kind, obj.name, uid, err))
				continue
			}
			if err := awaitCreatedObjectGone(cleanupCtx, env, obj); err != nil {
				errs = append(errs, err)
				continue
			}
			if err := env.ForgetCreatedUID(obj.kind, obj.name, uid); err != nil {
				errs = append(errs, fmt.Errorf("retire rollback authority for %s %s UID %s: %w", obj.kind, obj.name, uid, err))
			}
		}
		return errors.Join(errs...)
	}
	fresh := func(kind, name string, get func() error) error {
		current, err := env.NamespaceCurrent(ctx)
		if err != nil || !current {
			if err == nil {
				err = fmt.Errorf("original namespace is absent")
			}
			return fmt.Errorf("refusing %s %s creation without exact namespace identity: %w", kind, name, err)
		}
		err = get()
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("check fresh %s %s: %w", kind, name, err)
		}
		if err == nil {
			return fmt.Errorf("refusing to adopt existing %s %s", kind, name)
		}
		current, err = env.NamespaceCurrent(ctx)
		if err != nil || !current {
			if err == nil {
				err = fmt.Errorf("original namespace is absent")
			}
			return fmt.Errorf("refusing %s %s creation after namespace identity changed: %w", kind, name, err)
		}
		return nil
	}
	bind := func(kind, name string, uid types.UID, del func(context.Context, metav1.DeleteOptions) error, get func(context.Context) (metav1.Object, error)) error {
		if uid == "" {
			return fmt.Errorf("create %s %s returned no authoritative UID", kind, name)
		}
		created = append(created, createdRBACObject{kind: kind, name: name, uid: uid, del: del, get: get})
		if err := env.RecordCreatedUID(kind, name, uid); err != nil {
			return err
		}
		return nil
	}

	if err := fresh("serviceaccounts", saName, func() error {
		_, err := env.Kube.CoreV1().ServiceAccounts(ns).Get(ctx, saName, metav1.GetOptions{})
		return err
	}); err != nil {
		return err
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: saName, Namespace: ns, Labels: env.OwnedLabels(nil)}}
	env.Log.Command(fmt.Sprintf("kubectl create serviceaccount %s -n %s", saName, ns))
	createdSA, err := env.Kube.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create serviceaccount %s (not retried): %w", saName, err)
	}
	if createdSA == nil {
		return fmt.Errorf("create serviceaccount %s returned no object; outcome is ambiguous", saName)
	}
	if err := bind("serviceaccounts", saName, createdSA.UID, func(ctx context.Context, opts metav1.DeleteOptions) error {
		return env.Kube.CoreV1().ServiceAccounts(ns).Delete(ctx, saName, opts)
	}, func(ctx context.Context) (metav1.Object, error) {
		return env.Kube.CoreV1().ServiceAccounts(ns).Get(ctx, saName, metav1.GetOptions{})
	}); err != nil {
		return rollback(err)
	}

	roleName := saName + "-role"
	if err := fresh("roles", roleName, func() error {
		_, err := env.Kube.RbacV1().Roles(ns).Get(ctx, roleName, metav1.GetOptions{})
		return err
	}); err != nil {
		return rollback(err)
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: ns, Labels: env.OwnedLabels(nil)},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"},
		}},
	}
	env.Log.Command(fmt.Sprintf("kubectl create role %s --verb=list --resource=pods -n %s", roleName, ns))
	createdRole, err := env.Kube.RbacV1().Roles(ns).Create(ctx, role, metav1.CreateOptions{})
	if err != nil {
		return rollback(fmt.Errorf("create role %s (not retried): %w", roleName, err))
	}
	if createdRole == nil {
		return rollback(fmt.Errorf("create role %s returned no object; outcome is ambiguous", roleName))
	}
	if err := bind("roles", roleName, createdRole.UID, func(ctx context.Context, opts metav1.DeleteOptions) error {
		return env.Kube.RbacV1().Roles(ns).Delete(ctx, roleName, opts)
	}, func(ctx context.Context) (metav1.Object, error) {
		return env.Kube.RbacV1().Roles(ns).Get(ctx, roleName, metav1.GetOptions{})
	}); err != nil {
		return rollback(err)
	}

	rbName := saName + "-rb"
	if err := fresh("rolebindings", rbName, func() error {
		_, err := env.Kube.RbacV1().RoleBindings(ns).Get(ctx, rbName, metav1.GetOptions{})
		return err
	}); err != nil {
		return rollback(err)
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: rbName, Namespace: ns, Labels: env.OwnedLabels(nil)},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: roleName},
	}
	env.Log.Command(fmt.Sprintf("kubectl create rolebinding %s --role=%s --serviceaccount=%s:%s -n %s", rbName, roleName, ns, saName, ns))
	createdRB, err := env.Kube.RbacV1().RoleBindings(ns).Create(ctx, rb, metav1.CreateOptions{})
	if err != nil {
		return rollback(fmt.Errorf("create rolebinding %s (not retried): %w", rbName, err))
	}
	if createdRB == nil {
		return rollback(fmt.Errorf("create rolebinding %s returned no object; outcome is ambiguous", rbName))
	}
	if err := bind("rolebindings", rbName, createdRB.UID, func(ctx context.Context, opts metav1.DeleteOptions) error {
		return env.Kube.RbacV1().RoleBindings(ns).Delete(ctx, rbName, opts)
	}, func(ctx context.Context) (metav1.Object, error) {
		return env.Kube.RbacV1().RoleBindings(ns).Get(ctx, rbName, metav1.GetOptions{})
	}); err != nil {
		return rollback(err)
	}
	return nil
}

func awaitCreatedObjectGone(ctx context.Context, env *core.Env, obj createdRBACObject) error {
	for {
		current, err := env.NamespaceCurrent(ctx)
		if err != nil {
			return fmt.Errorf("verify rollback %s %s namespace identity: %w", obj.kind, obj.name, err)
		}
		if !current {
			return nil
		}
		got, err := obj.get(ctx)
		switch {
		case apierrors.IsNotFound(err):
			return nil
		case err != nil:
			return fmt.Errorf("verify rollback %s %s UID %s absence: %w", obj.kind, obj.name, obj.uid, err)
		case got.GetUID() != obj.uid:
			return fmt.Errorf("rollback %s %s UID %s encountered replacement UID %s; replacement left untouched", obj.kind, obj.name, obj.uid, got.GetUID())
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("rollback %s %s UID %s remains (terminating=%t finalizers=%v): %w", obj.kind, obj.name, obj.uid, got.GetDeletionTimestamp() != nil, got.GetFinalizers(), ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// BackdoorMarkerPath is the on-pod path an attacker writes its persistence marker
// to; the persistence oracle reads it.
const BackdoorMarkerPath = "/tmp/.r6th_backdoor"

// BackdoorMarker is the unique sleeper-process marker string.
const BackdoorMarker = "R6TH-BACKDOOR-SLEEPER"

// deployTarget creates a fresh target and follows only the UID returned by that
// Create. A predecessor, ambiguous create, or same-name replacement is a setup
// failure; no object is stripped or deleted to make the name reusable.
func deployTarget(ctx context.Context, env *core.Env, name, saName string, extraLabels map[string]string) (*corev1.Pod, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	labels := mocks.LabelMap(map[string]string{defenders.RotationTargetLabel: "true", "app": name}, extraLabels)
	pb := mocks.NewPod(env, name, labels).WithBusyboxLoop("app", nil, 100, 32)
	if saName != "" {
		pb = pb.WithServiceAccount(saName)
	}
	return createFreshPod(ctx, env, pb.Build(), "target workload")
}

// deployPlain stands up a fresh benign pod that is not a rotation target.
func deployPlain(ctx context.Context, env *core.Env, name string) (*corev1.Pod, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	pod := mocks.NewPod(env, name, map[string]string{"app": name}).
		WithBusyboxLoop("app", nil, 100, 32).
		Build()
	return createFreshPod(ctx, env, pod, "plain workload")
}

func createFreshPod(ctx context.Context, env *core.Env, pod *corev1.Pod, purpose string) (*corev1.Pod, error) {
	ns, name := env.Config.Namespace, pod.Name
	current, err := env.NamespaceCurrent(ctx)
	if err != nil || !current {
		if err == nil {
			err = fmt.Errorf("original namespace is absent")
		}
		return nil, fmt.Errorf("refusing pod %s creation without exact namespace identity: %w", name, err)
	}
	if _, err := env.Kube.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{}); err == nil {
		return nil, fmt.Errorf("refusing to adopt existing pod %s", name)
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("check fresh pod %s: %w", name, err)
	}
	current, err = env.NamespaceCurrent(ctx)
	if err != nil || !current {
		if err == nil {
			err = fmt.Errorf("original namespace is absent")
		}
		return nil, fmt.Errorf("refusing pod %s creation after namespace identity changed: %w", name, err)
	}
	env.Log.Command(fmt.Sprintf("POST /api/v1/namespaces/%s/pods name=%s images=%s  # %s", ns, name, strings.Join(podImageRefs(pod), ","), purpose))
	created, err := env.Kube.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create pod %s (not retried): %w", name, err)
	}
	if created == nil || created.UID == "" {
		return nil, fmt.Errorf("create pod %s returned no authoritative UID; outcome is ambiguous", name)
	}
	if err := env.RecordCreatedUID("pods", name, created.UID); err != nil {
		return nil, err
	}
	return waitCreatedPodRunning(ctx, env, name, created.UID, 60*time.Second)
}

func podImageRefs(pod *corev1.Pod) []string {
	images := make([]string, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	for i := range pod.Spec.InitContainers {
		images = append(images, pod.Spec.InitContainers[i].Image)
	}
	for i := range pod.Spec.Containers {
		images = append(images, pod.Spec.Containers[i].Image)
	}
	return images
}

func waitCreatedPodRunning(ctx context.Context, env *core.Env, name string, uid types.UID, timeout time.Duration) (*corev1.Pod, error) {
	deadline := time.Now().Add(timeout)
	for {
		current, err := env.NamespaceCurrent(ctx)
		if err != nil || !current {
			if err == nil {
				err = fmt.Errorf("original namespace is absent")
			}
			return nil, fmt.Errorf("pod %s readiness lost namespace authority: %w", name, err)
		}
		pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return nil, fmt.Errorf("created pod %s UID %s disappeared before readiness", name, uid)
		case err != nil:
			return nil, fmt.Errorf("read created pod %s: %w", name, err)
		case pod.UID != uid:
			return nil, fmt.Errorf("created pod %s was replaced: expected UID %s, current UID %s", name, uid, pod.UID)
		case pod.DeletionTimestamp != nil:
			return nil, fmt.Errorf("created pod %s UID %s began terminating before readiness", name, uid)
		case pod.Status.Phase == corev1.PodRunning:
			return pod, nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("created pod %s UID %s did not reach Running within %s", name, uid, timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// firstContainerName looks up a pod by name and returns its first container name
// (or "app" as a safe default for harness-built pods).
func firstContainerName(podName string, env *core.Env) string {
	p, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil || len(p.Spec.Containers) == 0 {
		return "app"
	}
	return p.Spec.Containers[0].Name
}

// plantBackdoor writes a bounded marker file and sleeper process inside the
// target pod. This fixture measures only ephemeral in-container state; it does
// not execute or model a container escape, runc overwrite, or other exploit.
// Returns the commands issued.
func plantBackdoor(ctx context.Context, env *core.Env, pod, container string) []string {
	cmds, _ := plantBackdoorObserved(ctx, env, pod, container)
	return cmds
}

// plantBackdoorObserved is the error-preserving form for scenarios that must
// prove their stimulus completed. The compatibility wrapper above retains the
// older call contract for scenarios whose independent checks already establish
// their stimulus.
func plantBackdoorObserved(ctx context.Context, env *core.Env, pod, container string) ([]string, error) {
	// Write the marker (the clobbered file the attacker drops) and spawn a
	// DETACHED sleeper that re-touches the marker, so a liveness probe of the
	// process succeeds. Real backdoor tradecraft detaches from the controlling
	// stream (nohup-style: redirect stdin/stdout/stderr away) so the operator's
	// interactive exec returns immediately while the sleeper persists. We model
	// the live process by the marker file's presence + a background sleep whose
	// pid we record. The redirects are LOAD-BEARING: without them the backgrounded
	// loop inherits the exec's stdout stream and the SPDY exec would block until
	// it closes (i.e. never).
	script := fmt.Sprintf(
		"echo %s > %s; (while true; do echo %s > %s; sleep 5; done) </dev/null >/dev/null 2>&1 & echo backdoor-pid=$!",
		BackdoorMarker, BackdoorMarkerPath, BackdoorMarker, BackdoorMarkerPath)
	res := env.Exec(ctx, pod, container, []string{"sh", "-c", script})
	env.Log.Logf("plantBackdoor stdout=%q stderr=%q exit=%d", strings.TrimSpace(res.Stdout), strings.TrimSpace(res.Stderr), res.ExitCode)
	cmds := []string{"sh -c '" + script + "'"}
	if err := stimulusExec(ctx, res); err != nil {
		return cmds, err
	}
	return cmds, nil
}

// backdoorAlive checks whether the backdoor marker is still present in ANY pod
// matching the app label (so a rotation that replaced the pod with a fresh
// identity correctly reports the backdoor as gone). Returns (alive, observedPod).
func backdoorAlive(ctx context.Context, env *core.Env, appLabel string) (bool, string, error) {
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=" + appLabel,
	})
	if err != nil {
		return false, "", err
	}
	for i := range pods.Items {
		p := pods.Items[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		res := env.Exec(ctx, p.Name, firstContainer(&p), []string{"sh", "-c", "cat " + BackdoorMarkerPath + " 2>/dev/null"})
		if strings.Contains(res.Stdout, BackdoorMarker) {
			return true, p.Name, nil
		}
	}
	return false, "", nil
}

// firstContainer returns the first container name of a pod (the attacker target).
func firstContainer(p *corev1.Pod) string {
	if len(p.Spec.Containers) > 0 {
		return p.Spec.Containers[0].Name
	}
	return ""
}

// runningPodByApp returns the first Running, NON-terminating pod matching app=<label>.
// It POLLS for up to ~25s: a fresh target may still be coming up, or a prior trial's
// same-named pod may still be terminating (the runner reuses pod names across trials).
// Without this poll the attack Execute can spuriously fail with "no running pod",
// which then falsely reads as an eviction (a measurement-validity bug). Polling makes
// the foothold reliably plant so disruption reflects REAL eviction, not a race.
func runningPodByApp(ctx context.Context, env *core.Env, appLabel string) (*corev1.Pod, error) {
	deadline := time.Now().Add(40 * time.Second)
	var lastLookupErr error
	for {
		pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app=" + appLabel,
		})
		if err == nil {
			lastLookupErr = nil
			for i := range pods.Items {
				if pods.Items[i].Status.Phase == corev1.PodRunning && pods.Items[i].DeletionTimestamp == nil {
					return &pods.Items[i], nil
				}
			}
		} else {
			lastLookupErr = err
		}
		if time.Now().After(deadline) {
			if lastLookupErr != nil {
				return nil, fmt.Errorf("pod lookup failed for app=%s after polling: %w", appLabel, lastLookupErr)
			}
			return nil, fmt.Errorf("no running pod for app=%s after polling", appLabel)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// teardownByApp deletes only Pods whose exact create-response UIDs are recorded
// in this Env and whose full owner/scenario/trial/app labels match. Enumeration is
// bracketed by the captured namespace UID, and every delete carries a UID
// precondition. Foreign or replacement objects are reported and left untouched.
func teardownByApp(ctx context.Context, env *core.Env, appLabels ...string) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	var problems []error
	type target struct {
		name string
		uid  types.UID
	}
	var targets []target
	seen := map[string]bool{}
	for _, app := range appLabels {
		current, err := env.NamespaceCurrent(ctx)
		if err != nil || !current {
			if err == nil {
				err = fmt.Errorf("original namespace is absent")
			}
			return fmt.Errorf("refusing teardown without exact namespace identity: %w", err)
		}
		ownerLabels := env.OwnedLabels(nil)
		selector := fmt.Sprintf("app=%s,%s=%s,%s=%s,%s=%s", app,
			core.OwnedLabelKey, ownerLabels[core.OwnedLabelKey],
			core.ScenarioLabelKey, ownerLabels[core.ScenarioLabelKey],
			core.TrialLabelKey, ownerLabels[core.TrialLabelKey])
		pods, err := env.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			problems = append(problems, fmt.Errorf("list app=%s pods: %w", app, err))
			continue
		}
		current, err = env.NamespaceCurrent(ctx)
		if err != nil || !current {
			if err == nil {
				err = fmt.Errorf("original namespace is absent")
			}
			return fmt.Errorf("refusing teardown after namespace identity changed: %w", err)
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			recorded, ok := env.CreatedUID("pods", pod.Name)
			if !ok {
				problems = append(problems, fmt.Errorf("refusing unrecorded pod %s UID %s matching app=%s", pod.Name, pod.UID, app))
				continue
			}
			if recorded != pod.UID {
				problems = append(problems, fmt.Errorf("refusing replacement pod %s: recorded UID %s, current UID %s", pod.Name, recorded, pod.UID))
				continue
			}
			key := pod.Name + "/" + string(pod.UID)
			if !seen[key] {
				seen[key] = true
				targets = append(targets, target{name: pod.Name, uid: pod.UID})
			}
		}
	}
	for _, target := range targets {
		current, err := env.NamespaceCurrent(ctx)
		if err != nil || !current {
			if err == nil {
				err = fmt.Errorf("original namespace is absent")
			}
			problems = append(problems, fmt.Errorf("refusing delete pod %s without exact namespace identity: %w", target.name, err))
			continue
		}
		uid := target.uid
		env.Log.Command(fmt.Sprintf("kubectl delete pod %s -n %s --precondition-uid=%s", target.name, ns, uid))
		if err := env.Kube.CoreV1().Pods(ns).Delete(ctx, target.name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, fmt.Errorf("delete pod %s UID %s: %w", target.name, uid, err))
			continue
		}
		if err := awaitExactPodGone(ctx, env, target.name, uid); err != nil {
			problems = append(problems, err)
			continue
		}
		if err := env.ForgetCreatedUID("pods", target.name, uid); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func awaitExactPodGone(ctx context.Context, env *core.Env, name string, uid types.UID) error {
	deadline := time.Now().Add(core.DefaultResidueWait)
	for {
		current, err := env.NamespaceCurrent(ctx)
		if err != nil {
			return fmt.Errorf("verify pod %s cleanup namespace identity: %w", name, err)
		}
		if !current {
			return nil
		}
		pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return nil
		case err != nil:
			return fmt.Errorf("verify pod %s UID %s absence: %w", name, uid, err)
		case pod.UID != uid:
			return fmt.Errorf("pod %s UID %s was replaced by UID %s during cleanup; replacement left untouched", name, uid, pod.UID)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("pod %s UID %s remains after cleanup budget (terminating=%t finalizers=%v)", name, uid, pod.DeletionTimestamp != nil, pod.Finalizers)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// measureSurvival POLLS until the foothold is evicted (the backdoor marker is gone
// from every app-labeled running pod) or maxWindow elapses, returning the REAL
// foothold-survival seconds and whether it was still alive at the end. This is the
// genuine dwell-to-eviction metric the report LEADS with (the runner's
// AttackerDwellSeconds is merely trial-elapsed time, not survival). A fast-evicting
// arm (PX on a high-risk pod) yields a small survival; a slow periodic timer yields a
// survival near its interval; an arm that never evicts yields the full window.
func measureSurvival(ctx context.Context, env *core.Env, appLabel string, maxWindow time.Duration) (float64, bool) {
	start := time.Now()
	deadline := start.Add(maxWindow)
	for {
		alive, _, _ := backdoorAlive(ctx, env, appLabel)
		if !alive {
			return time.Since(start).Seconds(), false
		}
		if time.Now().After(deadline) {
			return time.Since(start).Seconds(), true
		}
		select {
		case <-ctx.Done():
			return time.Since(start).Seconds(), true
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// survivalMarker formats the parseable ObservedState markers the post-processor reads
// for the dwell-led, feasibility and harm metrics. Keep keys stable.
func survivalMarker(survivalSec float64, stillAlive bool) string {
	return fmt.Sprintf("[survival=%.1fs] [evicted=%v]", survivalSec, !stillAlive)
}

// dwellCheck waits dwell seconds (bounded for smoke) then reports whether the
// backdoor survived. It is the shared persistence-dwell measurement.
func dwellCheck(ctx context.Context, env *core.Env, appLabel string, dwell time.Duration) (bool, string) {
	// Bound the actual wait so smoke trials stay fast.
	const maxWait = 10 * time.Second
	w := dwell
	if w > maxWait {
		w = maxWait
	}
	select {
	case <-ctx.Done():
	case <-time.After(w):
	}
	alive, pod, err := backdoorAlive(ctx, env, appLabel)
	if err != nil {
		env.Log.Logf("dwellCheck error: %v", err)
	}
	return alive, pod
}
