package actuator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	validation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/servingcontext"
)

type ServingSecurityMode string

const (
	ServingSecuritySecureRequired  ServingSecurityMode = "secure-required"
	ServingSecurityLegacyPlaintext ServingSecurityMode = "legacy-plaintext"
	servingSecurityVersion                             = 1
	maxServingSecurityBytes                            = 1 << 20
	maxServingSecurityBindings                         = 1024
	maxServingBearerBytes                              = 16 << 10
	maxServingCABytes                                  = 512 << 10
)

type ServingSecurityBinding struct {
	Namespace      string `json:"namespace"`
	PolicyName     string `json:"policyName"`
	PolicyUID      string `json:"policyUID"`
	ServiceAccount string `json:"serviceAccount"`
	ProfileID      string `json:"profileID"`
	SecretName     string `json:"secretName"`
	BearerKey      string `json:"bearerKey"`
	CAKey          string `json:"caKey"`
	ServerName     string `json:"serverName"`
}

type ServingSecurityConfig struct {
	Version           int                      `json:"version"`
	Bindings          []ServingSecurityBinding `json:"bindings"`
	mode              ServingSecurityMode
	operatorNamespace string
	byKey             map[string]ServingSecurityBinding
	validationErr     error
}

type servingCredentialSnapshot struct {
	binding         ServingSecurityBinding
	digest          string
	token           string
	client          *http.Client
	legacy          bool
	policyNamespace string
	policyName      string
	policyUID       string
	selector        labels.Selector
	action          model.Action
}

func servingBindingKey(namespace, policyName, policyUID, serviceAccount string) string {
	return strings.Join([]string{namespace, policyName, policyUID, serviceAccount}, "\x00")
}

func normalizeServiceAccount(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

func ParseServingSecurityMode(raw string) (ServingSecurityMode, error) {
	mode := ServingSecurityMode(strings.TrimSpace(raw))
	switch mode {
	case ServingSecuritySecureRequired, ServingSecurityLegacyPlaintext:
		return mode, nil
	default:
		return "", fmt.Errorf("serving security mode must be %q or %q", ServingSecuritySecureRequired, ServingSecurityLegacyPlaintext)
	}
}

func LoadServingSecurityFile(path string, mode ServingSecurityMode, operatorNamespace string) (*ServingSecurityConfig, error) {
	if _, err := ParseServingSecurityMode(string(mode)); err != nil {
		return nil, err
	}
	config := &ServingSecurityConfig{Version: servingSecurityVersion, mode: mode, operatorNamespace: operatorNamespace, byKey: map[string]ServingSecurityBinding{}}
	if strings.TrimSpace(path) == "" {
		return config, nil
	}
	if errs := validation.IsDNS1123Label(operatorNamespace); len(errs) != 0 {
		return nil, fmt.Errorf("serving security operator namespace is invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("serving security configuration: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxServingSecurityBytes+1))
	if err != nil {
		return nil, fmt.Errorf("serving security configuration: %w", err)
	}
	if len(b) > maxServingSecurityBytes {
		return nil, fmt.Errorf("serving security configuration exceeds %d bytes", maxServingSecurityBytes)
	}
	if err := rejectDuplicateJSONFields(b); err != nil {
		return nil, fmt.Errorf("serving security configuration: %w", err)
	}
	if err := validateServingSecurityJSONKeys(b); err != nil {
		return nil, fmt.Errorf("serving security configuration: %w", err)
	}
	var decoded ServingSecurityConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("serving security configuration: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("serving security configuration has trailing content")
	}
	config = &decoded
	config.mode, config.operatorNamespace = mode, operatorNamespace
	if err := config.validate(); err != nil {
		return nil, err
	}
	return config, nil
}

func validateServingSecurityJSONKeys(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil || root == nil {
		return fmt.Errorf("document must be a JSON object")
	}
	for key := range root {
		if key != "version" && key != "bindings" {
			return fmt.Errorf("field %q does not use an exact published key", key)
		}
	}
	bindingsJSON, ok := root["bindings"]
	if !ok || bytes.Equal(bytes.TrimSpace(bindingsJSON), []byte("null")) {
		return fmt.Errorf("field %q must be an array", "bindings")
	}
	var bindings []json.RawMessage
	if err := json.Unmarshal(bindingsJSON, &bindings); err != nil {
		return fmt.Errorf("field %q must be an array", "bindings")
	}
	allowed := map[string]struct{}{
		"namespace": {}, "policyName": {}, "policyUID": {}, "serviceAccount": {}, "profileID": {},
		"secretName": {}, "bearerKey": {}, "caKey": {}, "serverName": {},
	}
	for i, raw := range bindings {
		var binding map[string]json.RawMessage
		if err := json.Unmarshal(raw, &binding); err != nil || binding == nil {
			return fmt.Errorf("binding %d must be a JSON object", i)
		}
		for key := range binding {
			if _, ok := allowed[key]; !ok {
				return fmt.Errorf("binding %d field %q does not use an exact published key", i, key)
			}
		}
	}
	return nil
}

func (c *ServingSecurityConfig) validate() error {
	if c == nil || c.Version != servingSecurityVersion || len(c.Bindings) > maxServingSecurityBindings {
		return fmt.Errorf("serving security configuration requires version %d and at most %d bindings", servingSecurityVersion, maxServingSecurityBindings)
	}
	if c.mode == ServingSecurityLegacyPlaintext && len(c.Bindings) != 0 {
		return fmt.Errorf("legacy plaintext mode does not accept trusted credential bindings")
	}
	byKey := make(map[string]ServingSecurityBinding, len(c.Bindings))
	for i, b := range c.Bindings {
		if len(validation.IsDNS1123Label(b.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(b.PolicyName)) != 0 ||
			len(validation.IsDNS1123Subdomain(b.ServiceAccount)) != 0 || len(validation.IsDNS1123Label(b.ProfileID)) != 0 ||
			len(validation.IsDNS1123Subdomain(b.SecretName)) != 0 || len(validation.IsConfigMapKey(b.BearerKey)) != 0 ||
			len(validation.IsConfigMapKey(b.CAKey)) != 0 || len(validation.IsDNS1123Subdomain(b.ServerName)) != 0 ||
			b.PolicyUID == "" || len(b.PolicyUID) > 253 || strings.TrimSpace(b.PolicyUID) != b.PolicyUID || strings.ContainsAny(b.PolicyUID, "\x00\r\n") {
			return fmt.Errorf("serving security binding %d has an invalid exact identity or key", i)
		}
		key := servingBindingKey(b.Namespace, b.PolicyName, b.PolicyUID, b.ServiceAccount)
		if _, exists := byKey[key]; exists {
			return fmt.Errorf("serving security binding %d duplicates an exact workload binding", i)
		}
		byKey[key] = b
	}
	c.byKey = byKey
	c.validationErr = nil
	return nil
}

func snapshotServingSecurity(c *ServingSecurityConfig) *ServingSecurityConfig {
	if c == nil {
		return nil
	}
	out := &ServingSecurityConfig{Version: c.Version, Bindings: append([]ServingSecurityBinding(nil), c.Bindings...), mode: c.mode, operatorNamespace: c.operatorNamespace}
	if err := out.validate(); err != nil {
		out.validationErr = err
		out.byKey = map[string]ServingSecurityBinding{}
	}
	return out
}

func (c *ServingSecurityConfig) Mode() ServingSecurityMode {
	if c == nil {
		return ServingSecuritySecureRequired
	}
	return c.mode
}

func (c *ServingSecurityConfig) SecretNames() []string {
	if c == nil || c.mode != ServingSecuritySecureRequired {
		return nil
	}
	set := map[string]struct{}{}
	for _, binding := range c.Bindings {
		set[binding.SecretName] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (c *ServingSecurityConfig) binding(namespace, policyName, policyUID, serviceAccount string) (ServingSecurityBinding, bool) {
	if c == nil || c.validationErr != nil || c.mode == ServingSecurityLegacyPlaintext {
		return ServingSecurityBinding{}, c != nil && c.mode == ServingSecurityLegacyPlaintext
	}
	b, ok := c.byKey[servingBindingKey(namespace, policyName, policyUID, normalizeServiceAccount(serviceAccount))]
	return b, ok
}

func servingBindingDigest(operatorNamespace string, b ServingSecurityBinding) string {
	payload, _ := json.Marshal(struct {
		Version                                                                                                                  int `json:"version"`
		OperatorNamespace, Namespace, PolicyName, PolicyUID, ServiceAccount, ProfileID, SecretName, BearerKey, CAKey, ServerName string
	}{servingSecurityVersion, operatorNamespace, b.Namespace, b.PolicyName, b.PolicyUID, b.ServiceAccount, b.ProfileID, b.SecretName, b.BearerKey, b.CAKey, b.ServerName})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func servingHTTPAction(action model.Action) bool {
	switch action {
	case model.ActionWarmSwap, model.ActionModelShardReplace, model.ActionMIGRebind, model.ActionKVReset,
		model.ActionAdapterRotate, model.ActionRequestDrain, model.ActionGuardrailRotate, model.ActionKVMigrateInvalidate:
		return true
	default:
		return false
	}
}

func secureServingReceipt(r operationReceipt) bool {
	switch r.Kind {
	case string(model.ActionWarmSwap), string(model.ActionModelShardReplace):
		return r.Version == warmSecureReceiptVersion
	case string(model.ActionRequestDrain):
		return r.Version == requestDrainSecureReceiptVersion
	case string(model.ActionAdapterRotate):
		return r.Version == adapterRotateSecureReceiptVersion
	case string(model.ActionKVReset), string(model.ActionKVMigrateInvalidate), string(model.ActionGuardrailRotate):
		return r.Version == servingEffectReceiptVersion && !r.ServingLegacy
	default:
		return false
	}
}

func (c *ServingSecurityConfig) supports(action model.Action, target Target) (bool, string) {
	if !servingHTTPAction(action) {
		return true, ""
	}
	if c == nil || c.validationErr != nil {
		return false, "serving-security: trusted configuration unavailable"
	}
	if c.mode == ServingSecurityLegacyPlaintext {
		return true, "legacy-plaintext: serving control is explicitly insecure"
	}
	if target.PolicyName == "" || target.PolicyUID == "" || target.ServiceAccount == "" {
		return false, "serving-security: exact policy or ServiceAccount identity unavailable"
	}
	if _, ok := c.binding(target.Namespace, target.PolicyName, target.PolicyUID, target.ServiceAccount); !ok {
		return false, "serving-security: no exact trusted workload binding"
	}
	return true, ""
}

func (c *ServingSecurityConfig) prepare(ctx context.Context, reader client.Reader, req Request, expectedUID string) (*corev1.Pod, *servingCredentialSnapshot, error) {
	if c == nil || c.validationErr != nil || reader == nil {
		return nil, nil, fmt.Errorf("serving security authority unavailable")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, policy); err != nil {
		return nil, nil, fmt.Errorf("serving security current policy unavailable: %w", err)
	}
	if string(policy.UID) != req.PolicyUID || policy.DeletionTimestamp != nil || policy.Spec.IsDryRun() {
		return nil, nil, fmt.Errorf("serving security policy identity or mode changed")
	}
	if !policyActionEnabled(policy, req.Action) {
		return nil, nil, fmt.Errorf("serving security action is disabled by current policy")
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		return nil, nil, fmt.Errorf("serving security current target unavailable: %w", err)
	}
	if string(pod.UID) != expectedUID || pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil {
		return nil, nil, fmt.Errorf("serving security target identity changed")
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
		return nil, nil, fmt.Errorf("serving security target left current policy scope")
	}
	if !servingcontext.FromAnnotations(pod.Annotations).Declared() {
		return nil, nil, fmt.Errorf("serving security target has no serving declaration")
	}
	if _, err := validatedEndpointForPod(pod); err != nil {
		return nil, nil, fmt.Errorf("serving security endpoint declaration invalid")
	}
	if c.mode == ServingSecurityLegacyPlaintext {
		return pod, &servingCredentialSnapshot{legacy: true, policyNamespace: req.Namespace, policyName: req.PolicyName, policyUID: req.PolicyUID, selector: selector, action: req.Action}, nil
	}
	binding, ok := c.binding(req.Namespace, req.PolicyName, req.PolicyUID, normalizeServiceAccount(pod.Spec.ServiceAccountName))
	if !ok {
		return nil, nil, fmt.Errorf("serving security exact trusted binding unavailable")
	}
	snapshot, err := c.snapshotForBinding(ctx, reader, binding)
	if err != nil {
		return nil, nil, err
	}
	snapshot.policyNamespace, snapshot.policyName, snapshot.policyUID, snapshot.selector, snapshot.action = req.Namespace, req.PolicyName, req.PolicyUID, selector, req.Action
	return pod, snapshot, nil
}

func (c *ServingSecurityConfig) snapshotForBinding(ctx context.Context, reader client.Reader, binding ServingSecurityBinding) (*servingCredentialSnapshot, error) {
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: c.operatorNamespace, Name: binding.SecretName}, secret); err != nil {
		return nil, fmt.Errorf("serving security credential Secret unavailable: %w", err)
	}
	if secret.UID == "" || secret.ResourceVersion == "" || secret.DeletionTimestamp != nil {
		return nil, fmt.Errorf("serving security credential Secret identity invalid")
	}
	bearer, ca := secret.Data[binding.BearerKey], secret.Data[binding.CAKey]
	if len(bearer) == 0 || len(bearer) > maxServingBearerBytes || !bytes.Equal(bearer, bytes.TrimSpace(bearer)) || bytes.IndexFunc(bearer, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("serving security bearer material is missing or invalid")
	}
	if len(ca) == 0 || len(ca) > maxServingCABytes {
		return nil, fmt.Errorf("serving security CA material is missing or invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("serving security CA material is invalid")
	}
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("serving security standard transport unavailable")
	}
	transport := baseTransport.Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: binding.ServerName}
	return &servingCredentialSnapshot{
		binding: binding,
		digest:  servingBindingDigest(c.operatorNamespace, binding),
		token:   string(append([]byte(nil), bearer...)),
		client:  &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (c *ServingSecurityConfig) prepareRecovery(ctx context.Context, reader client.Reader, r operationReceipt) (*servingCredentialSnapshot, error) {
	if c == nil || c.validationErr != nil || reader == nil {
		return nil, fmt.Errorf("serving security recovery authority unavailable")
	}
	if c.mode == ServingSecurityLegacyPlaintext && secureServingReceipt(r) {
		return nil, fmt.Errorf("secure serving receipt cannot be resumed in legacy plaintext mode")
	}
	if c.mode != ServingSecurityLegacyPlaintext && (!validDigest(r.ServingBindingSHA256) || r.ServingServiceAccount == "") {
		return nil, fmt.Errorf("protected operation predates trusted serving binding; network recovery refused")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.PolicyName}, policy); err != nil || string(policy.UID) != r.PolicyUID || policy.DeletionTimestamp != nil || policy.Spec.IsDryRun() || !policyActionEnabled(policy, model.Action(r.Kind)) {
		return nil, fmt.Errorf("serving security recovery policy authority unavailable")
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, fmt.Errorf("serving security recovery policy selector invalid")
	}
	if c.mode == ServingSecurityLegacyPlaintext {
		return &servingCredentialSnapshot{legacy: true, policyNamespace: r.PolicyNamespace, policyName: r.PolicyName, policyUID: r.PolicyUID, selector: selector, action: model.Action(r.Kind)}, nil
	}
	binding, ok := c.binding(r.PolicyNamespace, r.PolicyName, r.PolicyUID, r.ServingServiceAccount)
	if !ok || servingBindingDigest(c.operatorNamespace, binding) != r.ServingBindingSHA256 {
		return nil, fmt.Errorf("serving security recovery binding changed")
	}
	snapshot, err := c.snapshotForBinding(ctx, reader, binding)
	if err != nil {
		return nil, err
	}
	snapshot.policyNamespace, snapshot.policyName, snapshot.policyUID, snapshot.selector, snapshot.action = r.PolicyNamespace, r.PolicyName, r.PolicyUID, selector, model.Action(r.Kind)
	return snapshot, nil
}

func prepareServingAttempt(ctx context.Context, ec *EnactCtx, req Request) error {
	if !servingHTTPAction(req.Action) {
		return nil
	}
	ec.ServingRequest = req
	if ec.ServingSecurity == nil {
		if servingFamilyInjected(*ec, req.Action) {
			return nil // explicit test/control-plane injection; production always wires configuration
		}
		return RefusedWithoutEffect(fmt.Errorf("serving security configuration is not wired"))
	}
	pod, snapshot, err := ec.ServingSecurity.prepare(ctx, ec.Reader, req, req.TargetUID)
	if err != nil {
		return RefusedWithoutEffect(err)
	}
	ec.ServingAttempt = snapshot
	ec.ServingTarget = pod
	return nil
}

func servingEndpointForPod(ctx context.Context, ec EnactCtx, req Request, pod *corev1.Pod) (servingEndpoint, error) {
	if ec.ServingSecurity == nil {
		if !servingFamilyInjected(ec, req.Action) {
			return servingEndpoint{}, fmt.Errorf("serving security configuration is not wired")
		}
		return validatedEndpointForPod(pod)
	}
	snapshot := ec.ServingAttempt
	if snapshot == nil {
		return servingEndpoint{}, fmt.Errorf("serving credential snapshot is unavailable")
	}
	fresh := &corev1.Pod{}
	if ec.Reader == nil || ec.Reader.Get(ctx, client.ObjectKeyFromObject(pod), fresh) != nil || fresh.UID != pod.UID || fresh.DeletionTimestamp != nil {
		return servingEndpoint{}, fmt.Errorf("serving participant identity changed")
	}
	if fresh.Namespace != snapshot.policyNamespace || req.Namespace != snapshot.policyNamespace || req.PolicyName != snapshot.policyName || req.PolicyUID != snapshot.policyUID || req.Action != snapshot.action || snapshot.selector == nil || snapshot.selector.Empty() || !snapshot.selector.Matches(labels.Set(fresh.Labels)) {
		return servingEndpoint{}, fmt.Errorf("serving participant left the trusted policy scope")
	}
	if !servingcontext.FromAnnotations(fresh.Annotations).Declared() {
		return servingEndpoint{}, fmt.Errorf("serving participant has no serving declaration")
	}
	if !snapshot.legacy && normalizeServiceAccount(fresh.Spec.ServiceAccountName) != snapshot.binding.ServiceAccount {
		return servingEndpoint{}, fmt.Errorf("serving participant ServiceAccount does not match the trusted profile")
	}
	ep, err := validatedEndpointForPod(fresh)
	if err != nil {
		return servingEndpoint{}, err
	}
	if snapshot.legacy {
		ep.scheme = "http"
		return ep, nil
	}
	ep.scheme, ep.token, ep.client = "https", snapshot.token, snapshot.client
	return ep, nil
}

func servingFamilyInjected(ec EnactCtx, action model.Action) bool {
	switch action {
	case model.ActionGuardrailRotate:
		return ec.Guardrail != nil
	case model.ActionKVMigrateInvalidate:
		return ec.KVXfer != nil
	case model.ActionMIGRebind:
		return ec.VLLM != nil
	case model.ActionWarmSwap, model.ActionModelShardReplace, model.ActionKVReset, model.ActionAdapterRotate, model.ActionRequestDrain:
		return ec.VLLM != nil
	default:
		return false
	}
}

func policyActionEnabled(policy *v1alpha1.PhorvexPolicy, action model.Action) bool {
	if policy == nil || action == "" {
		return false
	}
	if len(policy.Spec.Actions.Enabled) == 0 {
		return action == model.ActionRotate || action == model.ActionQuarantine
	}
	for _, enabled := range policy.Spec.Actions.Enabled {
		if model.Action(enabled) == action {
			return true
		}
	}
	return false
}
