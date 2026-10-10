package verificationloop

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const creator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
const opns = "phorvex-system"
const tlsName = "lease.verification.local"

// Fictional private PodIP is API fixture metadata, mapped to local TLS only.
const fixturePodIP = "10.240.0.10"

type fixture struct {
	client                client.Client
	policy                *v1alpha1.PhorvexPolicy
	pod                   *corev1.Pod
	state                 *corev1.ConfigMap
	journal               *corev1.ConfigMap
	source                string
	proxyImage            string
	engineImage           string
	a, b, admin, upstream string
	aID, bID              string
	secret                *corev1.Secret
	security              *actuator.ServingSecurityConfig
	ca                    []byte
	config                map[string]any
}

func newScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, discoveryv1.AddToScheme, networkingv1.AddToScheme, rbacv1.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func token() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
func boolPtr(b bool) *bool { return &b }
func hmacID(seed []byte, value string) string {
	h := hmac.New(sha256.New, seed)
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
func privateFile(dir, name string, raw []byte) (string, error) {
	p := filepath.Join(dir, name)
	return p, os.WriteFile(p, raw, 0600)
}

func tlsFiles(dir string) (certPath, keyPath string, ca []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: tlsName}, DNSNames: []string{tlsName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPath, err = privateFile(dir, "runtime.crt", ca)
	if err != nil {
		return "", "", nil, err
	}
	keyPath, err = privateFile(dir, "runtime.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPath, keyPath, ca, err
}

func provision(ctx context.Context, c client.Client, cfg *rest.Config, root, tmp string) (*fixture, error) {
	f := &fixture{client: c, proxyImage: "fixture.invalid/lease-proxy@sha256:" + SHA256([]byte("unexecuted-container-image-fixture-proxy")), engineImage: "fixture.invalid/engine@sha256:" + SHA256([]byte("unexecuted-container-image-fixture-engine"))}
	var err error
	for _, out := range []*string{&f.a, &f.b, &f.admin, &f.upstream} {
		*out, err = token()
		if err != nil {
			return nil, err
		}
	}
	seedText, err := token()
	if err != nil {
		return nil, err
	}
	seed := []byte(seedText)
	f.aID, f.bID = hmacID(seed, f.a), hmacID(seed, f.b)
	create := func(o client.Object) error { return c.Create(ctx, o) }
	for _, ns := range []string{endpointlease.Namespace, opns} {
		if err = create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			return nil, err
		}
	}
	if err = create(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "lease-proxy", Namespace: endpointlease.Namespace}}); err != nil {
		return nil, err
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.ServiceName, Namespace: endpointlease.Namespace}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "vllm"}, Ports: []corev1.ServicePort{{Port: 8000, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8000)}}}}
	if err = create(svc); err != nil {
		return nil, err
	}
	f.secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.SecretName, Namespace: endpointlease.Namespace}, Immutable: boolPtr(true), Data: map[string][]byte{"client-a": []byte(f.a), "client-b": []byte(f.b), "seed": seed}}
	if err = create(f.secret); err != nil {
		return nil, err
	}
	files := []string{"guardrail_proxy.py", "dual_server.py", "endpoint_lease.py", "drain_v11.py", "drain_v11_init.py"}
	parts := make([][]byte, len(files))
	data := map[string]string{}
	for i, name := range files {
		directory := "build/integrations/vllm-live-runtime"
		if name == "guardrail_proxy.py" || name == "drain_v11.py" || name == "drain_v11_init.py" {
			directory = "build/test-harness/guardrail"
		}
		parts[i], err = os.ReadFile(filepath.Join(root, directory, name))
		if err != nil {
			return nil, err
		}
		data[name] = string(parts[i])
	}
	f.source = endpointlease.SourceSHA256(parts[0], parts[1], parts[2], parts[3], parts[4])
	if err = create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.SourceConfigMapName, Namespace: endpointlease.Namespace}, Immutable: boolPtr(true), Data: data}); err != nil {
		return nil, err
	}
	allowed := []string{f.aID, f.bID}
	if allowed[0] > allowed[1] {
		allowed[0], allowed[1] = allowed[1], allowed[0]
	}
	state := endpointlease.State{Version: 1, ServiceUID: string(svc.UID), SecretUID: string(f.secret.UID), SeedSHA256: SHA256(seed), ProxySourceSHA256: f.source, AllowedClientHMACs: allowed, RevokedClientHMACs: []string{}}
	stateRaw, err := endpointlease.EncodeState(state)
	if err != nil {
		return nil, err
	}
	f.state = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.PolicyConfigMapName, Namespace: endpointlease.Namespace}, Data: map[string]string{endpointlease.PolicyKey: stateRaw}}
	if err = create(f.state); err != nil {
		return nil, err
	}
	f.journal = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.JournalName, Namespace: opns, Labels: map[string]string{endpointlease.JournalLabel: "v1"}}, Data: map[string]string{endpointlease.JournalKey: `{"receipts":[],"version":1}`}}
	if err = create(f.journal); err != nil {
		return nil, err
	}
	ann := map[string]string{endpointlease.SourceConfigMapAnnotation: endpointlease.SourceConfigMapName, endpointlease.SourceSHAAnnotation: f.source, endpointlease.PolicyUIDAnnotation: string(f.state.UID), endpointlease.EventCreatorAnnotation: creator, "phorvex.ai/serving-port": "8443", "phorvex.ai/model-id": "synthetic-admission-fixture"}
	envs := []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}}
	for k, v := range map[string]string{"PHORVEX_ENDPOINT_LEASE_REQUIRED": "true", "PHORVEX_ENDPOINT_LEASE_SECRET_DIR": "/etc/phorvex/endpoint-lease-keys", "PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID": string(f.state.UID), "PHORVEX_ENDPOINT_LEASE_SECRET_UID": string(f.secret.UID), "PHORVEX_ENDPOINT_LEASE_SERVICE_UID": string(svc.UID), "PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256": f.source} {
		envs = append(envs, corev1.EnvVar{Name: k, Value: v})
	}
	mounts := []corev1.VolumeMount{{Name: "lease-keys", MountPath: "/etc/phorvex/endpoint-lease-keys", ReadOnly: true}}
	for _, name := range files {
		mounts = append(mounts, corev1.VolumeMount{Name: "lease-source", MountPath: "/src/" + name, SubPath: name, ReadOnly: true})
	}
	spec := corev1.PodSpec{ServiceAccountName: "lease-proxy", Volumes: []corev1.Volume{{Name: "lease-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: endpointlease.SourceConfigMapName}}}}, {Name: "lease-keys", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: endpointlease.SecretName}}}}, Containers: []corev1.Container{{Name: "vllm", Image: f.engineImage, Args: []string{"--model", "fixture", "--host", "127.0.0.1", "--port", "8001"}, Env: []corev1.EnvVar{{Name: "VLLM_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "vllm-control"}, Key: "api-key"}}}}}, {Name: endpointlease.ProxyContainerName, Image: f.proxyImage, Command: []string{"python3", "-B", "/src/dual_server.py"}, Env: envs, VolumeMounts: mounts}}}
	replicas := int32(1)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.ServiceName, Namespace: endpointlease.Namespace}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "vllm"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "vllm"}, Annotations: ann}, Spec: spec}}}
	if err = create(dep); err != nil {
		return nil, err
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "vllm-rs", Namespace: endpointlease.Namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: boolPtr(true)}}}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: dep.Spec.Selector, Template: dep.Spec.Template}}
	if err = create(rs); err != nil {
		return nil, err
	}
	f.pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "vllm-a", Namespace: endpointlease.Namespace, Labels: map[string]string{"app": "vllm"}, Annotations: ann, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: boolPtr(true)}}}, Spec: spec}
	if err = create(f.pod); err != nil {
		return nil, err
	}
	f.pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: fixturePodIP, StartTime: &metav1.Time{Time: time.Now().UTC()}, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "vllm", Ready: true, ContainerID: "fixture://engine-process", ImageID: f.engineImage}, {Name: endpointlease.ProxyContainerName, Ready: true, ContainerID: "fixture://python-process", ImageID: f.proxyImage}}}
	if err = c.Status().Update(ctx, f.pod); err != nil {
		return nil, err
	}
	port, protocol := int32(8000), corev1.ProtocolTCP
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "vllm-slice", Namespace: endpointlease.Namespace, Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: boolPtr(true)}}}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &protocol}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{fixturePodIP}, Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: f.pod.Namespace, Name: f.pod.Name, UID: f.pod.UID}}}}
	if err = create(slice); err != nil {
		return nil, err
	}
	f.policy = &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "lease-defense", Namespace: endpointlease.Namespace}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Triggers: v1alpha1.TriggersSpec{EventDriven: true, ReactiveOnly: true}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Second}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "vllm"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionEndpointLeaseRevoke), v1alpha1.ActionType(model.ActionEndpointRotate), v1alpha1.ActionType(model.ActionRotate)}}}}
	if err = create(f.policy); err != nil {
		return nil, err
	}
	certPath, keyPath, ca, err := tlsFiles(tmp)
	if err != nil {
		return nil, err
	}
	f.ca = ca
	adminSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "lease-admin", Namespace: opns}, Data: map[string][]byte{"bearer": []byte(f.admin), "ca.crt": ca}}
	if err = create(adminSecret); err != nil {
		return nil, err
	}
	binding := actuator.ServingSecurityBinding{Namespace: f.policy.Namespace, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), ServiceAccount: "lease-proxy", ProfileID: "local-lease", SecretName: adminSecret.Name, BearerKey: "bearer", CAKey: "ca.crt", ServerName: tlsName}
	securityRaw, _ := json.Marshal(map[string]any{"version": 1, "bindings": []actuator.ServingSecurityBinding{binding}})
	securityPath, err := privateFile(tmp, "security.json", securityRaw)
	if err != nil {
		return nil, err
	}
	f.security, err = actuator.LoadServingSecurityFile(securityPath, actuator.ServingSecuritySecureRequired, opns)
	if err != nil {
		return nil, err
	}
	secretDir := filepath.Join(tmp, "projection")
	generation := filepath.Join(secretDir, "..generation")
	if err = os.MkdirAll(generation, 0700); err != nil {
		return nil, err
	}
	for name, value := range f.secret.Data {
		if _, err = privateFile(generation, name, value); err != nil {
			return nil, err
		}
	}
	if err = os.Symlink("..generation", filepath.Join(secretDir, "..data")); err != nil {
		return nil, err
	}
	apiCA, err := privateFile(tmp, "api-ca.crt", cfg.CAData)
	if err != nil {
		return nil, err
	}
	apiCert, err := privateFile(tmp, "api-client.crt", cfg.CertData)
	if err != nil {
		return nil, err
	}
	apiKey, err := privateFile(tmp, "api-client.key", cfg.KeyData)
	if err != nil {
		return nil, err
	}
	f.config = map[string]any{"repo_root": root, "host": "127.0.0.1", "api_url": cfg.Host, "api_ca_file": apiCA, "api_client_cert_file": apiCert, "api_client_key_file": apiKey, "pod_uid": string(f.pod.UID), "service_uid": string(svc.UID), "policy_configmap_uid": string(f.state.UID), "secret_uid": string(f.secret.UID), "source_sha256": f.source, "secret_dir": secretDir, "admin_token": f.admin, "tls_cert_file": certPath, "tls_key_file": keyPath, "upstream_key": f.upstream, "ready_file": filepath.Join(tmp, "ready.json")}
	if f.pod.UID == "" || f.state.ResourceVersion == "" {
		return nil, fmt.Errorf("API generated identity unavailable")
	}
	return f, nil
}
