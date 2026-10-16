package currentobserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/ownership"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const MaxManifestBytes = 4096

type ManifestV1 struct {
	SchemaVersion string `json:"schemaVersion"`
	Version       string `json:"version"`
	Bytes         int64  `json:"bytes"`
	SHA256        string `json:"sha256"`
}
type Config struct {
	URL                                                                              string
	PolicyEpoch                                                                      model.PolicyEpoch
	TargetNamespace, TargetName, TargetUID                                           string
	ConfigMapName, ConfigMapKey, VolumeName, ContainerName, MountPath, ProjectedPath string
	ProtectedScope                                                                   model.ProtectedScope
	EvidenceID, RuleDigest, ObserverIdentity                                         string
	TTL, Timeout                                                                     time.Duration
}

func ObserveOnce(ctx context.Context, c client.Client, httpClient *http.Client, cfg Config, now func() time.Time) (*amtdv1beta1.SecurityEvent, error) {
	if c == nil || httpClient == nil || now == nil || cfg.Timeout <= 0 || cfg.TTL <= 0 || cfg.TTL > currentinventory.MaxObservationTTL {
		return nil, errors.New("invalid current inventory observer configuration")
	}
	manifestURL, err := url.Parse(cfg.URL)
	if err != nil || manifestURL.Scheme != "https" || manifestURL.Host == "" || manifestURL.User != nil || manifestURL.Fragment != "" {
		return nil, errors.New("current inventory manifest URL must be an exact HTTPS endpoint")
	}
	opctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	var policy v1alpha1.PhorvexPolicy
	if err := c.Get(opctx, client.ObjectKey{Namespace: cfg.PolicyEpoch.Namespace, Name: cfg.PolicyEpoch.Name}, &policy); err != nil || string(policy.UID) != cfg.PolicyEpoch.UID || policy.Generation != cfg.PolicyEpoch.Generation {
		return nil, errors.New("policy epoch identity mismatch")
	}
	tenant := policy.Spec.Tenant
	if tenant == "" {
		tenant = policy.Namespace
	}
	if tenant != cfg.ProtectedScope.Tenant {
		return nil, errors.New("policy tenant does not match protected scope")
	}
	var pod corev1.Pod
	if err := c.Get(opctx, client.ObjectKey{Namespace: cfg.TargetNamespace, Name: cfg.TargetName}, &pod); err != nil || string(pod.UID) != cfg.TargetUID {
		return nil, errors.New("target Pod identity mismatch")
	}
	var cm corev1.ConfigMap
	if err := c.Get(opctx, client.ObjectKey{Namespace: cfg.TargetNamespace, Name: cfg.ConfigMapName}, &cm); err != nil {
		return nil, fmt.Errorf("read current inventory ConfigMap: %w", err)
	}
	binding, err := currentinventory.BindingFor(&pod, &cm, cfg.ConfigMapKey, cfg.VolumeName, cfg.ContainerName, cfg.MountPath, cfg.ProjectedPath)
	if err != nil {
		return nil, err
	}
	immediate, stable, err := ownership.ResolveStableWorkloadOwner(opctx, c, cfg.TargetNamespace, cfg.TargetName, cfg.TargetUID)
	if err != nil {
		return nil, err
	}
	started := now().UTC()
	req, err := http.NewRequestWithContext(opctx, http.MethodGet, cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	requestClient := *httpClient
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, MaxManifestBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	var extra [1]byte
	n, eofErr := resp.Body.Read(extra[:])
	eof := n == 0 && eofErr == io.EOF
	if len(raw) == 0 || len(raw) > MaxManifestBytes || resp.StatusCode != http.StatusOK || !eof || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 || resp.Request == nil || resp.Request.URL.String() != cfg.URL {
		return nil, errors.New("current inventory manifest response incomplete")
	}
	if err := currentinventory.RejectDuplicateFields(raw); err != nil {
		return nil, err
	}
	var manifest ManifestV1
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("trailing manifest JSON data")
	}
	if manifest.SchemaVersion != model.CurrentInventorySchemaV1 || manifest.Version != cfg.ProtectedScope.Version || manifest.Bytes != binding.Bytes || manifest.SHA256 != binding.SHA256 {
		return nil, errors.New("serving manifest does not match authoritative ConfigMap bytes")
	}
	completed := now().UTC()
	var afterPod corev1.Pod
	var afterCM corev1.ConfigMap
	if err := c.Get(opctx, client.ObjectKey{Namespace: cfg.TargetNamespace, Name: cfg.TargetName}, &afterPod); err != nil {
		return nil, err
	}
	if err := c.Get(opctx, client.ObjectKey{Namespace: cfg.TargetNamespace, Name: cfg.ConfigMapName}, &afterCM); err != nil {
		return nil, err
	}
	afterBinding, err := currentinventory.BindingFor(&afterPod, &afterCM, cfg.ConfigMapKey, cfg.VolumeName, cfg.ContainerName, cfg.MountPath, cfg.ProjectedPath)
	if err != nil || string(afterPod.UID) != cfg.TargetUID || !currentinventory.SameBinding(binding, afterBinding) {
		return nil, errors.New("current inventory source changed during observation")
	}
	afterImmediate, afterStable, err := ownership.ResolveStableWorkloadOwner(opctx, c, cfg.TargetNamespace, cfg.TargetName, cfg.TargetUID)
	if err != nil || afterImmediate != immediate || afterStable != stable {
		return nil, errors.New("target ownership changed during current inventory observation")
	}
	var afterPolicy v1alpha1.PhorvexPolicy
	if err := c.Get(opctx, client.ObjectKey{Namespace: cfg.PolicyEpoch.Namespace, Name: cfg.PolicyEpoch.Name}, &afterPolicy); err != nil || string(afterPolicy.UID) != cfg.PolicyEpoch.UID || afterPolicy.Generation != cfg.PolicyEpoch.Generation {
		return nil, errors.New("policy epoch changed during current inventory observation")
	}
	payload := model.CurrentInventoryV1{SchemaVersion: model.CurrentInventorySchemaV1, EvidenceID: cfg.EvidenceID, PolicyEpoch: cfg.PolicyEpoch, DecisionAsset: model.DecisionAssetIdentity{Namespace: cfg.TargetNamespace, Name: cfg.TargetName, TargetUID: cfg.TargetUID}, ImmediateController: immediate, StableWorkloadOwner: stable, ProtectedScope: cfg.ProtectedScope, SourceBinding: binding, Classification: model.CurrentInventoryClassification{RuleVersion: model.CurrentInventoryRuleVersionV1, RuleDigest: cfg.RuleDigest, InventoryClass: model.CurrentInventoryClass, PossibleOutcome: "unauthorized-disclosure", ObserverIdentity: cfg.ObserverIdentity}, Observation: model.CurrentInventoryObservation{StartedAt: started, CompletedAt: completed, ValidUntil: completed.Add(cfg.TTL), StatusCode: resp.StatusCode, ManifestEOF: true}, Synthetic: true}
	encoded, _, err := currentinventory.Marshal(payload)
	if err != nil {
		return nil, err
	}
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{GenerateName: "phorvex-current-inventory-", Annotations: map[string]string{currentinventory.Annotation: encoded}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{cfg.TargetNamespace + "/" + cfg.TargetName}, Rule: amtdv1beta1.Rule{Type: model.CurrentInventoryRuleType, ThreatLevel: "high", Source: model.CurrentInventorySource}, Description: model.CurrentInventoryDescription}}
	if err := c.Create(opctx, event); err != nil {
		return nil, fmt.Errorf("create current inventory SecurityEvent: %w", err)
	}
	return event, nil
}
