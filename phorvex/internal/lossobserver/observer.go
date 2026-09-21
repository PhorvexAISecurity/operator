package lossobserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type ObserverConfig struct {
	URL              string
	PolicyEpoch      model.PolicyEpoch
	TargetNamespace  string
	TargetName       string
	TargetUID        string
	ProtectedScope   model.ProtectedScope
	EvidenceID       string
	RuleVersion      string
	RuleDigest       string
	ObserverIdentity string
	ExpectedBytes    int64
	ExpectedSHA256   string
	Timeout          time.Duration
}

// ObserveOnce performs one bounded external read and creates a SecurityEvent
// only after exact completion. Failed observations create no loss evidence.
func ObserveOnce(ctx context.Context, c client.Client, httpClient *http.Client, cfg ObserverConfig, now func() time.Time) (*amtdv1beta1.SecurityEvent, error) {
	if c == nil || httpClient == nil || now == nil || cfg.URL == "" || cfg.Timeout <= 0 {
		return nil, errors.New("observer configuration incomplete")
	}
	parsedURL, err := url.Parse(cfg.URL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return nil, errors.New("observer URL must be an exact HTTPS endpoint")
	}
	if strings.TrimSpace(cfg.ObserverIdentity) == "" || strings.ContainsAny(cfg.ObserverIdentity, "\x00\r\n") ||
		!disclosure.ValidDigest(cfg.RuleDigest) || cfg.ExpectedBytes <= 0 || cfg.ExpectedBytes > disclosure.MaxResponseBytes ||
		!disclosure.ValidDigest(cfg.ExpectedSHA256) {
		return nil, errors.New("observer expected response is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	immediate, stable, err := ingest.ResolveStableWorkloadOwner(operationCtx, c, cfg.TargetNamespace, cfg.TargetName, cfg.TargetUID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(operationCtx, http.MethodGet, cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	started := now().UTC()
	boundedClient := *httpClient
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := boundedClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("synthetic canary retrieval failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("synthetic canary status %d is not completed", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.ExpectedBytes+1))
	completed := now().UTC()
	if err != nil {
		return nil, fmt.Errorf("synthetic canary response incomplete: %w", err)
	}
	if int64(len(body)) != cfg.ExpectedBytes {
		return nil, errors.New("synthetic canary response length mismatch")
	}
	sum := sha256.Sum256(body)
	observedDigest := hex.EncodeToString(sum[:])
	if observedDigest != cfg.ExpectedSHA256 {
		return nil, errors.New("synthetic canary response digest mismatch")
	}
	// Prevent a copy completed across target/owner replacement from being bound
	// to either generation. This second authoritative read creates no new GET to
	// the canary endpoint.
	afterImmediate, afterStable, err := ingest.ResolveStableWorkloadOwner(operationCtx, c, cfg.TargetNamespace, cfg.TargetName, cfg.TargetUID)
	if err != nil || afterImmediate != immediate || afterStable != stable {
		return nil, errors.New("target ownership changed during observation")
	}
	payload := model.CompletedDisclosureV1{
		SchemaVersion: model.CompletedDisclosureSchemaV1, EvidenceID: cfg.EvidenceID,
		PolicyEpoch:         cfg.PolicyEpoch,
		DecisionAsset:       model.DecisionAssetIdentity{Namespace: cfg.TargetNamespace, Name: cfg.TargetName, TargetUID: cfg.TargetUID},
		ImmediateController: immediate, StableWorkloadOwner: stable, ProtectedScope: cfg.ProtectedScope,
		Classification: model.DisclosureClassification{RuleVersion: cfg.RuleVersion, RuleDigest: cfg.RuleDigest,
			ObserverClass: model.CompletedDisclosureClass, ObserverIdentity: cfg.ObserverIdentity},
		Observation: model.DisclosureObservation{StartedAt: started, CompletedAt: completed, StatusCode: resp.StatusCode,
			ExpectedBytes: cfg.ExpectedBytes, ObservedBytes: int64(len(body)), ReachedEOF: true,
			ExpectedSHA256: cfg.ExpectedSHA256, ObservedSHA256: observedDigest},
		Synthetic: true,
	}
	raw, _, err := disclosure.Marshal(payload)
	if err != nil {
		return nil, err
	}
	event := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "phorvex-loss-", Annotations: map[string]string{disclosure.Annotation: raw}},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{cfg.TargetNamespace + "/" + cfg.TargetName},
			Rule:        amtdv1beta1.Rule{Type: model.CompletedDisclosureRuleType, ThreatLevel: "high", Source: model.CompletedDisclosureSource},
			Description: model.CompletedDisclosureDescription,
		},
	}
	if err := c.Create(operationCtx, event); err != nil {
		return nil, fmt.Errorf("create completed-disclosure SecurityEvent: %w", err)
	}
	return event, nil
}
