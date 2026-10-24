package identityfixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

// FederationInventory is the subset of the authoritative EKS API used to prove
// that a fixture ServiceAccount has no EKS Pod Identity association. It is an
// interface so permanent tests can prove the absence logic without AWS.
type FederationInventory interface {
	ListPodIdentityAssociations(ctx context.Context, params *eks.ListPodIdentityAssociationsInput, optFns ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
}

var (
	// federationInventoryTimeout bounds the whole paginated inventory read. The
	// operator image is distroless, so this runs in-process through the AWS SDK;
	// there is no CLI or shell to invoke.
	federationInventoryTimeout = 4 * time.Second
	// maxFederationPages refuses an unbounded or repeated NextToken chain.
	maxFederationPages = 32
	// newFederationInventory is the credential-loading seam. Production uses the
	// AWS SDK default chain (IRSA, web identity, instance profile), scoped to the
	// profile-pinned region.
	newFederationInventory = func(ctx context.Context, region string) (FederationInventory, error) {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, err
		}
		return eks.NewFromConfig(cfg), nil
	}
)

// FederationAbsent uses the authoritative EKS API, including its pagination.
// Missing credentials, denial, transport failure, a malformed/partial response
// or a repeated page token means unavailable, never an assertion of absence.
// A single returned association proves federation is present. IRSA and injected
// Pod Identity credentials are checked separately against admitted Pod/SA objects.
func FederationAbsent(ctx context.Context, p Profile, account string) error {
	if p.Validate() != nil || account == "" {
		return errors.New("federation scope unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, federationInventoryTimeout)
	defer cancel()
	inventory, err := newFederationInventory(bounded, p.Region)
	if err != nil {
		return fmt.Errorf("authoritative EKS federation inventory unavailable: %w", err)
	}
	var nextToken *string
	for page := 0; page < maxFederationPages; page++ {
		out, err := inventory.ListPodIdentityAssociations(bounded, &eks.ListPodIdentityAssociationsInput{
			ClusterName:    aws.String(p.Cluster),
			Namespace:      aws.String(p.Namespace),
			ServiceAccount: aws.String(account),
			NextToken:      nextToken,
		})
		if err != nil {
			return fmt.Errorf("authoritative EKS federation inventory unavailable: %w", err)
		}
		if out == nil {
			return errors.New("authoritative EKS federation inventory unavailable: empty response")
		}
		if len(out.Associations) != 0 {
			return errors.New("EKS federation absent/inventory completeness unproven")
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return nil
		}
		nextToken = out.NextToken
	}
	return errors.New("EKS federation inventory completeness unproven: page limit reached")
}

// ValidateFederation applies the same fail-closed rules to raw EKS
// ListPodIdentityAssociations JSON (for callers that already hold inventory
// bytes). The compiled SDK path above is the runtime authority.
func ValidateFederation(raw []byte) error {
	var result struct {
		Associations *[]json.RawMessage `json:"associations"`
		NextToken    string             `json:"nextToken"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Associations == nil || len(*result.Associations) != 0 || result.NextToken != "" {
		return errors.New("EKS federation absent/inventory completeness unproven")
	}
	return nil
}
