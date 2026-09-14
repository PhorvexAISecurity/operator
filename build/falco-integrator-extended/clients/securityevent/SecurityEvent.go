package securityevent

import (
	"context"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	"k8s.io/client-go/rest"
)

// SecurityEventInterface is the minimal cluster-scoped SecurityEvent client the
// integrator needs: Create for delivery and Get for verifying an AlreadyExists
// readback (V3-M164). SecurityEvent's shipped CRD is Cluster scoped, so neither
// call takes a namespace; the logical target namespace lives in spec.targets.
type SecurityEventInterface interface {
	Create(ctx context.Context, obj *amtdapi.SecurityEvent) (*amtdapi.SecurityEvent, error)
	Get(ctx context.Context, name string) (*amtdapi.SecurityEvent, error)
}

type securityEventClient struct {
	client rest.Interface
}

func NewSecurityEventClient(client rest.Interface) SecurityEventInterface {
	return &securityEventClient{
		client: client,
	}
}

func (c *securityEventClient) Create(ctx context.Context, obj *amtdapi.SecurityEvent) (*amtdapi.SecurityEvent, error) {
	result := &amtdapi.SecurityEvent{}
	err := c.client.
		Post().
		Resource("securityevents").
		Body(obj).
		Do(ctx).
		Into(result)
	return result, err
}

func (c *securityEventClient) Get(ctx context.Context, name string) (*amtdapi.SecurityEvent, error) {
	result := &amtdapi.SecurityEvent{}
	err := c.client.
		Get().
		Resource("securityevents").
		Name(name).
		Do(ctx).
		Into(result)
	return result, err
}
