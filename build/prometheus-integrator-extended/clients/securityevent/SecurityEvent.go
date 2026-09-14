/*
 * Copyright (C) 2024 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

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
