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

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// FingerprintAnnotation carries the full delivery fingerprint of the payload
	// the event was created from. It is never rewritten; a stored event whose
	// fingerprint differs from a retried payload is a collision, not a duplicate.
	FingerprintAnnotation = "amtd.r6security.com/delivery-fingerprint"
	// IdentityAnnotation names the identity scheme ("<prefix>/<IdentityVersion>").
	IdentityAnnotation = "amtd.r6security.com/delivery-identity"

	// DefaultTimeout bounds each downstream API call (Create, and Get on readback).
	DefaultTimeout = 10 * time.Second
	// maxMessage bounds any upstream error text echoed back to the webhook caller.
	maxMessage = 240
)

// Outcome is the honest per-event delivery result.
type Outcome string

const (
	// Accepted: the API server persisted the event in this request (201).
	Accepted Outcome = "accepted"
	// Duplicate: Create hit AlreadyExists and the stored object was read back with
	// the same name, fingerprint and spec — a proven identical retry.
	Duplicate Outcome = "duplicate"
	// Conflict: an object with this name exists but its fingerprint or spec differ
	// (or it was replaced). Nothing was written; a retry with the same payload will
	// not succeed until the stored object is removed.
	Conflict Outcome = "conflict"
	// Failed: Create was rejected, timed out, could not be verified after
	// AlreadyExists, or was not attempted because the request was cancelled. The
	// event is NOT acknowledged; a later retry resolves via Create/readback.
	Failed Outcome = "failed"
)

// Result is one event's outcome as returned on the wire.
type Result struct {
	Outcome Outcome `json:"outcome"`
	// Event is the deterministic object name.
	Event string `json:"event"`
	// DeliveryFingerprint is the full payload digest ("sha256:<64 hex>").
	DeliveryFingerprint string `json:"deliveryFingerprint"`
	// Reason is a stable machine token (e.g. "api:Forbidden", "timeout",
	// "readback_failed", "readback_mismatch", "canceled", "transport").
	Reason string `json:"reason,omitempty"`
	// Message is a bounded, credential-free description for operators.
	Message string `json:"message,omitempty"`
}

// HTTPStatus maps an outcome to the webhook's documented status: 2xx only for
// accepted/proven-identical, 409 for an unverified collision, 503 otherwise.
func HTTPStatus(o Outcome) int {
	switch o {
	case Accepted, Duplicate:
		return http.StatusOK
	case Conflict:
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}

// Client is the subset of the SecurityEvent REST client delivery needs.
type Client interface {
	Create(ctx context.Context, obj *amtdapi.SecurityEvent) (*amtdapi.SecurityEvent, error)
	Get(ctx context.Context, name string) (*amtdapi.SecurityEvent, error)
}

// Deliverer performs bounded Create-then-verify delivery through a real client.
type Deliverer struct {
	Client  Client
	Timeout time.Duration // per API call; <=0 selects DefaultTimeout
}

func (d Deliverer) timeout() time.Duration {
	if d.Timeout <= 0 {
		return DefaultTimeout
	}
	return d.Timeout
}

// Stamp records the identity on the object: deterministic name, no namespace
// (the CRD is Cluster scoped; the logical target stays in spec.targets) and the
// fingerprint/identity annotations used for exact readback comparison.
func Stamp(event *amtdapi.SecurityEvent, prefix string, id Identity) {
	event.Name = id.Name
	event.Namespace = ""
	if event.Annotations == nil {
		event.Annotations = map[string]string{}
	}
	event.Annotations[FingerprintAnnotation] = id.Fingerprint
	event.Annotations[IdentityAnnotation] = prefix + "/" + IdentityVersion
}

// Deliver creates the event once with a bounded deadline. On AlreadyExists it
// reads the stored object back and accepts only an exact match. There is no
// retry loop here: the caller's upstream (Falco, Alertmanager) owns retries and
// receives a non-2xx status for anything that is not accepted or proven identical.
func (d Deliverer) Deliver(ctx context.Context, event *amtdapi.SecurityEvent) Result {
	res := Result{Event: event.Name, DeliveryFingerprint: event.Annotations[FingerprintAnnotation]}
	if err := ctx.Err(); err != nil {
		return fail(res, "canceled", "not attempted: request context is done")
	}
	cctx, cancel := context.WithTimeout(ctx, d.timeout())
	_, err := d.Client.Create(cctx, event)
	cancel()
	switch {
	case err == nil:
		res.Outcome = Accepted
		return res
	case apierrors.IsAlreadyExists(err):
		return d.verifyExisting(ctx, event, res)
	default:
		reason, msg := classify(ctx, err)
		return fail(res, reason, "create rejected: "+msg)
	}
}

func (d Deliverer) verifyExisting(ctx context.Context, event *amtdapi.SecurityEvent, res Result) Result {
	gctx, cancel := context.WithTimeout(ctx, d.timeout())
	existing, err := d.Client.Get(gctx, event.Name)
	cancel()
	if err != nil {
		reason, msg := classify(ctx, err)
		return fail(res, "readback_failed", "event name already exists but readback failed ("+reason+"): "+msg)
	}
	if why := mismatch(existing, event); why != "" {
		res.Outcome = Conflict
		res.Reason = "readback_mismatch"
		res.Message = "an event with this name exists but is not this payload: " + why
		return res
	}
	res.Outcome = Duplicate
	return res
}

// mismatch returns "" when the stored object is exactly this delivery: same name,
// same fingerprint annotation, and byte-identical serialized spec (targets, rule,
// description, score, metrics, evidence). Anything else names the first difference.
func mismatch(existing, event *amtdapi.SecurityEvent) string {
	if existing.Name != event.Name {
		return "name differs"
	}
	if existing.Annotations[FingerprintAnnotation] != event.Annotations[FingerprintAnnotation] {
		return "delivery fingerprint differs"
	}
	if existing.Annotations[IdentityAnnotation] != event.Annotations[IdentityAnnotation] {
		return "delivery identity scheme differs"
	}
	a, errA := json.Marshal(existing.Spec)
	b, errB := json.Marshal(event.Spec)
	if errA != nil || errB != nil || string(a) != string(b) {
		return "spec differs"
	}
	return ""
}

func fail(res Result, reason, msg string) Result {
	res.Outcome = Failed
	res.Reason = reason
	res.Message = bound(msg)
	return res
}

// classify turns a client error into a stable reason and a bounded message. API
// Status errors keep their reason and message; deadlines and cancellations are
// reported as such (the Create may or may not have happened; a retry resolves it
// by readback); anything else is a transport failure.
func classify(parent context.Context, err error) (string, string) {
	if parent.Err() != nil {
		return "canceled", "request context done before the API call completed: " + parent.Err().Error()
	}
	var status apierrors.APIStatus
	if errors.As(err, &status) && status.Status().Reason != "" {
		st := status.Status()
		return "api:" + string(st.Reason), st.Message
	}
	if errors.Is(err, context.DeadlineExceeded) || apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) {
		return "timeout", "API call exceeded its deadline"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout", "API call exceeded its deadline"
	}
	if errors.As(err, &status) {
		st := status.Status()
		return "api:unknown", st.Message
	}
	return "transport", err.Error()
}

func bound(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxMessage {
		return strings.ToValidUTF8(s[:maxMessage], "") + "…"
	}
	return s
}
