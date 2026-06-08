/*
 * Copyright (C) 2023 R6 Security, Inc.
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

package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// gatekeeperRoutedAMTD builds an AMTD (MatcherMode=Scored) whose strategy MATCHES a
// GatekeeperViolation SecurityEvent (Source=GatekeeperIntegrator,
// Type=gatekeeper-violation, metrics.gatekeeper.constraint Eq <constraint>) and
// routes it to a Rotate whose PolicyRef points at the named ContextMutationPolicy.
// This is the canonical receiver strategy from gatekeeper_receiver.go documented in
// code — NO matcher change is needed (metrics.<k> Eq is already supported).
func gatekeeperRoutedAMTD(ns, name, cmpName, constraint string) *amtdv1beta1.AdaptiveMovingTargetDefense {
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "nim-inference"},
			MatcherMode: amtdv1beta1.MatcherModeScored,
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule: amtdv1beta1.Rule{
						Source: GatekeeperViolationSource,
						Type:   GatekeeperViolationType,
						Match:  []amtdv1beta1.MatchExpression{gatekeeperConstraintMatchExpression(constraint)},
					},
					Action: amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{
						PolicyRef: &amtdv1beta1.LocalPolicyRef{Kind: "ContextMutationPolicy", Name: cmpName},
					}},
				},
			},
		},
	}
}

// TestGatekeeperReceiver_RoutesToRotateCMP is the receiver end-to-end proof:
//
//	inject a GatekeeperViolation SecurityEvent (receiver convention; modeling what a
//	  FUTURE GatekeeperIntegrator emitter would produce — NO emitter is created)
//	-> AMTD(Scored) strategy matches it (Source/Type guard + metrics.constraint Eq)
//	-> Rotate branch -> executeRotate -> MutationApplier resolves the named CMP
//	-> projects its Mutations[] -> D3 durable owner-template patch
//	=> the Deployment template carries the CMP image + RUNTIME_MODE=SECURE +
//	   nvidia.com/gpu:0, the triggering pod is cold-rescheduled, and the AMTD Status
//	   records EffectiveSource="ContextMutationPolicy", MutationDurable=true.
func TestGatekeeperReceiver_RoutesToRotateCMP(t *testing.T) {
	ctx := context.Background()
	const ns = "default"
	const constraint = "disallowed-hostpath"

	cmp := cmpListing1(ns, "nim-risk-based-mutation")
	amtd := gatekeeperRoutedAMTD(ns, "amtd-gk", "nim-risk-based-mutation", constraint)
	// The CMP targets container "nim", so the durable patch lands on a template whose
	// container is named "nim" (deploymentTemplate uses "app").
	dep := deploymentWithContainer("nim-dep", ns, "nim", "old:1")
	rs := replicaSetOwnedBy("nim-dep-abc", ns, "nim-dep")
	pod := managedOwnedPod("nim-dep-abc-1", ns, "amtd-gk", "ReplicaSet", "nim-dep-abc", true, nil)
	// The injected gatekeeper-violation event targets the pod and carries the
	// constraint in Metrics (the receiver convention).
	ev := NewGatekeeperViolationEvent("gk-ev1", constraint, ns+"/nim-dep-abc-1")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(cmp, amtd, dep, rs, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()

	reconcileEvent(t, cl, "gk-ev1")

	// The Deployment template carries the CMP mutation (durable, all replicas).
	var gotDep appsv1.Deployment
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "nim-dep"}, &gotDep); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	c := containerByName(gotDep.Spec.Template.Spec.Containers, "nim")
	if c == nil {
		t.Fatalf("expected a 'nim' container in the patched template, got %+v", gotDep.Spec.Template.Spec.Containers)
	}
	if c.Image != "nvcr.io/nim/secure-nim:latest" {
		t.Errorf("template image = %q, want nvcr.io/nim/secure-nim:latest (CMP mutation applied)", c.Image)
	}
	if q, ok := c.Resources.Limits[gpuResourceName]; !ok || q.String() != "0" {
		t.Errorf("template nvidia.com/gpu limit = %v (ok=%v), want 0", q, ok)
	}
	gotEnv := false
	for _, e := range c.Env {
		if e.Name == "RUNTIME_MODE" && e.Value == "SECURE" {
			gotEnv = true
		}
	}
	if !gotEnv {
		t.Error("template must carry RUNTIME_MODE=SECURE from the CMP EnvPatch")
	}

	// Pod cold-rescheduled after the durable patch.
	if podExists(cl, ns, "nim-dep-abc-1") {
		t.Error("triggering pod must be cold-rescheduled (deleted) after the durable CMP patch")
	}

	// AMTD Status audit: the CMP was the effective source and the mutation was durable.
	a := getAMTD(t, cl, ns, "amtd-gk")
	if a.Status.EffectiveSource != "ContextMutationPolicy" {
		t.Errorf("Status.EffectiveSource = %q, want ContextMutationPolicy", a.Status.EffectiveSource)
	}
	if !a.Status.MutationDurable {
		t.Error("Status.MutationDurable must be true on the durable CMP route")
	}
	if a.Status.RotationPathFired != "Rotate" {
		t.Errorf("Status.RotationPathFired = %q, want Rotate", a.Status.RotationPathFired)
	}
}

// containerByName returns the container with the given name, or nil.
func containerByName(cs []corev1.Container, name string) *corev1.Container {
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	return nil
}

// deploymentWithContainer builds a Deployment whose template carries a single
// container with the given name/image (so a CMP targeting that container name can
// patch the template durably).
func deploymentWithContainer(name, namespace, containerName, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: containerName, Image: image}}},
			},
		},
	}
}
