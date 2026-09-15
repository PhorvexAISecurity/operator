// The explicit native demo reports effects, refusals, unavailable capabilities,
// and fixture/observation/cleanup failures separately. It never claims that a
// busybox fixture proves serving or hardware effects.

package main

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuator"
)

func runNativeActuatorDemo(ns, adminNS string) error {
	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	return runNativeDemo(context.Background(), c, ns, adminNS, nil)
}

// Both production demo paths and caller-level tests use this wiring.
func newDemoActuator(c client.Client) *actuator.NativeActuator {
	n := actuator.NewNativeActuator(c)
	n.SetBoundaryReader(c) // client.New above is an uncached direct reader.
	return n
}

func demoActuate(ctx context.Context, n *actuator.NativeActuator, req actuator.Request) (actuator.Result, error) {
	if req.TargetUID == "" {
		var p corev1.Pod
		if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, &p); err != nil {
			return actuator.Result{}, err
		}
		req.TargetUID = string(p.UID)
	}
	return n.Actuate(ctx, req)
}

// --- demo helpers ------------------------------------------------------------------------

func waitPodRunning(ctx context.Context, c client.Client, ns, name string) (*corev1.Pod, error) {
	var last error
	for i := 0; i < 60; i++ {
		var p corev1.Pod
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p); err == nil {
			if p.Status.Phase == corev1.PodRunning {
				return &p, nil
			}
		} else if !apierrors.IsNotFound(err) {
			return nil, err
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if last != nil {
		return nil, fmt.Errorf("Pod %s/%s did not become Running: %w", ns, name, last)
	}
	return nil, fmt.Errorf("Pod %s/%s did not become Running in bounded wait", ns, name)
}
