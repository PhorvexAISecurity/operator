package mocks

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// createOwnedPod requires a fresh name and binds teardown authority solely to
// the UID returned by this Create. A read or Create with an ambiguous outcome is
// surfaced and never converted into adoption or a retry.
func createOwnedPod(ctx context.Context, env *core.Env, pod *corev1.Pod) (*corev1.Pod, error) {
	ns := env.Config.Namespace
	current, err := env.NamespaceCurrent(ctx)
	if err != nil || !current {
		if err == nil {
			err = fmt.Errorf("original namespace is absent")
		}
		return nil, fmt.Errorf("refusing mock pod %s creation without exact namespace identity: %w", pod.Name, err)
	}
	if _, err := env.Kube.CoreV1().Pods(ns).Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		return nil, fmt.Errorf("refusing to adopt existing mock pod %s", pod.Name)
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("check fresh mock pod %s: %w", pod.Name, err)
	}
	current, err = env.NamespaceCurrent(ctx)
	if err != nil || !current {
		if err == nil {
			err = fmt.Errorf("original namespace is absent")
		}
		return nil, fmt.Errorf("refusing mock pod %s creation after namespace identity changed: %w", pod.Name, err)
	}
	created, err := env.Kube.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create mock pod %s (not retried): %w", pod.Name, err)
	}
	if created == nil || created.UID == "" {
		return nil, fmt.Errorf("create mock pod %s returned no authoritative UID; outcome is ambiguous", pod.Name)
	}
	if err := env.RecordCreatedUID("pods", created.Name, created.UID); err != nil {
		return nil, err
	}
	return created, nil
}

func requireCreatedPodCurrent(ctx context.Context, env *core.Env, name string, expected *corev1.Pod) error {
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("verify created mock pod %s: %w", name, err)
	}
	if expected == nil {
		return fmt.Errorf("created mock pod %s has no create-response identity", name)
	}
	if expected.UID == "" || pod.UID != expected.UID {
		return fmt.Errorf("created mock pod %s was replaced: expected UID %s, current UID %s", name, expected.UID, pod.UID)
	}
	return nil
}

func createOwnedService(ctx context.Context, env *core.Env, svc *corev1.Service) (*corev1.Service, error) {
	ns := env.Config.Namespace
	current, err := env.NamespaceCurrent(ctx)
	if err != nil || !current {
		if err == nil {
			err = fmt.Errorf("original namespace is absent")
		}
		return nil, fmt.Errorf("refusing mock service %s creation without exact namespace identity: %w", svc.Name, err)
	}
	if _, err := env.Kube.CoreV1().Services(ns).Get(ctx, svc.Name, metav1.GetOptions{}); err == nil {
		return nil, fmt.Errorf("refusing to adopt existing mock service %s", svc.Name)
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("check fresh mock service %s: %w", svc.Name, err)
	}
	current, err = env.NamespaceCurrent(ctx)
	if err != nil || !current {
		if err == nil {
			err = fmt.Errorf("original namespace is absent")
		}
		return nil, fmt.Errorf("refusing mock service %s creation after namespace identity changed: %w", svc.Name, err)
	}
	created, err := env.Kube.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create mock service %s (not retried): %w", svc.Name, err)
	}
	if created == nil || created.UID == "" {
		return nil, fmt.Errorf("create mock service %s returned no authoritative UID; outcome is ambiguous", svc.Name)
	}
	if err := env.RecordCreatedUID("services", created.Name, created.UID); err != nil {
		return nil, err
	}
	return created, nil
}
