package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The response case owns only fixed names in the precreated fixture namespace.
// Every effect intent is fsynced before one CREATE; ambiguous CREATE is a stop,
// never a same-name adoption or replay.
func natsResponsePhase(env *core.Env, phase, resource, name string, uid types.UID) error {
	if env == nil || env.Config.NATSExposureFixture == nil || env.Config.OutDir == "" ||
		env.NamespaceUID() == "" || !natsResponseNonce.MatchString(env.Config.NATSExposureFixture.Nonce) ||
		phase == "" || resource == "" || name == "" {
		return errors.New("NATS response phase authority incomplete")
	}
	raw, err := json.Marshal(struct {
		Schema       string    `json:"schema"`
		RunID        string    `json:"runId"`
		Nonce        string    `json:"nonce"`
		NamespaceUID types.UID `json:"namespaceUID"`
		Phase        string    `json:"phase"`
		Resource     string    `json:"resource"`
		Name         string    `json:"name"`
		UID          types.UID `json:"uid,omitempty"`
		At           string    `json:"at"`
	}{natsResponseSchema, env.Config.NATSExposureFixture.RunID, env.Config.NATSExposureFixture.Nonce,
		env.NamespaceUID(), phase, resource, name, uid, time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil || len(raw) > 1024 {
		return errors.New("NATS response phase oversized")
	}
	path := filepath.Join(env.Config.OutDir, "nats-response-phases.jsonl")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_APPEND|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("NATS response phase journal is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("NATS response phase journal is linked")
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(env.Config.OutDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// createNATSResponseFixture is called after the runner pins the existing
// namespace and broker route. No Deployment starts until the static Service,
// PDB, and policy have been admitted. Policy target-role is assigned only
// after the two actual ReplicaSet-owned Pods are identified.
func createNATSResponseFixture(ctx context.Context, env *core.Env, route natsRouteIdentity) (natsResponseFixture, map[string]any, error) {
	var fixture natsResponseFixture
	if env == nil || env.Config.NATSExposureFixture == nil || env.NamespaceUID() == "" {
		return fixture, nil, errors.New("NATS response namespace not pinned")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return fixture, nil, err
	}
	if err := requireNATSRoute(ctx, env, route); err != nil {
		return fixture, nil, err
	}
	if err := noNATSResponsePolicyCollision(ctx, env); err != nil {
		return fixture, nil, err
	}
	return createNATSResponseOwnedObjects(ctx, env, route)
}

// The inner producer is separated solely for isolated actual-API admission
// tests. Production always enters through createNATSResponseFixture's live
// namespace/route/collision gates.
func createNATSResponseOwnedObjects(ctx context.Context, env *core.Env, route natsRouteIdentity) (natsResponseFixture, map[string]any, error) {
	var fixture natsResponseFixture
	fixture.Name, fixture.NamespaceUID = natsResponseName(env.Config.NATSExposureFixture.Nonce), env.NamespaceUID()
	rawConfig, err := natsResponseObserverConfig(env.Config.NATSExposureFixture.Nonce, route)
	if err != nil {
		return fixture, nil, err
	}
	fixture.ConfigSHA256 = natsSHA(rawConfig)
	name, ns := fixture.Name, env.Config.Namespace
	record := func(resource string, uid types.UID) error {
		if uid == "" {
			return fmt.Errorf("NATS response %s create response lacks UID", resource)
		}
		if err := env.RecordCreatedUID(resource, name, uid); err != nil {
			return err
		}
		return natsResponsePhase(env, "CREATED", resource, name, uid)
	}
	intent := func(resource string) error { return natsResponsePhase(env, "CREATE_INTENT", resource, name, "") }
	if err := intent("configmaps"); err != nil {
		return fixture, nil, err
	}
	cm, err := env.Kube.CoreV1().ConfigMaps(ns).Create(ctx, natsResponseConfigMap(env, name, rawConfig), metav1.CreateOptions{})
	if err != nil {
		return fixture, nil, fmt.Errorf("NATS response ConfigMap CREATE uncertain; no retry: %w", err)
	}
	fixture.ConfigMapUID = cm.UID
	if err := record("configmaps", cm.UID); err != nil {
		return fixture, nil, err
	}
	if err := intent("services"); err != nil {
		return fixture, nil, err
	}
	svc, err := env.Kube.CoreV1().Services(ns).Create(ctx, natsResponseService(env, name), metav1.CreateOptions{})
	if err != nil {
		return fixture, nil, fmt.Errorf("NATS response Service CREATE uncertain; no retry: %w", err)
	}
	fixture.ServiceUID = svc.UID
	if err := record("services", svc.UID); err != nil {
		return fixture, nil, err
	}
	if err := intent("poddisruptionbudgets"); err != nil {
		return fixture, nil, err
	}
	pdb, err := env.Kube.PolicyV1().PodDisruptionBudgets(ns).Create(ctx, natsResponsePDB(env, name), metav1.CreateOptions{})
	if err != nil {
		return fixture, nil, fmt.Errorf("NATS response PDB CREATE uncertain; no retry: %w", err)
	}
	fixture.PDBUID = pdb.UID
	if err := record("poddisruptionbudgets", pdb.UID); err != nil {
		return fixture, nil, err
	}
	requested := natsResponsePolicy(env, name)
	if err := intent("phorvexpolicies"); err != nil {
		return fixture, nil, err
	}
	created := requested.DeepCopy()
	if err := env.Ctrl.Create(ctx, created); err != nil {
		return fixture, nil, fmt.Errorf("NATS response policy CREATE uncertain; no retry: %w", err)
	}
	fixture.PolicyUID, fixture.PolicyGen = created.GetUID(), created.GetGeneration()
	if err := record("phorvexpolicies", fixture.PolicyUID); err != nil {
		return fixture, nil, err
	}
	admittedSpec, err := natsResponseAdmittedPolicySpec(requested, created)
	if err != nil {
		return fixture, nil, err
	}
	specRaw, err := json.Marshal(admittedSpec)
	if err != nil || len(specRaw) > 16<<10 {
		return fixture, nil, errors.New("NATS response admitted policy spec unavailable")
	}
	fixture.PolicySpecSHA256 = natsSHA(specRaw)
	if err := intent("deployments"); err != nil {
		return fixture, nil, err
	}
	dep, err := env.Kube.AppsV1().Deployments(ns).Create(ctx, natsResponseDeployment(env, name), metav1.CreateOptions{})
	if err != nil {
		return fixture, nil, fmt.Errorf("NATS response Deployment CREATE uncertain; no retry: %w", err)
	}
	fixture.DeploymentUID = dep.UID
	if err := record("deployments", dep.UID); err != nil {
		return fixture, nil, err
	}
	return fixture, admittedSpec, nil
}
