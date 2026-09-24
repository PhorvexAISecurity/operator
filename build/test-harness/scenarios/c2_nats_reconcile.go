package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

type natsReconciliationReceipt struct {
	Schema                 string `json:"schema"`
	RunID                  string `json:"runId"`
	AttemptID              string `json:"attemptId"`
	Nonce                  string `json:"nonce"`
	Namespace              string `json:"namespace"`
	NamespaceUID           string `json:"namespaceUID"`
	ClusterUID             string `json:"clusterUID"`
	AnchorSHA256           string `json:"anchorSHA256"`
	RouteSHA256            string `json:"routeSHA256"`
	FixtureResourcesAbsent bool   `json:"fixtureResourcesAbsent"`
	StreamAbsent           bool   `json:"streamAbsent"`
	OriginalProcessGone    bool   `json:"originalProcessGone"`
	SafeToRetry            bool   `json:"safeToRetry"`
	ObservedAt             string `json:"observedAt"`
}

// ReconcileNATSExposure is a single read-only, no-replay check of exact owned
// names after the original harness process has stopped. It never deletes an
// ambiguous resource or assumes a missing journal means no mutation.
func ReconcileNATSExposure(ctx context.Context, env *core.Env, out, attemptID string) error {
	return reconcileNATSWithSources(ctx, env, out, attemptID, captureNATSRoute, natsStreamAbsent)
}

func reconcileNATSWithSources(ctx context.Context, env *core.Env, out, attemptID string, routeSource func(context.Context, *core.Env) (natsRouteIdentity, error), streamCheck func(context.Context, *core.Env, natsRouteIdentity, string) error) error {
	f := env.Config.NATSExposureFixture
	if f == nil || env.NamespaceUID() == "" || out == "" || len(attemptID) != 32 {
		return errors.New("NATS reconciliation identity unavailable")
	}
	if _, err := hex.DecodeString(attemptID); err != nil {
		return errors.New("NATS reconciliation attempt ID invalid")
	}
	path := filepath.Join(out, "nats-baseline-anchor.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8192 {
		return errors.New("durable NATS pre-effect anchor unavailable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var a natsRecoveryAnchor
	if json.Unmarshal(raw, &a) != nil || a.Schema != "nats-baseline-anchor-v1" || a.RunID != f.RunID || a.Nonce != f.Nonce || a.ClusterUID != a.Route.ClusterUID || string(a.ClusterUID) != f.ClusterUID || a.Namespace != env.Config.Namespace || a.NamespaceUID != env.NamespaceUID() || a.ObserverName != "nats-observer-"+f.Nonce || a.Stream != "CAT_"+f.Nonce || a.PID < 1 || a.ProcessStartTicks == "" || a.FenceIdentity == "" || a.FenceIdentity != env.NATSFenceIdentity {
		return errors.New("NATS anchor identity differs")
	}
	start, processErr := natsProcessStartTicks(a.PID)
	if processErr == nil && start == a.ProcessStartTicks {
		return errors.New("original NATS harness process remains alive")
	}
	if processErr != nil && !os.IsNotExist(processErr) {
		return errors.New("original NATS process exit unverified")
	}
	current, err := routeSource(ctx, env)
	if err != nil || !routeEqual(a.Route, current) {
		return errors.New("NATS serving route changed since pre-effect anchor")
	}
	if err := env.VerifyNATSFixtureClean(ctx); err != nil {
		return err
	}
	if err := streamCheck(ctx, env, current, a.Stream); err != nil {
		return err
	}
	confirmed, err := routeSource(ctx, env)
	if err != nil || !routeEqual(current, confirmed) {
		return errors.New("NATS serving route changed across absence checks")
	}
	if err := env.VerifyNATSFixtureClean(ctx); err != nil {
		return err
	}
	routeRaw, _ := json.Marshal(current)
	rh := sha256.Sum256(routeRaw)
	ah := sha256.Sum256(raw)
	receipt := natsReconciliationReceipt{Schema: "nats-baseline-reconciliation-v1", RunID: f.RunID, AttemptID: attemptID, Nonce: f.Nonce, Namespace: env.Config.Namespace, NamespaceUID: string(env.NamespaceUID()), ClusterUID: f.ClusterUID, AnchorSHA256: hex.EncodeToString(ah[:]), RouteSHA256: hex.EncodeToString(rh[:]), FixtureResourcesAbsent: true, StreamAbsent: true, OriginalProcessGone: true, SafeToRetry: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return writeNATSBaselineArtifact(filepath.Join(out, "nats-baseline-reconciliation.json"), encoded)
}

func natsStreamAbsent(ctx context.Context, env *core.Env, route natsRouteIdentity, name string) error {
	if name == "" || len(route.Brokers) < 1 || len(route.Brokers) > 3 {
		return errors.New("NATS stream absence source unavailable")
	}
	for _, broker := range route.Brokers {
		port, closeForward, err := forwardNATSPod(ctx, env.Rest, natsExposureNamespace, broker.Name, 4222)
		if err != nil {
			return err
		}
		address := fmt.Sprintf("127.0.0.1:%d", port)
		conn, connectErr := nats.Connect("nats://"+address, nats.Timeout(3*time.Second), nats.NoReconnect(), nats.MaxReconnects(0), nats.RetryOnFailedConnect(false), nats.DontRandomize(), nats.SkipHostLookup(), nats.SetCustomDialer(natsExposureFixedDialer{address: address}))
		if connectErr == nil {
			if conn.ConnectedServerId() != broker.ServerID {
				connectErr = errors.New("NATS reconciliation server ID differs")
			} else {
				js, jsErr := jetstream.New(conn)
				if jsErr != nil {
					connectErr = jsErr
				} else {
					queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
					_, queryErr := js.Stream(queryCtx, name)
					cancel()
					if !errors.Is(queryErr, jetstream.ErrStreamNotFound) {
						if queryErr == nil {
							connectErr = errors.New("owned NATS stream still exists or was replaced")
						} else {
							connectErr = fmt.Errorf("NATS stream absence unverified: %w", queryErr)
						}
					}
				}
			}
			conn.Close()
		}
		closeErr := closeForward()
		if connectErr != nil || closeErr != nil {
			return errors.Join(connectErr, closeErr)
		}
	}
	return nil
}
