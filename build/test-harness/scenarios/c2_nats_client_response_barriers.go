package scenarios

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func natsResponseWaitLog(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	route natsRouteIdentity, want int, maxWait time.Duration, allowPhoenixQuarantine bool) ([]byte, []natsResponseObserverReceipt, error) {
	return natsResponseWaitAnyLog(ctx, env, fixture, route, want, maxWait, false, allowPhoenixQuarantine)
}

func natsResponseWaitPeerLog(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	route natsRouteIdentity, want int, maxWait time.Duration) ([]byte, []natsResponseObserverReceipt, error) {
	return natsResponseWaitAnyLog(ctx, env, fixture, route, want, maxWait, true, false)
}

func natsResponseWaitAnyLog(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	route natsRouteIdentity, want int, maxWait time.Duration, peer, allowPhoenixQuarantine bool) ([]byte, []natsResponseObserverReceipt, error) {
	if maxWait <= 0 || maxWait > 5*time.Minute || want < 2 || want > 4 {
		return nil, nil, errors.New("NATS response log wait outside admitted bound")
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		var raw []byte
		var rows []natsResponseObserverReceipt
		var err error
		if peer {
			raw, rows, err = natsResponsePeerLog(waitCtx, env, fixture, route, want)
		} else {
			raw, rows, err = natsResponseObserverLog(waitCtx, env, fixture, route, want, allowPhoenixQuarantine)
		}
		if err == nil {
			return raw, rows, nil
		}
		select {
		case <-waitCtx.Done():
			return nil, nil, errors.New("NATS response original client receipt absent or invalid by phase deadline")
		case <-ticker.C:
		}
	}
}

// The coordinator publishes one immutable decision after independently
// joining Kubernetes, manager audit and event effects. The harness never
// treats request bytes or a file appearing at the same path as authority.
func natsResponseWaitDecision(ctx context.Context, out string, request natsResponseSignalRequest) (natsResponseSignalDecision, error) {
	var decision natsResponseSignalDecision
	waitCtx, cancel := context.WithTimeout(ctx, 160*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		root, err := natsResponseRoot(out)
		if err != nil {
			return decision, err
		}
		_, statErr := root.Lstat("nats-response-signal-decision.json")
		closeErr := root.Close()
		if closeErr != nil {
			return decision, closeErr
		}
		if statErr == nil {
			decision, err = readNATSResponseDecision(out, request)
			if err != nil {
				return decision, err // published but invalid is terminal, never a retry
			}
			if err := natsResponseVerifyDecisionEvidence(out, decision.DecisionEvidenceSHA256); err != nil {
				return decision, err
			}
			return decision, nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return decision, errors.New("NATS response decision path unavailable")
		}
		select {
		case <-waitCtx.Done():
			return decision, errors.New("NATS response exact manager decision/effect barrier not published")
		case <-ticker.C:
		}
	}
}

func natsResponseVerifyDecisionEvidence(out, expectedSHA string) error {
	if len(expectedSHA) != 64 {
		return errors.New("NATS response decision evidence digest incomplete")
	}
	root, err := natsResponseRoot(out)
	if err != nil {
		return err
	}
	defer root.Close()
	const name = "nats-response-decision-evidence.json"
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 32<<10 {
		return errors.New("NATS response decision evidence absent or oversized")
	}
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return errors.New("NATS response decision evidence changed during read")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("NATS response decision evidence has another hard link")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
	if err != nil || len(raw) != int(info.Size()) || natsSHA(raw) != expectedSHA {
		return errors.New("NATS response decision evidence digest differs")
	}
	return nil
}

func natsResponseRequestPath(out string) string {
	return filepath.Join(out, "nats-response-signal-request.json")
}
