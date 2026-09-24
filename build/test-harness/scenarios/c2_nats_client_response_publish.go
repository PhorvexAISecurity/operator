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

	"github.com/nats-io/nats.go"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Record every complete library receipt before it lets the next protocol
// effect proceed. A phase string alone is insufficient after an interruption.
func natsResponseProtocolRecord(env *core.Env, phase string, receipt natsexposure.Receipt) error {
	if env == nil || env.Config.NATSExposureFixture == nil || env.Config.OutDir == "" ||
		receipt.Nonce != env.Config.NATSExposureFixture.Nonce || receipt.Stream == "" ||
		(phase != "M0" && phase != "M1") {
		return errors.New("NATS response protocol recorder authority incomplete")
	}
	raw, err := json.Marshal(struct {
		Schema       string               `json:"schema"`
		RunID        string               `json:"runId"`
		NamespaceUID string               `json:"namespaceUID"`
		Phase        string               `json:"phase"`
		Receipt      natsexposure.Receipt `json:"receipt"`
		At           string               `json:"at"`
	}{natsResponseSchema, env.Config.NATSExposureFixture.RunID, string(env.NamespaceUID()), phase,
		receipt, time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil || len(raw) > 4096 || env.NamespaceUID() == "" {
		return errors.New("NATS response protocol journal row invalid")
	}
	path := filepath.Join(env.Config.OutDir, "nats-response-protocol.jsonl")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_APPEND|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > (128<<10)-int64(len(raw))-1 {
		return errors.New("NATS response protocol journal not regular")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("NATS response protocol journal has another link")
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

// The local writer and reference use the exact server-owned broker Pod. The
// independently observed client is the in-cluster Pod, not this reference.
func natsResponsePublishPhase(ctx context.Context, env *core.Env, route natsRouteIdentity, phase string,
	barrier natsexposure.BeforePublish) (receipt natsexposure.Receipt, runErr error) {
	if phase != "M0" && phase != "M1" || len(route.Brokers) == 0 || barrier == nil {
		return receipt, errors.New("NATS response publication phase incomplete")
	}
	if err := requireNATSRoute(ctx, env, route); err != nil {
		return receipt, err
	}
	broker := route.Brokers[0]
	current, err := env.Kube.CoreV1().Pods(natsExposureNamespace).Get(ctx, broker.Name, metav1.GetOptions{})
	if err != nil || current.UID != broker.UID {
		return receipt, errors.New("NATS response broker Pod replaced before forward")
	}
	port, closeForward, err := forwardNATSPod(ctx, env.Rest, natsExposureNamespace, broker.Name, 4222)
	if err != nil {
		return receipt, err
	}
	defer func() {
		if closeErr := closeForward(); closeErr != nil {
			runErr = errors.Join(runErr, errors.New("NATS response broker forward stop unconfirmed"))
		}
	}()
	current, err = env.Kube.CoreV1().Pods(natsExposureNamespace).Get(ctx, broker.Name, metav1.GetOptions{})
	if err != nil || current.UID != broker.UID {
		return receipt, errors.New("NATS response broker Pod replaced across forward")
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	connect := func() (*nats.Conn, error) {
		return nats.Connect("nats://"+address, nats.Timeout(3*time.Second), nats.NoReconnect(),
			nats.MaxReconnects(0), nats.RetryOnFailedConnect(false), nats.DontRandomize(),
			nats.SkipHostLookup(), nats.PermissionErrOnSubscribe(true),
			nats.SetCustomDialer(natsExposureFixedDialer{address: address}))
	}
	writer, err := connect()
	if err != nil {
		return receipt, errors.New("NATS response writer connection unavailable")
	}
	defer writer.Close()
	reference, err := connect()
	if err != nil {
		return receipt, errors.New("NATS response local reference unavailable")
	}
	defer reference.Close()
	if writer.ConnectedServerId() != broker.ServerID || reference.ConnectedServerId() != broker.ServerID {
		return receipt, errors.New("NATS response broker process identity differed")
	}
	index := 0
	if phase == "M1" {
		index = 1
	}
	subjects, payloads := natsResponseSubjects(env.Config.NATSExposureFixture.Nonce), natsResponsePayloads(env.Config.NATSExposureFixture.Nonce)
	stream := "CAT_" + env.Config.NATSExposureFixture.Nonce + "_" + phase
	cfg := natsexposure.Config{Nonce: env.Config.NATSExposureFixture.Nonce, Stream: stream,
		Subject: subjects[index], Consumer: stream + "_C", ExpectedWriterServerID: broker.ServerID,
		ExpectedAdversaryServerID: broker.ServerID, RequestTimeout: 3 * time.Second,
		ReceiveTimeout: 3 * time.Second, AckWait: 5 * time.Second, BarrierTimeout: 30 * time.Second}
	recorder := func(_ context.Context, r natsexposure.Receipt) error {
		return natsResponseProtocolRecord(env, phase, r)
	}
	receipt, runErr = natsexposure.Run(ctx, cfg, writer, reference, payloads[index], recorder, barrier)
	if err := requireNATSRoute(ctx, env, route); err != nil {
		runErr = errors.Join(runErr, err)
	}
	return receipt, runErr
}
