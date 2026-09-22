// Command native-route-catalogue executes one fixed native selector cutover and rollback.
// It is intentionally not a generic actuator command surface.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/routecatalogue"
)

const commandSchema = "phorvex.native-route-catalogue.command.v1"
const writeJournalSchema = "phorvex.native-route-catalogue.write-journal.v1"

type commandConfig struct {
	Schema             string                   `json:"schema"`
	Kubeconfig         string                   `json:"kubeconfig"`
	Context            string                   `json:"context"`
	MaxDurationSeconds int                      `json:"maxDurationSeconds"`
	Run                routecatalogue.RunConfig `json:"run"`
}

func main() {
	var configPath, outputPath string
	flag.StringVar(&configPath, "config", "", "private typed route catalogue config")
	flag.StringVar(&outputPath, "output", "", "new private receipt path")
	flag.Parse()
	if flag.NArg() != 0 || configPath == "" || outputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: native-route-catalogue -config <private.json> -output <new-receipt.json>")
		os.Exit(2)
	}
	if err := run(configPath, outputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(configPath, outputPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if err := validateBuild(cfg.Run.SourceRevision); err != nil {
		return err
	}
	if !filepath.IsAbs(outputPath) || filepath.Clean(outputPath) != outputPath {
		return errors.New("route catalogue output must be a clean absolute path")
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		if err == nil {
			return errors.New("route catalogue output already exists")
		}
		return fmt.Errorf("route catalogue output authority: %w", err)
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = cfg.Kubeconfig
	overrides := &clientcmd.ConfigOverrides{CurrentContext: cfg.Context}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	raw, err := loader.RawConfig()
	if err != nil {
		return fmt.Errorf("route catalogue kubeconfig: %w", err)
	}
	if raw.CurrentContext != cfg.Context || raw.Contexts[cfg.Context] == nil {
		return errors.New("route catalogue kube context authority differs")
	}
	restConfig, err := loader.ClientConfig()
	if err != nil {
		return fmt.Errorf("route catalogue REST config: %w", err)
	}
	restConfig.UserAgent = "phorvex-native-route-catalogue/v1"
	runtimeScheme := runtime.NewScheme()
	if err := scheme.AddToScheme(runtimeScheme); err != nil {
		return err
	}
	if err := routecatalogue.AddToScheme(runtimeScheme); err != nil {
		return err
	}
	kubeClient, err := client.New(restConfig, client.Options{Scheme: runtimeScheme})
	if err != nil {
		return fmt.Errorf("route catalogue Kubernetes client: %w", err)
	}
	adapter, err := routecatalogue.New(kubeClient, kubeClient, nil)
	if err != nil {
		return err
	}
	journal, err := newWriteJournal(outputPath + ".writes.jsonl")
	if err != nil {
		return err
	}
	if err := adapter.SetWriteJournal(journal); err != nil {
		_ = journal.Close()
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.MaxDurationSeconds)*time.Second)
	defer cancel()
	receipt, runErr := adapter.Run(ctx, cfg.Run)
	closeErr := journal.Close()
	journalSHA, journalBytes, journalErr := hashFile(journal.path)
	receipt.WriteJournalSchema = writeJournalSchema
	receipt.WriteJournalSHA256 = journalSHA
	receipt.WriteJournalBytes = journalBytes
	if err := writeReceipt(outputPath, receipt); err != nil {
		return errors.Join(runErr, closeErr, journalErr, err)
	}
	return errors.Join(runErr, closeErr, journalErr)
}

type writeJournal struct {
	path string
	file *os.File
}

func newWriteJournal(path string) (*writeJournal, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("route catalogue create write journal: %w", err)
	}
	journal := &writeJournal{path: path, file: file}
	header, _ := json.Marshal(map[string]string{"schema": writeJournalSchema})
	if _, err := file.Write(append(header, '\n')); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return journal, nil
}

func (j *writeJournal) Append(observation routecatalogue.WriteObservation) error {
	if j == nil || j.file == nil {
		return errors.New("route catalogue write journal is closed")
	}
	raw, err := json.Marshal(struct {
		Schema      string                          `json:"schema"`
		Observation routecatalogue.WriteObservation `json:"observation"`
	}{Schema: writeJournalSchema, Observation: observation})
	if err != nil {
		return err
	}
	if _, err := j.file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return j.file.Sync()
}

func (j *writeJournal) Close() error {
	if j == nil || j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(h, io.LimitReader(file, 16<<20+1))
	closeErr := file.Close()
	if n > 16<<20 {
		return "", n, errors.Join(copyErr, closeErr, errors.New("route catalogue write journal exceeded 16 MiB"))
	}
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func loadConfig(path string) (commandConfig, error) {
	var cfg commandConfig
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return cfg, errors.New("route catalogue config must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return cfg, fmt.Errorf("route catalogue config metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 2 || info.Size() > 1<<20 {
		return cfg, errors.New("route catalogue config must be a private regular file of at most 1 MiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("route catalogue config decode: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return cfg, errors.New("route catalogue config has trailing content")
	}
	if cfg.Schema != commandSchema || cfg.Context == "" || strings.TrimSpace(cfg.Context) != cfg.Context || !filepath.IsAbs(cfg.Kubeconfig) || filepath.Clean(cfg.Kubeconfig) != cfg.Kubeconfig || cfg.MaxDurationSeconds < 30 || cfg.MaxDurationSeconds > 180 {
		return cfg, errors.New("route catalogue command authority or bounds are invalid")
	}
	if _, err := os.Stat(cfg.Kubeconfig); err != nil {
		return cfg, fmt.Errorf("route catalogue kubeconfig metadata: %w", err)
	}
	return cfg, nil
}

func validateBuild(want string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("route catalogue build information unavailable")
	}
	revision, modified := "", ""
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if revision != want || modified != "false" {
		return fmt.Errorf("route catalogue binary source differs: revision=%q modified=%q", revision, modified)
	}
	return nil
}

func writeReceipt(path string, receipt routecatalogue.Receipt) error {
	dir := filepath.Dir(path)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("route catalogue output directory must exist and be private")
	}
	tmp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("route catalogue create receipt: %w", err)
	}
	encErr := json.NewEncoder(tmp).Encode(receipt)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(encErr, syncErr, closeErr); err != nil {
		_ = os.Remove(path + ".tmp")
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		_ = os.Remove(path + ".tmp")
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	return errors.Join(err, d.Close())
}
