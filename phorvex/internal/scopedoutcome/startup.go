package scopedoutcome

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/phorvex/phorvex/internal/currentinventory"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	StartupConfigSchemaV1 = "phorvex.scoped-outcome-startup.v1"
	maxStartupConfigBytes = 32 << 10
	maxTLSMaterialBytes   = 64 << 10
	maxStartupStoreBytes  = int64(maxRetainedOperations * maxEvidenceBytes)
)

// StartupConfig is one preregistered synthetic observation. Merely providing
// this file does not authorize arbitrary endpoints or workload discovery: the
// exact policy, workload, Pod and two mTLS sessions must all validate at boot.
type StartupConfig struct {
	SchemaVersion     string        `json:"schemaVersion"`
	Prepare           PrepareConfig `json:"prepare"`
	CAFile            string        `json:"caFile"`
	ClientCertFile    string        `json:"clientCertFile"`
	ClientKeyFile     string        `json:"clientKeyFile"`
	ServerName        string        `json:"serverName"`
	EvidenceDirectory string        `json:"evidenceDirectory"`
	EvidenceMaxItems  int           `json:"evidenceMaxItems"`
	EvidenceMaxBytes  int64         `json:"evidenceMaxBytes"`
	HTTPTimeout       string        `json:"httpTimeout"`
	AuthorityTimeout  string        `json:"authorityTimeout"`
}

// StartupError exposes only a bounded category to runtime logs. Underlying
// parser, path and TLS errors remain available to focused tests via Unwrap.
type StartupError struct {
	code string
	err  error
}

func (e *StartupError) Error() string { return "scoped outcome startup " + e.code }
func (e *StartupError) Unwrap() error { return e.err }

func startupError(code string, err error) error { return &StartupError{code: code, err: err} }

// StartupErrorCode returns a stable, non-sensitive log value.
func StartupErrorCode(err error) string {
	var startup *StartupError
	if errors.As(err, &startup) {
		return startup.code
	}
	return "unknown"
}

// OpenStartupProducer opens and prepares exactly one configured observation.
// The caller owns Close on a successful return. Any partial producer is closed
// before an error is returned.
func OpenStartupProducer(ctx context.Context, path string, reader client.Reader, processEpochID string, now func() time.Time) (*Producer, error) {
	config, httpTimeout, authorityTimeout, err := loadStartupConfig(path)
	if err != nil {
		return nil, err
	}
	roots, certificate, err := loadTLSIdentity(config)
	if err != nil {
		return nil, startupError("tls-invalid", err)
	}
	httpClient, err := NewMTLSClient(roots, certificate, config.ServerName, httpTimeout)
	if err != nil {
		return nil, startupError("tls-invalid", err)
	}
	store, err := NewDirectoryEvidenceStore(config.EvidenceDirectory, config.EvidenceMaxItems, config.EvidenceMaxBytes)
	if err != nil {
		return nil, startupError("store-unavailable", err)
	}
	producer, err := New(httpClient, store, KubernetesBindingResolver{Reader: reader, Timeout: authorityTimeout}, processEpochID, now)
	if err != nil {
		return nil, startupError("producer-invalid", err)
	}
	if err := producer.Prepare(ctx, config.Prepare); err != nil {
		producer.Close()
		return nil, startupError("preregistration-refused", err)
	}
	return producer, nil
}

func loadStartupConfig(path string) (StartupConfig, time.Duration, time.Duration, error) {
	var config StartupConfig
	if !filepath.IsAbs(path) {
		return config, 0, 0, startupError("config-invalid", errors.New("configuration path is not absolute"))
	}
	raw, err := readBoundedRegular(path, maxStartupConfigBytes)
	if err != nil {
		return config, 0, 0, startupError("config-read", err)
	}
	if err := currentinventory.RejectDuplicateFields(raw); err != nil {
		return config, 0, 0, startupError("config-decode", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, 0, 0, startupError("config-decode", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return config, 0, 0, startupError("config-decode", err)
	}
	httpTimeout, err := parseStartupTimeout(config.HTTPTimeout)
	if err != nil {
		return config, 0, 0, startupError("config-invalid", err)
	}
	authorityTimeout, err := parseStartupTimeout(config.AuthorityTimeout)
	if err != nil {
		return config, 0, 0, startupError("config-invalid", err)
	}
	if config.SchemaVersion != StartupConfigSchemaV1 || config.ServerName == "" || len(config.ServerName) > 253 ||
		config.EvidenceMaxItems <= 0 || config.EvidenceMaxItems > maxRetainedOperations ||
		config.EvidenceMaxBytes <= 0 || config.EvidenceMaxBytes > maxStartupStoreBytes || !filepath.IsAbs(config.EvidenceDirectory) {
		return config, 0, 0, startupError("config-invalid", errors.New("configuration identity or capacity is invalid"))
	}
	for _, value := range []string{config.CAFile, config.ClientCertFile, config.ClientKeyFile} {
		if !filepath.IsAbs(value) {
			return config, 0, 0, startupError("config-invalid", errors.New("TLS material path is not absolute"))
		}
	}
	if err := validatePrepare(config.Prepare); err != nil {
		return config, 0, 0, startupError("config-invalid", err)
	}
	return config, httpTimeout, authorityTimeout, nil
}

func parseStartupTimeout(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > 5*time.Second {
		return 0, errors.New("timeout must be positive and no greater than five seconds")
	}
	return duration, nil
}

func loadTLSIdentity(config StartupConfig) (*x509.CertPool, tls.Certificate, error) {
	caPEM, err := readBoundedRegular(config.CAFile, maxTLSMaterialBytes)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	certPEM, err := readBoundedRegular(config.ClientCertFile, maxTLSMaterialBytes)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	keyPEM, err := readBoundedRegular(config.ClientKeyFile, maxTLSMaterialBytes)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, tls.Certificate{}, errors.New("CA material has no certificate")
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, tls.Certificate{}, errors.New("client certificate and key do not match")
	}
	return roots, certificate, nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("file is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("file exceeds its byte bound")
	}
	return raw, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("configuration has trailing JSON")
		}
		return fmt.Errorf("configuration trailing data: %w", err)
	}
	return nil
}
