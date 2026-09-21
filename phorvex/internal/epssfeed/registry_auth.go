package epssfeed

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	RegistryAuthSchemaV1 = "phorvex.epss-registry-auth.v1"
	maxRegistryAuthBytes = 64 << 10
	maxRegistryAuthValue = 8 << 10
)

var privateECRHost = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$`)

// RegistryAuthProvider selects a pinned Docker configuration for one exact image.
// The boolean reports whether the scan is authenticated, so callers can suppress
// diagnostics whose redaction cannot be proved complete.
type RegistryAuthProvider interface {
	DockerConfigFor(image string, now time.Time, minimumValidity time.Duration) (directory string, authenticated bool, err error)
}

type dockerAuthFile struct {
	Auths   map[string]dockerAuthEntry `json:"auths"`
	Phorvex dockerAuthMetadata         `json:"x-phorvex"`
}

type dockerAuthEntry struct {
	Auth string `json:"auth"`
}

type dockerAuthMetadata struct {
	SchemaVersion string            `json:"schemaVersion"`
	ExpiresAt     map[string]string `json:"expiresAt"`
}

type registryCredential struct {
	expiresAt time.Time
}

// DockerConfigAuth is an immutable, validated view of one caller-provided
// Docker config snapshot. It stores no generated credential material.
type DockerConfigAuth struct {
	directory string
	path      string
	info      os.FileInfo
	digest    [sha256.Size]byte
	hosts     map[string]registryCredential
}

// LoadDockerConfigAuth validates and pins a direct file or a standard Kubernetes
// projected-Secret version. The configured allowlist must equal both key sets in
// the file; a stale member makes the entire required credential set unavailable.
func LoadDockerConfigAuth(path string, allowlist []string, now time.Time, minimumValidity time.Duration) (*DockerConfigAuth, error) {
	if strings.TrimSpace(path) == "" || len(allowlist) == 0 {
		return nil, errors.New("registry authentication requires a credential file and registry allowlist")
	}
	if now.IsZero() || minimumValidity <= 0 {
		return nil, errors.New("registry authentication requires a current time and positive validity horizon")
	}
	allowed := make(map[string]struct{}, len(allowlist))
	for _, host := range allowlist {
		host = strings.TrimSpace(host)
		if !privateECRHost.MatchString(host) {
			return nil, errors.New("registry authentication allowlist contains a non-canonical private ECR host")
		}
		if _, exists := allowed[host]; exists {
			return nil, errors.New("registry authentication allowlist contains a duplicate host")
		}
		allowed[host] = struct{}{}
	}

	resolved, err := resolveDockerConfigSnapshot(path)
	if err != nil {
		return nil, err
	}
	raw, info, err := readPrivateRegularFile(resolved)
	if err != nil {
		return nil, err
	}
	config, err := decodeDockerAuth(raw)
	if err != nil {
		return nil, err
	}
	if config.Phorvex.SchemaVersion != RegistryAuthSchemaV1 {
		return nil, errors.New("registry authentication metadata has an unsupported schema")
	}
	if len(config.Auths) != len(allowed) || len(config.Phorvex.ExpiresAt) != len(allowed) {
		return nil, errors.New("registry authentication host sets do not match the configured allowlist")
	}
	hosts := make(map[string]registryCredential, len(allowed))
	for host := range allowed {
		entry, authOK := config.Auths[host]
		expiresText, expiryOK := config.Phorvex.ExpiresAt[host]
		if !authOK || !expiryOK {
			return nil, errors.New("registry authentication host sets do not match the configured allowlist")
		}
		if err := validateDockerAuth(entry.Auth); err != nil {
			return nil, err
		}
		expiresAt, parseErr := time.Parse(time.RFC3339, expiresText)
		if parseErr != nil || expiresAt.Format(time.RFC3339) != expiresText {
			return nil, errors.New("registry authentication metadata has an invalid expiry")
		}
		if !expiresAt.After(now.Add(minimumValidity)) {
			return nil, errors.New("registry authentication credential is expired or too near expiry")
		}
		hosts[host] = registryCredential{expiresAt: expiresAt}
	}
	for host := range config.Auths {
		if _, ok := allowed[host]; !ok {
			return nil, errors.New("registry authentication contains a foreign host")
		}
	}
	for host := range config.Phorvex.ExpiresAt {
		if _, ok := allowed[host]; !ok {
			return nil, errors.New("registry authentication metadata contains a foreign host")
		}
	}
	return &DockerConfigAuth{
		directory: filepath.Dir(resolved), path: resolved, info: info,
		digest: sha256.Sum256(raw), hosts: hosts,
	}, nil
}

func decodeDockerAuth(raw []byte) (dockerAuthFile, error) {
	if len(raw) == 0 || len(raw) > maxRegistryAuthBytes || !utf8.Valid(raw) {
		return dockerAuthFile{}, errors.New("registry authentication file has invalid size or encoding")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return dockerAuthFile{}, errors.New("registry authentication file has duplicate object keys")
	}
	var config dockerAuthFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return dockerAuthFile{}, errors.New("registry authentication file is malformed")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return dockerAuthFile{}, errors.New("registry authentication file has trailing data")
	}
	if config.Auths == nil || config.Phorvex.ExpiresAt == nil {
		return dockerAuthFile{}, errors.New("registry authentication file lacks required host maps")
	}
	return config, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeUniqueJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func consumeUniqueJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, keyErr := dec.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for dec.More() {
			if err := consumeUniqueJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func validateDockerAuth(encoded string) error {
	if encoded == "" || len(encoded) > maxRegistryAuthValue || !utf8.ValidString(encoded) {
		return errors.New("registry authentication entry has invalid encoding")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maxRegistryAuthValue || !utf8.Valid(decoded) {
		return errors.New("registry authentication entry has invalid encoding")
	}
	username, password, found := strings.Cut(string(decoded), ":")
	if !found || username != "AWS" || password == "" || len(password) > maxRegistryAuthValue {
		return errors.New("registry authentication entry is not a bounded ECR token")
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return errors.New("registry authentication entry contains control characters")
		}
	}
	return nil
}

func resolveDockerConfigSnapshot(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", errors.New("registry authentication path is invalid")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", errors.New("registry authentication file is unavailable")
	}
	if info.Mode().IsRegular() {
		if filepath.Base(abs) != "config.json" {
			return "", errors.New("registry authentication file must be named config.json")
		}
		return abs, nil
	}
	if info.Mode()&os.ModeSymlink == 0 || filepath.Base(abs) != "config.json" {
		return "", errors.New("registry authentication path is not a regular file or projected Secret key")
	}
	keyTarget, err := os.Readlink(abs)
	if err != nil || keyTarget != filepath.Join("..data", "config.json") {
		return "", errors.New("registry authentication projected key has an invalid link")
	}
	dir := filepath.Dir(abs)
	dataLink := filepath.Join(dir, "..data")
	dataInfo, err := os.Lstat(dataLink)
	if err != nil || dataInfo.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("registry authentication projected data link is unavailable")
	}
	version, err := os.Readlink(dataLink)
	if err != nil || filepath.Base(version) != version || !strings.HasPrefix(version, "..") || version == "..data" || version == ".." {
		return "", errors.New("registry authentication projected version is invalid")
	}
	versionInfo, err := os.Lstat(filepath.Join(dir, version))
	if err != nil || !versionInfo.IsDir() || versionInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("registry authentication projected version directory is invalid")
	}
	resolved := filepath.Join(dir, version, "config.json")
	if filepath.Dir(filepath.Dir(resolved)) != dir {
		return "", errors.New("registry authentication projected version escapes its mount")
	}
	return resolved, nil
}

func readPrivateRegularFile(path string) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, errors.New("registry authentication snapshot is not a regular file")
	}
	perm := before.Mode().Perm()
	if perm&0o227 != 0 || perm&0o111 != 0 {
		return nil, nil, errors.New("registry authentication snapshot permissions are not private read-only")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("registry authentication snapshot cannot be opened")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, nil, errors.New("registry authentication snapshot changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxRegistryAuthBytes+1))
	if err != nil || len(raw) > maxRegistryAuthBytes {
		return nil, nil, errors.New("registry authentication snapshot cannot be read within its bound")
	}
	return raw, after, nil
}

func (a *DockerConfigAuth) DockerConfigFor(image string, now time.Time, minimumValidity time.Duration) (string, bool, error) {
	host := registryHost(image)
	canonicalHost := strings.ToLower(host)
	if !privateECRHost.MatchString(canonicalHost) {
		return "", false, nil
	}
	if host != canonicalHost {
		return "", false, errors.New("private ECR image registry is not canonical")
	}
	credential, ok := a.hosts[host]
	if !ok {
		return "", false, errors.New("private ECR image registry is not in the credential allowlist")
	}
	if !credential.expiresAt.After(now.Add(minimumValidity)) {
		return "", false, errors.New("private ECR credential is expired or too near expiry")
	}
	raw, info, err := readPrivateRegularFile(a.path)
	if err != nil || !os.SameFile(a.info, info) || sha256.Sum256(raw) != a.digest {
		return "", false, errors.New("registry authentication snapshot changed after validation")
	}
	return a.directory, true, nil
}

func registryHost(image string) string {
	first, _, hasSlash := strings.Cut(strings.TrimSpace(image), "/")
	if !hasSlash || (!strings.Contains(first, ".") && !strings.Contains(first, ":") && first != "localhost") {
		return "docker.io"
	}
	return first
}

func configuredPrivateECR(image string) bool {
	return privateECRHost.MatchString(strings.ToLower(registryHost(image)))
}

func registryAllowlist(raw string) []string {
	var out []string
	for _, host := range strings.Split(raw, ",") {
		if host = strings.TrimSpace(host); host != "" {
			out = append(out, host)
		}
	}
	return out
}

func LoadRegistryAuthConfiguration(path, registries string, now time.Time, minimumValidity time.Duration) (RegistryAuthProvider, error) {
	hasPath, hasRegistries := strings.TrimSpace(path) != "", strings.TrimSpace(registries) != ""
	if !hasPath && !hasRegistries {
		return nil, nil
	}
	if hasPath != hasRegistries {
		return nil, fmt.Errorf("registry authentication file and allowlist must be configured together")
	}
	return LoadDockerConfigAuth(path, registryAllowlist(registries), now, minimumValidity)
}
