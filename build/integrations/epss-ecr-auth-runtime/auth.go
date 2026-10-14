package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	expectedRole    = "arn:aws:iam::753556437180:role/phorvex-dev-epss-feed"
	expectedRegion  = "us-east-2"
	tokenPath       = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	outputDirectory = "/var/run/secrets/phorvex-epss-registry-auth"
	ownedHost       = "753556437180.dkr.ecr.us-east-2.amazonaws.com"
	eksHost         = "602401143452.dkr.ecr.us-east-2.amazonaws.com"
	minimumValidity = 3600*time.Second + 600*time.Second
	runtimeUID      = 65532
	schemaVersion   = "phorvex.epss-registry-auth.v1"
)

// No environment/shared-config credential chain is constructed, even on errors.
func validateEnvironment(getenv func(string) string) error {
	if getenv("AWS_ROLE_ARN") != expectedRole || getenv("AWS_REGION") != expectedRegion || getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != tokenPath {
		return errors.New("unexpected web identity configuration")
	}
	if region := getenv("AWS_DEFAULT_REGION"); region != "" && region != expectedRegion {
		return errors.New("unexpected web identity configuration")
	}
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
		"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_ECR",
	} {
		if getenv(key) != "" {
			return errors.New("alternate AWS credential or endpoint configuration is forbidden")
		}
	}
	return nil
}

type boundedTokenFile string

// EKS projected tokens use symlinks. Permit that layout, but bound all reads and
// never return file paths, token bytes or underlying OS errors to the caller.
func (path boundedTokenFile) GetIdentityToken() ([]byte, error) {
	f, err := os.Open(string(path))
	if err != nil {
		return nil, errors.New("web identity token unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid web identity token file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 || len(strings.TrimSpace(string(raw))) == 0 || !utf8.Valid(raw) {
		return nil, errors.New("invalid web identity token file")
	}
	return raw, nil
}

type ecrAPI interface {
	GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

func webIdentityProvider(client stscreds.AssumeRoleWithWebIdentityAPIClient, token stscreds.IdentityTokenRetriever) aws.CredentialsProvider {
	return aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(client, expectedRole, token, func(o *stscreds.WebIdentityRoleOptions) {
		o.RoleSessionName = "phorvex-epss-feed"
		o.Duration = time.Hour
	}))
}

func newECRClient() ecrAPI {
	// Proxy nil, redirects refused and explicit regional endpoints prevent ambient
	// proxy/endpoint settings from receiving web identity or ECR credentials.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
	cfg := aws.Config{Region: expectedRegion, HTTPClient: client, Credentials: aws.AnonymousCredentials{},
		Retryer: func() aws.Retryer { return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 3 }) }}
	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = aws.String("https://sts.us-east-2.amazonaws.com") })
	cfg.Credentials = webIdentityProvider(stsClient, boundedTokenFile(tokenPath))
	return ecr.NewFromConfig(cfg, func(o *ecr.Options) { o.BaseEndpoint = aws.String("https://api.ecr.us-east-2.amazonaws.com") })
}

type dockerAuthEntry struct {
	Auth string `json:"auth"`
}
type dockerAuthMetadata struct {
	SchemaVersion string            `json:"schemaVersion"`
	ExpiresAt     map[string]string `json:"expiresAt"`
}
type dockerConfig struct {
	Auths    map[string]dockerAuthEntry `json:"auths"`
	Metadata dockerAuthMetadata         `json:"x-phorvex"`
}

func fetchConfig(ctx context.Context, client ecrAPI, now func() time.Time) ([]byte, error) {
	// ECR's one returned token is valid for both registries to the extent that the
	// principal's repository policies permit reads. Never request/accept extra hosts.
	result, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, errors.New("ECR authorization failed")
	}
	if result == nil || len(result.AuthorizationData) != 1 {
		return nil, errors.New("invalid ECR authorization response")
	}
	entry := result.AuthorizationData[0]
	endpoint := aws.ToString(entry.ProxyEndpoint)
	if endpoint != "https://"+ownedHost && endpoint != "https://"+eksHost {
		return nil, errors.New("unexpected ECR authorization endpoint")
	}
	token := aws.ToString(entry.AuthorizationToken)
	if len(token) == 0 || len(token) > 8<<10 {
		return nil, errors.New("invalid ECR authorization token")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(token)
	username, password, found := strings.Cut(string(decoded), ":")
	if err != nil || !utf8.Valid(decoded) || !found || username != "AWS" || password == "" {
		return nil, errors.New("invalid ECR authorization token")
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return nil, errors.New("invalid ECR authorization token")
		}
	}
	current := now().UTC()
	if current.IsZero() || entry.ExpiresAt == nil {
		return nil, errors.New("insufficient ECR authorization lifetime")
	}
	// Round before checking, so serialized whole-second metadata also exceeds 4200s.
	expiry := entry.ExpiresAt.UTC().Truncate(time.Second)
	if !expiry.After(current.Add(minimumValidity)) {
		return nil, errors.New("insufficient ECR authorization lifetime")
	}
	config := dockerConfig{Auths: map[string]dockerAuthEntry{}, Metadata: dockerAuthMetadata{SchemaVersion: schemaVersion, ExpiresAt: map[string]string{}}}
	for _, host := range []string{ownedHost, eksHost} {
		config.Auths[host] = dockerAuthEntry{Auth: token}
		config.Metadata.ExpiresAt[host] = expiry.Format(time.RFC3339)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, errors.New("registry configuration encoding failed")
	}
	return raw, nil
}

func writeConfig(directory string, raw []byte) error {
	// Run unprivileged; do not chown with elevated capabilities. The feed has the
	// same UID. Kubelet sets fsGroup before init, then this newly created file is 0400.
	if os.Getuid() != runtimeUID || os.Getgid() != runtimeUID {
		return errors.New("registry writer requires UID and GID 65532")
	}
	if len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("invalid registry configuration size")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid registry output directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return errors.New("registry output directory must be empty")
	}
	dir, err := os.Open(directory)
	if err != nil {
		return errors.New("registry output directory unavailable")
	}
	defer dir.Close()
	f, err := os.CreateTemp(directory, ".config-*")
	if err != nil {
		return errors.New("registry temporary file unavailable")
	}
	temp := f.Name()
	defer os.Remove(temp)
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return errors.New("registry configuration write failed")
	}
	if err := f.Sync(); err != nil {
		return errors.New("registry configuration sync failed")
	}
	if err := f.Chmod(0o400); err != nil {
		return errors.New("registry configuration permission failed")
	}
	if err := f.Sync(); err != nil {
		return errors.New("registry configuration sync failed")
	}
	info, err = f.Stat()
	if err != nil {
		return errors.New("registry configuration stat failed")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != runtimeUID || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		return errors.New("registry configuration ownership or mode failed")
	}
	if err := f.Close(); err != nil {
		return errors.New("registry configuration close failed")
	}
	target := filepath.Join(directory, "config.json")
	if err := os.Rename(temp, target); err != nil {
		return errors.New("registry configuration publication failed")
	}
	if err := dir.Sync(); err != nil {
		_ = os.Remove(target)
		_ = dir.Sync()
		return errors.New("registry directory sync failed")
	}
	return nil
}

func prepare(ctx context.Context, client ecrAPI, now func() time.Time, directory string) error {
	raw, err := fetchConfig(ctx, client, now)
	if err != nil {
		return err
	}
	return writeConfig(directory, raw)
}
