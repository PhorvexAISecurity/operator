package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

var fixtureNow = time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC)

func validResult(now time.Time) *ecr.GetAuthorizationTokenOutput {
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{
		AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString([]byte("AWS:synthetic-test-password"))),
		ProxyEndpoint:      aws.String("https://" + ownedHost), ExpiresAt: aws.Time(now.Add(12 * time.Hour)),
	}}}
}

type fakeECR struct {
	result *ecr.GetAuthorizationTokenOutput
	err    error
	calls  int
}

func (f *fakeECR) GetAuthorizationToken(_ context.Context, in *ecr.GetAuthorizationTokenInput, _ ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	f.calls++
	if len(in.RegistryIds) != 0 {
		return nil, errors.New("unexpected registry IDs")
	}
	return f.result, f.err
}

func TestOneTokenForExactlyBothHosts(t *testing.T) {
	for _, endpoint := range []string{ownedHost, eksHost} {
		f := &fakeECR{result: validResult(fixtureNow)}
		f.result.AuthorizationData[0].ProxyEndpoint = aws.String("https://" + endpoint)
		raw, err := fetchConfig(context.Background(), f, func() time.Time { return fixtureNow })
		if err != nil {
			t.Fatal(err)
		}
		var config dockerConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		if len(config.Auths) != 2 || len(config.Metadata.ExpiresAt) != 2 || config.Metadata.SchemaVersion != schemaVersion || f.calls != 1 {
			t.Fatal("wrong credential host/schema contract")
		}
		for _, host := range []string{ownedHost, eksHost} {
			if config.Auths[host].Auth != aws.ToString(f.result.AuthorizationData[0].AuthorizationToken) || config.Metadata.ExpiresAt[host] != fixtureNow.Add(12*time.Hour).Format(time.RFC3339) {
				t.Fatal("wrong token or expiry")
			}
		}
	}
}

func TestRejectAuthorizationResponses(t *testing.T) {
	cases := map[string]func(*ecr.GetAuthorizationTokenOutput){
		"missing": func(o *ecr.GetAuthorizationTokenOutput) { o.AuthorizationData = nil },
		"multiple": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData = append(o.AuthorizationData, o.AuthorizationData[0])
		},
		"foreign": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ProxyEndpoint = aws.String("https://111111111111.dkr.ecr.us-east-2.amazonaws.com")
		},
		"path": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ProxyEndpoint = aws.String("https://" + ownedHost + "/")
		},
		"userinfo": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ProxyEndpoint = aws.String("https://user@" + ownedHost)
		},
		"http": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ProxyEndpoint = aws.String("http://" + ownedHost)
		},
		"uppercase": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ProxyEndpoint = aws.String(strings.ToUpper("https://" + ownedHost))
		},
		"region": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ProxyEndpoint = aws.String(strings.ReplaceAll("https://"+ownedHost, "us-east-2", "us-west-2"))
		},
		"query": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ProxyEndpoint = aws.String("https://" + ownedHost + "?token=synthetic")
		},
		"missing-token": func(o *ecr.GetAuthorizationTokenOutput) { o.AuthorizationData[0].AuthorizationToken = nil },
		"base64": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].AuthorizationToken = aws.String("%%%")
		},
		"username": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].AuthorizationToken = aws.String(base64.StdEncoding.EncodeToString([]byte("user:password")))
		},
		"empty-password": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].AuthorizationToken = aws.String(base64.StdEncoding.EncodeToString([]byte("AWS:")))
		},
		"control": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].AuthorizationToken = aws.String(base64.StdEncoding.EncodeToString([]byte("AWS:password\n")))
		},
		"oversized": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].AuthorizationToken = aws.String(strings.Repeat("a", (8<<10)+1))
		},
		"expiry-nil": func(o *ecr.GetAuthorizationTokenOutput) { o.AuthorizationData[0].ExpiresAt = nil },
		"expired": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ExpiresAt = aws.Time(fixtureNow.Add(-time.Second))
		},
		"at-horizon": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ExpiresAt = aws.Time(fixtureNow.Add(minimumValidity))
		},
		"subsecond-horizon": func(o *ecr.GetAuthorizationTokenOutput) {
			o.AuthorizationData[0].ExpiresAt = aws.Time(fixtureNow.Add(minimumValidity + time.Millisecond))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			result := validResult(fixtureNow)
			mutate(result)
			raw, err := fetchConfig(context.Background(), &fakeECR{result: result}, func() time.Time { return fixtureNow })
			if err == nil || raw != nil {
				t.Fatal("invalid response accepted")
			}
			if strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "password") {
				t.Fatal("credential leaked in error")
			}
		})
	}
}

func TestSanitizedFailureAndElapsedRequest(t *testing.T) {
	raw, err := fetchConfig(context.Background(), &fakeECR{err: errors.New("synthetic-token upstream body")}, time.Now)
	if raw != nil || err == nil || err.Error() != "ECR authorization failed" {
		t.Fatal("unsafe upstream error")
	}
	// Check validity at response receipt, not at request start.
	raw, err = fetchConfig(context.Background(), &fakeECR{result: validResult(fixtureNow)}, func() time.Time { return fixtureNow.Add(11 * time.Hour) })
	if raw != nil || err == nil {
		t.Fatal("elapsed request lifetime ignored")
	}
	dir := t.TempDir()
	err = prepare(context.Background(), &fakeECR{err: errors.New("synthetic-token")}, time.Now, dir)
	entries, _ := os.ReadDir(dir)
	if err == nil || len(entries) != 0 {
		t.Fatal("failed auth published a file")
	}
}

func validEnvironment() map[string]string {
	return map[string]string{"AWS_ROLE_ARN": expectedRole, "AWS_REGION": expectedRegion, "AWS_WEB_IDENTITY_TOKEN_FILE": tokenPath}
}
func TestEnvironmentFailsClosed(t *testing.T) {
	valid := validEnvironment()
	if err := validateEnvironment(func(k string) string { return valid[k] }); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"AWS_ROLE_ARN", "AWS_REGION", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_ECR"} {
		t.Run(key, func(t *testing.T) {
			values := validEnvironment()
			values[key] = "synthetic-sensitive-value"
			err := validateEnvironment(func(k string) string { return values[k] })
			if err == nil || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("invalid environment accepted or leaked")
			}
		})
	}
	for _, key := range []string{"AWS_ROLE_ARN", "AWS_REGION", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		values := validEnvironment()
		delete(values, key)
		if validateEnvironment(func(k string) string { return values[k] }) == nil {
			t.Fatal("missing configuration accepted")
		}
	}
}

type fakeSTS struct {
	calls int
	fail  bool
}

func (f *fakeSTS) AssumeRoleWithWebIdentity(_ context.Context, in *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.calls++
	if aws.ToString(in.RoleArn) != expectedRole || aws.ToString(in.WebIdentityToken) != "synthetic-jwt" || aws.ToString(in.RoleSessionName) != "phorvex-epss-feed" {
		return nil, errors.New("incorrect explicit provider inputs")
	}
	if f.fail {
		return nil, errors.New("synthetic STS denied")
	}
	return &sts.AssumeRoleWithWebIdentityOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("webidentity-access"), SecretAccessKey: aws.String("synthetic-secret"), SessionToken: aws.String("synthetic-session"), Expiration: aws.Time(time.Now().Add(time.Hour))}}, nil
}
func TestWebIdentityHasNoFallback(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "static-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "static-secret")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1:1")
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("synthetic-jwt"), 0o400); err != nil {
		t.Fatal(err)
	}
	f := &fakeSTS{}
	credentials, err := webIdentityProvider(f, boundedTokenFile(path)).Retrieve(context.Background())
	if err != nil || credentials.AccessKeyID != "webidentity-access" || f.calls != 1 {
		t.Fatal("explicit web identity not used")
	}
	f.fail = true
	if _, err := webIdentityProvider(f, boundedTokenFile(path)).Retrieve(context.Background()); err == nil {
		t.Fatal("STS denial fell back")
	}
	if _, err := webIdentityProvider(f, boundedTokenFile(path+"-missing")).Retrieve(context.Background()); err == nil {
		t.Fatal("missing token fell back")
	}
	if f.calls != 2 {
		t.Fatal("missing file reached STS")
	}
}

func TestBoundedTokenFile(t *testing.T) {
	for _, raw := range []string{"", "  ", strings.Repeat("x", (64<<10)+1), "\xff"} {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte(raw), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := boundedTokenFile(path).GetIdentityToken(); err == nil {
			t.Fatal("invalid token file accepted")
		}
	}
}

func TestWriterRequiresUnprivilegedIdentity(t *testing.T) {
	if os.Getuid() == runtimeUID && os.Getgid() == runtimeUID {
		t.Skip("covered by UID fixture")
	}
	if writeConfig(t.TempDir(), []byte("{}")) == nil {
		t.Fatal("wrong UID accepted")
	}
}

func TestWriterFilesystem(t *testing.T) {
	if os.Getuid() != runtimeUID || os.Getgid() != runtimeUID {
		t.Skip("execute CI fixture as UID/GID 65532")
	}
	dir := t.TempDir()
	raw, err := fetchConfig(context.Background(), &fakeECR{result: validResult(time.Now())}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConfig(dir, raw); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Sys().(*syscall.Stat_t).Uid != runtimeUID {
		t.Fatal("wrong file mode/owner/type")
	}
	content, err := os.ReadFile(path)
	entries, _ := os.ReadDir(dir)
	if err != nil || string(content) != string(raw) || len(entries) != 1 {
		t.Fatal("incomplete publication or temporary credential retained")
	}
	if writeConfig(dir, raw) == nil {
		t.Fatal("nonempty output accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if writeConfig(link, raw) == nil {
		t.Fatal("symlink output directory accepted")
	}
	blocked := t.TempDir()
	if err := os.Symlink(path, filepath.Join(blocked, "config.json")); err != nil {
		t.Fatal(err)
	}
	if writeConfig(blocked, raw) == nil {
		t.Fatal("existing symlink output accepted")
	}
}

// This fixture lives only in a Go test binary; the published helper has no
// fake-token, alternate-path or test-mode switch. The loader integration invokes
// the actual prepare/writeConfig functions under the real runtime UID.
func TestEmitLoaderFixture(t *testing.T) {
	dir := os.Getenv("EPSS_AUTH_TEST_DIRECTORY")
	if dir == "" {
		t.Skip("loader integration fixture only")
	}
	if err := prepare(context.Background(), &fakeECR{result: validResult(time.Now())}, time.Now, dir); err != nil {
		t.Fatal(err)
	}
}

func TestMainSafeError(t *testing.T) {
	if os.Getenv("EPSS_AUTH_TEST_MAIN") == "1" {
		os.Args = []string{"epss-auth", "synthetic-sensitive-value"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSafeError$")
	cmd.Env = append(os.Environ(), "EPSS_AUTH_TEST_MAIN=1")
	out, err := cmd.CombinedOutput()
	if err == nil || string(out) != "EPSS registry authentication initialization failed\n" {
		t.Fatal("unsafe process failure output")
	}
}
