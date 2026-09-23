package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	authProbeResponseLimit = 1 << 20
	authProbeTokenLimit    = 16 << 10
	authProbeTimeout       = 10 * time.Second
)

type authHTTPConfig struct {
	FixedLoopback   string
	ScopedTokenFile string
	ExpectedSubject string
	AllowedTenant   string
	DeniedTenant    string
	DeniedTarget    string
}

type authHTTPObservation struct {
	Step       string
	Method     string
	Path       string
	Status     int
	SchemaKeys []string
	BodySHA256 string
}

type authHTTPResult struct {
	Observations []authHTTPObservation
	BeforeSHA256 string
	AfterSHA256  string
}

type authProbeHooks struct {
	Intent func(step, method, path string) error
	Event  func(authHTTPObservation) error
}

func validateAuthHTTPConfig(c authHTTPConfig, scoped bool) error {
	u, err := url.Parse(c.FixedLoopback)
	if err != nil {
		return fmt.Errorf("fixed loopback origin: %w", err)
	}
	if u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("fixed loopback must be an http origin without credentials, path, query, or fragment")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return errors.New("fixed loopback must use a literal loopback IP and explicit port")
	}
	if !filepath.IsAbs(c.ScopedTokenFile) || filepath.Clean(c.ScopedTokenFile) != c.ScopedTokenFile {
		return errors.New("scoped token file must be a clean absolute path")
	}
	if strings.TrimSpace(c.ExpectedSubject) == "" || c.ExpectedSubject != strings.TrimSpace(c.ExpectedSubject) {
		return errors.New("expected subject must be nonempty and trimmed")
	}
	if scoped {
		for label, value := range map[string]string{
			"allowed tenant": c.AllowedTenant,
			"denied tenant":  c.DeniedTenant,
			"denied target":  c.DeniedTarget,
		} {
			if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
				return fmt.Errorf("%s must be nonempty and trimmed", label)
			}
		}
		if c.AllowedTenant == c.DeniedTenant {
			return errors.New("allowed and denied tenants must differ")
		}
	}
	return nil
}

func readScopedToken(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("scoped token metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > authProbeTokenLimit {
		return nil, errors.New("scoped token must be a private regular file of 32..16384 bytes")
	}
	if info.Mode().Perm()&0o137 != 0 {
		return nil, errors.New("scoped token file permits only owner read/write and optional group read")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scoped token: %w", err)
	}
	if len(raw) < 32 || len(raw) > authProbeTokenLimit || bytes.ContainsAny(raw, "\r\n\x00") || string(raw) != strings.TrimSpace(string(raw)) {
		return nil, errors.New("scoped token content is malformed")
	}
	return raw, nil
}

func authProbeClient(configured *http.Client) *http.Client {
	client := &http.Client{}
	if configured != nil {
		*client = *configured
	}
	if client.Transport == nil {
		client.Transport = &http.Transport{
			Proxy:               nil,
			DisableKeepAlives:   true,
			MaxIdleConns:        0,
			IdleConnTimeout:     time.Second,
			TLSHandshakeTimeout: 3 * time.Second,
		}
	}
	if client.Timeout <= 0 || client.Timeout > authProbeTimeout {
		client.Timeout = authProbeTimeout
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are forbidden")
	}
	return client
}

func runAuthUnauthenticatedControl(ctx context.Context, client *http.Client, c authHTTPConfig, hooks authProbeHooks) (authHTTPResult, error) {
	if err := validateAuthHTTPConfig(c, false); err != nil {
		return authHTTPResult{}, err
	}
	token, err := readScopedToken(c.ScopedTokenFile)
	if err != nil {
		return authHTTPResult{}, err
	}
	defer zeroBytes(token)
	client = authProbeClient(client)
	steps := []authProbeStep{
		{name: "missing-credential", path: "/api/session", want: http.StatusUnauthorized, schema: []string{"error"}},
		{name: "unsigned-alb-identity", path: "/api/session", want: http.StatusUnauthorized, schema: []string{"error"}, unsignedALB: true},
		{name: "legitimate-session-before", path: "/api/session", want: http.StatusOK, schema: []string{"authModes", "canEdit", "canRead", "grantsConfigured", "issuer", "lens", "roles", "source", "subject", "targets", "tenants"}, expectedSubject: c.ExpectedSubject, bearer: true},
		{name: "legitimate-session-after", path: "/api/session", want: http.StatusOK, schema: []string{"authModes", "canEdit", "canRead", "grantsConfigured", "issuer", "lens", "roles", "source", "subject", "targets", "tenants"}, expectedSubject: c.ExpectedSubject, bearer: true},
	}
	result, err := runAuthProbeSteps(ctx, client, c.FixedLoopback, token, steps, hooks)
	if err != nil {
		return result, err
	}
	result.BeforeSHA256 = result.Observations[2].BodySHA256
	result.AfterSHA256 = result.Observations[3].BodySHA256
	if result.BeforeSHA256 != result.AfterSHA256 {
		return result, errors.New("legitimate session projection changed across read-only boundary probes")
	}
	return result, nil
}

func runAuthScopedControl(ctx context.Context, client *http.Client, c authHTTPConfig, hooks authProbeHooks) (authHTTPResult, error) {
	if err := validateAuthHTTPConfig(c, true); err != nil {
		return authHTTPResult{}, err
	}
	token, err := readScopedToken(c.ScopedTokenFile)
	if err != nil {
		return authHTTPResult{}, err
	}
	defer zeroBytes(token)
	client = authProbeClient(client)
	steps := []authProbeStep{
		{name: "legitimate-session", path: "/api/session", want: http.StatusOK, schema: []string{"authModes", "canEdit", "canRead", "grantsConfigured", "issuer", "lens", "roles", "source", "subject", "targets", "tenants"}, expectedSubject: c.ExpectedSubject, bearer: true},
		{name: "allowed-tenant-before", path: "/api/owner/events?tenant=" + url.QueryEscape(c.AllowedTenant), want: http.StatusOK, schema: []string{"empty", "events", "note", "partial", "rollup"}, bearer: true},
		{name: "denied-tenant", path: "/api/owner/events?tenant=" + url.QueryEscape(c.DeniedTenant), want: http.StatusForbidden, schema: []string{"error"}, bearer: true},
		{name: "denied-target", path: "/api/workloads?target=" + url.QueryEscape(c.DeniedTarget), want: http.StatusForbidden, schema: []string{"error"}, bearer: true},
		{name: "allowed-tenant-after", path: "/api/owner/events?tenant=" + url.QueryEscape(c.AllowedTenant), want: http.StatusOK, schema: []string{"empty", "events", "note", "partial", "rollup"}, bearer: true},
	}
	result, err := runAuthProbeSteps(ctx, client, c.FixedLoopback, token, steps, hooks)
	if err != nil {
		return result, err
	}
	result.BeforeSHA256 = result.Observations[1].BodySHA256
	result.AfterSHA256 = result.Observations[4].BodySHA256
	return result, nil
}

type authProbeStep struct {
	name            string
	path            string
	want            int
	schema          []string
	expectedSubject string
	bearer          bool
	unsignedALB     bool
}

func runAuthProbeSteps(ctx context.Context, client *http.Client, origin string, token []byte, steps []authProbeStep, hooks authProbeHooks) (authHTTPResult, error) {
	result := authHTTPResult{Observations: make([]authHTTPObservation, 0, len(steps))}
	var expectationErrors []error
	for _, step := range steps {
		if hooks.Intent != nil {
			if err := hooks.Intent(step.name, http.MethodGet, step.path); err != nil {
				return result, fmt.Errorf("%s persist intent: %w", step.name, err)
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(origin, "/")+step.path, nil)
		if err != nil {
			return result, fmt.Errorf("%s request: %w", step.name, err)
		}
		req.Header.Set("Accept", "application/json")
		if step.bearer {
			req.Header.Set("Authorization", "Bearer "+string(token))
		}
		if step.unsignedALB {
			req.Header.Set("x-amzn-oidc-identity", "limited-v1-unsigned-control")
			req.Header.Set("x-amzn-oidc-accesstoken", "limited-v1-opaque-control")
		}
		resp, err := client.Do(req)
		if err != nil {
			return result, fmt.Errorf("%s request: %w", step.name, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, authProbeResponseLimit+1))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return result, fmt.Errorf("%s response: %w", step.name, readErr)
		}
		if closeErr != nil {
			return result, fmt.Errorf("%s close response: %w", step.name, closeErr)
		}
		if len(body) > authProbeResponseLimit {
			return result, fmt.Errorf("%s response exceeds %d bytes", step.name, authProbeResponseLimit)
		}
		if bytes.Contains(body, token) {
			return result, fmt.Errorf("%s response echoed credential material", step.name)
		}
		keys, err := topLevelJSONKeys(body)
		if err != nil {
			return result, fmt.Errorf("%s response JSON: %w", step.name, err)
		}
		sum := sha256.Sum256(body)
		observation := authHTTPObservation{
			Step: step.name, Method: http.MethodGet, Path: step.path, Status: resp.StatusCode,
			SchemaKeys: keys, BodySHA256: hex.EncodeToString(sum[:]),
		}
		result.Observations = append(result.Observations, observation)
		if hooks.Event != nil {
			if err := hooks.Event(observation); err != nil {
				return result, fmt.Errorf("%s persist event: %w", step.name, err)
			}
		}
		if resp.StatusCode != step.want {
			expectationErrors = append(expectationErrors, authStatusError{Step: step.name, Got: resp.StatusCode, Want: step.want})
			continue
		}
		if !containsAll(keys, step.schema) {
			return result, fmt.Errorf("%s response schema %v lacks required keys %v", step.name, keys, step.schema)
		}
		if step.expectedSubject != "" {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(body, &object); err != nil {
				return result, fmt.Errorf("%s subject response: %w", step.name, err)
			}
			var subject string
			if err := json.Unmarshal(object["subject"], &subject); err != nil || subject != step.expectedSubject {
				return result, fmt.Errorf("%s subject authority differs", step.name)
			}
		}
	}
	return result, errors.Join(expectationErrors...)
}

type authStatusError struct {
	Step string
	Got  int
	Want int
}

func (e authStatusError) Error() string {
	return fmt.Sprintf("%s status %d, want %d", e.Step, e.Got, e.Want)
}

func topLevelJSONKeys(body []byte) ([]string, error) {
	var object map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("top-level JSON object required")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("one JSON value required")
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func containsAll(got, want []string) bool {
	have := make(map[string]bool, len(got))
	for _, value := range got {
		have[value] = true
	}
	for _, value := range want {
		if !have[value] {
			return false
		}
	}
	return true
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
