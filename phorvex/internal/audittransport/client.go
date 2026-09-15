package audittransport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type ClientConfig struct{ URL, ServerDNSName, CertFile, KeyFile, CAFile string }
type Client struct{ cfg ClientConfig }

func NewClient(c ClientConfig) (*Client, error) {
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("audit source must be a bare HTTPS origin")
	}
	if c.ServerDNSName == "" || c.CertFile == "" || c.KeyFile == "" || c.CAFile == "" {
		return nil, errors.New("incomplete audit client TLS configuration")
	}
	return &Client{cfg: c}, nil
}

// A fresh TLS transport on each request reloads mounted certificate files and
// validates the server on every connection. It avoids retaining a connection
// authorized by a certificate that was rotated or revoked after the last read.
func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	ca, e := certPool(c.cfg.CAFile)
	if e != nil {
		return nil, e
	}
	cert, e := tls.LoadX509KeyPair(c.cfg.CertFile, c.cfg.KeyFile)
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca, ServerName: c.cfg.ServerDNSName, Certificates: []tls.Certificate{cert}}, DisableKeepAlives: true, ResponseHeaderTimeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", c.cfg.URL+path, nil)
	if e != nil {
		return nil, e
	}
	return (&http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
}

func (c *Client) Manifest(ctx context.Context) (Manifest, error) {
	resp, e := c.get(ctx, "/v1/manifest")
	if e != nil {
		return Manifest{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("audit source manifest: HTTP %d", resp.StatusCode)
	}
	var m Manifest
	dec := json.NewDecoder(io.LimitReader(resp.Body, 8192))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&m); e != nil {
		return Manifest{}, e
	}
	if len(m.Segments) == 0 || len(m.Segments) > 2*(MaxSegments+1) {
		return Manifest{}, errors.New("invalid audit manifest segment count")
	}
	if m.Segments[0].ID != "live" {
		return Manifest{}, errors.New("live audit segment is missing")
	}
	observed := time.Unix(0, m.FetchedAt)
	if observed.IsZero() || time.Since(observed) > 10*time.Second || observed.After(time.Now().Add(2*time.Second)) {
		return Manifest{}, errors.New("audit manifest observation is stale or clock-skewed")
	}
	seen := map[string]bool{}
	for _, s := range m.Segments {
		if s.Size < 0 || s.Generation == "" || s.Anchor == "" || seen[s.ID] {
			return Manifest{}, errors.New("invalid audit manifest segment")
		}
		seen[s.ID] = true
	}
	return m, nil
}

func (c *Client) Chunk(ctx context.Context, s Segment, off int64) ([]byte, error) {
	if off < 0 || off > s.Size {
		return nil, errors.New("invalid audit chunk offset")
	}
	path := "/v1/segment/" + url.PathEscape(s.ID) + "?generation=" + url.QueryEscape(s.Generation) + "&anchor=" + url.QueryEscape(s.Anchor) + "&offset=" + strconv.FormatInt(off, 10) + "&size=" + strconv.FormatInt(s.Size, 10)
	resp, e := c.get(ctx, path)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit segment changed or unavailable: HTTP %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Audit-Generation") != s.Generation {
		return nil, errors.New("audit segment generation mismatch")
	}
	if resp.Header.Get("X-Audit-Size") != strconv.FormatInt(s.Size, 10) {
		return nil, errors.New("audit segment size changed during read")
	}
	n := min(int64(ChunkBytes), s.Size-off)
	b, e := io.ReadAll(io.LimitReader(resp.Body, ChunkBytes+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != n {
		return nil, errors.New("audit segment size changed during read")
	}
	return b, nil
}

func (c *Client) Probe() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.ProbeContext(ctx)
}
func (c *Client) ProbeContext(ctx context.Context) error { _, e := c.Manifest(ctx); return e }
