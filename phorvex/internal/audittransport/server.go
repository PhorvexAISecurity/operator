package audittransport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const ChunkBytes = 1 << 20
const MaxSegments = 16

type Segment struct {
	ID         string `json:"id"`
	Generation string `json:"generation"`
	Size       int64  `json:"size"`
	Anchor     string `json:"anchor"`
}
type Manifest struct {
	Segments  []Segment `json:"segments"`
	FetchedAt int64     `json:"fetchedAt"`
}

type ServerConfig struct {
	Addr, AuditPath, CertFile, KeyFile, CAFile, ClientDNSName string
	VClusterAuditPath                                         string
	MaxBackups                                                int
}

func certPool(path string) (*x509.CertPool, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid audit CA")
	}
	return p, nil
}

func (c ServerConfig) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cert, e := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if e != nil {
			return nil, e
		}
		ca, e := certPool(c.CAFile)
		if e != nil {
			return nil, e
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca, VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) < 1 {
				return errors.New("audit client must present a certificate")
			}
			if e := cs.PeerCertificates[0].VerifyHostname(c.ClientDNSName); e != nil {
				return fmt.Errorf("audit client identity: %w", e)
			}
			return nil
		}}, nil
	}}
}

// TLSConfig is also used by in-process integration fixtures; production
// listeners use Start so the same peer checks cannot be bypassed.
func (c ServerConfig) TLSConfig() *tls.Config { return c.tlsConfig() }

func regular(path string) (*os.File, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("audit segment is not regular")
	}
	return f, nil
}

func prefixAnchor(f *os.File, n int64) (string, error) {
	b := make([]byte, n)
	if n > 0 {
		if _, e := f.ReadAt(b, 0); e != nil {
			return "", e
		}
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16]), nil
}

func generation(f *os.File) (string, int64, string, error) {
	s, e := f.Stat()
	if e != nil {
		return "", 0, "", e
	}
	id, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return "", 0, "", errors.New("audit inode unavailable")
	}
	a, e := prefixAnchor(f, min(s.Size(), int64(256)))
	return fmt.Sprintf("%x-%x", id.Dev, id.Ino), s.Size(), a, e
}

func (c ServerConfig) segmentPath(id string) (string, bool) {
	if strings.HasPrefix(id, "vcluster-") {
		if c.VClusterAuditPath == "" {
			return "", false
		}
		other := c
		other.AuditPath = c.VClusterAuditPath
		other.VClusterAuditPath = ""
		return other.segmentPath(strings.TrimPrefix(id, "vcluster-"))
	}
	if id == "live" {
		return c.AuditPath, true
	}
	if !strings.HasPrefix(id, "backup-") {
		return "", false
	}
	n, e := strconv.Atoi(strings.TrimPrefix(id, "backup-"))
	if e != nil || n < 1 || n > c.MaxBackups || n > MaxSegments {
		return "", false
	}
	if id != "backup-"+strconv.Itoa(n) {
		return "", false
	}
	return c.AuditPath + "." + strconv.Itoa(n), true
}

func (c ServerConfig) openPinned(prefix, g, anchor string, target int64) (*os.File, int64, error) {
	if prefix != "" && c.VClusterAuditPath == "" {
		return nil, 0, errors.New("provider audit unavailable")
	}
	for i := 0; i <= min(c.MaxBackups, MaxSegments); i++ {
		id := prefix + "live"
		if i > 0 {
			id = prefix + "backup-" + strconv.Itoa(i)
		}
		path, _ := c.segmentPath(id)
		f, e := regular(path)
		if e != nil {
			continue
		}
		actual, size, _, e := generation(f)
		if e == nil && actual == g && size >= target {
			captured, anchorErr := prefixAnchor(f, min(target, int64(256)))
			if anchorErr == nil && captured == anchor {
				return f, size, nil
			}
		}
		f.Close()
	}
	return nil, 0, errors.New("audit generation no longer retained")
}

func (c ServerConfig) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/manifest", func(w http.ResponseWriter, r *http.Request) {
		m := Manifest{FetchedAt: time.Now().UnixNano()}
		for _, prefix := range []string{"", "vcluster-"} {
			if prefix != "" && c.VClusterAuditPath == "" {
				continue
			}
			for i := 0; i <= min(c.MaxBackups, MaxSegments); i++ {
				id := prefix + "live"
				if i > 0 {
					id = prefix + "backup-" + strconv.Itoa(i)
				}
				p, _ := c.segmentPath(id)
				f, e := regular(p)
				if errors.Is(e, os.ErrNotExist) {
					continue
				}
				if e != nil {
					http.Error(w, "audit source unavailable", http.StatusServiceUnavailable)
					return
				}
				g, size, anchor, e := generation(f)
				f.Close()
				if e != nil {
					http.Error(w, "audit source unavailable", http.StatusServiceUnavailable)
					return
				}
				m.Segments = append(m.Segments, Segment{ID: id, Generation: g, Size: size, Anchor: anchor})
			}
		}
		if len(m.Segments) == 0 {
			http.Error(w, "audit source unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	})
	mux.HandleFunc("GET /v1/segment/{id}", func(w http.ResponseWriter, r *http.Request) {
		path, ok := c.segmentPath(r.PathValue("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		g := r.URL.Query().Get("generation")
		anchor := r.URL.Query().Get("anchor")
		off, e := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		target, targetErr := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
		if g == "" || len(anchor) != 32 || e != nil || off < 0 || targetErr != nil || target < 0 || off > target {
			http.Error(w, "invalid audit boundary", http.StatusBadRequest)
			return
		}
		_ = path // path identifier was validated; generation can move on rotation.
		prefix := ""
		if strings.HasPrefix(r.PathValue("id"), "vcluster-") {
			prefix = "vcluster-"
		}
		f, _, e := c.openPinned(prefix, g, anchor, target)
		if e != nil {
			http.Error(w, "audit segment changed", http.StatusConflict)
			return
		}
		defer f.Close()
		n := min(int64(ChunkBytes), target-off)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Audit-Generation", g)
		w.Header().Set("X-Audit-Size", strconv.FormatInt(target, 10))
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		if n > 0 {
			_, e = io.CopyN(w, io.NewSectionReader(f, off, n), n)
			if e != nil {
				return
			}
		}
	})
	limited := make(chan struct{}, 4)
	bounded := http.TimeoutHandler(mux, 8*time.Second, "audit read timeout")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case limited <- struct{}{}:
			defer func() { <-limited }()
		case <-r.Context().Done():
			return
		default:
			http.Error(w, "audit reader limit reached", http.StatusServiceUnavailable)
			return
		}
		bounded.ServeHTTP(w, r)
	})
}

func (c ServerConfig) Start() (*http.Server, error) {
	if c.Addr == "" || c.AuditPath == "" || c.CertFile == "" || c.KeyFile == "" || c.CAFile == "" || c.ClientDNSName == "" || c.MaxBackups < 0 || c.MaxBackups > MaxSegments {
		return nil, errors.New("incomplete audit transport configuration")
	}
	if !filepath.IsAbs(c.AuditPath) {
		return nil, errors.New("audit path must be absolute")
	}
	if c.VClusterAuditPath != "" && !filepath.IsAbs(c.VClusterAuditPath) {
		return nil, errors.New("vCluster audit path must be absolute")
	}
	if _, e := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); e != nil {
		return nil, e
	}
	if _, e := certPool(c.CAFile); e != nil {
		return nil, e
	}
	ln, e := net.Listen("tcp", c.Addr)
	if e != nil {
		return nil, e
	}
	s := &http.Server{Handler: c.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = s.Serve(tls.NewListener(ln, c.tlsConfig())) }()
	return s, nil
}
