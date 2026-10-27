package servingbudget

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	core "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type bucket struct {
	tokens float64
	at     time.Time
}

// Proxy owns the aggregate buckets. Only one live proxy incarnation is supported.
// Identity comes from the socket peer and an API-derived Pod IP/ServiceAccount map;
// X-Forwarded-For and caller-supplied identity headers have no authority.
type Proxy struct {
	mu                                        sync.Mutex
	status                                    Status
	identities                                map[string]string
	synced                                    time.Time
	abusive                                   bucket
	quietSince                                time.Time
	lastSample                                time.Time
	lastAttempted                             uint64
	calibrationAbusive, calibrationLegitimate uint64
	forward                                   http.Handler
	now                                       func() time.Time
}

func NewProxy(backend, podUID string) (*Proxy, error) {
	u, e := url.Parse(backend)
	if e != nil || u.Scheme != "http" || u.Host == "" {
		return nil, errors.New("invalid fixed backend")
	}
	seed := make([]byte, 16)
	if _, e = rand.Read(seed); e != nil {
		return nil, e
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 256, ResponseHeaderTimeout: 5 * time.Second}
	return &Proxy{status: Status{PodUID: podUID, BootID: hex.EncodeToString(seed)}, identities: map[string]string{}, forward: rp, now: time.Now}, nil
}
func (p *Proxy) Apply(c Contract, configUID string, identities map[string]string, now time.Time) error {
	if !c.Valid() || configUID == "" {
		return errors.New("invalid config")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status.ConfigUID != "" && p.status.ConfigUID != configUID {
		return errors.New("config incarnation changed; restart required")
	}
	if p.status.ConfigUID != "" && (p.status.Contract.SourceSHA256 != c.SourceSHA256 || p.status.Contract.ProxyImage != c.ProxyImage || p.status.Contract.AbusiveAccount != c.AbusiveAccount || p.status.Contract.LegitimateAccount != c.LegitimateAccount || p.status.Contract.Path != c.Path) {
		return errors.New("identity contract changed; restart required")
	}
	if c.Enabled && p.status.ConfigUID == "" {
		p.status.Baseline = c.Baseline
		p.status.Reserved = c.Reserved
		p.status.CalibrationStart = c.CalibrationStart
		p.status.CalibrationEnd = c.CalibrationEnd
	}
	if c.Enabled && (c.Baseline != p.status.Baseline || c.Reserved != p.status.Reserved || p.status.CalibrationEnd.IsZero()) {
		return errors.New("budget differs from measured calibration")
	}
	if c.Enabled != p.status.Contract.Enabled || c.Revision != p.status.Contract.Revision {
		p.abusive = bucket{tokens: c.Burst, at: now}
		p.status.ReleasedAt = time.Time{}
		p.status.ReleaseReason = ""
		p.quietSince = time.Time{}
		p.lastSample = now
		p.lastAttempted = p.status.Abusive.Attempted
	}
	if c.Calibrating && !p.status.Contract.Calibrating {
		p.status.CalibrationStart = now
		p.status.CalibrationEnd = time.Time{}
		p.status.Baseline = 0
		p.status.Reserved = 0
		p.calibrationAbusive = p.status.Abusive.Admitted
		p.calibrationLegitimate = p.status.Legitimate.Admitted
	}
	p.status.ConfigUID = configUID
	p.status.Contract = c
	p.identities = identities
	p.synced = now
	p.releaseIfQuiet(now)
	if c.Calibrating && p.status.CalibrationStart.IsZero() {
		p.status.CalibrationStart = now
	}
	if c.Calibrating && p.status.CalibrationEnd.IsZero() && now.Sub(p.status.CalibrationStart) >= Horizon {
		elapsed := now.Sub(p.status.CalibrationStart).Seconds()
		// Preserve the measured finite request-per-second budget over the quiet
		// window. An idle class remains zero and cannot authorize an action.
		p.status.Baseline = float64(p.status.Abusive.Admitted-p.calibrationAbusive) / elapsed
		p.status.Reserved = float64(p.status.Legitimate.Admitted-p.calibrationLegitimate) / elapsed
		p.status.CalibrationEnd = now
	}
	return nil
}

// releaseIfQuiet runs under the mutex at successful identity refreshes only.
// Missing samples cannot establish quiet. Once released, repeated reads of the
// same durable revision cannot reactivate the cap. Its absolute lease also expires
// without the detector, brain or API being available.
func (p *Proxy) releaseIfQuiet(now time.Time) {
	c := p.status.Contract
	if !c.Enabled || !p.status.ReleasedAt.IsZero() {
		return
	}
	if !now.Before(c.ExpiresAt) {
		p.status.ReleasedAt, p.status.ReleaseReason = now, "lease-expired"
		return
	}
	dt := now.Sub(p.lastSample)
	if dt > 0 {
		if dt > 5*time.Second || p.status.Abusive.Attempted < p.lastAttempted ||
			float64(p.status.Abusive.Attempted-p.lastAttempted)/dt.Seconds() > 3*c.Baseline {
			p.quietSince = time.Time{}
		} else {
			if p.quietSince.IsZero() {
				p.quietSince = p.lastSample
			}
			if now.Sub(p.quietSince) >= Horizon {
				p.status.ReleasedAt, p.status.ReleaseReason = now, "quiet-window"
			}
		}
		p.lastSample, p.lastAttempted = now, p.status.Abusive.Attempted
	}
}
func (p *Proxy) capActive(now time.Time) bool {
	return p.status.Contract.Enabled && now.Before(p.status.Contract.ExpiresAt) && p.status.ReleasedAt.IsZero()
}
func (p *Proxy) Snapshot(now time.Time) Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.status
	s.CapActive = p.capActive(now)
	s.UpdatedAt = now
	return s
}
func take(b *bucket, rate, burst float64, now time.Time) bool {
	elapsed := now.Sub(b.at).Seconds()
	if elapsed < 0 {
		return false
	}
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) {
	if w.code == 0 {
		w.code = c
		w.ResponseWriter.WriteHeader(c)
	}
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := p.now()
	p.mu.Lock()
	if now.Sub(p.synced) > 5*time.Second || p.status.ConfigUID == "" {
		p.mu.Unlock()
		http.Error(w, "admission identity unavailable", 503)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	identity := p.identities[host]
	c := p.status.Contract
	if err != nil || identity == "" || r.URL.Path != c.Path {
		p.mu.Unlock()
		http.Error(w, "unattributed admission path", 403)
		return
	}
	var counts *Counts
	var b *bucket
	var rate, burst float64
	switch identity {
	case c.AbusiveAccount:
		counts = &p.status.Abusive
		b = &p.abusive
		rate = c.Baseline
		burst = c.Burst
	case c.LegitimateAccount:
		counts = &p.status.Legitimate
		// Reserved is the measured quiet floor, never a legitimate ceiling.
		// Legitimate growth and bursts retain all available backend headroom.
	default:
		p.mu.Unlock()
		http.Error(w, "unconfigured caller", 403)
		return
	}
	counts.Attempted++
	if identity == c.AbusiveAccount && p.capActive(now) && !take(b, rate, burst, now) {
		counts.Rejected++
		p.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "serving budget exhausted", 429)
		return
	}
	counts.Admitted++
	p.mu.Unlock()
	sw := &statusWriter{ResponseWriter: w}
	p.forward.ServeHTTP(sw, r)
	if sw.code == 200 {
		p.mu.Lock()
		counts.OK++
		p.mu.Unlock()
	}
}

// Sync reads only the named control ConfigMap and the namespace's IP identity
// inventory, then publishes effective state. A failed refresh cannot keep stale
// peer identities alive. Status is not advanced when the contract cannot apply.
func (p *Proxy) Sync(ctx context.Context, c client.Client, ns string) error {
	var cm core.ConfigMap
	if e := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ConfigName}, &cm); e != nil {
		return e
	}
	contract, e := Parse(cm.Data[Key])
	if e != nil {
		return e
	}
	var pods core.PodList
	if e = c.List(ctx, &pods, client.InNamespace(ns)); e != nil {
		return e
	}
	ids := map[string]string{}
	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" && pod.DeletionTimestamp == nil && pod.Status.Phase == core.PodRunning && !pod.Spec.HostNetwork {
			sa := pod.Spec.ServiceAccountName
			if sa == "" {
				sa = "default"
			}
			ids[pod.Status.PodIP] = "system:serviceaccount:" + ns + ":" + sa
		}
	}
	now := p.now()
	if e = p.Apply(contract, string(cm.UID), ids, now); e != nil {
		return e
	}
	var status core.ConfigMap
	if e = c.Get(ctx, client.ObjectKey{Namespace: ns, Name: StatusName}, &status); e != nil {
		return e
	}
	if status.Data == nil {
		status.Data = map[string]string{}
	}
	status.Data[Key] = Encode(p.Snapshot(now))
	return c.Update(ctx, &status)
}
