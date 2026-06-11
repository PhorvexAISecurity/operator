/*
 * Phorvex Console (P4a) — SSRF-HARDENED server-side fetch (the highest-severity P4a fix).
 *
 * /api/metrics?url= passes a caller-controlled URL to a server-side GET. Without this,
 * a caller could reach cloud-metadata (IMDS 169.254.169.254 -> IAM credential theft) or
 * internal endpoints. This module: enforces http/https; resolves the host; BLOCKS
 * link-local/metadata/unspecified/multicast ALWAYS; ALLOWS loopback (the operator's own
 * /metrics); requires an explicit allowlist for any other (private/remote) host; and
 * DIAL-PINS to the validated IP so a DNS-rebind cannot swap the target after validation.
 * GET-only, no redirects, bounded. The console must stay localhost-bound until real authn
 * ([PENDING-P-VCLUSTER]); this closes the SSRF regardless.
 */

package console

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// blockedTarget reports IPs a server-side fetch must NEVER reach: cloud-metadata /
// link-local / unspecified / multicast. Loopback is intentionally NOT blocked here (the
// operator's own /metrics); private ranges are gated by the allowlist, not blocked outright.
func blockedTarget(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true // catches IPv4 IMDS 169.254.169.254 (link-local)
	}
	// AWS IPv6 IMDS fd00:ec2::254 lives in fd00:ec2::/32.
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil && v6[0] == 0xfd && v6[1] == 0x00 && v6[2] == 0xec && v6[3] == 0x02 {
		return true
	}
	return false
}

// validateFetchTarget parses rawURL, enforces http/https, resolves the host, blocks
// metadata/link-local ALWAYS, allows loopback, and requires the allowlist for any other
// host. Returns the validated dial "ip:port" to pin the connection to.
func validateFetchTarget(rawURL string, allow []string) (dialIP string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("url scheme must be http or https")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("url has no host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
	if lerr != nil || len(ips) == 0 {
		return "", fmt.Errorf("cannot resolve host %q", host)
	}
	allLoopback := true
	for _, ipa := range ips {
		if blockedTarget(ipa.IP) {
			return "", fmt.Errorf("target blocked: %s resolves to a metadata/link-local address (%s)", host, ipa.IP)
		}
		if !ipa.IP.IsLoopback() {
			allLoopback = false
		}
	}
	hostport := net.JoinHostPort(host, port)
	dial := net.JoinHostPort(ips[0].IP.String(), port)
	if allLoopback {
		return dial, nil
	}
	for _, a := range allow {
		if a == host || a == hostport {
			return dial, nil
		}
	}
	return "", fmt.Errorf("target %q is not on the metrics allowlist (loopback is allowed by default; add private/remote Prometheus hosts via --metrics-allow)", hostport)
}

// safeGet performs an SSRF-hardened GET: validate the target, DIAL-PIN to the validated IP
// (defeats DNS rebinding), GET-only, no redirects, 3s timeout. Callers cap the body.
func safeGet(rawURL string, allow []string) (*http.Response, error) {
	dialIP, err := validateFetchTarget(rawURL, allow)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		// Ignore the address the URL asks for; connect ONLY to the pre-validated IP.
		DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", dialIP)
		},
		DisableKeepAlives: true,
	}
	cl := &http.Client{
		Timeout:       3 * time.Second,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // no redirect-based SSRF
	}
	return cl.Get(rawURL)
}
