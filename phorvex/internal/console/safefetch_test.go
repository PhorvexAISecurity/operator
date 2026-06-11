package console

import "testing"

// TestSSRFGuard — the P4a highest-severity fix. Caller-controlled URLs that resolve to
// cloud-metadata / link-local / disallowed hosts are REJECTED; loopback is allowed.
func TestSSRFGuard(t *testing.T) {
	cases := []struct {
		url     string
		allow   []string
		blocked bool
	}{
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil, true}, // AWS IMDS
		{"http://169.254.169.254/", nil, true},
		{"http://[fd00:ec2::254]/latest/meta-data/", nil, true}, // IPv6 IMDS
		{"http://metadata.google.internal/computeMetadata/v1/", nil, true}, // GCP metadata (resolves link-local or not at all)
		{" file:///etc/passwd", nil, true}, // non-http scheme
		{"gopher://127.0.0.1:6379/", nil, true},
		{"http://10.0.0.5:9090/metrics", nil, true},      // RFC1918, not allowlisted
		{"http://10.0.0.5:9090/metrics", []string{"10.0.0.5:9090"}, false}, // RFC1918 but allowlisted
		{"http://127.0.0.1:18080/metrics", nil, false},   // loopback — allowed
		{"http://localhost:18080/metrics", nil, false},   // loopback name — allowed
	}
	for _, c := range cases {
		_, err := validateFetchTarget(c.url, c.allow)
		gotBlocked := err != nil
		if gotBlocked != c.blocked {
			t.Errorf("validateFetchTarget(%q, %v): blocked=%v, want %v (err=%v)", c.url, c.allow, gotBlocked, c.blocked, err)
		}
	}
}
