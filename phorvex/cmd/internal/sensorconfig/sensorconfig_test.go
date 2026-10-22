package sensorconfig

import (
	"encoding/json"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/platform"
)

func parse(t *testing.T, args ...string) Flags {
	t.Helper()
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDescribeNormalizesTheTrustedIdentities(t *testing.T) {
	a := parse(t, "--trusted-detectors=vllm/b, vllm/a,,vllm/a", "--trusted-loss-observers=ops/loss")
	b := parse(t, "--trusted-detectors=vllm/a,vllm/b", "--trusted-loss-observers=ops/loss")
	if a.Describe().SHA256() != b.Describe().SHA256() {
		t.Fatalf("the same identities describe differently: %+v vs %+v", a.Describe(), b.Describe())
	}
	if got := a.Describe().TrustedDetectors; strings.Join(got, ",") != strings.Join(eventtrust.NewTrustedDetectors([]string{"vllm/a", "vllm/b"}).List(), ",") {
		t.Fatalf("detectors = %v", got)
	}
	c := parse(t, "--trusted-detectors=vllm/a,vllm/b")
	if c.Describe().SHA256() == a.Describe().SHA256() {
		t.Fatal("dropping a loss observer must change the configuration")
	}
}

func TestApplyTrustInstallsWhatItDescribes(t *testing.T) {
	f := parse(t, "--trusted-detectors=vllm/detector")
	if err := f.ApplyTrust(); err != nil {
		t.Fatal(err)
	}
	if got := eventtrust.EventTrust().List(); strings.Join(got, ",") != strings.Join(f.Describe().TrustedDetectors, ",") {
		t.Fatalf("installed detectors %v, described %v", got, f.Describe().TrustedDetectors)
	}
	bad := parse(t, "--endpoint-lease-approved-source-sha256=not-a-digest")
	if err := bad.ApplyTrust(); err == nil {
		t.Fatal("an invalid endpoint lease source was accepted")
	}
	if err := parse(t).ApplyTrust(); err != nil {
		t.Fatal(err)
	}
}

func TestEPSSConfigurationAndRefresher(t *testing.T) {
	if err := (EPSS{Authoritative: true, CachePath: "/cache"}).Configure(logr.Discard()); err == nil {
		t.Fatal("incomplete authoritative EPSS accepted")
	}
	complete := EPSS{Authoritative: true, CachePath: "/cache", MetadataPath: "/meta", CacheKey: "c", MetadataKey: "m",
		ConfigMapNamespace: "ns", ConfigMapName: "epss", Refresh: time.Minute, AuthoritativeTimeout: time.Second,
		ScopeNamespaces: "vllm", ScopeDigests: "repo@sha256:" + strings.Repeat("a", 64)}
	if err := complete.Configure(logr.Discard()); err != nil {
		t.Fatalf("complete authoritative EPSS refused: %v", err)
	}
	if _, ok := complete.Refresher(nil, logr.Discard()).(*platform.AuthoritativeEPSSRefresher); !ok {
		t.Fatal("authoritative EPSS must refresh from the ConfigMap")
	}
	if _, ok := (EPSS{CachePath: "/cache", Refresh: time.Minute}).Refresher(nil, logr.Discard()).(*platform.EPSSRefresher); !ok {
		t.Fatal("a plain cache with a refresh interval must be re-read")
	}
	if r := (EPSS{CachePath: "/cache"}).Refresher(nil, logr.Discard()); r != nil {
		t.Fatal("a cache without a refresh interval is read once at startup")
	}
	if err := (EPSS{}).Configure(logr.Discard()); err != nil {
		t.Fatalf("no EPSS cache is honest-absent, not an error: %v", err)
	}
}

// The sensor handshake compares the policy scope, as a set.
func TestDescribeComparesThePolicyScope(t *testing.T) {
	var a, b Flags
	a.Scope.Namespaces, b.Scope.Namespaces = "staging-b,staging-a", "staging-a,staging-b"
	if a.Describe().SHA256() != b.Describe().SHA256() {
		t.Fatal("the same scope describes differently")
	}
	if a.Describe().SHA256() == (Flags{}).Describe().SHA256() {
		t.Fatal("a scoped sensor matches an unscoped manager")
	}
}

func TestDescribeComparesTheInjector(t *testing.T) {
	staging := parse(t, "--injector-identity=phorvex-staging/staging-attacks")
	if got := staging.Describe().InjectorIdentity; got != "system:serviceaccount:phorvex-staging:staging-attacks" {
		t.Fatalf("described injector = %q", got)
	}
	if staging.Describe().SHA256() == parse(t).Describe().SHA256() {
		t.Fatal("a sensor with another injector matches a manager with the default")
	}
	// The default describes as it did before the injector was configurable.
	raw, err := json.Marshal(parse(t).Describe())
	if err != nil || strings.Contains(string(raw), "InjectorIdentity") {
		t.Fatalf("default configuration = %s (%v)", raw, err)
	}
	t.Cleanup(func() { _ = eventtrust.ConfigureInjector("") })
	if err := staging.ApplyTrust(); err != nil || eventtrust.Injector() != staging.Describe().InjectorIdentity {
		t.Fatalf("installed injector %q (%v)", eventtrust.Injector(), err)
	}
	if err := parse(t, "--injector-identity=not-a-service-account").ApplyTrust(); err == nil {
		t.Fatal("an invalid injector was accepted")
	}
}
