// Package sensorconfig holds the command-line configuration of the cluster
// projection: detector and observer trust, the reviewed endpoint lease authority,
// telemetry and the EPSS feed. The manager and the sensor service register the
// same flags and apply them the same way, and the sensor handshake compares the
// part the dispatcher also reads (ADR-0001).
package sensorconfig

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/phorvex/phorvex/cmd/internal/trustconfig"
	"github.com/phorvex/phorvex/internal/epssmeta"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// Flags is the projection's configuration. The detector trust and the endpoint
// lease authority are shared with the actuator (trustconfig).
type Flags struct {
	trustconfig.Trust
	TrustedLossObservers             string
	TrustedCurrentInventoryObservers string
	PrometheusURL                    string
	PCIeClassTable                   string
	EPSS                             EPSS
}

// EPSS configures the exploitability feed of the physics witness.
type EPSS struct {
	CachePath            string
	Refresh              time.Duration
	Authoritative        bool
	MetadataPath         string
	CacheKey             string
	ConfigMapNamespace   string
	ConfigMapName        string
	MetadataKey          string
	AuthoritativeTimeout time.Duration
	ScopeNamespaces      string
	ScopeDigests         string
}

// Register defines the flags on fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.PCIeClassTable, "pcie-class-table", os.Getenv("PHORVEX_PCIE_CLASS_TABLE"), "JSON map of DCGM modelName -> {gen,width} used as the PCIe capacity fallback when the exporter publishes no link gen/width (M-114). Merged over the shipped default {\"Tesla T4\":{\"gen\":3,\"width\":16}}.")
	f.Trust.Register(fs)
	fs.StringVar(&f.TrustedLossObservers, "trusted-loss-observers", os.Getenv("PHORVEX_TRUSTED_LOSS_OBSERVERS"), "Comma-separated dedicated ServiceAccount identities allowed to create synthetic completed-disclosure evidence. General detector trust does not grant this authority.")
	fs.StringVar(&f.TrustedCurrentInventoryObservers, "trusted-current-inventory-observers", os.Getenv("PHORVEX_TRUSTED_CURRENT_INVENTORY_OBSERVERS"), "Comma-separated dedicated ServiceAccount identities allowed to create synthetic current protected-version observations.")
	fs.StringVar(&f.PrometheusURL, "prometheus-url", "", "Prometheus base URL for telemetry ingest (empty = no telemetry, K8s-only signals).")
	e := &f.EPSS
	fs.StringVar(&e.CachePath, "epss-cache", os.Getenv("PHORVEX_EPSS_CACHE"), "Path to a JSON image-digest->{epss,cvss} exploitability cache (scanner/NVD-FIRST export). Empty/missing = EPSS honest-absent (1.0).")
	fs.DurationVar(&e.Refresh, "epss-cache-refresh", 0, "Re-read --epss-cache at this interval so a scanner pipeline that owns the ConfigMap is actually observed (0 = read once at startup, the previous behaviour). A failed read keeps the existing cache.")
	fs.BoolVar(&e.Authoritative, "epss-authoritative", false, "Require mounted EPSS cache and metadata to match the current ConfigMap API object before use.")
	fs.StringVar(&e.MetadataPath, "epss-metadata", "", "[epss-authoritative] path to canonical provenance metadata beside --epss-cache.")
	fs.StringVar(&e.CacheKey, "epss-cache-key", "epss-cache.json", "[epss-authoritative] source ConfigMap cache data key.")
	fs.StringVar(&e.ConfigMapNamespace, "epss-configmap-namespace", os.Getenv("POD_NAMESPACE"), "[epss-authoritative] namespace of the source ConfigMap.")
	fs.StringVar(&e.ConfigMapName, "epss-configmap-name", "phorvex-epss", "[epss-authoritative] source ConfigMap name.")
	fs.StringVar(&e.MetadataKey, "epss-metadata-key", "epss-metadata.json", "EPSS provenance metadata ConfigMap key.")
	fs.DurationVar(&e.AuthoritativeTimeout, "epss-authoritative-timeout", 5*time.Second, "Bound for each authoritative EPSS API verification.")
	fs.StringVar(&e.ScopeNamespaces, "epss-authoritative-scope-namespaces", "", "[epss-authoritative] exact namespace authority used by the producer.")
	fs.StringVar(&e.ScopeDigests, "epss-authoritative-scope-digests", "", "[epss-authoritative] exact digest authority used by the producer.")
}

// Describe returns the configuration the sensor handshake compares, with the
// identity lists normalized as the projection reads them.
func (f Flags) Describe() sensorapi.Config {
	return sensorapi.Config{
		TrustedDetectors:                 identities(f.TrustedDetectors).List(),
		TrustedLossObservers:             identities(f.TrustedLossObservers).List(),
		TrustedCurrentInventoryObservers: identities(f.TrustedCurrentInventoryObservers).List(),
		EndpointLeaseApprovedSource:      f.EndpointLeaseApprovedSource,
		EndpointLeaseApprovedProxyImage:  f.EndpointLeaseApprovedProxyImage,
		EndpointLeaseApprovedEngineImage: f.EndpointLeaseApprovedEngineImage,
	}
}

// ApplyTrust installs the endpoint lease authority and the detector and observer
// trust the projection reads.
func (f Flags) ApplyTrust() error {
	if err := ingest.ConfigureEndpointLeaseApprovedAuthority(f.EndpointLeaseApprovedSource, f.EndpointLeaseApprovedProxyImage, f.EndpointLeaseApprovedEngineImage); err != nil {
		return fmt.Errorf("endpoint lease source configuration invalid: %w", err)
	}
	eventtrust.ConfigureEventTrust(identities(f.TrustedDetectors))
	eventtrust.ConfigureCompletedDisclosureTrust(identities(f.TrustedLossObservers))
	eventtrust.ConfigureCurrentInventoryTrust(identities(f.TrustedCurrentInventoryObservers))
	return nil
}

func identities(list string) eventtrust.TrustedDetectors {
	return eventtrust.NewTrustedDetectors(strings.Split(list, ","))
}

// Configure validates the feed and seeds the exploitability cache. A missing or
// unreadable plain cache leaves EPSS honest-absent and is only logged; an
// incomplete authoritative configuration is an error.
func (e EPSS) Configure(log logr.Logger) error {
	if e.Authoritative {
		if e.CachePath == "" || e.MetadataPath == "" || e.CacheKey == "" || e.MetadataKey == "" || e.CacheKey == e.MetadataKey ||
			e.ConfigMapNamespace == "" || e.ConfigMapName == "" || e.Refresh <= 0 || e.AuthoritativeTimeout <= 0 {
			return errors.New("incomplete authoritative EPSS configuration")
		}
		if _, err := e.scope().Canonical(); err != nil {
			return fmt.Errorf("invalid authoritative EPSS scope: %w", err)
		}
		platform.ConfigureAuthoritativeEPSSUnavailable()
		return nil
	}
	if err := platform.LoadEPSSFromFile(e.CachePath); err != nil {
		log.Error(err, "epss-cache load failed (continuing with EPSS honest-absent)", "path", e.CachePath)
	} else if n := platform.EPSSLoaded(); n > 0 {
		log.Info("epss: exploitability cache seeded", "images", n, "path", e.CachePath)
	}
	return nil
}

// Refresher re-reads the cache while running, or returns nil when the cache is read
// once at startup. Off by default: with a hand-curated ConfigMap there is nothing to
// observe, and a startup-only read is the honest description of that. It is turned
// on where a scanner pipeline owns the file (PHVX-14b).
func (e EPSS) Refresher(reader client.Reader, log logr.Logger) manager.Runnable {
	switch {
	case e.Authoritative && e.CachePath != "" && e.Refresh > 0:
		return &platform.AuthoritativeEPSSRefresher{CachePath: e.CachePath, MetadataPath: e.MetadataPath,
			Namespace: e.ConfigMapNamespace, ConfigMapName: e.ConfigMapName, CacheKey: e.CacheKey, MetadataKey: e.MetadataKey,
			Scope: e.scope(), Reader: reader, Interval: e.Refresh, Timeout: e.AuthoritativeTimeout,
			OnReload: func(entries int, changed bool) {
				if changed {
					log.Info("epss: authoritative snapshot published", "images", entries)
				}
			},
			OnError: func(err error) { log.Error(err, "epss: authoritative refresh unavailable") }}
	case e.CachePath != "" && e.Refresh > 0:
		log.Info("epss: cache refresh enabled", "interval", e.Refresh, "path", e.CachePath)
		return &platform.EPSSRefresher{
			Path:     e.CachePath,
			Interval: e.Refresh,
			OnReload: func(entries int, changed bool) {
				if changed {
					log.Info("epss: exploitability cache reloaded", "images", entries, "path", e.CachePath)
				}
			},
			OnError: func(err error) {
				log.Error(err, "epss-cache refresh failed (previous cache kept in force)", "path", e.CachePath)
			},
		}
	}
	return nil
}

func (e EPSS) scope() epssmeta.Scope {
	return epssmeta.Scope{Namespaces: splitNonempty(e.ScopeNamespaces), Digests: splitNonempty(e.ScopeDigests)}
}

func splitNonempty(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
