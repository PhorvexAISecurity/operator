/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PCIe link capacity discovery (PHORVEXSEC-197 / M-114). The LinkBandwidth denominator used
// to be one hard-coded number — the Tesla T4's Gen3 x16 aggregate — applied to every device.
// Now the denominator is DISCOVERED, in this order, and never chosen:
//
//  1. the device's negotiated link (DCGM_FI_DEV_PCIE_LINK_GEN × _WIDTH) through the PCIe spec
//     table below — published per-lane rates, keyed by generation, not by product name;
//  2. an explicit hardware-class table from the chart, keyed by the exporter's own
//     `modelName` label (a discovered identity, not an assumption) — for exporters that do not
//     publish link gen/width (the live dcgm-exporter counter list does not, PHORVEXSEC-138);
//  3. neither → the signal is ABSENT with a reason (T1-C), never the T4 number.
//
// The numerator sums RX and TX, so the capacity is the aggregate of both directions. On a
// MIG-partitioned device the link is shared by every instance: the capacity is the physical
// device's and the record says so (LinkCapacitySource); it is never divided per instance.

// pcieLaneBytesPerSec is the usable per-lane, per-direction payload rate by PCIe generation.
// Source: PCI-SIG base specifications — Gen1 2.5 GT/s and Gen2 5 GT/s with 8b/10b encoding
// (×0.8); Gen3 8 GT/s, Gen4 16 GT/s, Gen5 32 GT/s with 128b/130b encoding (×128/130).
// Gen3 x16 = 16 × 0.98462 GB/s = 15.754 GB/s per direction — exactly the T4 figure the old
// constant carried, so an all-T4 fleet is predicted to read byte-identically.
var pcieLaneBytesPerSec = map[int]float64{
	1: 2.5e9 / 8 * 0.8,
	2: 5.0e9 / 8 * 0.8,
	3: 8.0e9 / 8 * 128.0 / 130.0,
	4: 16.0e9 / 8 * 128.0 / 130.0,
	5: 32.0e9 / 8 * 128.0 / 130.0,
}

// PCIeLink is a negotiated (or class-declared) link: generation and lane width.
type PCIeLink struct {
	Gen   int `json:"gen"`
	Width int `json:"width"`
}

// PCIeCapacityBytesPerSec is the RX+TX aggregate capacity of a link, or (0,false) for an
// unknown generation / non-positive width.
func PCIeCapacityBytesPerSec(l PCIeLink) (float64, bool) {
	rate, ok := pcieLaneBytesPerSec[l.Gen]
	if !ok || l.Width <= 0 {
		return 0, false
	}
	return 2 * float64(l.Width) * rate, true
}

// PCIeClassTable maps the exporter's device model name (DCGM `modelName`) to its link. It is
// chart configuration (phorvex.gpu.pcieClassCapacity), the second discovery step.
type PCIeClassTable map[string]PCIeLink

// DefaultPCIeClassTable is the shipped table: the one device class the fleet has been
// measured on. Tesla T4 is PCIe 3.0 x16 (NVIDIA T4 datasheet).
func DefaultPCIeClassTable() PCIeClassTable {
	return PCIeClassTable{"Tesla T4": {Gen: 3, Width: 16}}
}

// ParsePCIeClassTable parses the chart value (JSON object modelName -> {gen,width}); empty
// input yields the shipped default. Merges over the default so a site can add classes.
func ParsePCIeClassTable(raw string) (PCIeClassTable, error) {
	out := DefaultPCIeClassTable()
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	var extra map[string]PCIeLink
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		return nil, fmt.Errorf("pcie class table: %w", err)
	}
	for k, v := range extra {
		if _, ok := PCIeCapacityBytesPerSec(v); !ok {
			return nil, fmt.Errorf("pcie class table: %q has an unsupported link gen=%d width=%d", k, v.Gen, v.Width)
		}
		out[k] = v
	}
	return out, nil
}

// PCIe capacity sources for the record.
const (
	PCIeSourceLink   = "dcgm-link"    // negotiated gen × width from DCGM_FI_DEV_PCIE_LINK_*
	PCIeSourceClass  = "class-config" // chart hardware-class table keyed by modelName
	PCIeSourceAbsent = "absent"       // undiscoverable: signal absent, never a borrowed number
)

// PCIeCapacity resolves the denominator in the ruled order. negotiated is the device's
// current link when the exporter published it (zero value = unknown); model is the
// exporter's modelName label ("" = unknown).
func PCIeCapacity(negotiated PCIeLink, model string, classes PCIeClassTable) (capacity float64, link PCIeLink, source, reason string) {
	if c, ok := PCIeCapacityBytesPerSec(negotiated); ok {
		return c, negotiated, PCIeSourceLink, ""
	}
	if l, ok := classes[model]; ok && model != "" {
		if c, ok := PCIeCapacityBytesPerSec(l); ok {
			return c, l, PCIeSourceClass, ""
		}
	}
	switch {
	case model == "":
		return 0, PCIeLink{}, PCIeSourceAbsent, "pcie-capacity-undiscoverable: no link telemetry and no device model label"
	default:
		return 0, PCIeLink{}, PCIeSourceAbsent, "pcie-capacity-undiscoverable: no link telemetry and no class entry for " + model
	}
}
