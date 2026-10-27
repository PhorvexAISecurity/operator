// Package servingbudget is the shared authoritative cost-admission contract.
package servingbudget

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	ConfigName       = "phorvex-serving-rate-budget"
	StatusName       = "phorvex-serving-rate-status"
	JournalName      = "phorvex-throttle-journal"
	Annotation       = "phorvex.ai/serving-rate-observation-v1"
	DetectorIdentity = "system:serviceaccount:costbench-opus:cost-load-detector"
	Source           = "phorvex-cost-load-detector"
	DeploymentName   = "cost-admission"
	ServiceName      = "cost-target"
	BackendName      = "cost-target-backend"
	Key              = "state.json"
	Horizon          = 60 * time.Second
	MaxLease         = 15 * time.Minute
	EventRefresh     = 30 * time.Second
	EventLabel       = "phorvex.ai/cost-load-detector"
)

type Contract struct {
	ActivatedAt       time.Time `json:"activatedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	CalibrationStart  time.Time `json:"calibrationStart"`
	CalibrationEnd    time.Time `json:"calibrationEnd"`
	Version           int       `json:"version"`
	Revision          uint64    `json:"revision"`
	OperationID       string    `json:"operationID"`
	SourceSHA256      string    `json:"sourceSHA256"`
	ProxyImage        string    `json:"proxyImage"`
	AbusiveAccount    string    `json:"abusiveAccount"`
	LegitimateAccount string    `json:"legitimateAccount"`
	Path              string    `json:"path"`
	Calibrating       bool      `json:"calibrating"`
	Enabled           bool      `json:"enabled"`
	Baseline          float64   `json:"baseline"`
	Reserved          float64   `json:"reserved"`
	Burst             float64   `json:"burst"`
}

func Positive(v float64) bool { return v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }
func SHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (c Contract) Valid() bool {
	return c.Version == 1 && SHA(c.SourceSHA256) && ValidImage(c.ProxyImage) && c.AbusiveAccount != "" && c.LegitimateAccount != "" && c.AbusiveAccount != c.LegitimateAccount && c.Path == "/" && (!c.Enabled || !c.ActivatedAt.IsZero() && c.ExpiresAt.After(c.ActivatedAt) && c.ExpiresAt.Sub(c.ActivatedAt) <= MaxLease && !c.Calibrating && Positive(c.Baseline) && Positive(c.Reserved) && Positive(c.Burst) && c.Burst <= math.Max(1, c.Baseline) && !c.CalibrationStart.IsZero() && c.CalibrationEnd.Sub(c.CalibrationStart) >= Horizon && c.OperationID != "")
}
func Parse(raw string) (Contract, error) {
	var c Contract
	err := json.Unmarshal([]byte(raw), &c)
	if err != nil || !c.Valid() {
		return c, errors.New("invalid serving admission contract")
	}
	return c, nil
}
func Approved(c Contract) bool {
	return c.SourceSHA256 == os.Getenv("PHORVEX_THROTTLE_SOURCE_SHA256") && c.ProxyImage == os.Getenv("PHORVEX_THROTTLE_PROXY_IMAGE") && SHA(c.SourceSHA256)
}
func Encode(v any) string { b, _ := json.Marshal(v); return string(b) }

type Counts struct {
	Attempted uint64 `json:"attempted"`
	Admitted  uint64 `json:"admitted"`
	Rejected  uint64 `json:"rejected"`
	OK        uint64 `json:"ok"`
}
type Status struct {
	CapActive        bool      `json:"capActive"`
	ReleasedAt       time.Time `json:"releasedAt"`
	ReleaseReason    string    `json:"releaseReason"`
	PodUID           string    `json:"podUID"`
	BootID           string    `json:"bootID"`
	ConfigUID        string    `json:"configUID"`
	Contract         Contract  `json:"contract"`
	UpdatedAt        time.Time `json:"updatedAt"`
	CalibrationStart time.Time `json:"calibrationStart"`
	CalibrationEnd   time.Time `json:"calibrationEnd"`
	Baseline         float64   `json:"baseline"`
	Reserved         float64   `json:"reserved"`
	Abusive          Counts    `json:"abusive"`
	Legitimate       Counts    `json:"legitimate"`
}

func (s Status) Fresh(now time.Time) bool {
	return s.fresh(now, 0)
}

func (s Status) fresh(now time.Time, futureMargin time.Duration) bool {
	return s.PodUID != "" && s.BootID != "" && s.ConfigUID != "" && s.Contract.Valid() && !s.UpdatedAt.After(now.Add(futureMargin)) && now.Sub(s.UpdatedAt) < 10*time.Second
}
func ParseObservation(raw string) (*model.ServingRateBudgetObservation, error) {
	var o model.ServingRateBudgetObservation
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		return nil, err
	}
	o.EventName = "pending"
	o.EventUID = "pending"
	o.CreatorIdentity = DetectorIdentity
	p := model.Pod{UID: o.TargetPodUID, ControllerUID: o.ControllerUID, ServingRateBudgetObservation: &o}
	if !p.HasBoundServingRateBudgetObservation() || o.ScenarioID != "aml-t0034-cost-harvest" || o.EvidenceSource != "AUTHORITATIVE_PROXY" {
		return nil, errors.New("invalid serving observation")
	}
	return &o, nil
}

func decode(raw string, v any) error { return json.Unmarshal([]byte(raw), v) }

func ValidImage(s string) bool {
	repo, digest, ok := strings.Cut(s, "@sha256:")
	return ok && repo != "" && SHA(digest)
}
