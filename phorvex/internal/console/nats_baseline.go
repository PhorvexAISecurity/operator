package console

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

const natsBaselineConfig = "nats-exposure-baseline"

// NATSConfigurationResult is a no-signal synthetic configuration observation.
// Accepted means the whole owned cleanup chain verified; it never means a
// Phorvex defense or attack-success score.
type NATSConfigurationResult struct {
	Finding                 string   `json:"finding"`
	ObservedFinding         string   `json:"observedFinding"`
	Accepted                bool     `json:"accepted"`
	RemoteStatus            string   `json:"remoteStatus"`
	RemotePodUID            string   `json:"remotePodUID,omitempty"`
	BrokerPodUID            string   `json:"brokerPodUID,omitempty"`
	LegitimateAcked         bool     `json:"legitimateAcked"`
	StoredPayloadSHA256     string   `json:"storedPayloadSHA256,omitempty"`
	StreamCleanup           string   `json:"streamCleanup"`
	ObserverCleanup         string   `json:"observerCleanup"`
	FixtureResourcesCleanup string   `json:"fixtureResourcesCleanup"`
	BrainMode               string   `json:"brainMode"`
	SecurityEfficacy        string   `json:"securityEfficacy"`
	SourceAttestation       string   `json:"sourceAttestation"`
	Issues                  []string `json:"issues,omitempty"`
}

type natsBaselineArtifactRow struct {
	Schema               string `json:"schema"`
	RunID                string `json:"runId"`
	Nonce                string `json:"nonce"`
	Namespace            string `json:"namespace"`
	NamespaceUID         string `json:"namespaceUID"`
	ObserverPodUID       string `json:"observerPodUID"`
	ObserverConfigMapUID string `json:"observerConfigMapUID"`
	ObserverContainerID  string `json:"observerContainerID"`
	ObserverImageID      string `json:"observerImageID"`
	Route                struct {
		ClusterUID              string `json:"clusterUID"`
		ServiceUID              string `json:"serviceUID"`
		StatefulSetUID          string `json:"statefulSetUID"`
		ConfigMapUID            string `json:"configMapUID"`
		EndpointSliceUID        string `json:"endpointSliceUID"`
		NodeUID                 string `json:"nodeUID"`
		ConfigSHA256            string `json:"configSHA256"`
		ConfigSourceAttestation string `json:"configSourceAttestation"`
		Brokers                 []struct {
			PodUID   string `json:"uid"`
			ServerID string `json:"serverID"`
		} `json:"brokers"`
	} `json:"route"`
	Subscription struct {
		Kind     string `json:"kind"`
		Status   string `json:"status"`
		Subject  string `json:"subject"`
		Nonce    string `json:"nonce"`
		ServerID string `json:"serverID"`
		Flushed  bool   `json:"flushed"`
	} `json:"subscription"`
	Observation struct {
		Kind               string `json:"kind"`
		Status             string `json:"status"`
		Subject            string `json:"subject"`
		Nonce              string `json:"nonce"`
		ServerID           string `json:"serverID"`
		PayloadSHA256      string `json:"payloadSHA256"`
		NonceHeaderMatches bool   `json:"nonceHeaderMatches"`
		PayloadHashMatches bool   `json:"payloadHashMatches"`
	} `json:"observation"`
	Protocol struct {
		Nonce               string `json:"nonce"`
		Stream              string `json:"stream"`
		Subject             string `json:"subject"`
		Consumer            string `json:"consumer"`
		PublishAttempted    bool   `json:"publishAttempted"`
		PubAckSequence      uint64 `json:"pubAckSequence"`
		PayloadSHA256       string `json:"payloadSHA256"`
		StoredPayloadSHA256 string `json:"storedPayloadSHA256"`
		LegitimateAcked     bool   `json:"legitimateAcked"`
		Cleanup             string `json:"cleanup"`
	} `json:"protocol"`
	ConfigurationFinding string `json:"configurationFinding"`
	Validity             string `json:"validity"`
	Cleanup              string `json:"cleanup"`
	BrainMode            string `json:"brainMode"`
	SecurityEfficacy     string `json:"securityEfficacy"`
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil || !linkInfo.Mode().IsRegular() {
		return nil, errors.New("regular non-symlink evidence file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(linkInfo, info) || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("bounded regular evidence file required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("evidence file exceeded bound")
	}
	return raw, nil
}

func rejectAmbiguousNATSJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate evidence field")
				}
				seen[key] = true
				switch key {
				case "eventUID", "decisionID", "defenseVerdict", "securityOutcome", "actuator":
					return errors.New("NATS no-signal artifact contains defense claim")
				}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("evidence object delimiter differs")
			}
			return nil
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("evidence array delimiter differs")
			}
			return nil
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing evidence JSON")
	}
	return nil
}

func oneMetricEvidence(path string) (runMetricRow, error) {
	var metric runMetricRow
	raw, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return metric, err
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 4096), 1<<20)
	if !sc.Scan() {
		return metric, errors.New("NATS baseline metric absent")
	}
	if err := json.Unmarshal(sc.Bytes(), &metric); err != nil {
		return metric, err
	}
	if sc.Scan() || sc.Err() != nil {
		return metric, errors.New("NATS baseline requires exactly one metric row")
	}
	return metric, nil
}

func hashNATSBytes(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func readNATSConfigurationResult(out, id, namespace string) (NATSConfigurationResult, error) {
	result := NATSConfigurationResult{Finding: "UNKNOWN", ObservedFinding: "UNKNOWN", FixtureResourcesCleanup: "UNVERIFIED", BrainMode: "NO_SIGNAL", SecurityEfficacy: "NOT_EVALUATED"}
	raw, err := readBoundedFile(filepath.Join(out, "nats-baseline.json"), 64<<10)
	if err != nil {
		return result, fmt.Errorf("NATS artifact unavailable: %w", err)
	}
	if err := rejectAmbiguousNATSJSON(raw); err != nil {
		return result, err
	}
	var a natsBaselineArtifactRow
	if err := json.Unmarshal(raw, &a); err != nil {
		return result, errors.New("NATS artifact JSON invalid")
	}
	result.RemoteStatus, result.RemotePodUID = a.Observation.Status, a.ObserverPodUID
	result.LegitimateAcked, result.StoredPayloadSHA256 = a.Protocol.LegitimateAcked, a.Protocol.StoredPayloadSHA256
	result.StreamCleanup, result.ObserverCleanup = a.Protocol.Cleanup, a.Cleanup
	result.SourceAttestation = a.Route.ConfigSourceAttestation
	add := func(problem string) { result.Issues = append(result.Issues, problem) }
	if a.Schema != "nats-baseline-v1" || a.RunID != id || a.Namespace != namespace || a.Namespace != "phorvex-nats-exposure-fixture" || a.NamespaceUID == "" || a.ObserverPodUID == "" || a.ObserverConfigMapUID == "" || a.ObserverContainerID == "" || a.ObserverImageID == "" {
		add("artifact run/observer identity differs")
	}
	if len(a.Nonce) != 24 || a.BrainMode != "NO_SIGNAL" || a.SecurityEfficacy != "NOT_EVALUATED" {
		add("artifact mode or nonce differs")
	}
	if a.Route.ClusterUID == "" || a.Route.ServiceUID == "" || a.Route.StatefulSetUID == "" || a.Route.ConfigMapUID == "" || a.Route.EndpointSliceUID == "" || a.Route.NodeUID == "" || a.Route.ConfigSourceAttestation != "DECLARED_CM_ONLY" || len(a.Route.ConfigSHA256) != 64 {
		add("reviewed source declaration unavailable")
	}
	expectedSubject := "cat.exposure." + a.Nonce
	payloadHash := hashNATSBytes([]byte("phorvex-owned-nats-exposure:" + a.Nonce))
	if a.Protocol.Nonce != a.Nonce || a.Protocol.Stream != "CAT_"+a.Nonce || a.Protocol.Consumer != "CAT_"+a.Nonce+"_C" || a.Protocol.Subject != expectedSubject || !a.Protocol.PublishAttempted || a.Protocol.PubAckSequence != 1 || a.Protocol.PayloadSHA256 != payloadHash || a.Protocol.StoredPayloadSHA256 != payloadHash || !a.Protocol.LegitimateAcked {
		add("legitimate protocol positive control incomplete")
	}
	if a.Subscription.Kind != "subscription" || a.Subscription.Subject != expectedSubject || a.Subscription.Nonce != a.Nonce || !a.Subscription.Flushed || a.Observation.Kind != "observation" || a.Observation.Subject != expectedSubject || a.Observation.Nonce != a.Nonce || a.Observation.ServerID != a.Subscription.ServerID {
		add("independent observer receipt identity differs")
	}
	brokerCount := 0
	for _, b := range a.Route.Brokers {
		if b.ServerID == a.Observation.ServerID && b.PodUID != "" {
			brokerCount++
			result.BrokerPodUID = b.PodUID
		}
	}
	if brokerCount != 1 {
		add("remote server ID has no unique Ready broker Pod binding")
	}
	derived := "UNKNOWN"
	if a.Subscription.Status == "READY" && a.Observation.Status == "EXACT_PAYLOAD_RECEIVED" && a.Observation.PayloadSHA256 == payloadHash && a.Observation.NonceHeaderMatches && a.Observation.PayloadHashMatches {
		derived = "EXPOSED"
	}
	if a.Subscription.Status == "SUBSCRIPTION_DENIED" && a.Observation.Status == "PERMISSION_DENIED" {
		derived = "NOT_EXPOSED_IN_THIS_CONTROL"
	}
	result.ObservedFinding = derived
	if derived != a.ConfigurationFinding {
		add("configuration finding is inconsistent with remote receipt")
	}
	if a.Protocol.Cleanup != "CONFIRMED_ABSENT" || a.Cleanup != "OBSERVER_AND_STREAM_CONFIRMED_ABSENT" || a.Validity != "MEASUREMENT_COMPLETE" {
		add("owned stream/observer cleanup or measurement incomplete")
	}
	metric, err := oneMetricEvidence(filepath.Join(out, "metrics.jsonl"))
	if err != nil {
		add("metric unavailable or ambiguous")
	} else if metric.Scenario != "c2-nats-uncredentialed-exposure" || metric.Defender != "d-nomtd" || metric.Trial != 1 || !metric.ScenarioBenignControl || metric.verdict().Scorable || metric.BenchmarkEvidence["nats_baseline_artifact_sha256"] != hashNATSBytes(raw) {
		add("metric identity/digest/benign scoring differs")
	}
	terminalRaw, terminalErr := readBoundedFile(filepath.Join(out, "nats-baseline-terminal.json"), 4096)
	terminalVerified := false
	if terminalErr != nil {
		add("UID-bound terminal teardown receipt unavailable")
	} else {
		var terminal struct {
			Schema                 string `json:"schema"`
			RunID                  string `json:"runId"`
			Nonce                  string `json:"nonce"`
			Namespace              string `json:"namespace"`
			NamespaceUID           string `json:"namespaceUID"`
			ArtifactSHA256         string `json:"artifactSHA256"`
			FixtureResourcesAbsent bool   `json:"fixtureResourcesAbsent"`
			NamespacePreserved     bool   `json:"namespacePreserved"`
		}
		if json.Unmarshal(terminalRaw, &terminal) != nil || terminal.Schema != "nats-baseline-terminal-v1" || terminal.RunID != id || terminal.Nonce != a.Nonce || terminal.Namespace != namespace || terminal.NamespaceUID != a.NamespaceUID || terminal.ArtifactSHA256 != hashNATSBytes(raw) || !terminal.FixtureResourcesAbsent || !terminal.NamespacePreserved {
			add("terminal fixture namespace UID, resource absence or artifact digest does not join")
		} else {
			terminalVerified = true
		}
	}
	provenanceRaw, err := readBoundedFile(filepath.Join(out, "provenance.json"), 1<<20)
	if err != nil {
		add("terminal provenance unavailable")
	} else {
		var p struct {
			Run struct {
				Complete      bool `json:"complete"`
				FinalTeardown *struct {
					Attempted bool `json:"attempted"`
					Verified  bool `json:"verified"`
				} `json:"finalTeardown"`
			} `json:"run"`
			Namespace string `json:"namespace"`
		}
		if json.Unmarshal(provenanceRaw, &p) != nil || p.Namespace != namespace || p.Run.FinalTeardown == nil || !p.Run.FinalTeardown.Attempted || !p.Run.FinalTeardown.Verified {
			add("final fixture-resource verification unverified")
		} else if terminalVerified {
			result.FixtureResourcesCleanup = "VERIFIED"
		}
		if !p.Run.Complete {
			add("run execution incomplete")
		}
	}
	if len(result.Issues) == 0 && derived != "UNKNOWN" {
		result.Accepted = true
		result.Finding = derived
	}
	return result, nil
}

// readNATSNoEffect accepts a producer's explicit terminal pre-effect exit,
// never an absent phase journal. The exited child is checked by the caller.
func readNATSNoEffect(out, id, namespace, generatedConfig string) bool {
	raw, err := readBoundedFile(filepath.Join(out, "nats-baseline-no-effect.json"), 2048)
	if err != nil || rejectAmbiguousNATSJSON(raw) != nil {
		return false
	}
	var receipt struct {
		Schema        string `json:"schema"`
		RunID         string `json:"runId"`
		Nonce         string `json:"nonce"`
		Namespace     string `json:"namespace"`
		NamespaceUID  string `json:"namespaceUID"`
		ClusterUID    string `json:"clusterUID"`
		ConfigSHA256  string `json:"configSHA256"`
		Phase         string `json:"phase"`
		EffectStarted bool   `json:"effectStarted"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Schema != "nats-baseline-no-effect-v1" || receipt.RunID != id || receipt.EffectStarted {
		return false
	}
	cfgRaw, err := readBoundedFile(generatedConfig, 64<<10)
	if err != nil {
		return false
	}
	if receipt.Phase == "CONFIG_LOAD_REFUSED" {
		return receipt.ConfigSHA256 != "" && receipt.ConfigSHA256 == hashNATSBytes(cfgRaw)
	}
	var cfg struct {
		Namespace           string `json:"namespace"`
		NATSExposureFixture struct {
			RunID      string `json:"runID"`
			Nonce      string `json:"nonce"`
			ClusterUID string `json:"clusterUID"`
		} `json:"natsExposureFixture"`
	}
	if yaml.Unmarshal(cfgRaw, &cfg) != nil {
		return false
	}
	if cfg.Namespace != namespace || cfg.NATSExposureFixture.RunID != id || cfg.NATSExposureFixture.Nonce != receipt.Nonce || cfg.NATSExposureFixture.ClusterUID != receipt.ClusterUID || receipt.Namespace != namespace || receipt.Nonce == "" {
		return false
	}
	switch receipt.Phase {
	case "PRE_MATRIX_REFUSED":
		return receipt.NamespaceUID == ""
	case "SCENARIO_PRE_EFFECT_EXIT":
		return receipt.NamespaceUID != ""
	default:
		return false
	}
}

func readNATSReconciliation(out, id, namespace, generatedConfig, attemptID string) bool {
	anchorRaw, err := readBoundedFile(filepath.Join(out, "nats-baseline-anchor.json"), 8192)
	if err != nil || rejectAmbiguousNATSJSON(anchorRaw) != nil {
		return false
	}
	var anchor struct {
		Schema            string          `json:"schema"`
		RunID             string          `json:"runId"`
		Nonce             string          `json:"nonce"`
		Namespace         string          `json:"namespace"`
		NamespaceUID      string          `json:"namespaceUID"`
		ClusterUID        string          `json:"clusterUID"`
		PID               int             `json:"pid"`
		ProcessStartTicks string          `json:"processStartTicks"`
		FenceIdentity     string          `json:"fenceIdentity"`
		Route             json.RawMessage `json:"route"`
	}
	if json.Unmarshal(anchorRaw, &anchor) != nil || anchor.Schema != "nats-baseline-anchor-v1" || anchor.RunID != id || anchor.Namespace != namespace || anchor.NamespaceUID == "" || anchor.ClusterUID == "" || anchor.Nonce == "" || anchor.PID < 1 || anchor.ProcessStartTicks == "" || !strings.HasPrefix(anchor.FenceIdentity, "flock-v1:") || len(anchor.Route) == 0 {
		return false
	}
	if ticks, err := processStartTicks(anchor.PID); err == nil && ticks == anchor.ProcessStartTicks {
		return false
	} else if err != nil && !os.IsNotExist(err) {
		return false
	}
	cfgRaw, err := readBoundedFile(generatedConfig, 64<<10)
	if err != nil {
		return false
	}
	var cfg struct {
		Namespace           string `json:"namespace"`
		NATSExposureFixture struct {
			RunID      string `json:"runID"`
			Nonce      string `json:"nonce"`
			ClusterUID string `json:"clusterUID"`
		} `json:"natsExposureFixture"`
	}
	if yaml.Unmarshal(cfgRaw, &cfg) != nil || cfg.Namespace != namespace || cfg.NATSExposureFixture.RunID != id || cfg.NATSExposureFixture.Nonce != anchor.Nonce || cfg.NATSExposureFixture.ClusterUID != anchor.ClusterUID {
		return false
	}
	resultRaw, err := readBoundedFile(filepath.Join(out, "nats-baseline-reconciliation.json"), 4096)
	if err != nil || rejectAmbiguousNATSJSON(resultRaw) != nil {
		return false
	}
	var receipt struct {
		Schema                 string `json:"schema"`
		RunID                  string `json:"runId"`
		AttemptID              string `json:"attemptId"`
		Nonce                  string `json:"nonce"`
		Namespace              string `json:"namespace"`
		NamespaceUID           string `json:"namespaceUID"`
		ClusterUID             string `json:"clusterUID"`
		AnchorSHA256           string `json:"anchorSHA256"`
		RouteSHA256            string `json:"routeSHA256"`
		FixtureResourcesAbsent bool   `json:"fixtureResourcesAbsent"`
		StreamAbsent           bool   `json:"streamAbsent"`
		OriginalProcessGone    bool   `json:"originalProcessGone"`
		SafeToRetry            bool   `json:"safeToRetry"`
	}
	if json.Unmarshal(resultRaw, &receipt) != nil {
		return false
	}
	return receipt.Schema == "nats-baseline-reconciliation-v1" && receipt.RunID == id && receipt.AttemptID == attemptID && receipt.Nonce == anchor.Nonce && receipt.Namespace == namespace && receipt.NamespaceUID == anchor.NamespaceUID && receipt.ClusterUID == anchor.ClusterUID && receipt.AnchorSHA256 == hashNATSBytes(anchorRaw) && receipt.RouteSHA256 == hashNATSBytes(anchor.Route) && receipt.FixtureResourcesAbsent && receipt.StreamAbsent && receipt.OriginalProcessGone && receipt.SafeToRetry
}

func (rm *RunManager) NATSConfigurationResult(id string) (*NATSConfigurationResult, error) {
	rm.mu.Lock()
	st := rm.runs[id]
	out := rm.runOut[id]
	if st == nil || st.Config != natsBaselineConfig {
		rm.mu.Unlock()
		return nil, nil
	}
	namespace := st.Namespace
	state := st.State
	rm.mu.Unlock()
	if out == "" || strings.Contains(out, "..") {
		return nil, errors.New("NATS run output path unavailable")
	}
	result, err := readNATSConfigurationResult(rm.cfg.runOutputPath(out), id, namespace)
	if err != nil {
		return nil, err
	}
	if state != "done" {
		result.Accepted = false
		result.Issues = append(result.Issues, "run terminal state is not done")
	}
	return &result, nil
}
