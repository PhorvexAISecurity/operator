// Command brain-replay replays recorded Math Lab decision snapshots on the unmodified
// production decision engine, offline. It reads snapshot files and an arm definition,
// and writes one JSON result per (snapshot, arm). It has no Kubernetes client, opens no
// network connection and dispatches nothing.
//
// The first arm is always the recorded baseline; its result says whether the replay
// reproduced production exactly. A snapshot recorded by a different source revision than
// this binary is refused (VERSION_MISMATCH) unless -allow-cross-version is given, in
// which case every result is flagged cross_version and must be treated as observational.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/mathlab"
)

type output struct {
	mathlab.ArmResult
	CrossVersion  bool   `json:"cross_version"`
	ReplayGitSHA  string `json:"replay_git_sha"`
	SnapshotError string `json:"snapshot_error,omitempty"`
}

type summary struct {
	Schema           string         `json:"schema_version"`
	ReplayGitSHA     string         `json:"replay_git_sha"`
	ReplayBrainImage string         `json:"replay_brain_image"`
	Snapshots        int            `json:"snapshots"`
	Arms             []string       `json:"arms"`
	ByStatus         map[string]int `json:"results_by_status"`
	BaselineChecked  int            `json:"baseline_checked"`
	BaselineExact    int            `json:"baseline_reproduced"`
	VersionMismatch  int            `json:"version_mismatch"`
	DecodeFailures   int            `json:"decode_failures"`
}

func main() {
	var snapshotsDir, armsPath, outPath, summaryPath string
	var allowCross, printVersion, inspect, exportStudy bool
	var endpointStudy, endpointConfig string
	flag.StringVar(&snapshotsDir, "snapshots", "", "Directory of *.pxms snapshot files (read-only).")
	flag.StringVar(&armsPath, "arms", "", "JSON array of arms; the first must be the baseline with no overrides. Empty replays the baseline only.")
	flag.StringVar(&outPath, "out", "", "Output JSON-lines path (one result per snapshot x arm); endpoint-study emits one JSON result.")
	flag.StringVar(&summaryPath, "summary", "", "Optional summary JSON path.")
	flag.BoolVar(&allowCross, "allow-cross-version", false, "Replay snapshots recorded by another source revision; results are flagged cross_version.")
	flag.BoolVar(&printVersion, "version", false, "Print the build identity and exit.")
	flag.BoolVar(&inspect, "inspect", false, "Write one inspection (configured spec, operator-resolved effective values, learned state) per snapshot instead of replaying.")
	flag.BoolVar(&exportStudy, "export-study-candidates", false, "Export the source-pinned real pre-cost candidate universe after exact baseline replay (JSONL).")
	flag.StringVar(&endpointStudy, "endpoint-study", "", "Explicit offline paired V2/V3 study: normalized recorded endpoint trace bound to these snapshot digests.")
	flag.StringVar(&endpointConfig, "endpoint-study-config", "", "Optional bounded endpoint-study constants JSON; never production configuration.")
	flag.Parse()
	id := replayIdentity()
	if printVersion {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"gitSHA": id.GitSHA, "brainImage": id.BrainImage, "snapshotSchema": mathlab.SnapshotSchema,
			"replaySchema": mathlab.ReplaySchema, "overridableParameters": mathlab.OverridableParameters,
			"studyCandidatesSchema": mathlab.StudyCandidatesSchema, "endpointStudyMode": "PAIRED_BRAIN_REPLAY"})
		return
	}
	if exportStudy || endpointStudy != "" || endpointConfig != "" {
		if err := runEndpointMode(snapshotsDir, outPath, summaryPath, endpointStudy, endpointConfig, exportStudy, inspect || armsPath != "", allowCross, id); err != nil {
			fmt.Fprintln(os.Stderr, "brain-replay:", err)
			os.Exit(1)
		}
		return
	}
	if inspect {
		if err := runInspect(snapshotsDir, outPath); err != nil {
			fmt.Fprintln(os.Stderr, "brain-replay:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(snapshotsDir, armsPath, outPath, summaryPath, allowCross, id); err != nil {
		fmt.Fprintln(os.Stderr, "brain-replay:", err)
		os.Exit(1)
	}
}

func loadArms(path string) ([]mathlab.Arm, error) {
	if path == "" {
		return []mathlab.Arm{{ID: "baseline"}}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var arms []mathlab.Arm
	if err := dec.Decode(&arms); err != nil {
		return nil, fmt.Errorf("arms: %w", err)
	}
	if len(arms) == 0 || len(arms[0].Overrides) != 0 {
		return nil, errors.New("arms: the first arm must be the baseline with no overrides")
	}
	seen := map[string]bool{}
	for _, a := range arms {
		if seen[a.ID] {
			return nil, fmt.Errorf("arms: duplicate arm_id %q", a.ID)
		}
		seen[a.ID] = true
		if err := mathlab.ValidateArm(a); err != nil {
			return nil, fmt.Errorf("arm %q: %w", a.ID, err)
		}
	}
	return arms, nil
}

func run(dir, armsPath, outPath, summaryPath string, allowCross bool, id buildinfo.Identity) error {
	if dir == "" || outPath == "" {
		return errors.New("-snapshots and -out are required")
	}
	arms, err := loadArms(armsPath)
	if err != nil {
		return err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.pxms"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	sum := summary{Schema: "math-lab.replay-summary.v1", ReplayGitSHA: id.GitSHA, ReplayBrainImage: id.BrainImage, ByStatus: map[string]int{}}
	for _, a := range arms {
		sum.Arms = append(sum.Arms, a.ID)
	}
	for _, path := range files {
		sum.Snapshots++
		digest := strings.TrimSuffix(filepath.Base(path), ".pxms")
		raw, err := mathlab.ReadVerified(path, digest)
		var snap *mathlab.Snapshot
		if err == nil {
			snap, err = mathlab.Decode(raw)
		}
		if err != nil {
			sum.DecodeFailures++
			for _, a := range arms {
				res := output{ArmResult: mathlab.ArmResult{Schema: mathlab.ReplaySchema, ArmID: a.ID, Status: mathlab.StatusUnreplayable,
					Reasons: []string{"snapshot-unreadable"}}, ReplayGitSHA: id.GitSHA, SnapshotError: err.Error()}
				res.Snapshot.Digest = digest
				sum.ByStatus[res.Status]++
				if err := enc.Encode(res); err != nil {
					return err
				}
			}
			continue
		}
		cross := snap.Header.GitSHA != id.GitSHA
		var results []mathlab.ArmResult
		if cross && !allowCross {
			sum.VersionMismatch++
			for _, a := range arms {
				r := mathlab.ArmResult{Schema: mathlab.ReplaySchema, ArmID: a.ID, Status: mathlab.StatusUnreplayable,
					Reasons: []string{fmt.Sprintf("VERSION_MISMATCH: snapshot recorded by %s, replay binary is %s", snap.Header.GitSHA, id.GitSHA)}}
				r.Snapshot.Digest = snap.Digest
				results = append(results, r)
			}
		} else {
			results, err = mathlab.Replay(snap, mathlab.ReplayOptions{Arms: arms})
			if err != nil {
				return err
			}
		}
		for _, r := range results {
			if r.Baseline != nil {
				sum.BaselineChecked++
				if r.Baseline.Reproduced {
					sum.BaselineExact++
				}
			}
			sum.ByStatus[r.Status]++
			if err := enc.Encode(output{ArmResult: r, CrossVersion: cross, ReplayGitSHA: id.GitSHA}); err != nil {
				return err
			}
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if summaryPath != "" {
		raw, err := json.MarshalIndent(sum, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(summaryPath, append(raw, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func runInspect(dir, outPath string) error {
	if dir == "" || outPath == "" {
		return errors.New("-snapshots and -out are required")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.pxms"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	for _, path := range files {
		digest := strings.TrimSuffix(filepath.Base(path), ".pxms")
		raw, err := mathlab.ReadVerified(path, digest)
		if err != nil {
			if err := enc.Encode(map[string]string{"snapshot_digest": digest, "error": err.Error()}); err != nil {
				return err
			}
			continue
		}
		snap, err := mathlab.Decode(raw)
		if err != nil {
			if err := enc.Encode(map[string]string{"snapshot_digest": digest, "error": err.Error()}); err != nil {
				return err
			}
			continue
		}
		if err := enc.Encode(mathlab.Inspect(snap)); err != nil {
			return err
		}
	}
	return w.Flush()
}
