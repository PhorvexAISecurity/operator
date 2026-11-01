package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/cost/endpoint"
	"github.com/phorvex/phorvex/internal/mathlab"
)

// A runtime PHORVEX_GIT_SHA override is not proof of the replay binary's source.
func replayIdentity() buildinfo.Identity {
	id := buildinfo.Embedded()
	id.BrainImage = buildinfo.Current().BrainImage
	return id
}

func readStudyJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err != nil || len(raw) > 64<<20 {
		return fmt.Errorf("study JSON unavailable or exceeds 64 MiB: %v", err)
	}
	if err := studyUniqueKeys(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("study input must contain exactly one JSON value")
	}
	return nil
}

func studyUniqueKeys(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("study JSON nesting exceeds 64")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid study JSON key")
			}
			seen[name] = true
			if err := studyUniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err := studyUniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

func runEndpointMode(dir, outputPath, summaryPath, tracePath, configPath string, export, conflicting, allowCross bool, id buildinfo.Identity) error {
	if dir == "" || outputPath == "" || conflicting || export && (tracePath != "" || configPath != "") || !export && tracePath == "" {
		return fmt.Errorf("endpoint study requires snapshots/out and exactly one export or trace mode; arms and inspect are incompatible")
	}
	if len(id.GitSHA) != 40 {
		return fmt.Errorf("endpoint study requires an exact source-pinned replay binary")
	}
	if _, err := hex.DecodeString(id.GitSHA); err != nil || id.GitSHA != strings.ToLower(id.GitSHA) {
		return fmt.Errorf("endpoint study requires an exact lowercase source SHA")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.pxms"))
	if err != nil || len(files) == 0 || len(files) > 5000 {
		return fmt.Errorf("endpoint study requires 1..5000 snapshot files: %v", err)
	}
	sort.Strings(files)
	snapshots := make([]*mathlab.Snapshot, 0, len(files))
	snapshotSource := ""
	totalBytes := 0
	source := mathlab.StudySource{ReplayGitSHA: id.GitSHA, AllowCrossVersion: allowCross}
	for _, path := range files {
		digest := strings.TrimSuffix(filepath.Base(path), ".pxms")
		raw, err := mathlab.ReadVerified(path, digest)
		if err != nil {
			return err
		}
		totalBytes += len(raw)
		if totalBytes > 512<<20 {
			return fmt.Errorf("study snapshot cohort exceeds 512 MiB")
		}
		s, err := mathlab.Decode(raw)
		if err != nil {
			return err
		}
		if s.Header.GitSHA != id.GitSHA && !allowCross {
			return fmt.Errorf("VERSION_MISMATCH: snapshot %s source %s, replay %s", digest, s.Header.GitSHA, id.GitSHA)
		}
		if snapshotSource != "" && snapshotSource != s.Header.GitSHA {
			return fmt.Errorf("study snapshot cohort mixes source revisions")
		}
		snapshotSource = s.Header.GitSHA
		snapshots = append(snapshots, s)
	}
	var output bytes.Buffer
	enc := json.NewEncoder(&output)
	if export {
		for _, s := range snapshots {
			if err := enc.Encode(mathlab.ExportStudyCandidates(s, source)); err != nil {
				return err
			}
		}
		return os.WriteFile(outputPath, output.Bytes(), 0600)
	}
	var trace endpoint.Trace
	if err := readStudyJSON(tracePath, &trace); err != nil {
		return err
	}
	if trace.SourceRevision != id.GitSHA {
		return fmt.Errorf("VERSION_MISMATCH: endpoint trace source differs from replay binary")
	}
	cfg := endpoint.Defaults()
	if configPath != "" {
		if err := readStudyJSON(configPath, &cfg); err != nil {
			return err
		}
	}
	stateDir, err := os.MkdirTemp("", "brain-endpoint-study-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateDir)
	result, err := mathlab.RunEndpointStudy(snapshots, trace, cfg, endpoint.FileStore{Dir: stateDir}, source)
	if err != nil {
		return err
	}
	if err := enc.Encode(result); err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, output.Bytes(), 0600); err != nil {
		return err
	}
	if summaryPath != "" {
		raw, err := json.MarshalIndent(map[string]any{"schema": "math-lab.endpoint-study-summary.v1", "mode": result.Mode,
			"state": result.State, "source_revision": id.GitSHA, "baseline_exact_count": result.BaselineExactCount,
			"replay_git_sha": result.ReplayGitSHA, "snapshot_source_revision": result.SnapshotSourceRevision,
			"cross_version": result.CrossVersion, "observational": result.Observational,
			"snapshot_digests": result.SnapshotDigests, "brain_selection_parity": result.BrainParity,
			"comparable_ticks": result.Comparable, "changed_choices": result.Changed}, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(summaryPath, append(raw, '\n'), 0600)
	}
	return nil
}
