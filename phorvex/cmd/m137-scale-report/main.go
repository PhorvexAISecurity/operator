package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/phorvex/phorvex/internal/scaleprobe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: m137-scale-report REPORT.json [...]")
		os.Exit(2)
	}
	type row struct {
		Path            string                           `json:"path"`
		Case            string                           `json:"case"`
		Environment     scaleprobe.Environment           `json:"environment"`
		Fixture         scaleprobe.Fixture               `json:"fixture"`
		Summary         scaleprobe.Summary               `json:"summary"`
		Warmups         []scaleprobe.Warmup              `json:"warmups"`
		AgePrerequisite scaleprobe.AgePrerequisite       `json:"workloadAgePrerequisite"`
		Memory          scaleprobe.Memory                `json:"memory"`
		StartupHTTP     map[string]int64                 `json:"startupHTTP"`
		SampleHTTP      map[string]int64                 `json:"sampleHTTP"`
		ConvergenceHTTP map[string]int64                 `json:"sampleConvergenceHTTP"`
		ControlHTTP     map[string]int64                 `json:"controlHTTP"`
		REST            map[string]scaleprobe.RESTConfig `json:"restConfigs"`
		Checks          scaleprobe.Correctness           `json:"correctness"`
		Verdict         string                           `json:"nfrVerdict"`
		Detail          string                           `json:"nfrDetail"`
		Limits          []string                         `json:"limitations"`
	}
	rows := make([]row, 0, len(os.Args)-1)
	for _, path := range os.Args[1:] {
		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		report, decodeErr := scaleprobe.Decode(file)
		_ = file.Close()
		if decodeErr != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, decodeErr)
			os.Exit(1)
		}
		rows = append(rows, row{Path: path, Case: report.Fixture.Case, Environment: report.Environment, Fixture: report.Fixture, Summary: report.Summary, Warmups: report.Warmups, AgePrerequisite: report.AgePrerequisite, Memory: report.Memory, StartupHTTP: report.StartupHTTP, SampleHTTP: report.SampleHTTP, ConvergenceHTTP: report.ConvergenceHTTP, ControlHTTP: report.ControlHTTP, REST: report.RESTConfigs, Checks: report.Correctness, Verdict: report.NFRVerdict, Detail: report.NFRDetail, Limits: report.Limitations})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(rows); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
