package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/r6security/phoenix-test-harness/internal/cataloguecollector"
)

func main() {
	index := flag.String("index", "", "explicit local run index JSON")
	jsonOut := flag.String("json", "", "machine-readable report output")
	markdownOut := flag.String("markdown", "", "Markdown report output")
	flag.Parse()
	if *index == "" || *jsonOut == "" || *markdownOut == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: catalogue-collector -index INDEX.json -json REPORT.json -markdown REPORT.md")
		os.Exit(2)
	}
	report, err := cataloguecollector.Collect(*index)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, err := cataloguecollector.MarshalReport(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b = append(b, '\n')
	if err := writeAtomic(*jsonOut, b); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := writeAtomic(*markdownOut, []byte(cataloguecollector.Markdown(report))); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".catalogue-collector-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
