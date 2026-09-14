/*
 * Phorvex — producer-driven recon cover map (M-123): command entrypoint.
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("covermap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "compare a fresh producer run with the checked-in report; exit 1 on drift, never write")
	write := fs.Bool("write", false, "regenerate the report")
	out := fs.String("out", "", "report path (default: <module>/"+DefaultOutput+")")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *check == *write {
		fmt.Fprintln(stderr, "covermap: exactly one of --check or --write is required")
		return 2
	}
	root, err := ModuleRoot(".")
	if err != nil {
		fmt.Fprintln(stderr, "covermap:", err)
		return 2
	}
	path := *out
	if path == "" {
		path = filepath.Join(root, filepath.FromSlash(DefaultOutput))
	}
	rep, err := Build(root)
	if err != nil {
		fmt.Fprintln(stderr, "covermap: build:", err)
		return 2
	}
	fresh, err := Render(rep)
	if err != nil {
		fmt.Fprintln(stderr, "covermap: render:", err)
		return 2
	}
	if *write {
		if err := os.WriteFile(path, fresh, 0o644); err != nil {
			fmt.Fprintln(stderr, "covermap: write:", err)
			return 2
		}
		fmt.Fprintf(stdout, "covermap: wrote %s (inputs-sha256 %s, %d fixtures x %d profiles)\n", path, rep.InputsSHA256, len(rep.Fixtures), len(rep.Profiles))
		return 0
	}
	ok, msg, err := Check(path, fresh)
	if err != nil {
		fmt.Fprintln(stderr, "covermap: check:", err)
		return 2
	}
	if !ok {
		fmt.Fprintf(stderr, "covermap: DRIFT in %s: %s\n", path, msg)
		return 1
	}
	fmt.Fprintf(stdout, "covermap: %s is %s (inputs-sha256 %s)\n", path, msg, rep.InputsSHA256)
	return 0
}
