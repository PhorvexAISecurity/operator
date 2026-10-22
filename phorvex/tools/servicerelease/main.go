package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "affected" && args[0] != "plan") {
		fmt.Fprintln(stderr, "usage: servicerelease affected --base <rev> [--head <rev>] [--markdown] | plan [--head <rev>] [--json]")
		return 2
	}
	fs := flag.NewFlagSet("servicerelease "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("base", "", "[affected] the revision the change starts from")
	head := fs.String("head", "HEAD", "the revision the change ends at")
	asJSON := fs.Bool("json", false, "[plan] print the plans as JSON")
	markdown := fs.Bool("markdown", false, "[affected] print a Markdown summary, as for a CI job summary")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	root, err := git(".", "rev-parse", "--show-toplevel")
	if err != nil {
		fmt.Fprintln(stderr, "servicerelease:", err)
		return 2
	}
	root = strings.TrimSpace(root)

	switch args[0] {
	case "affected":
		if *base == "" {
			fmt.Fprintln(stderr, "servicerelease affected: --base is required")
			return 2
		}
		names, err := Affected(root, *base, *head, ResolveInputs)
		if err != nil {
			fmt.Fprintln(stderr, "servicerelease:", err)
			return 1
		}
		if *markdown {
			fmt.Fprintln(stdout, "### Services this change affects")
			if len(names) == 0 {
				fmt.Fprintln(stdout, "\nNone: no service's image is built from a changed file.")
			}
			for _, n := range names {
				fmt.Fprintf(stdout, "\n- `%s`", n)
			}
			fmt.Fprintln(stdout)
			return 0
		}
		for _, n := range names {
			fmt.Fprintln(stdout, n)
		}
	case "plan":
		plans, err := PlanReleases(root, *head, ResolveInputs)
		if err != nil {
			fmt.Fprintln(stderr, "servicerelease:", err)
			return 1
		}
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(plans); err != nil {
				fmt.Fprintln(stderr, "servicerelease:", err)
				return 1
			}
			return 0
		}
		for _, p := range plans {
			switch {
			case p.Tag == "":
				fmt.Fprintf(stdout, "%-9s first release %s (%d commits)\n", p.Component, p.Next, len(p.Commits))
			case p.Next == "":
				fmt.Fprintf(stdout, "%-9s %s, unchanged since %s\n", p.Component, p.Current, p.Tag)
			default:
				fmt.Fprintf(stdout, "%-9s %s -> %s (%s, %d commits since %s)\n", p.Component, p.Current, p.Next, p.Bump, len(p.Commits), p.Tag)
			}
		}
	}
	return 0
}
