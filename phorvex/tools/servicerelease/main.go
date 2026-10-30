package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage:
  servicerelease affected --base <rev> [--head <rev>] [--markdown]
  servicerelease plan [--head <rev>] [--json]
  servicerelease prepare [--dir release] [--date YYYY-MM-DD] --title-file <path> --body-file <path>
  servicerelease batch [--dir release] [--head <rev>] [--environment staging]
  servicerelease batch-source [--dir release] [--head <rev>]
  servicerelease pending [--dir release]
  servicerelease record --environment staging --component <name> --repository <repo> --tag <version> --digest <sha256:...> --source <sha>
  servicerelease deploy --environment <env> --component <name> --repository <repo> --tag <version> --digest <sha256:...> [--source <sha>]
  servicerelease pull-request --head <branch> --base <branch> --title-file <path> --body-file <path>
  servicerelease dispatch --ref <branch> --workflows <file>[,<file>...]
  servicerelease close-pull-request --head <branch> --base <branch>`

// exitNothing is prepare's exit status when no component changed.
const exitNothing = 3

func run(args []string, stdout, stderr io.Writer) int {
	commands := map[string]bool{"affected": true, "plan": true, "prepare": true, "batch": true, "batch-source": true, "pending": true, "record": true, "deploy": true, "pull-request": true, "dispatch": true, "close-pull-request": true}
	if len(args) == 0 || !commands[args[0]] {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("servicerelease "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("base", "", "[affected] the revision the change starts from; [pull-request] the branch the PR merges into")
	head := fs.String("head", "HEAD", "the revision the change ends at; [pull-request] the PR's branch")
	asJSON := fs.Bool("json", false, "[plan] print the plans as JSON")
	markdown := fs.Bool("markdown", false, "[affected] print a Markdown summary, as for a CI job summary")
	dir := fs.String("dir", "release", "[prepare, batch, batch-source, pending, record] the release directory, relative to the repository root")
	date := fs.String("date", time.Now().UTC().Format("2006-01-02"), "[prepare] the release date in the changelogs")
	titleFile := fs.String("title-file", "", "[prepare, pull-request] the release PR's title")
	bodyFile := fs.String("body-file", "", "[prepare, pull-request] the release PR's Markdown body")
	environment := fs.String("environment", "", "[batch, record, deploy] the environment under deploy/environments")
	component := fs.String("component", "", "[record, deploy] the released component")
	repository := fs.String("repository", "", "[record, deploy] the image repository, with its registry")
	tag := fs.String("tag", "", "[record, deploy] the released version")
	digest := fs.String("digest", "", "[record, deploy] the pushed image's digest")
	source := fs.String("source", "", "[record, deploy] the released commit")
	ref := fs.String("ref", "", "[dispatch] the branch the workflows run on")
	workflows := fs.String("workflows", "", "[dispatch] comma-separated workflow files")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	root, err := git(".", "rev-parse", "--show-toplevel")
	if err != nil {
		fmt.Fprintln(stderr, "servicerelease:", err)
		return 2
	}
	root = strings.TrimSpace(root)
	releaseDir := *dir
	if !filepath.IsAbs(releaseDir) {
		releaseDir = filepath.Join(root, releaseDir)
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "servicerelease:", err)
		return 1
	}

	switch args[0] {
	case "affected":
		if *base == "" {
			fmt.Fprintln(stderr, "servicerelease affected: --base is required")
			return 2
		}
		names, err := Affected(root, *base, *head, ResolveInputs)
		if err != nil {
			return fail(err)
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
			return fail(err)
		}
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(plans); err != nil {
				return fail(err)
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
	case "prepare":
		if *titleFile == "" || *bodyFile == "" {
			fmt.Fprintln(stderr, "servicerelease prepare: --title-file and --body-file are required")
			return 2
		}
		plans, err := PlanReleases(root, *head, ResolveInputs)
		if err != nil {
			return fail(err)
		}
		if err := os.MkdirAll(releaseDir, 0o755); err != nil {
			return fail(err)
		}
		title, body, err := Prepare(releaseDir, *date, plans)
		if errors.Is(err, ErrNothingToRelease) {
			fmt.Fprintln(stdout, "nothing to release")
			return exitNothing
		} else if err != nil {
			return fail(err)
		}
		if err := os.WriteFile(*titleFile, []byte(title+"\n"), 0o644); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(*bodyFile, []byte(body), 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, title)
	case "batch":
		env := *environment
		if env == "" {
			env = ReleaseEnvironment
		}
		batch, _, err := EnsureBatch(root, releaseDir, *head, env)
		if err != nil {
			return fail(err)
		}
		if batch != nil {
			fmt.Fprintln(stdout, batch.Source)
		}
	case "batch-source":
		batch, err := LoadBatch(root, releaseDir, *head, true)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, batch.Source)
	case "pending":
		pending, err := PendingReleases(root, releaseDir, *head)
		if err != nil {
			return fail(err)
		}
		// One release per line, tab-separated, for the release workflow; the last
		// field is the image's docker build options.
		for _, p := range pending {
			var buildArgs []string
			for _, a := range p.BuildArgs {
				buildArgs = append(buildArgs, "--build-arg", a)
			}
			if p.Target != "" {
				buildArgs = append(buildArgs, "--target", p.Target)
			}
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", p.Component, p.Version, p.Dockerfile, p.Repository, strings.Join(buildArgs, " "))
		}
	case "record":
		if *environment == "" || *component == "" || *repository == "" || *tag == "" || *digest == "" || *source == "" {
			fmt.Fprintln(stderr, "servicerelease record: --environment, --component, --repository, --tag, --digest and --source are required")
			return 2
		}
		if err := RecordRelease(root, releaseDir, *head, *environment, *component, *repository, *tag, *digest, *source); err != nil {
			return fail(err)
		}
	case "deploy":
		if *environment == "" || *component == "" || *repository == "" {
			fmt.Fprintln(stderr, "servicerelease deploy: --environment, --component and --repository are required")
			return 2
		}
		if err := Deploy(root, *environment, *component, *repository, *tag, *digest, *source); err != nil {
			return fail(err)
		}
	case "dispatch":
		g, code := gitHub(stderr)
		if code != 0 {
			return code
		}
		if *ref == "" || *workflows == "" {
			fmt.Fprintln(stderr, "servicerelease dispatch: --ref and --workflows are required")
			return 2
		}
		for _, w := range strings.Split(*workflows, ",") {
			if err := g.Dispatch(strings.TrimSpace(w), *ref); err != nil {
				return fail(err)
			}
			fmt.Fprintf(stdout, "started %s on %s\n", w, *ref)
		}
	case "close-pull-request":
		if *base == "" || *head == "HEAD" {
			fmt.Fprintln(stderr, "servicerelease close-pull-request: --head and --base are required")
			return 2
		}
		g, code := gitHub(stderr)
		if code != 0 {
			return code
		}
		u, err := g.CloseOpen(*head, *base, "Closing: every service is released, so there is nothing left to release. The release workflow opens a new release PR when a merged change affects a service again.")
		if err != nil {
			return fail(err)
		}
		if u != "" {
			fmt.Fprintln(stdout, "Nothing to release; closed the release PR", u)
		} else {
			fmt.Fprintln(stdout, "Nothing to release.")
		}
	case "pull-request":
		if *base == "" || *head == "HEAD" || *titleFile == "" || *bodyFile == "" {
			fmt.Fprintln(stderr, "servicerelease pull-request: --head, --base, --title-file and --body-file are required")
			return 2
		}
		title, err := os.ReadFile(*titleFile)
		if err != nil {
			return fail(err)
		}
		body, err := os.ReadFile(*bodyFile)
		if err != nil {
			return fail(err)
		}
		g, code := gitHub(stderr)
		if code != 0 {
			return code
		}
		u, err := g.Upsert(*head, *base, strings.TrimSpace(string(title)), string(body))
		if errors.Is(err, ErrCreateRefused) {
			// The pushed branch waits for someone to open the PR; once open, the
			// workflow keeps it up to date.
			server := os.Getenv("GITHUB_SERVER_URL")
			if server == "" {
				server = "https://github.com"
			}
			fmt.Fprintf(stdout, "The release branch %s is ready. GitHub Actions may not open pull requests in this organization, so open it: %s/%s/compare/%s...%s?expand=1\n",
				*head, server, g.Repository, *base, *head)
			return 0
		} else if err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, "The release PR is up to date:", u)
	}
	return 0
}

// gitHub is the API client of the workflow's repository and token.
func gitHub(stderr io.Writer) (PullRequests, int) {
	api := os.Getenv("GITHUB_API_URL")
	if api == "" {
		api = "https://api.github.com"
	}
	g := PullRequests{API: api, Repository: os.Getenv("GITHUB_REPOSITORY"), Token: os.Getenv("GITHUB_TOKEN")}
	if g.Repository == "" || g.Token == "" {
		fmt.Fprintln(stderr, "servicerelease: GITHUB_REPOSITORY and GITHUB_TOKEN are required")
		return g, 2
	}
	return g, 0
}
