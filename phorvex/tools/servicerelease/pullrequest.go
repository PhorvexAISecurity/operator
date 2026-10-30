package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrCreateRefused reports that GitHub refused to let the workflow open the PR:
// the organization does not allow GitHub Actions to create pull requests.
var ErrCreateRefused = errors.New("GitHub Actions may not open pull requests here")

// PullRequests opens or updates the release PR through the GitHub REST API.
type PullRequests struct {
	API, Repository, Token string
	Client                 *http.Client
}

func (g PullRequests) call(method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, strings.TrimSuffix(g.API, "/")+"/repos/"+g.Repository+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		err := fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
		if method == "POST" && resp.StatusCode == http.StatusForbidden {
			return errors.Join(ErrCreateRefused, err)
		}
		return err
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Dispatch starts a workflow_dispatch run of a workflow file on ref. GitHub starts
// no pull_request run for a PR the workflow's own token opened or updated, so the
// release workflow starts the PR checks this way.
func (g PullRequests) Dispatch(workflow, ref string) error {
	return g.call("POST", "/actions/workflows/"+url.PathEscape(workflow)+"/dispatches", map[string]string{"ref": ref}, nil)
}

// CloseOpen closes the open PR from head into base, if there is one, with a
// comment saying why, and returns its URL; empty when none was open.
func (g PullRequests) CloseOpen(head, base, why string) (string, error) {
	open, err := g.open(head, base)
	if err != nil || len(open) == 0 {
		return "", err
	}
	if err := g.call("POST", fmt.Sprintf("/issues/%d/comments", open[0].Number), map[string]string{"body": why}, nil); err != nil {
		return "", err
	}
	return open[0].HTMLURL, g.call("PATCH", fmt.Sprintf("/pulls/%d", open[0].Number), map[string]string{"state": "closed"}, nil)
}

type openPull struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (g PullRequests) open(head, base string) ([]openPull, error) {
	owner, _, _ := strings.Cut(g.Repository, "/")
	var open []openPull
	q := url.Values{"state": {"open"}, "head": {owner + ":" + head}, "base": {base}}
	err := g.call("GET", "/pulls?"+q.Encode(), nil, &open)
	return open, err
}

// VerifyOpen proves that Upsert resulted in exactly the requested open PR. It is
// used by lanes for which a pushed branch without a review object is failure.
func (g PullRequests) VerifyOpen(head, base, expectedURL string) error {
	open, err := g.open(head, base)
	if err != nil {
		return err
	}
	if len(open) != 1 || open[0].Number <= 0 || open[0].HTMLURL == "" || open[0].HTMLURL != expectedURL ||
		open[0].Head.Ref != head || open[0].Base.Ref != base {
		return fmt.Errorf("GitHub did not return exactly the requested open %s -> %s pull request", head, base)
	}
	return nil
}

// Upsert updates the open PR from head into base, or opens one, and returns its URL.
func (g PullRequests) Upsert(head, base, title, body string) (string, error) {
	open, err := g.open(head, base)
	if err != nil {
		return "", err
	}
	var pr struct {
		HTMLURL string `json:"html_url"`
	}
	if len(open) > 0 {
		err := g.call("PATCH", fmt.Sprintf("/pulls/%d", open[0].Number), map[string]string{"title": title, "body": body}, &pr)
		return pr.HTMLURL, err
	}
	err = g.call("POST", "/pulls", map[string]string{"head": head, "base": base, "title": title, "body": body}, &pr)
	return pr.HTMLURL, err
}
