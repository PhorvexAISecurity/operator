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

// Upsert updates the open PR from head into base, or opens one, and returns its URL.
func (g PullRequests) Upsert(head, base, title, body string) (string, error) {
	owner, _, _ := strings.Cut(g.Repository, "/")
	var open []struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	q := url.Values{"state": {"open"}, "head": {owner + ":" + head}, "base": {base}}
	if err := g.call("GET", "/pulls?"+q.Encode(), nil, &open); err != nil {
		return "", err
	}
	var pr struct {
		HTMLURL string `json:"html_url"`
	}
	if len(open) > 0 {
		err := g.call("PATCH", fmt.Sprintf("/pulls/%d", open[0].Number), map[string]string{"title": title, "body": body}, &pr)
		return pr.HTMLURL, err
	}
	err := g.call("POST", "/pulls", map[string]string{"head": head, "base": base, "title": title, "body": body}, &pr)
	return pr.HTMLURL, err
}
