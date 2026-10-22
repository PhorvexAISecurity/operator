package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Inputs is what a component's image is built from: exact files, and
// directories every file under which is an input.
type Inputs struct {
	Files map[string]bool
	Dirs  []string
}

// Contains reports whether the repo-relative path is an input.
func (in Inputs) Contains(path string) bool {
	if in.Files[path] {
		return true
	}
	for _, dir := range in.Dirs {
		if strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

// listedPackage is the part of `go list -json` output read here.
type listedPackage struct {
	Dir                                           string
	Standard                                      bool
	GoFiles, CgoFiles, EmbedFiles, SFiles, HFiles []string
	CFiles, CXXFiles, SysoFiles                   []string
	Module                                        *struct{ GoMod string }
}

// ResolveInputs lists a component's inputs in the repository at root. The import
// graph is read for the images' platform, linux/amd64 without cgo, so files
// another platform would compile are not inputs.
func ResolveInputs(root string, c Component) (Inputs, error) {
	in := Inputs{Files: map[string]bool{c.Dockerfile: true}, Dirs: append([]string(nil), c.Paths...)}
	if c.Chart != "" {
		in.Dirs = append(in.Dirs, c.Chart)
	}
	for _, b := range c.Builds {
		cmd := exec.Command("go", append([]string{"list", "-mod=readonly", "-deps", "-json"}, b.Packages...)...)
		cmd.Dir = filepath.Join(root, filepath.FromSlash(b.Module))
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return Inputs{}, fmt.Errorf("go list in %s: %v: %s", b.Module, err, strings.TrimSpace(stderr.String()))
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		for {
			var p listedPackage
			if err := dec.Decode(&p); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return Inputs{}, fmt.Errorf("go list in %s: %w", b.Module, err)
			}
			dir, ok := within(root, p.Dir)
			if p.Standard || !ok {
				continue // the standard library and the module cache are pinned by go.mod/go.sum
			}
			for _, files := range [][]string{p.GoFiles, p.CgoFiles, p.EmbedFiles, p.SFiles, p.HFiles, p.CFiles, p.CXXFiles, p.SysoFiles} {
				for _, f := range files {
					in.Files[joinRel(dir, f)] = true
				}
			}
			if p.Module != nil && p.Module.GoMod != "" {
				if mod, ok := within(root, p.Module.GoMod); ok {
					in.Files[mod] = true
					in.Files[strings.TrimSuffix(mod, "go.mod")+"go.sum"] = true
				}
			}
		}
	}
	sort.Strings(in.Dirs)
	return in, nil
}

// within returns path relative to root, with forward slashes, when it lies inside root.
func within(root, path string) (string, bool) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func joinRel(dir, file string) string {
	if dir == "." {
		return file
	}
	return dir + "/" + filepath.ToSlash(file)
}
