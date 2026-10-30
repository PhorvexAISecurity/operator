package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

// pathIdentity is retained across every authoritative read/write boundary. It
// detects a parent rename/swap as well as a leaf replacement. Release files are
// also required to have one link so a write cannot mutate an untracked alias.
type pathIdentity struct {
	Path  string
	Dev   uint64
	Ino   uint64
	Mode  fs.FileMode
	Size  int64
	MTime int64
	CTime int64
}

func identity(path string, info fs.FileInfo) pathIdentity {
	id := pathIdentity{Path: path, Mode: info.Mode()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		id.Dev = uint64(stat.Dev)
		id.Ino = stat.Ino
		if info.Mode().IsRegular() {
			id.Size = stat.Size
			id.MTime = stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec
			id.CTime = stat.Ctim.Sec*1_000_000_000 + stat.Ctim.Nsec
		}
	}
	return id
}

func pathSnapshot(path string, allowMissingLeaf bool) ([]pathIdentity, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	volume := filepath.VolumeName(abs)
	current := volume + string(filepath.Separator)
	parts := splitPathComponents(abs[len(current):])
	identities := make([]pathIdentity, 0, len(parts)+1)
	rootInfo, err := os.Lstat(current)
	if err != nil {
		return nil, err
	}
	identities = append(identities, identity(current, rootInfo))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissingLeaf && i == len(parts)-1 {
			return identities, nil
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s: symlinks are not permitted in release-authoritative paths", current)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("%s: non-directory path component", current)
		}
		if info.Mode().IsRegular() && info.Sys().(*syscall.Stat_t).Nlink != 1 {
			return nil, fmt.Errorf("%s: hard-linked release-authoritative files are not permitted", current)
		}
		identities = append(identities, identity(current, info))
	}
	return identities, nil
}

func splitPathComponents(path string) []string {
	var parts []string
	for path != "." && path != string(filepath.Separator) && path != "" {
		dir, base := filepath.Split(path)
		if base != "" {
			parts = append([]string{base}, parts...)
		}
		path = filepath.Clean(dir)
	}
	return parts
}

func safeRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	snapshot, err := pathSnapshot(abs, false)
	if err != nil {
		return "", fmt.Errorf("repository root: %w", err)
	}
	if len(snapshot) == 0 || !snapshot[len(snapshot)-1].Mode.IsDir() {
		return "", fmt.Errorf("repository root %s is not a directory", abs)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if filepath.Clean(resolved) != abs {
		return "", fmt.Errorf("repository root %s resolves to %s", abs, resolved)
	}
	return abs, nil
}

func withinRoot(root, path string) (string, error) {
	root, err := safeRoot(root)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || filepath.IsAbs(rel) || (len(rel) > 3 && rel[:3] == ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("release-authoritative path %q escapes repository root %q", path, root)
	}
	return abs, nil
}

func safeRepoPath(root, relative string, directory bool) (string, error) {
	relative, err := cleanRepoPath(relative)
	if err != nil {
		return "", err
	}
	path, err := withinRoot(root, filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return "", err
	}
	snapshot, err := pathSnapshot(path, false)
	if err != nil {
		return "", err
	}
	last := snapshot[len(snapshot)-1]
	if directory && !last.Mode.IsDir() {
		return "", fmt.Errorf("%s: expected directory", path)
	}
	if !directory && !last.Mode.IsRegular() {
		return "", fmt.Errorf("%s: expected regular file", path)
	}
	return path, nil
}

func readRegularFile(path string) ([]byte, error) {
	before, err := pathSnapshot(path, false)
	if err != nil {
		return nil, err
	}
	if len(before) == 0 || !before[len(before)-1].Mode.IsRegular() {
		return nil, fmt.Errorf("%s: expected regular file", path)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if identity(path, opened) != before[len(before)-1] {
		_ = file.Close()
		return nil, fmt.Errorf("%s: file identity changed before read", path)
	}
	raw, readErr := io.ReadAll(file)
	closeErr := file.Close()
	after, snapshotErr := pathSnapshot(path, false)
	if readErr != nil || closeErr != nil || snapshotErr != nil {
		return nil, errors.Join(readErr, closeErr, snapshotErr)
	}
	if !reflect.DeepEqual(before, after) {
		return nil, fmt.Errorf("%s: path identity changed during read", path)
	}
	return raw, nil
}

func readRepoFile(root, relative string) ([]byte, error) {
	path, err := safeRepoPath(root, relative, false)
	if err != nil {
		return nil, err
	}
	return readRegularFile(path)
}

// pinnedCommand executes the already-opened executable inode through a private
// inherited descriptor. A rename/swap after validation cannot change the code
// that execve receives.
func pinnedCommand(path string, args ...string) (*exec.Cmd, func(), error) {
	before, err := pathSnapshot(path, false)
	if err != nil {
		return nil, nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if identity(path, info) != before[len(before)-1] {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s: executable identity changed before open", path)
	}
	cmd := exec.Command("/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{file}
	cleanup := func() { _ = file.Close() }
	return cmd, cleanup, nil
}

// beforeAtomicReplace is a deterministic test seam for rename/symlink races.
// Production leaves it nil and still repeats the complete identity check at
// the rename boundary.
var beforeAtomicReplace func(string)

func writeAtomicFile(path string, raw []byte) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	parentBefore, err := pathSnapshot(parent, false)
	if err != nil {
		return err
	}
	if !parentBefore[len(parentBefore)-1].Mode.IsDir() {
		return fmt.Errorf("%s: write parent is not a directory", parent)
	}
	targetBefore, targetErr := pathSnapshot(path, true)
	if targetErr != nil {
		return targetErr
	}
	temp, err := os.CreateTemp(parent, ".servicerelease-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if _, err := pathSnapshot(tempPath, false); err != nil {
		return err
	}
	if beforeAtomicReplace != nil {
		beforeAtomicReplace(path)
	}
	parentAfter, err := pathSnapshot(parent, false)
	if err != nil {
		return err
	}
	targetAfter, err := pathSnapshot(path, true)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(parentBefore, parentAfter) || !reflect.DeepEqual(targetBefore, targetAfter) {
		return fmt.Errorf("%s: path identity changed before atomic replace", path)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	written, err := readRegularFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(written, raw) {
		return fmt.Errorf("%s: atomic write verification failed", path)
	}
	return nil
}

// VerifyBuildPaths repeats the filesystem authority proof immediately before a
// Docker build. The Dockerfile, ignore contract and every tracked context entry
// must be a non-symlink path below the exact repository root.
func VerifyBuildPaths(root, dockerfile, context string) error {
	if _, err := safeRoot(root); err != nil {
		return err
	}
	if _, err := safeRepoPath(root, dockerfile, false); err != nil {
		return fmt.Errorf("Dockerfile: %w", err)
	}
	if _, err := safeRepoPath(root, ".dockerignore", false); err != nil {
		return fmt.Errorf("Docker context ignore file: %w", err)
	}
	contextPath := root
	contextArg := "."
	if context != "." {
		clean, err := cleanRepoPath(context)
		if err != nil {
			return err
		}
		contextArg = clean
		contextPath, err = safeRepoPath(root, clean, true)
		if err != nil {
			return err
		}
	}
	if _, err := pathSnapshot(contextPath, false); err != nil {
		return err
	}
	tracked, err := git(root, "ls-files", "--stage", "-z", "--", contextArg)
	if err != nil {
		return err
	}
	if strings.TrimSpace(tracked) == "" {
		return fmt.Errorf("Docker build context %q has no tracked files", context)
	}
	for _, entry := range strings.Split(strings.TrimSuffix(tracked, "\x00"), "\x00") {
		tab := strings.IndexByte(entry, '\t')
		if tab < 0 {
			return fmt.Errorf("malformed tracked Docker context entry %q", entry)
		}
		metadata, path := entry[:tab], entry[tab+1:]
		mode := strings.Fields(metadata)
		if len(mode) != 3 {
			return fmt.Errorf("malformed tracked Docker context metadata %q", metadata)
		}
		if mode[0] == "120000" {
			return fmt.Errorf("tracked symlink %s is not permitted in a release Docker context", path)
		}
		if _, err := safeRepoPath(root, path, false); err != nil {
			return fmt.Errorf("Docker context entry %s: %w", path, err)
		}
	}
	return nil
}
