//go:build linux

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	privateDirMode       = 0700
	fsGroupPrivateDir    = 02700
	fsGroupMaterialDir   = 02770
	privateFileMode      = 0600
	fsGroupMaterialFile  = 0660
	parameterDigestBytes = sha256.Size * 2
)

type materialDir struct {
	name string
	fd   int
}

// preparePrivateMaterialStore repairs only the modes Kubernetes fsGroup is
// documented to widen. It binds every traversal step and every chmod to an open
// descriptor, refuses links and foreign objects, and leaves the audit volume
// and all unrelated paths untouched.
func preparePrivateMaterialStore(root string) error {
	if !filepath.IsAbs(root) {
		return errors.New("parameter material root must be absolute")
	}
	parentPath, rootName := filepath.Split(filepath.Clean(root))
	rootName = strings.TrimSuffix(rootName, string(filepath.Separator))
	if rootName == "" || rootName == "." || rootName == ".." {
		return errors.New("parameter material root has an invalid name")
	}
	parentFD, err := openAbsoluteDirNoFollow(filepath.Clean(parentPath))
	if err != nil {
		return fmt.Errorf("open parameter material parent: %w", err)
	}
	defer unix.Close(parentFD)

	rootFD, err := mkdirOpenDirAt(parentFD, rootName)
	if err != nil {
		return fmt.Errorf("open parameter material root: %w", err)
	}
	defer unix.Close(rootFD)
	// Refuse a foreign or unexpected existing root before creating anything
	// below it.
	if err := validateOwnedDir(rootFD); err != nil {
		return fmt.Errorf("validate parameter material root: %w", err)
	}

	dirs := make([]materialDir, 0, 2)
	for _, name := range []string{ParameterMaterialManifest, ParameterMaterialPolicyOverrides} {
		fd, openErr := mkdirOpenDirAt(rootFD, name)
		if openErr != nil {
			closeMaterialDirs(dirs)
			return fmt.Errorf("open parameter material %s directory: %w", name, openErr)
		}
		if validateErr := validateOwnedDir(fd); validateErr != nil {
			_ = unix.Close(fd)
			closeMaterialDirs(dirs)
			return fmt.Errorf("validate parameter material %s directory: %w", name, validateErr)
		}
		dirs = append(dirs, materialDir{name: name, fd: fd})
	}
	defer closeMaterialDirs(dirs)

	rootEntries, err := readDirNames(rootFD, 3)
	if err != nil {
		return err
	}
	if len(rootEntries) != 2 || rootEntries[0] != ParameterMaterialManifest || rootEntries[1] != ParameterMaterialPolicyOverrides {
		return errors.New("parameter material root contains an unexpected entry")
	}

	total := 0
	for _, dir := range dirs {
		if err := validateOwnedDir(dir.fd); err != nil {
			return fmt.Errorf("validate parameter material %s directory: %w", dir.name, err)
		}
		names, err := readDirNames(dir.fd, MaxParameterMaterialDocuments+1)
		if err != nil {
			return err
		}
		total += len(names)
		if total > MaxParameterMaterialDocuments {
			return errors.New("parameter material capacity exhausted")
		}
		for _, name := range names {
			if err := inspectMaterialFileAt(dir.fd, name, false); err != nil {
				return fmt.Errorf("validate parameter material entry: %w", err)
			}
		}
	}

	// Reopen and revalidate every object immediately before changing that exact
	// descriptor. A name swap cannot redirect chmod to a symlink or other type.
	for _, dir := range dirs {
		names, err := readDirNames(dir.fd, MaxParameterMaterialDocuments+1)
		if err != nil {
			return err
		}
		for _, name := range names {
			if err := inspectMaterialFileAt(dir.fd, name, true); err != nil {
				return fmt.Errorf("restore parameter material entry: %w", err)
			}
		}
		if err := restoreDirMode(dir.fd); err != nil {
			return fmt.Errorf("restore parameter material %s directory: %w", dir.name, err)
		}
	}
	if err := restoreDirMode(rootFD); err != nil {
		return fmt.Errorf("restore parameter material root: %w", err)
	}
	return nil
}

func openAbsoluteDirNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, errors.New("path must be absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if component == "" || component == "." {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func mkdirOpenDirAt(parentFD int, name string) (int, error) {
	if strings.Contains(name, "/") || name == "" || name == "." || name == ".." {
		return -1, errors.New("invalid directory name")
	}
	if err := unix.Mkdirat(parentFD, name, privateDirMode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	return unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func closeMaterialDirs(dirs []materialDir) {
	for _, dir := range dirs {
		_ = unix.Close(dir.fd)
	}
}

func readDirNames(dirFD, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, errors.New("directory entry limit must be positive")
	}
	fd, err := unix.Openat(dirFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "parameter-material-directory")
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap parameter material directory descriptor")
	}
	defer f.Close()
	entries, err := f.ReadDir(limit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	// os.File.ReadDir returns directory order, so explicitly sort before exact
	// hierarchy comparisons and deterministic validation.
	sort.Strings(names)
	return names, nil
}

func validateOwnedDir(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("object is not a directory")
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return errors.New("directory is not owned by the manager process")
	}
	mode := stat.Mode & 07777
	if mode != privateDirMode && mode != fsGroupPrivateDir && mode != fsGroupMaterialDir {
		return fmt.Errorf("directory mode %#o is outside the recoverable set", mode)
	}
	return nil
}

func restoreDirMode(fd int) error {
	if err := validateOwnedDir(fd); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, privateDirMode); err != nil {
		return err
	}
	return validateExactMode(fd, unix.S_IFDIR, privateDirMode)
}

func inspectMaterialFileAt(dirFD int, name string, restore bool) error {
	digest, temporary, ok := materialEntryName(name)
	if !ok {
		return errors.New("unexpected parameter material file name")
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return errors.New("parameter material entry is not an unlinked regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return errors.New("parameter material entry is not owned by the manager process")
	}
	mode := stat.Mode & 07777
	if mode != privateFileMode && mode != fsGroupMaterialFile {
		return fmt.Errorf("parameter material file mode %#o is outside the recoverable set", mode)
	}
	if stat.Size < 0 || stat.Size > MaxParameterMaterialBytes || (!temporary && stat.Size == 0) {
		return errors.New("parameter material entry exceeds its size bound")
	}
	if !temporary {
		raw, readErr := readDescriptor(fd, stat.Size)
		if readErr != nil || !json.Valid(raw) {
			return errors.New("parameter material document is not valid bounded JSON")
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != digest {
			return errors.New("parameter material document digest does not match its name")
		}
	}
	if restore {
		if err := unix.Fchmod(fd, privateFileMode); err != nil {
			return err
		}
		return validateExactMode(fd, unix.S_IFREG, privateFileMode)
	}
	return nil
}

func readDescriptor(fd int, size int64) ([]byte, error) {
	readFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if _, err := unix.Seek(readFD, 0, io.SeekStart); err != nil {
		_ = unix.Close(readFD)
		return nil, err
	}
	f := os.NewFile(uintptr(readFD), "parameter-material-document")
	if f == nil {
		_ = unix.Close(readFD)
		return nil, errors.New("wrap parameter material descriptor")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxParameterMaterialBytes+1))
	if err != nil || int64(len(raw)) != size {
		return nil, errors.New("parameter material document changed while reading")
	}
	return raw, nil
}

func validateExactMode(fd int, kind uint32, want uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != kind || stat.Mode&07777 != want {
		return errors.New("parameter material mode restoration did not persist")
	}
	return nil
}

func materialEntryName(name string) (digest string, temporary bool, ok bool) {
	if len(name) == parameterDigestBytes+len(".json") && strings.HasSuffix(name, ".json") {
		digest = strings.TrimSuffix(name, ".json")
		return digest, false, validLowerHex(digest, parameterDigestBytes)
	}
	if len(name) != 1+parameterDigestBytes+len(".json.")+24+len(".tmp") || name[0] != '.' || !strings.HasSuffix(name, ".tmp") {
		return "", false, false
	}
	digest = name[1 : 1+parameterDigestBytes]
	randomStart := 1 + parameterDigestBytes + len(".json.")
	if name[1+parameterDigestBytes:randomStart] != ".json." || !validLowerHex(digest, parameterDigestBytes) || !validLowerHex(name[randomStart:randomStart+24], 24) {
		return "", false, false
	}
	return digest, true, true
}

func validLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == length
}
