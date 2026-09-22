//go:build !linux

package audit

import (
	"os"
	"path/filepath"
)

func preparePrivateMaterialStore(root string) error {
	for _, dir := range []string{root, filepath.Join(root, ParameterMaterialManifest), filepath.Join(root, ParameterMaterialPolicyOverrides)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := validatePrivateMaterialDir(dir); err != nil {
			return err
		}
	}
	return nil
}
