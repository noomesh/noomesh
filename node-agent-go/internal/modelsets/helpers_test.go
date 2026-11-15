// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

func configWithCA(path string) *config.Config { return &config.Config{TLSCA: path} }

// reopenFilesForTest makes every regular file under dir 0644: test planting
// only. Production never chmods a file outside sealing (see
// TestNothingWritesIntoAnExistingFileOrChmodsOne).
func reopenFilesForTest(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			return os.Chmod(p, 0o644)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
