// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"context"
	"path/filepath"
	"strings"
	"time"
)

// FileSource tails one plain log file — the darwin lane, where hostd and
// the harness are launchd jobs whose plists send stdout/stderr to files
// (hostd install.go: `<root>/.noo-host-spool/hostd.log`,
// `/var/log/noo-hostd.log`; api/hostlogs.go: `/tmp/noomesh-harness.log`).
// No journal, no daemon: read the file the platform already writes.
//
// Lines carry no timestamp we can trust, so TS is the read time; the
// first sight starts at the end of the file (never its history).
type FileSource struct {
	path     string
	name     string
	stateDir string
}

// NewFileSource tails path as `name` (source=file).
func NewFileSource(path, name, stateDir string) *FileSource {
	return &FileSource{path: path, name: name, stateDir: stateDir}
}

func (f *FileSource) Name() string { return SourceFile + ":" + f.name }

func (f *FileSource) Run(ctx context.Context, emit func(Entry)) {
	key := strings.NewReplacer("/", "_", ".", "_").Replace(f.path)
	t := newTailer(f.path, filepath.Join(f.stateDir, "logship", "file-"+key+".offset"))
	t.run(ctx, time.Second, func(line string) {
		emit(Entry{TS: time.Now().UnixNano(), Line: line, Labels: Labels{
			Source: SourceFile, Name: f.name, Stream: StreamStdout, Level: ExtractLevel(line),
		}})
	})
}
