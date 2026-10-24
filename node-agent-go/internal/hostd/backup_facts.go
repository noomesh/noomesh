// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BackupFacts is what the controller's backup directory says about the
// newest Postgres dump, published in the hostd heartbeat.
//
// Why it rides the heartbeat: the `database_backup` task is scheduled by the
// gateway, which lives in the stack that goes down. On 2026-10-24 the data
// disk failed, Postgres was down for 17 hours, the 03:30 run never happened,
// and the only record of "the last good backup" was a table in the database
// that was down. This daemon runs on the host and survives a dead database, so
// the age of the newest dump is read from the FILES (what protects the data),
// not from the scheduler's history (what the scheduler believes). A reader
// that cannot reach the database, or finds the scheduler wedged, can still
// answer "when was the last backup?" from one small file in the spool.
type BackupFacts struct {
	// Dir is the directory looked at ($NOO_BACKUP_DIR, else ~/noo-backups).
	Dir string `json:"dir"`
	// NewestPg is the newest pg_*.sql.gz.enc by modification time; empty when
	// there is none. NewestTS is its mtime (RFC3339 UTC), NewestBytes its size.
	NewestPg    string `json:"newest_pg,omitempty"`
	NewestTS    string `json:"newest_ts,omitempty"`
	NewestBytes int64  `json:"newest_bytes,omitempty"`
	// Count is how many such dumps the directory holds.
	Count int `json:"count"`
	// Error is why the directory could not be read ("not a dump yet" is
	// NOT an error: it is Count == 0 with no Error).
	Error string `json:"error,omitempty"`
}

// backupDumpName matches the dump the backup script writes.
func backupDumpName(n string) bool {
	return strings.HasPrefix(n, "pg_") && strings.HasSuffix(n, ".sql.gz.enc")
}

// BackupDir is where the backup script writes: the same resolution as
// `BACKUP_DIR="${NOO_BACKUP_DIR:-$HOME/noo-backups}"` in backup-controller.sh.
func BackupDir() string {
	if d := strings.TrimSpace(os.Getenv("NOO_BACKUP_DIR")); d != "" {
		return d
	}
	home := os.Getenv("HOME")
	if home == "" {
		home = "."
	}
	return filepath.Join(home, "noo-backups")
}

// CollectBackupFacts reads dir. A missing directory is Count 0 (nothing has
// ever been backed up here); any other read failure is reported in Error
// rather than as "no backups", because unreadable is not the same as empty.
func CollectBackupFacts(dir string) *BackupFacts {
	f := &BackupFacts{Dir: dir}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			f.Error = err.Error()
		}
		return f
	}
	type dump struct {
		name string
		mod  time.Time
		size int64
	}
	var dumps []dump
	for _, e := range ents {
		if e.IsDir() || !backupDumpName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		dumps = append(dumps, dump{e.Name(), info.ModTime().UTC(), info.Size()})
	}
	f.Count = len(dumps)
	if len(dumps) == 0 {
		return f
	}
	// Newest by mtime; the timestamped name breaks a tie deterministically.
	sort.Slice(dumps, func(i, j int) bool {
		if !dumps[i].mod.Equal(dumps[j].mod) {
			return dumps[i].mod.After(dumps[j].mod)
		}
		return dumps[i].name > dumps[j].name
	})
	f.NewestPg = dumps[0].name
	f.NewestTS = dumps[0].mod.Format("2006-01-02T15:04:05Z")
	f.NewestBytes = dumps[0].size
	return f
}
