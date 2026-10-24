// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func touch(t *testing.T, dir, name string, mod time.Time, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
}

// The newest dump is found by its modification time among the pg dumps only:
// the roles file, the age-key copy and the archive sit in the same directory
// and must not be mistaken for "the last backup".
func TestNewestDumpIsTheNewestPgFileOnly(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2026, 10, 22, 3, 31, 0, 0, time.UTC)
	mid := time.Date(2026, 10, 23, 3, 31, 0, 0, time.UTC)
	touch(t, dir, "pg_20261022_033000.sql.gz.enc", old, "aaa")
	touch(t, dir, "pg_20261023_033000.sql.gz.enc", mid, "bbbb")
	// Newer than every dump, but not a dump.
	touch(t, dir, "pgroles_20261024_100000.sql.enc", mid.Add(30*time.Hour), "x")
	touch(t, dir, "age-key_20261024_100000.txt.enc", mid.Add(30*time.Hour), "x")

	f := CollectBackupFacts(dir)
	if f.Count != 2 || f.NewestPg != "pg_20261023_033000.sql.gz.enc" {
		t.Fatalf("facts = %+v", f)
	}
	if f.NewestTS != "2026-10-23T03:31:00Z" || f.NewestBytes != 4 {
		t.Fatalf("facts = %+v", f)
	}
	if f.Error != "" {
		t.Fatalf("unexpected error %q", f.Error)
	}
}

// Nothing backed up yet is a fact; an unreadable directory is a DIFFERENT
// fact. Folding them together reports "no backups" for a disk that is
// failing, which is the 2026-10-24 shape.
func TestNoDumpsAndAnUnreadableDirectoryAreDifferentFacts(t *testing.T) {
	empty := CollectBackupFacts(t.TempDir())
	if empty.Count != 0 || empty.NewestTS != "" || empty.Error != "" {
		t.Fatalf("empty dir = %+v", empty)
	}
	missing := CollectBackupFacts(filepath.Join(t.TempDir(), "never-created"))
	if missing.Count != 0 || missing.Error != "" {
		t.Fatalf("missing dir = %+v", missing)
	}
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := CollectBackupFacts(file) // a file where a directory should be
	if bad.Error == "" {
		t.Fatalf("an unreadable backup dir read as plainly empty: %+v", bad)
	}
}

// The heartbeat a controller-mode daemon writes carries the facts; a worker's
// does not (it has no backup directory to speak of).
func TestTheHeartbeatCarriesTheBackupFactsInControllerModeOnly(t *testing.T) {
	dir := t.TempDir()
	mod := time.Date(2026, 10, 23, 3, 31, 0, 0, time.UTC)
	touch(t, dir, "pg_20261023_033000.sql.gz.enc", mod, "dump")
	t.Setenv("NOO_BACKUP_DIR", dir)

	read := func(mode string) Heartbeat {
		e, _ := testEngine(t)
		e.Mode = mode
		e.writeHeartbeat(stamp(), DefaultHeartbeatInterval)
		raw, err := os.ReadFile(filepath.Join(e.Spool, HeartbeatFile))
		if err != nil {
			t.Fatal(err)
		}
		var hb Heartbeat
		if err := json.Unmarshal(raw, &hb); err != nil {
			t.Fatal(err)
		}
		return hb
	}
	c := read(ModeController)
	if c.Backup == nil || c.Backup.NewestTS != "2026-10-23T03:31:00Z" || c.Backup.Dir != dir {
		t.Fatalf("controller heartbeat backup = %+v", c.Backup)
	}
	if w := read(ModeWorker); w.Backup != nil {
		t.Fatalf("a worker published backup facts: %+v", w.Backup)
	}
}

// 2026-10-24: `noo backups setup` wrote NOO_BACKUP_OFFSITE to the checkout's
// .env; hostd's backup op did not carry it, the script said "not configured",
// exited 0, and the run was recorded as a success.
func TestTheBackupOpCarriesTheOffsiteSettingFromDotEnv(t *testing.T) {
	t.Setenv("NOO_BACKUP_OFFSITE", "")
	e, fr := testEngine(t)
	if err := os.WriteFile(filepath.Join(e.Root, ".env"),
		[]byte("A=1\n# NOO_BACKUP_OFFSITE=dir:/old\nNOO_BACKUP_OFFSITE=\"dir:/mnt/fleet/backups x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opBackup(context.Background(), e, "noo-postgres", &Command{})
	if len(fr.envs) != 1 {
		t.Fatalf("runs = %d", len(fr.envs))
	}
	found := false
	for _, kv := range fr.envs[0] {
		if kv == "NOO_BACKUP_OFFSITE=dir:/mnt/fleet/backups x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the backup op's environment lacks the off-site setting: %v", fr.envs[0])
	}
	// An exported value wins, and an unset file adds nothing.
	t.Setenv("NOO_BACKUP_OFFSITE", "dir:/exported")
	if got := backupExtraEnv(e.Root); got != nil {
		t.Fatalf("an exported value must not be overridden: %v", got)
	}
	t.Setenv("NOO_BACKUP_OFFSITE", "")
	if got := backupExtraEnv(t.TempDir()); got != nil {
		t.Fatalf("no .env, no setting, got %v", got)
	}
}

// The off-site outcome rides the result, on success and on failure, and its
// marker line never leaks into the stderr an operator reads.
func TestTheOffsiteOutcomeIsCarriedInTheBackupResult(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "pg_1.sql.gz.enc")
	if err := os.WriteFile(dump, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := annotateBackup(Result{OK: true, Stderr: "NOO_BACKUP_ARTIFACT=" + dump +
		"\nNOO_BACKUP_OFFSITE_RESULT=copied 1 artifact(s) to dir:/mnt/x"})
	if ok.Offsite != "copied 1 artifact(s) to dir:/mnt/x" || strings.Contains(ok.Stderr, "OFFSITE_RESULT") {
		t.Fatalf("result = %+v", ok)
	}
	bad := annotateBackup(Result{OK: false, RC: 1, Stderr: "NOO_BACKUP_OFFSITE_RESULT=FAILED: /mnt/x missing"})
	if bad.Offsite != "FAILED: /mnt/x missing" || bad.OK {
		t.Fatalf("result = %+v", bad)
	}
}
