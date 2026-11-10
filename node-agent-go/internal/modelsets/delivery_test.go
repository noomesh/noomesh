// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// i607b: the heartbeat rows carry the delivery numbers.

func i64(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

func onlyRow(t *testing.T, s *Store) Row {
	t.Helper()
	rows, ok := s.Rows()
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %+v ok=%v", rows, ok)
	}
	return rows[0]
}

// progressRig fetches through the real preseed client, but reports what the
// store's rows say before a file and after it, with no network beyond the test's own httptest cache.
type progressRig struct {
	r     *rig
	mu    sync.Mutex
	steps []string // "<file> <point>: done/total"
	sizes map[string]int64
	inner *preseed.Client
}

func (p *progressRig) FetchOneVerified(ctx context.Context, u, dest, sha string) (bool, error) {
	return p.FetchOneVerifiedProgress(ctx, u, dest, sha, nil)
}

func (p *progressRig) FetchOneVerifiedProgress(ctx context.Context, u, dest, sha string, progress func(int64)) (bool, error) {
	rel, _ := filepath.Rel(p.r.store.dir(refA), dest)
	rel = filepath.ToSlash(rel)
	snap := func(point string) {
		row := onlyRow(p.r.t, p.r.store)
		p.mu.Lock()
		p.steps = append(p.steps, rel+" "+point+": "+itoa(i64(row.BytesDone))+"/"+itoa(i64(row.BytesTotal))+" "+row.State)
		p.mu.Unlock()
	}
	snap("before")
	// The real hook: the preseed client reports the bytes it wrote.
	wrote, err := p.inner.FetchOneVerifiedProgress(ctx, u, dest, sha, progress)
	if err == nil {
		snap("after")
	}
	return wrote, err
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestFetchingRowAdvancesBytesDoneAcrossTwoFiles(t *testing.T) {
	r := newRig(t)
	files := map[string][]byte{
		"model.bin": []byte(strings.Repeat("m", 40)),
		"tok.bin":   []byte(strings.Repeat("t", 10)),
	}
	r.stage(refA, files, r.key)
	sizes := map[string]int64{"model.bin": 40, "tok.bin": 10}
	p := &progressRig{r: r, sizes: sizes, inner: &preseed.Client{HTTP: r.srv.Client()}}
	r.store.Files = p

	r.store.Sync(context.Background(), []Ref{refA})
	r.store.Wait()

	// Whichever file the manifest lists first: done is 0 before it and its
	// full size after it; the second starts there and ends on the total.
	if len(p.steps) != 4 {
		t.Fatalf("steps = %v", p.steps)
	}
	first, second := strings.Fields(p.steps[0])[0], strings.Fields(p.steps[2])[0]
	if first == second {
		t.Fatalf("both steps are %s: %v", first, p.steps)
	}
	want := []string{
		first + " before: 0/50 fetching",
		first + " after: " + itoa(sizes[first]) + "/50 fetching",
		second + " before: " + itoa(sizes[first]) + "/50 fetching",
		second + " after: 50/50 fetching",
	}
	for i := range want {
		if p.steps[i] != want[i] {
			t.Fatalf("step %d = %q, want %q (all %v)", i, p.steps[i], want[i], p.steps)
		}
	}
	// Sealed: verified carries the total and no done.
	row := onlyRow(t, r.store)
	if row.State != "verified" || i64(row.BytesTotal) != 50 || row.BytesDone != nil || row.RetryAt != "" {
		t.Fatalf("verified row = %+v", row)
	}
}

// Rows of a fetch with no progress hook (an old Fetcher) still say fetching,
// and say nothing about bytes: unknown is not zero.
func TestFetchingRowWithoutProgressCarriesNoBytes(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	var rows []Row
	r.store.Files = fetcherFunc(func(ctx context.Context, u, dest, sha string) (bool, error) {
		rows = append(rows, onlyRow(t, r.store))
		return (&preseed.Client{HTTP: r.srv.Client()}).FetchOneVerified(ctx, u, dest, sha)
	})
	r.store.Sync(context.Background(), []Ref{refA})
	r.store.Wait()
	if len(rows) == 0 || rows[0].State != "fetching" {
		t.Fatalf("rows = %+v", rows)
	}
	// total is known once the manifest is read, done stays at what is on disk.
	if i64(rows[0].BytesTotal) != int64(len(filesA["model.bin"])+len(filesA["cfg/tok.json"])) || i64(rows[0].BytesDone) != 0 {
		t.Fatalf("fetching row = %+v", rows[0])
	}
	if rows[0].RetryAt != "" || rows[0].FreeBytes != nil || rows[0].NeedBytes != nil || rows[0].Reason != "" {
		t.Fatalf("a fetching row carries refusal fields: %+v", rows[0])
	}
}

func TestQueuedSetRowHasNoByteFields(t *testing.T) {
	r := newRig(t)
	// Wanted, nothing on disk, no fetch running yet: fetching, nothing known.
	r.store.mu.Lock()
	r.store.armed = true
	r.store.want = map[Ref]bool{refA: true}
	r.store.mu.Unlock()
	row := onlyRow(t, r.store)
	raw, _ := json.Marshal(row)
	if row.State != "fetching" || string(raw) != `{"id":"rh-stt-small","revision":"r1","state":"fetching"}` {
		t.Fatalf("row = %s", raw)
	}
}

func TestDiskRefusalRowRecordsFreeNeedAndRetryAt(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	r.store.Free = func(string) (uint64, error) { return DiskMarginMin, nil }
	r.store.Sync(context.Background(), []Ref{refA})
	r.store.Wait()

	total := int64(len(filesA["model.bin"]) + len(filesA["cfg/tok.json"]))
	row := onlyRow(t, r.store)
	if row.State != "refused" || row.Reason != nodewl.ReasonDisk {
		t.Fatalf("row = %+v", row)
	}
	if i64(row.FreeBytes) != int64(DiskMarginMin) || i64(row.NeedBytes) != total+int64(DiskMarginMin) {
		t.Fatalf("free/need = %d/%d, want %d/%d", i64(row.FreeBytes), i64(row.NeedBytes), int64(DiskMarginMin), total+int64(DiskMarginMin))
	}
	want := time.Unix(1_800_000_000, 0).Add(refusedRetry).UTC().Format(time.RFC3339)
	if row.RetryAt != want {
		t.Fatalf("retry_at = %q, want %q", row.RetryAt, want)
	}
	if row.BytesDone != nil || row.BytesTotal != nil {
		t.Fatalf("a refused row carries byte progress: %+v", row)
	}
	raw, _ := json.Marshal(row)
	if !strings.Contains(string(raw), `"reason":"disk"`) || !strings.Contains(string(raw), `"retry_at":"2027-01-15T08:30:00Z"`) {
		t.Fatalf("wire = %s", raw)
	}
}

// Any other refusal has a retry time but never the disk numbers.
func TestNonDiskRefusalRowHasRetryAtOnly(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, newKey(t)) // bad signature
	r.store.Sync(context.Background(), []Ref{refA})
	r.store.Wait()
	row := onlyRow(t, r.store)
	if row.State != "refused" || row.Reason != nodewl.ReasonSetUnverified || row.RetryAt == "" {
		t.Fatalf("row = %+v", row)
	}
	if row.FreeBytes != nil || row.NeedBytes != nil || row.BytesDone != nil || row.BytesTotal != nil {
		t.Fatalf("a non-disk refusal carries numbers: %+v", row)
	}
}

func TestFreeBytesReadsTheFilesystemTheDiskCheckReads(t *testing.T) {
	r := newRig(t)
	var asked string
	r.store.Free = func(p string) (uint64, error) { asked = p; return 12345, nil }
	n, ok := r.store.FreeBytes()
	if !ok || n != 12345 {
		t.Fatalf("FreeBytes = %d %v", n, ok)
	}
	if asked == "" || !strings.HasPrefix(r.store.Root, asked) {
		t.Fatalf("read at %q, not at/above the sets dir (nearest existing ancestor)", asked)
	}
	r.store.Free = func(string) (uint64, error) { return 0, errors.New("statfs") }
	if n, ok := r.store.FreeBytes(); ok {
		t.Fatalf("an unreadable disk reported %d", n)
	}
	if _, ok := (&Store{}).FreeBytes(); ok {
		t.Fatal("a store with no models dir reported free bytes")
	}
}
