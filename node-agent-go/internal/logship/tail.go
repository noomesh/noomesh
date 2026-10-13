// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tailer follows a file that another process appends to and rotates
// (rename to path+".1"), persisting (inode, offset) so an agent restart
// resumes where it left off rather than re-shipping the file.
//
// Behaviour:
//   - no saved offset: start at the END of the file (never re-ship a
//     file's history on first sight);
//   - inode changed: finish the old file if it is now at path+".1", then
//     start the new one at 0;
//   - file shrank below the offset: it was truncated — start at 0;
//   - a partial trailing line is left for the next pass.
type tailer struct {
	path       string
	offsetFile string
	ino        uint64
	off        int64
	maxLine    int
	readBudget int64
}

func newTailer(path, offsetFile string) *tailer {
	t := &tailer{path: path, offsetFile: offsetFile, maxLine: 1 << 20, readBudget: 4 << 20}
	t.load()
	return t
}

func (t *tailer) load() {
	if t.offsetFile == "" {
		return
	}
	b, err := os.ReadFile(t.offsetFile)
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return
	}
	ino, err1 := strconv.ParseUint(f[0], 10, 64)
	off, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 == nil && err2 == nil {
		t.ino, t.off = ino, off
	}
}

func (t *tailer) save() {
	if t.offsetFile == "" {
		return
	}
	tmp := t.offsetFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %d\n", t.ino, t.off)), 0o640); err != nil {
		return
	}
	_ = os.Rename(tmp, t.offsetFile)
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// run polls until ctx ends.
func (t *tailer) run(ctx context.Context, poll time.Duration, emit func(line string)) {
	tk := time.NewTicker(poll)
	defer tk.Stop()
	for {
		t.readOnce(emit)
		select {
		case <-ctx.Done():
			t.save()
			return
		case <-tk.C:
		}
	}
}

// readOnce does one pass: rotation/truncation handling, then reads new
// complete lines.
func (t *tailer) readOnce(emit func(string)) {
	fi, err := os.Stat(t.path)
	if err != nil {
		return
	}
	ino := inodeOf(fi)
	switch {
	case t.ino == 0:
		// First sight: start at the end.
		t.ino, t.off = ino, fi.Size()
		t.save()
		return
	case ino != t.ino:
		// Rotated. Drain the predecessor if it is our old inode.
		if pfi, err := os.Stat(t.path + ".1"); err == nil && inodeOf(pfi) == t.ino {
			t.readFrom(t.path+".1", pfi.Size(), emit)
		}
		t.ino, t.off = ino, 0
	case fi.Size() < t.off:
		t.off = 0
	}
	if fi.Size() > t.off {
		t.readFrom(t.path, fi.Size(), emit)
		t.save()
	}
}

// readFrom reads complete lines from t.off up to size (bounded per pass).
func (t *tailer) readFrom(path string, size int64, emit func(string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(t.off, io.SeekStart); err != nil {
		return
	}
	want := size - t.off
	if want > t.readBudget {
		want = t.readBudget
	}
	buf := make([]byte, want)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		// One partial line. If it is absurdly long, skip it rather than
		// wait forever for a newline that may never come.
		if len(buf) >= t.maxLine {
			t.off += int64(len(buf))
		}
		return
	}
	for _, line := range bytes.Split(buf[:last], []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if len(line) > t.maxLine {
			line = line[:t.maxLine]
		}
		emit(string(line))
	}
	t.off += int64(last + 1)
}
