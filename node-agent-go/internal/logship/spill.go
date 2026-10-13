// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// spill is the disk overflow: when the controller is away and the memory
// queue is full, entries go here as NDJSON, and come back out oldest first
// when it returns. Bounded: the live file rotates to `.1` past maxBytes
// and the previous `.1` is deleted — so at most 2×maxBytes on disk and the
// OLDEST lines are the ones lost, counted by the dropped callback.
//
// Layout under dir:
//
//	spill.ndjson     live, appended
//	spill.ndjson.1   rotated predecessor
//	spill.replay     the file currently being drained (renamed in from .1
//	                 or the live file, so the writer never appends to what
//	                 the reader is consuming)
type spill struct {
	dir      string
	maxBytes int64
	dropped  func(n int64)

	mu        sync.Mutex
	f         *os.File
	size      int64
	lines     int64 // in the live file
	prevLines int64 // in .1
	replayOff int64
}

func newSpill(dir string, maxBytes int64, dropped func(int64)) (*spill, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s := &spill{dir: dir, maxBytes: maxBytes, dropped: dropped}
	if s.dropped == nil {
		s.dropped = func(int64) {}
	}
	return s, nil
}

func (s *spill) live() string   { return filepath.Join(s.dir, "spill.ndjson") }
func (s *spill) prev() string   { return s.live() + ".1" }
func (s *spill) replay() string { return filepath.Join(s.dir, "spill.replay") }

func (s *spill) open() error {
	f, err := os.OpenFile(s.live(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f, s.size = f, st.Size()
	return nil
}

// write appends entries, rotating past the cap.
func (s *spill) write(entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		if err := s.open(); err != nil {
			return err
		}
	}
	w := bufio.NewWriter(s.f)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		if s.size > 0 && s.size+int64(len(b))+1 > s.maxBytes {
			if err := w.Flush(); err != nil {
				return err
			}
			if err := s.rotateLocked(); err != nil {
				return err
			}
			w = bufio.NewWriter(s.f)
		}
		n, err := w.Write(append(b, '\n'))
		if err != nil {
			return err
		}
		s.size += int64(n)
		s.lines++
	}
	return w.Flush()
}

func (s *spill) rotateLocked() error {
	_ = s.f.Close()
	s.f = nil
	if _, err := os.Stat(s.prev()); err == nil {
		// The oldest spilled lines are the ones we lose.
		s.dropped(s.prevLines)
		_ = os.Remove(s.prev())
	}
	if err := os.Rename(s.live(), s.prev()); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.prevLines, s.lines = s.lines, 0
	return s.open()
}

// pending reports whether anything is waiting on disk.
func (s *spill) pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range []string{s.replay(), s.prev(), s.live()} {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return true
		}
	}
	return false
}

// drain returns up to max entries, oldest first, and forgets them. Lines
// that fail to decode are skipped. nil, nil when nothing is pending.
func (s *spill) drain(max int) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(s.replay()); err != nil {
		// Promote the oldest file to the replay slot.
		src := ""
		if st, err := os.Stat(s.prev()); err == nil && st.Size() > 0 {
			src = s.prev()
			s.prevLines = 0
		} else if st, err := os.Stat(s.live()); err == nil && st.Size() > 0 {
			if s.f != nil {
				_ = s.f.Close()
				s.f = nil
			}
			src = s.live()
			s.lines, s.size = 0, 0
		}
		if src == "" {
			return nil, nil
		}
		if err := os.Rename(src, s.replay()); err != nil {
			return nil, err
		}
		s.replayOff = 0
	}
	f, err := os.Open(s.replay())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(s.replayOff, io.SeekStart); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(f, 256<<10)
	var out []Entry
	consumed := int64(0)
	for len(out) < max {
		line, err := r.ReadBytes('\n')
		consumed += int64(len(line))
		if len(line) > 0 {
			var e Entry
			if jerr := json.Unmarshal(line, &e); jerr == nil {
				out = append(out, e)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = os.Remove(s.replay())
				s.replayOff = 0
				return out, nil
			}
			return out, err
		}
	}
	s.replayOff += consumed
	return out, nil
}
