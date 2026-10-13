// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
)

// ContainerTarget is one container the docker source follows.
type ContainerTarget struct {
	Name           string
	ComposeService string
}

// DockerLogs is the slice of the docker client this source needs. An
// interface so the follow/demux/attach logic is testable without a daemon.
type DockerLogs interface {
	// LogTargets lists the RUNNING containers this node should ship
	// (compose-project labelled, or `noo-` prefixed).
	LogTargets(ctx context.Context) ([]ContainerTarget, error)
	// FollowLogs opens a following, timestamped stdout+stderr stream from
	// `since` (RFC3339Nano). tty reports whether the stream is unframed.
	FollowLogs(ctx context.Context, name, since string) (r io.ReadCloser, tty bool, err error)
	// ContainerStarts streams container start events until ctx ends; the
	// error channel yields when the event stream breaks.
	ContainerStarts(ctx context.Context) (<-chan ContainerTarget, <-chan error)
}

// DockerSource follows every managed container's stdout and stderr.
//
// On start it attaches from "now minus a small window" — never a
// container's whole history; a re-attach (container restart, stream
// break) resumes from the last timestamp it saw for that container.
type DockerSource struct {
	d      DockerLogs
	window time.Duration
	resync time.Duration

	mu       sync.Mutex
	attached map[string]bool
	lastTS   map[string]time.Time
}

// NewDockerSource returns a source over d.
func NewDockerSource(d DockerLogs) *DockerSource {
	return &DockerSource{d: d, window: 30 * time.Second, resync: time.Minute,
		attached: map[string]bool{}, lastTS: map[string]time.Time{}}
}

func (s *DockerSource) Name() string { return SourceDocker }

// Run attaches to what is running, then follows start events and
// re-lists periodically (events can be missed across a daemon restart).
func (s *DockerSource) Run(ctx context.Context, emit func(Entry)) {
	s.attachAll(ctx, emit)
	go s.watchStarts(ctx, emit)
	tk := time.NewTicker(s.resync)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			s.attachAll(ctx, emit)
		}
	}
}

func (s *DockerSource) attachAll(ctx context.Context, emit func(Entry)) {
	targets, err := s.d.LogTargets(ctx)
	if err != nil {
		return
	}
	for _, t := range targets {
		s.attach(ctx, t, emit)
	}
}

func (s *DockerSource) watchStarts(ctx context.Context, emit func(Entry)) {
	for ctx.Err() == nil {
		starts, errs := s.d.ContainerStarts(ctx)
	loop:
		for {
			select {
			case <-ctx.Done():
				return
			case t, ok := <-starts:
				if !ok {
					break loop
				}
				s.attach(ctx, t, emit)
			case <-errs:
				break loop
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// attach starts one follower for t unless one is live.
func (s *DockerSource) attach(ctx context.Context, t ContainerTarget, emit func(Entry)) {
	s.mu.Lock()
	if s.attached[t.Name] {
		s.mu.Unlock()
		return
	}
	s.attached[t.Name] = true
	since := time.Now().Add(-s.window)
	if last, ok := s.lastTS[t.Name]; ok {
		since = last.Add(time.Nanosecond)
	}
	s.mu.Unlock()

	r, tty, err := s.d.FollowLogs(ctx, t.Name, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		s.mu.Lock()
		delete(s.attached, t.Name)
		s.mu.Unlock()
		return
	}
	go func() {
		defer func() {
			_ = r.Close()
			s.mu.Lock()
			delete(s.attached, t.Name)
			s.mu.Unlock()
		}()
		s.follow(r, tty, t, emit)
	}()
}

// follow demuxes one stream into lines until it ends.
func (s *DockerSource) follow(r io.Reader, tty bool, t ContainerTarget, emit func(Entry)) {
	handle := func(stream string) func(string) {
		return func(raw string) {
			ts, line := splitDockerTimestamp(raw)
			if line == "" {
				return
			}
			s.mu.Lock()
			if ts.After(s.lastTS[t.Name]) {
				s.lastTS[t.Name] = ts
			}
			s.mu.Unlock()
			emit(Entry{TS: ts.UnixNano(), Line: line, Labels: Labels{
				Source: SourceDocker, Name: t.Name, Stream: stream,
				Level: ExtractLevel(line), ComposeService: t.ComposeService,
			}})
		}
	}
	if tty {
		scanLines(r, handle(StreamStdout))
		return
	}
	outR, outW := io.Pipe()
	errR, errW := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); scanLines(outR, handle(StreamStdout)) }()
	go func() { defer wg.Done(); scanLines(errR, handle(StreamStderr)) }()
	_, err := stdcopy.StdCopy(outW, errW, r)
	_ = outW.CloseWithError(err)
	_ = errW.CloseWithError(err)
	wg.Wait()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		slog.Debug("container log stream ended", "container", t.Name, "error", err)
	}
}

// splitDockerTimestamp strips the `Timestamps: true` prefix, returning the
// parsed time (now when unparseable) and the line.
func splitDockerTimestamp(raw string) (time.Time, string) {
	raw = strings.TrimRight(raw, "\r")
	sp := strings.IndexByte(raw, ' ')
	if sp > 0 {
		if ts, err := time.Parse(time.RFC3339Nano, raw[:sp]); err == nil {
			return ts, strings.TrimLeft(raw[sp+1:], " ")
		}
	}
	return time.Now(), raw
}

// scanLines reads r line by line, capping a line at 1 MiB (the remainder
// of an over-long line is discarded, not re-emitted as new lines).
func scanLines(r io.Reader, fn func(string)) {
	const maxLine = 1 << 20
	br := bufio.NewReaderSize(r, 64<<10)
	var acc []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if room := maxLine - len(acc); room > 0 {
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			acc = append(acc, chunk...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if line := strings.TrimRight(string(acc), "\r\n"); line != "" {
			fn(line)
		}
		acc = acc[:0]
		if err != nil {
			return
		}
	}
}
