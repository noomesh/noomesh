// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"testing/iotest"
)

// frame builds one docker multiplexed frame: 8-byte header (stream type,
// three zero bytes, big-endian payload length) followed by the payload.
func frame(stream byte, payload string) []byte {
	hdr := make([]byte, 8)
	hdr[0] = stream
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
	return append(hdr, payload...)
}

// The bug this pins: the old implementation called reader.Read ONCE into a
// fixed buffer and used whatever came back. OneByteReader is that failure
// made deterministic — it hands over a single byte per Read, so anything
// that does not drain the stream returns essentially nothing.
func TestLogLinesFromStreamDrainsTheWholeStream(t *testing.T) {
	var raw bytes.Buffer
	var want []string
	for i := 0; i < 250; i++ {
		line := fmt.Sprintf("line %d", i)
		want = append(want, line)
		raw.Write(frame(1, line+"\n"))
	}

	got, err := logLinesFromStream(iotest.OneByteReader(&raw), false, 2000)
	if err != nil {
		t.Fatalf("logLinesFromStream: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d — the stream was not drained", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// The second bug: the frame header is per FRAME and its length field is
// binary, so a payload of exactly 10 bytes puts a literal '\n' (0x0A) in
// the header. The old code split the raw bytes on '\n' first, which cut
// the header in half, and then stripped 8 bytes from any line whose first
// byte happened to be <= 2 — mangling real content either way.
func TestLogLinesFromStreamHandlesAHeaderContainingANewline(t *testing.T) {
	var raw bytes.Buffer
	raw.Write(frame(1, "0123456789")) // len 10 -> header ends 0x00 0x00 0x00 0x0A
	raw.Write(frame(2, "\nstderr line\n"))

	got, err := logLinesFromStream(&raw, false, 2000)
	if err != nil {
		t.Fatalf("logLinesFromStream: %v", err)
	}
	want := []string{"0123456789", "stderr line"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A tail must be the NEWEST lines. Returning the oldest it managed to read
// is the failure mode that makes a truncated fetch look like a quiet system.
func TestLogLinesFromStreamKeepsTheNewestLines(t *testing.T) {
	var raw bytes.Buffer
	for i := 0; i < 10; i++ {
		raw.Write(frame(1, fmt.Sprintf("line %d\n", i)))
	}

	got, err := logLinesFromStream(&raw, false, 3)
	if err != nil {
		t.Fatalf("logLinesFromStream: %v", err)
	}
	want := []string{"line 7", "line 8", "line 9"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A TTY container's stream is raw bytes with no frames at all; running it
// through the demuxer would fail or eat the first 8 bytes of real output.
func TestLogLinesFromStreamReadsATtyStreamRaw(t *testing.T) {
	got, err := logLinesFromStream(iotest.OneByteReader(strings.NewReader("alpha\nbeta\n")), true, 2000)
	if err != nil {
		t.Fatalf("logLinesFromStream: %v", err)
	}
	if strings.Join(got, "|") != "alpha|beta" {
		t.Fatalf("got %q, want [alpha beta]", got)
	}
}

func TestLogLinesFromStreamEmptyIsEmptyNotOneBlankLine(t *testing.T) {
	got, err := logLinesFromStream(&bytes.Buffer{}, false, 2000)
	if err != nil {
		t.Fatalf("logLinesFromStream: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want no lines", got)
	}
}
