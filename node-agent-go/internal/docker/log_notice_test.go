package docker

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// The shape seen on a node after the 2026-11-22 unclean restart (i1225):
// the container restarted at 20:01:48Z; a long read stopped at the NUL
// bytes the stop left, so it returned only lines up to 16:22:50Z, while a
// short read from the end returned lines from 20:26Z.
var (
	started = time.Date(2026, 11, 22, 20, 1, 48, 0, time.UTC)
	now     = time.Date(2026, 11, 22, 20, 27, 0, 0, time.UTC)
	before  = []string{
		"2026-11-22T16:22:49.100000000Z GET /metrics 200",
		"2026-11-22T16:22:50.614414420Z GET /metrics 200",
	}
	after = []string{
		"2026-11-22T20:26:03.474038384Z POST /v1/chat/completions 200",
		"2026-11-22T20:26:09.568819477Z POST /v1/chat/completions 200",
	}
)

func TestALongReadThatEndsBeforeTheStartIsNamed(t *testing.T) {
	if !logAnswerLooksCut(before, true, started) {
		t.Fatal("an answer whose newest line is older than the start must get a second read")
	}
	n := unreadableLogNotice("noo-vllm", before, after, started, "", now)
	for _, want := range []string{
		"Docker could not read noo-vllm's log past 2026-11-22T16:22:50Z",
		"started at 2026-11-22T20:01:48Z",
		"the newest at 2026-11-22T20:26:09Z",
		"a tail of 50 or fewer",
		"when the log rotates or the container is recreated",
	} {
		if !strings.Contains(n, want) {
			t.Errorf("notice lacks %q:\n%s", want, n)
		}
	}
}

func TestAnEmptySinceAnswerIsNamed(t *testing.T) {
	if !logAnswerLooksCut(nil, true, started) {
		t.Fatal("an empty answer from a running container must get a second read")
	}
	n := unreadableLogNotice("noo-vllm", nil, after, started, "3h", now)
	if !strings.Contains(n, "past its start") {
		t.Fatalf("an empty since answer must be named:\n%q", n)
	}
	// RFC 3339 and unix-seconds forms of the same window.
	for _, since := range []string{"2026-11-22T17:27:00Z", "1795368420"} {
		if unreadableLogNotice("noo-vllm", nil, after, started, since, now) == "" {
			t.Errorf("since %q: the probe's lines are inside the window, so the gap must be named", since)
		}
	}
}

func TestAQuietContainerIsNotAccused(t *testing.T) {
	// Logged before the restart, nothing since: the probe is no newer.
	if n := unreadableLogNotice("noo-vllm", before, before, started, "", now); n != "" {
		t.Fatalf("no line since the start, so nothing to name:\n%s", n)
	}
	// Lines since the start, but all older than the window asked for.
	if n := unreadableLogNotice("noo-vllm", nil, after, started, "10s", now); n != "" {
		t.Fatalf("the probe's lines are outside the since window:\n%s", n)
	}
	// A since Docker would read but we cannot: claim nothing.
	if n := unreadableLogNotice("noo-vllm", nil, after, started, "yesterday", now); n != "" {
		t.Fatalf("an unparsed since must not produce a claim:\n%s", n)
	}
	// The answer already holds the probe's newest line.
	full := append(append([]string{}, before...), after...)
	if logAnswerLooksCut(full, true, started) {
		t.Fatal("an answer with lines since the start needs no second read")
	}
	if n := unreadableLogNotice("noo-vllm", full, after, started, "", now); n != "" {
		t.Fatalf("nothing is missing:\n%s", n)
	}
	// A stopped container: old lines are all there is.
	if logAnswerLooksCut(before, false, started) {
		t.Fatal("a stopped container's old lines are not a cut")
	}
}

// The bytes as Docker's own file holds them after the stop: JSON lines, a
// run of NULs where the stop cut the file, then the restarted container's
// lines. Docker's reader stops at the NULs; the lines it returns before
// them, and the probe's lines after them, give the notice.
func TestTheNoticeFromAFileCarryingNULBytesInTheMiddle(t *testing.T) {
	var file bytes.Buffer
	for _, l := range before {
		ts, msg, _ := strings.Cut(l, " ")
		file.WriteString(`{"log":"` + msg + `\n","stream":"stdout","time":"` + ts + `"}` + "\n")
	}
	file.Write(make([]byte, 4096))
	for _, l := range after {
		ts, msg, _ := strings.Cut(l, " ")
		file.WriteString(`{"log":"` + msg + `\n","stream":"stdout","time":"` + ts + `"}` + "\n")
	}
	forward, fromEnd := readJSONFileLikeDocker(file.Bytes(), 0), readJSONFileLikeDocker(file.Bytes(), 50)
	// The NULs carry no newline, so the first line written after them is
	// damaged too: the read from the end gets every later line.
	if len(forward) != len(before) || len(fromEnd) != len(after)-1 {
		t.Fatalf("fixture: forward %d lines, from the end %d", len(forward), len(fromEnd))
	}
	if n := unreadableLogNotice("noo-vllm", forward, fromEnd, started, "", now); !strings.Contains(n, "past 2026-11-22T16:22:50Z") {
		t.Fatalf("the cut must be named at the last line before the NULs:\n%s", n)
	}
}

// readJSONFileLikeDocker models the two reads seen on the node: tail 0
// decodes forward from the start and stops at the first line that is not
// JSON (the NULs); a positive tail reads that many whole lines back from
// the end. Each line comes out as "<time> <log>".
func readJSONFileLikeDocker(file []byte, tail int) []string {
	raw := strings.Split(strings.TrimRight(string(file), "\n"), "\n")
	decode := func(l string) (string, bool) {
		ts, ok1 := between(l, `"time":"`, `"`)
		msg, ok2 := between(l, `{"log":"`, `\n"`)
		return ts + " " + msg, ok1 && ok2 && strings.HasPrefix(l, "{")
	}
	var out []string
	if tail == 0 {
		for _, l := range raw {
			line, ok := decode(l)
			if !ok {
				break
			}
			out = append(out, line)
		}
		return out
	}
	for i := len(raw) - 1; i >= 0 && len(out) < tail; i-- {
		line, ok := decode(raw[i])
		if !ok {
			break
		}
		out = append([]string{line}, out...)
	}
	return out
}

func between(s, open, close string) (string, bool) {
	_, rest, ok := strings.Cut(s, open)
	if !ok {
		return "", false
	}
	v, _, ok := strings.Cut(rest, close)
	return v, ok
}
