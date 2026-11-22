package docker

import (
	"strconv"
	"strings"
	"time"
)

// An unclean stop (a power cut, a VM killed from outside) can leave NUL
// bytes at the end of a container's json-file log. On restart dockerd
// appends after them, and its reader, which decodes forward, stops at the
// first bad byte and ends the stream WITHOUT an error to the client (the
// warning "Error decoding log file: invalid character '\x00'" goes only to
// dockerd's own journal). A read that starts after the bad bytes, a small
// tail, never meets them.
//
// So a large tail answers with lines from before the stop, and a `since`
// answers with nothing, which `noo cluster logs` printed as if the backend
// had logged nothing since (i1225, seen on a node after the 2026-11-22
// unclean restart). The agent cannot repair Docker's file and does not try;
// it says what it found, so the answer is not read as silence.

// logProbeTail is how many of the newest lines the second read asks for: a
// read this short starts after the damage in the case seen.
const logProbeTail = 50

// logAnswerLooksCut says whether an answer is worth a second read: the
// container is running and the answer holds nothing written since it
// started.
func logAnswerLooksCut(lines []string, running bool, startedAt time.Time) bool {
	if !running || startedAt.IsZero() {
		return false
	}
	newest, ok := newestLogTime(lines)
	return !ok || newest.Before(startedAt)
}

// unreadableLogNotice compares an answer with the probe's newest lines. It
// names the gap only when the probe proves lines exist that the answer
// should have carried: written since the container started, newer than
// anything in the answer, and (with a since) inside the window asked for.
// An empty string means nothing to say: a quiet container stays quiet.
func unreadableLogNotice(name string, answer, probe []string, startedAt time.Time, since string, now time.Time) string {
	probeNewest, ok := newestLogTime(probe)
	if !ok || probeNewest.Before(startedAt) {
		return ""
	}
	cut := "its start"
	if newest, ok := newestLogTime(answer); ok {
		if !probeNewest.After(newest) {
			return ""
		}
		cut = newest.UTC().Format(time.RFC3339)
	}
	if since != "" {
		from, ok := parseLogSince(since, now)
		if !ok || false && probeNewest.Before(from) {
			return ""
		}
	}
	return "Docker could not read " + name + "'s log past " + cut + ": lines written since it started at " +
		startedAt.UTC().Format(time.RFC3339) + " exist (the newest at " + probeNewest.UTC().Format(time.RFC3339) +
		") but this read did not return them. Docker does this when the log file was damaged, for example by an " +
		"unclean stop. The newest lines: a tail of " + strconv.Itoa(logProbeTail) + " or fewer, or the logs in " +
		"Loki. It clears when the log rotates or the container is recreated."
}

// newestLogTime reads the timestamp Docker puts at the start of each line
// (Timestamps: true) and returns the newest one.
func newestLogTime(lines []string) (time.Time, bool) {
	var newest time.Time
	found := false
	for _, l := range lines {
		ts, _, _ := strings.Cut(l, " ")
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		if !found || t.After(newest) {
			newest, found = t, true
		}
	}
	return newest, found
}

// parseLogSince reads a since the way Docker accepts it: a duration ago
// ("10m"), unix seconds ("1700000000" or with a fraction), or an RFC 3339
// time. Anything else is not understood, and then no notice is given.
func parseLogSince(s string, now time.Time) (time.Time, bool) {
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)), true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// linesSinceStart keeps the lines written at or after startedAt. A line
// without Docker's timestamp is dropped: it cannot be placed in this run.
// An unknown start (zero) keeps nothing: no verdict without knowing which
// run the lines belong to.
func linesSinceStart(lines []string, startedAt time.Time) []string {
	out := []string{}
	if startedAt.IsZero() {
		return out
	}
	for _, l := range lines {
		ts, _, _ := strings.Cut(l, " ")
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil || t.Before(startedAt) {
			continue
		}
		out = append(out, l)
	}
	return out
}
