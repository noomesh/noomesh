// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// JournalSource ships the host units' journal (Linux).
//
// It never reads the journal itself. It asks noo-hostd for the read-only
// `journal-follow` op, which writes `journalctl -o json -f` for the
// allowlisted units into <spool>/journal.follow (rotated at 16 MB), and
// tails that file with a persisted offset. Restart-safe on both sides: the
// hostd heartbeat says whether a follower is running, and this source
// re-requests one (rate-limited) whenever it is not — after a hostd
// restart, an agent restart, or a child that died.
type JournalSource struct {
	spool    string
	stateDir string
	units    []string
	every    time.Duration

	mu          sync.Mutex
	status      string
	lastRequest time.Time
	pendingCmd  string
}

// NewJournalSource tails the hostd spool at spool; units is the allowlist
// to request (hostd enforces its own regardless).
func NewJournalSource(spool, stateDir string, units []string) *JournalSource {
	return &JournalSource{spool: spool, stateDir: stateDir, units: units, every: 30 * time.Second, status: "starting"}
}

func (j *JournalSource) Name() string { return SourceJournal }

// Status is a one-line account for the heartbeat.
func (j *JournalSource) Status() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status
}

func (j *JournalSource) setStatus(s string) {
	j.mu.Lock()
	j.status = s
	j.mu.Unlock()
}

// Run keeps the follower alive and tails its output.
func (j *JournalSource) Run(ctx context.Context, emit func(Entry)) {
	go j.keepFollower(ctx)
	t := newTailer(filepath.Join(j.spool, hostd.JournalFollowFile), filepath.Join(j.stateDir, "logship", "journal.offset"))
	t.run(ctx, 500*time.Millisecond, func(line string) {
		if e, ok := ParseJournalLine(line); ok {
			emit(e)
		}
	})
}

// keepFollower checks the hostd heartbeat every `every` and requests the
// op when nothing is following.
func (j *JournalSource) keepFollower(ctx context.Context) {
	j.check(ctx)
	tk := time.NewTicker(j.every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			j.check(ctx)
		}
	}
}

func (j *JournalSource) check(ctx context.Context) {
	// Tidy the result of the previous request; results are read once.
	j.mu.Lock()
	if j.pendingCmd != "" {
		if res, err := hostd.ReadResult(j.spool, j.pendingCmd); err == nil {
			_ = os.Remove(filepath.Join(j.spool, j.pendingCmd+".result.json"))
			j.pendingCmd = ""
			if res.RC != 0 {
				slog.Warn("noo-hostd refused journal-follow", "stderr", res.Stderr)
				j.status = "hostd refused journal-follow: " + res.Stderr
			}
		}
	}
	j.mu.Unlock()

	hb, err := hostd.ReadHeartbeat(j.spool)
	if err != nil {
		j.setStatus("no hostd heartbeat at " + j.spool)
		return
	}
	if hb.Stale(time.Now().UTC()) {
		j.setStatus("hostd heartbeat stale (" + hb.TS + ")")
		return
	}
	if !hb.Supports(hostd.OpJournalFollow) {
		j.setStatus("hostd predates journal-follow (serves " + strings.Join(hb.Ops, " ") + "); run `noo upgrade --nodes`")
		return
	}
	if hb.JournalFollow != nil && hb.JournalFollow.Running {
		j.setStatus("running")
		return
	}
	j.mu.Lock()
	tooSoon := time.Since(j.lastRequest) < time.Minute
	j.mu.Unlock()
	if tooSoon {
		return
	}
	name := fmt.Sprintf("journal-follow-%d", time.Now().UTC().UnixNano())
	// No units named means "hostd's own allowlist". Naming the agent's
	// compiled-in list instead broke shipping whenever hostd lagged the
	// agent: a newer agent asked for `tailscaled`, an older hostd refused
	// the whole op as outside its allowlist, and the node shipped no journal
	// at all (sandbox worker-1, v0.2.83 rehearsal). hostd already defaults
	// to the full allowlist it knows.
	var args []string
	if len(j.units) > 0 {
		args = []string{"units=" + strings.Join(j.units, ",")}
	}
	err = hostd.WriteCommand(j.spool, name, hostd.Command{
		Op:          hostd.OpJournalFollow,
		Service:     "noo-node-agent",
		Args:        args,
		RequestedBy: "node-agent:logship",
	})
	j.mu.Lock()
	j.lastRequest = time.Now()
	if err != nil {
		j.status = "cannot queue journal-follow: " + err.Error()
	} else {
		j.pendingCmd = name
		j.status = "requested"
	}
	j.mu.Unlock()
}

// ParseJournalLine turns one `journalctl -o json` record into an entry.
// Non-UTF-8 MESSAGEs arrive as byte arrays and are decoded; records with
// no MESSAGE are skipped.
func ParseJournalLine(line string) (Entry, bool) {
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return Entry{}, false
	}
	msg := journalString(rec["MESSAGE"])
	if msg == "" {
		return Entry{}, false
	}
	unit := journalString(rec["_SYSTEMD_UNIT"])
	if unit == "" {
		unit = journalString(rec["USER_UNIT"])
	}
	if unit == "" {
		unit = journalString(rec["SYSLOG_IDENTIFIER"])
	}
	unit = strings.TrimSuffix(unit, ".service")
	if unit == "" {
		unit = "journal"
	}
	ts := time.Now().UnixNano()
	if us, err := strconv.ParseInt(journalString(rec["__REALTIME_TIMESTAMP"]), 10, 64); err == nil && us > 0 {
		ts = us * 1000
	}
	level := ExtractLevel(msg)
	if level == LevelUnknown {
		level = levelFromPriority(journalString(rec["PRIORITY"]))
	}
	return Entry{TS: ts, Line: msg, Labels: Labels{
		Source: SourceJournal, Name: unit, Stream: StreamJournal, Level: level,
	}}, true
}

func journalString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		b := make([]byte, 0, len(x))
		for _, n := range x {
			if f, ok := n.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return string(b)
	}
	return ""
}
