package gpuyield

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// A host with no docker (a Mac running a native ollama) must not warn every
// tick that it cannot list GPU backend containers: once per cause, then
// debug, and one line when it works again.
func TestListingFailureIsLoggedOncePerCause(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	d := &fakeDocker{listErr: errors.New("dial unix /var/run/docker.sock: no such file")}
	c := New(ConfigFromEnv(func(string) string { return "" }), &fakeProbe{}, d, "")
	for i := 0; i < 5; i++ {
		c.Tick(context.Background())
	}
	if n := strings.Count(buf.String(), "listing GPU backend containers failed"); n != 1 {
		t.Fatalf("same failure 5 ticks: want 1 warning, got %d:\n%s", n, buf.String())
	}
	d.listErr = errors.New("another cause")
	c.Tick(context.Background())
	if n := strings.Count(buf.String(), "listing GPU backend containers failed"); n != 2 {
		t.Fatalf("a new cause warns again: want 2, got %d:\n%s", n, buf.String())
	}
	d.listErr = nil
	c.Tick(context.Background())
	c.Tick(context.Background())
	if n := strings.Count(buf.String(), "works again"); n != 1 {
		t.Fatalf("recovery logged once: want 1, got %d:\n%s", n, buf.String())
	}
}
