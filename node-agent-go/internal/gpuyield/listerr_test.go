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

// node-mac's shape (0.6.25, 2026-11-16): a Mac with no docker socket, where
// BOTH listings fail on every tick. The noomesh-container listing warned
// every 15 s (about 5,760 lines a day); each listing now warns once per
// cause, and says once when it works again.
func TestADockerlessHostWarnsOncePerListing(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	noSock := errors.New("failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory")
	d := &fakeDocker{listErr: noSock, ownedErr: noSock}
	c := New(ConfigFromEnv(func(string) string { return "" }), &fakeProbe{}, d, "")
	for i := 0; i < 8; i++ {
		c.Tick(context.Background())
	}
	out := buf.String()
	if n := strings.Count(out, "listing noomesh containers failed; GPU attribution unknown"); n != 1 {
		t.Fatalf("8 ticks with no docker: want 1 noomesh-container warning, got %d:\n%s", n, out)
	}
	if n := strings.Count(out, "listing GPU backend containers failed"); n != 1 {
		t.Fatalf("8 ticks with no docker: want 1 GPU-backend warning, got %d:\n%s", n, out)
	}
	c.mu.Lock()
	still := c.ownedErr
	c.mu.Unlock()
	if still == nil {
		t.Fatalf("quieter logging must not hide the failure from the decision (GPU attribution unknown)")
	}
	d.ownedErr = nil
	c.Tick(context.Background())
	c.Tick(context.Background())
	if n := strings.Count(buf.String(), "listing noomesh containers works again"); n != 1 {
		t.Fatalf("recovery logged once: want 1, got %d:\n%s", n, buf.String())
	}
}
