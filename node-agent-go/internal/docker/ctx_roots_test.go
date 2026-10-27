package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerClientRootsNoContext is the D13 ratchet: Client methods take the
// caller's ctx, so a cancelled request, tick or shutdown stops its docker
// calls. The only places allowed to mint a root are listed here with the
// reason; a new context.Background() in this package fails the test.
func TestDockerClientRootsNoContext(t *testing.T) {
	allowed := map[string]int{
		"client.go":    1, // pingDocker: process startup, no caller yet
		"mcp_stdio.go": 1, // AttachedContainer.Close: io.Closer shape, runs after cancel
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		scanned++
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := strings.Count(string(b), "context.Background()"), allowed[f]; got != want {
			t.Errorf("%s: %d context.Background() roots, want %d — thread the caller's ctx", f, got, want)
		}
	}
	if scanned < 5 {
		t.Fatalf("scanned only %d files; the glob is broken", scanned)
	}
}
