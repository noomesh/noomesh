// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"os"
	"path/filepath"
	"testing"
)

// A world-writable store (o+w, no sticky) is listed with its path, store,
// mode and owner; a 0755, a 2775 and a sticky 1777 one are not; files are
// not looked at; first-level subdirectories are.
func TestStoresListOnlyWorldWritableDirectories(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, mode os.FileMode) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hf := mk("hf-cache", 0o777)
	hub := mk("hf-cache/hub", 0o777)
	models := mk("models", 0o755)
	mk("models/sets", 0o2775|os.ModeSetgid)
	mk("models/shared", 0o777|os.ModeSticky)
	ollama := mk("ollama", 0o755)
	if err := os.WriteFile(filepath.Join(models, "x.gguf"), nil, 0o666); err != nil {
		t.Fatal(err)
	}
	r := Roots{NooDataRoot: root, HFCacheDir: hf, ModelsDir: models, OllamaDataDir: ollama}
	got := StoresReport(r)
	bad := got["world_writable"].([]map[string]any)
	if len(bad) != 2 || bad[0]["path"] != hf || bad[1]["path"] != hub {
		t.Fatalf("world_writable = %v, want exactly hf-cache and hub", bad)
	}
	if bad[0]["store"] != "hf_cache" || bad[0]["mode"] != "0777" || bad[0]["uid"] != os.Getuid() {
		t.Fatalf("entry = %v", bad[0])
	}
	if c := got["checked"].(int); c < 6 {
		t.Fatalf("checked = %d, want the 4 roots plus their subdirectories", c)
	}
}

// The row's evidence must not depend on a symlinked store resolving away:
// a store path that is a symlink is not followed (Lstat), so it is never
// reported as a directory it points at.
func TestStoresDoNotFollowASymlinkedStore(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(target, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(target, 0o777)
	link := filepath.Join(root, "models")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	got := StoresReport(Roots{ModelsDir: link})
	if bad := got["world_writable"].([]map[string]any); len(bad) != 0 {
		t.Fatalf("followed the symlink: %v", bad)
	}
}

func TestModeOctalKeepsTheSpecialBits(t *testing.T) {
	for m, want := range map[os.FileMode]string{
		0o777: "0777", 0o755: "0755", 0o775 | os.ModeSetgid: "2775", 0o777 | os.ModeSticky: "1777",
	} {
		if got := modeOctal(m); got != want {
			t.Errorf("modeOctal(%v) = %s, want %s", m, got, want)
		}
	}
}
