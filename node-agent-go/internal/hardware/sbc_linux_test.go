// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hardware

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The real file is NUL-terminated (device-tree string convention). A Pi 5
// reads "Raspberry Pi 5 Model B Rev 1.0\x00" — the raw model must come back
// clean, or the controller-side family match sees a trailing NUL forever.
func TestDeviceTreeModelTrimsNulAndWhitespace(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "model")
	if err := os.WriteFile(fixture, []byte("Raspberry Pi 5 Model B Rev 1.0\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := deviceTreePath
	deviceTreePath = fixture
	defer func() { deviceTreePath = orig }()

	got := DeviceTreeModel()
	if got != "Raspberry Pi 5 Model B Rev 1.0" {
		t.Fatalf("got %q", got)
	}
}

// Absent file (every x86 host) must be a silent "", never an error — the
// agent reports facts, and "no device tree" is a fact.
func TestDeviceTreeModelAbsentIsEmpty(t *testing.T) {
	orig := deviceTreePath
	deviceTreePath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { deviceTreePath = orig }()

	if got := DeviceTreeModel(); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

// The field must reach the wire under the exact key the controller will
// read, and must be OMITTED when empty — an x86 worker's capabilities
// payload should not grow a permanently-empty key.
func TestCapabilitiesWireFormat(t *testing.T) {
	withModel, _ := json.Marshal(Capabilities{DeviceTreeModel: "NVIDIA Jetson Orin Nano"})
	if string(withModel) == "" || !json.Valid(withModel) {
		t.Fatal("marshal failed")
	}
	var m map[string]any
	_ = json.Unmarshal(withModel, &m)
	if m["device_tree_model"] != "NVIDIA Jetson Orin Nano" {
		t.Fatalf("wire key missing or wrong: %v", m["device_tree_model"])
	}

	without, _ := json.Marshal(Capabilities{})
	var m3 map[string]any
	_ = json.Unmarshal(without, &m3)
	if _, present := m3["device_tree_model"]; present {
		t.Fatal("empty model must be omitted (omitempty)")
	}
}
