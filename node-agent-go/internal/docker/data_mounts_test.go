// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"reflect"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

func TestManagedDataMounts(t *testing.T) {
	managed := map[string]string{"noo.managed-by": "node-agent-go"}
	ctrs := []container.Summary{
		{Names: []string{"/noo-vllm"}, Labels: managed, Mounts: []container.MountPoint{
			{Type: mount.TypeBind, Source: "/data/noo/hf-cache", Destination: "/root/.cache/huggingface"},
			{Type: mount.TypeBind, Source: "/etc/noo/pki/ca.crt", Destination: "/app/pki/ca.crt"},
			{Type: mount.TypeBind, Source: "/etc/noo/pki/services/vllm", Destination: "/app/pki/services/vllm"},
			{Type: mount.TypeVolume, Source: "/var/lib/docker/volumes/x/_data", Destination: "/v"},
			{Type: mount.TypeBind, Source: "/data/noo/hf-cache", Destination: "/dup"},
		}},
		// Not ours: a backend-looking name without the managed label.
		{Names: []string{"/noo-ollama"}, Mounts: []container.MountPoint{
			{Type: mount.TypeBind, Source: "/elsewhere", Destination: "/root/.ollama"}}},
		// A sidecar has no backend key.
		{Names: []string{"/noo-stunnel-vllm"}, Labels: managed, Mounts: []container.MountPoint{
			{Type: mount.TypeBind, Source: "/etc/stunnel", Destination: "/etc/stunnel"}}},
		// Managed backend with no data mounts: present, empty (not null).
		{Names: []string{"/noo-llamacpp"}, Labels: managed},
	}
	got := managedDataMounts(ctrs)
	want := map[string][]string{"vllm": {"/data/noo/hf-cache"}, "llamacpp": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if got := managedDataMounts(nil); got == nil || len(got) != 0 {
		t.Fatalf("no containers must be an empty non-nil map, got %#v", got)
	}
}
