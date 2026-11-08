// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/moby/moby/api/types/mount"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// i300 A12, the runtime half: the one exec scratch is mounted without noexec,
// owned by the worker uid, mode 0700; everything else about the worker is as
// before; and release removes its volume by its exact name.

func i64(v int64) *int64 { return &v }

// entryWithScratch is the fixture worker with its scratch replaced.
func entryWithScratch(t *testing.T, ss ...nodewl.Scratch) nodewl.Entry {
	t.Helper()
	e := fixtureEntry(t, 0)
	e.Decl.Scratch = ss
	return e
}

func volOpts(t *testing.T, m mount.Mount) map[string]bool {
	t.Helper()
	if m.Type != mount.TypeVolume || m.VolumeOptions == nil || m.VolumeOptions.DriverConfig == nil {
		t.Fatalf("not a driver-backed volume mount: %+v", m)
	}
	out := map[string]bool{}
	for _, o := range strings.Split(m.VolumeOptions.DriverConfig.Options["o"], ",") {
		out[o] = true
	}
	return out
}

func tmpfsFlags(m mount.Mount) map[string]bool {
	out := map[string]bool{}
	if m.TmpfsOptions != nil {
		for _, o := range m.TmpfsOptions.Options {
			out[o[0]] = true
		}
	}
	return out
}

// T2a: the exec scratch has no noexec, has nosuid and nodev, and is the
// worker's uid and gid at mode 0700 — for both declared kinds.
func TestExecScratchMountsWithoutNoexecOwnedByTheWorker(t *testing.T) {
	for name, s := range map[string]nodewl.Scratch{
		"max_mb":   {Target: "/cache/triton", MaxMB: i64(512), Exec: true},
		"tmpfs_mb": {Target: "/cache/triton", TmpfsMB: i64(512), Exec: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := entryWithScratch(t, s)
			ms := scratchMounts(e, 1000)
			if len(ms) != 1 {
				t.Fatalf("mounts %+v", ms)
			}
			m := ms[0]
			if m.Source != "noo-wl-rhaddon-worker-scratch0" || m.Target != "/cache/triton" || m.ReadOnly {
				t.Errorf("mount %+v", m)
			}
			dc := m.VolumeOptions.DriverConfig
			if dc.Name != "local" || dc.Options["type"] != "tmpfs" || dc.Options["device"] != "tmpfs" {
				t.Errorf("driver %+v: not a tmpfs-backed local volume", dc)
			}
			o := volOpts(t, m)
			if o["noexec"] {
				t.Errorf("the exec scratch carries noexec: %q", dc.Options["o"])
			}
			for _, want := range []string{"nosuid", "nodev", "uid=1000", "gid=1000", "mode=0700", "size=512m"} {
				if !o[want] {
					t.Errorf("option %q missing from %q", want, dc.Options["o"])
				}
			}
			if m.VolumeOptions.Labels[LabelManagedBy] != ManagedByAgent || m.VolumeOptions.Labels[LabelRole] != RoleWorker {
				t.Errorf("labels %v", m.VolumeOptions.Labels)
			}
		})
	}
}

// T2b: with one exec and two non-exec entries, only the exec one lacks noexec.
func TestEveryOtherScratchKeepsNoexec(t *testing.T) {
	e := entryWithScratch(t,
		nodewl.Scratch{Target: "/a", MaxMB: i64(100)},
		nodewl.Scratch{Target: "/exec", TmpfsMB: i64(64), Exec: true},
		nodewl.Scratch{Target: "/b", TmpfsMB: i64(32)},
	)
	ms := scratchMounts(e, 1000)
	if len(ms) != 3 {
		t.Fatalf("mounts %+v", ms)
	}
	a := volOpts(t, ms[0])
	for _, w := range []string{"noexec", "nosuid", "nodev"} {
		if !a[w] {
			t.Errorf("max_mb scratch lacks %s", w)
		}
	}
	if ms[1].Target != "/exec" || volOpts(t, ms[1])["noexec"] {
		t.Errorf("the exec scratch is mount 1 and has no noexec: %+v", ms[1])
	}
	b := tmpfsFlags(ms[2])
	for _, w := range []string{"noexec", "nosuid", "nodev"} {
		if !b[w] {
			t.Errorf("tmpfs_mb scratch lacks %s: %+v", w, ms[2].TmpfsOptions)
		}
	}
}

// T2c: an exec scratch changes nothing else of either spec.
func TestExecScratchLeavesTheRestOfTheSpecAlone(t *testing.T) {
	e := entryWithScratch(t,
		nodewl.Scratch{Target: "/exec", MaxMB: i64(256), Exec: true},
		nodewl.Scratch{Target: "/tmp", TmpfsMB: i64(32)},
	)
	sets := []setMount{{Source: "/var/lib/noo/models/sets/a/1", Target: "/models/main"}}
	specs, err := buildWorkloadSpecs(specInput{Entry: e, WorkerImage: imageID, DoorImage: "door:test", AdmitCN: testAgentCN,
		CAPath: "/pki/ca.crt", LeafCrt: "/pki/l.crt", LeafKey: "/pki/l.key", LeafPrint: "p", Sets: sets})
	if err != nil {
		t.Fatal(err)
	}
	h := specs.Worker.Host
	if !h.ReadonlyRootfs {
		t.Error("rootfs is not read-only")
	}
	if !reflect.DeepEqual(h.CapDrop, []string{"ALL"}) || !reflect.DeepEqual(h.SecurityOpt, []string{"no-new-privileges"}) {
		t.Errorf("caps %v sec %v", h.CapDrop, h.SecurityOpt)
	}
	if string(h.NetworkMode) != "container:"+WorkloadDoorName("rhaddon", "worker") {
		t.Errorf("network mode %q", h.NetworkMode)
	}
	if specs.Worker.Config.User != "1000" {
		t.Errorf("user %q", specs.Worker.Config.User)
	}
	var binds int
	for _, m := range h.Mounts {
		if m.Type == mount.TypeBind {
			binds++
			if !m.ReadOnly || m.Target != "/models/main" {
				t.Errorf("model mount %+v", m)
			}
		}
	}
	if binds != 1 || len(h.Mounts) != 3 {
		t.Errorf("mounts %+v", h.Mounts)
	}
	for _, m := range specs.Door.Host.Mounts {
		if m.Type != mount.TypeBind || !m.ReadOnly || m.Target == "/exec" || m.Target == "/tmp" {
			t.Errorf("door mount %+v: the sidecar gets no scratch", m)
		}
	}
	if len(specs.Door.Host.Mounts) != 3 {
		t.Errorf("door mounts %+v", specs.Door.Host.Mounts)
	}
}

// T2d: a spec with no exec entry is exactly what it was before A12 — the two
// mount forms pinned value by value as they stood on dev, and the spec hash
// of a whole pair pinned.
func TestNonExecScratchIsByteIdenticalToBeforeA12(t *testing.T) {
	e := entryWithScratch(t,
		nodewl.Scratch{Target: "/cache", MaxMB: i64(4096)},
		nodewl.Scratch{Target: "/tmp", TmpfsMB: i64(256)},
	)
	labels := map[string]string{"noo.addon": "rhaddon", "noo.workload": "worker", "noo.managed-by": "agent", "noo.role": "worker"}
	want := []mount.Mount{
		{
			Type: mount.TypeVolume, Source: "noo-wl-rhaddon-worker-scratch0", Target: "/cache",
			VolumeOptions: &mount.VolumeOptions{
				NoCopy: true, Labels: labels,
				DriverConfig: &mount.Driver{Name: "local", Options: map[string]string{
					"type": "tmpfs", "device": "tmpfs", "o": "size=4096m,uid=1000,gid=1000,mode=0700,nosuid,nodev,noexec",
				}},
			},
		},
		{
			Type: mount.TypeTmpfs, Target: "/tmp",
			TmpfsOptions: &mount.TmpfsOptions{SizeBytes: 256 << 20, Mode: 0o1777, Options: [][]string{{"nosuid"}, {"nodev"}, {"noexec"}}},
		},
	}
	if got := scratchMounts(e, 1000); !reflect.DeepEqual(got, want) {
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		t.Errorf("non-exec mounts changed\n got %s\nwant %s", gj, wj)
	}

	specs, err := buildWorkloadSpecs(specInput{Entry: e, WorkerImage: imageID, DoorImage: "door:test", AdmitCN: testAgentCN,
		CAPath: "/pki/ca.crt", LeafCrt: "/pki/l.crt", LeafKey: "/pki/l.key", LeafPrint: "p"})
	if err != nil {
		t.Fatal(err)
	}
	// Computed on origin/dev before this change (same input, unmodified tree).
	const pinned = "968a7e15a32dd2aee8f0410b23e056b624efbfcf8d4e2f65ef08ba22e2152dab"
	if specs.Hash != pinned {
		t.Errorf("spec hash of a non-exec pair = %s, was %s before A12", specs.Hash, pinned)
	}
}

// ---- release: the exec volume is removed by its exact name ----------------

// volDaemon is the volume slice of the Docker Engine API: inspect and remove.
type volDaemon struct {
	mu      sync.Mutex
	labels  map[string]map[string]string // volume name -> labels
	deleted []string
	inspect []string
}

func newVolDaemon(t *testing.T, d *volDaemon) dockerProvAPI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		i := strings.Index(r.URL.Path, "/volumes/")
		if i < 0 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"unexpected ` + r.Method + " " + r.URL.Path + `"}`))
			return
		}
		name := r.URL.Path[i+len("/volumes/"):]
		lb, ok := d.labels[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"get ` + name + `: no such volume"}`))
			return
		}
		switch r.Method {
		case http.MethodGet:
			d.inspect = append(d.inspect, name)
			b, _ := json.Marshal(map[string]any{"Name": name, "Driver": "local", "Labels": lb})
			_, _ = w.Write(b)
		case http.MethodDelete:
			d.deleted = append(d.deleted, name)
			delete(d.labels, name)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return dockerProvAPI{c}
}

// T3a: release removes the exec volume by its exact name, through the Engine API.
func TestReleaseRemovesTheExecVolumeByExactName(t *testing.T) {
	name := workloadVolumeName("rhaddon", "worker", 2)
	d := &volDaemon{labels: map[string]map[string]string{name: {LabelManagedBy: ManagedByAgent, LabelAddon: "rhaddon", LabelWorkload: "worker"}}}
	api := newVolDaemon(t, d)
	foreign, err := api.RemoveVolumeByName(context.Background(), name)
	if err != nil || foreign {
		t.Fatalf("foreign=%v err=%v", foreign, err)
	}
	if !reflect.DeepEqual(d.deleted, []string{"noo-wl-rhaddon-worker-scratch2"}) {
		t.Errorf("DELETE calls %v", d.deleted)
	}
	// Absent is not an error and issues no delete.
	if foreign, err := api.RemoveVolumeByName(context.Background(), name); err != nil || foreign || len(d.deleted) != 1 {
		t.Errorf("second release: foreign=%v err=%v deletes=%v", foreign, err, d.deleted)
	}
}

// T3b: a volume of that name the agent did not label is not removed, and is
// reported as foreign.
func TestReleaseNeverRemovesAForeignVolumeOfTheSameName(t *testing.T) {
	name := workloadVolumeName("rhaddon", "worker", 0)
	d := &volDaemon{labels: map[string]map[string]string{name: {"owner": "someone-else"}}}
	api := newVolDaemon(t, d)
	foreign, err := api.RemoveVolumeByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	if !foreign {
		t.Error("a foreign volume was not reported")
	}
	if len(d.deleted) != 0 {
		t.Errorf("a foreign volume was removed: %v", d.deleted)
	}
}

// T3a (provisioner side): teardown asks for every possible scratch name, so
// the exec volume's exact name is among them on Deprovision.
func TestDeprovisionRemovesTheExecVolumeByName(t *testing.T) {
	h := newHarness(t)
	h.entry.Decl.Scratch = []nodewl.Scratch{{Target: "/tmp", TmpfsMB: i64(32)}, {Target: "/exec", TmpfsMB: i64(64), Exec: true}}
	mustProvision(t, h)
	h.api.byName = nil
	if err := h.p.Deprovision(context.Background(), "rhaddon", "worker"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range h.api.byName {
		if n == "noo-wl-rhaddon-worker-scratch1" {
			found = true
		}
	}
	if !found {
		t.Errorf("by-name removals %v lack the exec volume", h.api.byName)
	}
	if _, ok := h.api.vols["noo-wl-rhaddon-worker-scratch1"]; ok {
		t.Error("the exec volume survived Deprovision")
	}
}

// T3c: release-then-recreate: the recreated worker's exec volume is a fresh
// one, and the old one was removed before the new worker was created.
func TestRecreateGivesAFreshExecVolume(t *testing.T) {
	h := newHarness(t)
	h.entry.Decl.Scratch = []nodewl.Scratch{{Target: "/exec", MaxMB: i64(64), Exec: true}}
	mustProvision(t, h)
	vn := "noo-wl-rhaddon-worker-scratch0"
	old, ok := h.api.vols[vn]
	if !ok {
		t.Fatal("the first create made no exec volume")
	}
	h.api.events = nil
	h.entry.Env["RHADDON_SLOTS"] = "2" // a spec change recreates the pair
	if err := h.provision(); err != nil {
		t.Fatal(err)
	}
	fresh, ok := h.api.vols[vn]
	if !ok || fresh == old {
		t.Errorf("exec volume generation %d -> %d (present %v): the old one survived the recreate", old, fresh, ok)
	}
	rm, create := -1, -1
	for i, c := range h.api.events {
		if c == "rmvol:"+vn && rm < 0 {
			rm = i
		}
		if c == "create:noo-wl-rhaddon-worker" {
			create = i
		}
	}
	if rm < 0 || create < 0 || rm > create {
		t.Errorf("events %v: the old exec volume must be removed before the worker is created", h.api.events)
	}
}

// A foreign same-named volume stops a recreate rather than being adopted.
func TestAForeignVolumeBlocksTheRecreate(t *testing.T) {
	h := newHarness(t)
	h.entry.Decl.Scratch = []nodewl.Scratch{{Target: "/exec", MaxMB: i64(64), Exec: true}}
	mustProvision(t, h)
	// fakeProv models the foreign verdict through a wrapper.
	fp := &foreignVol{fakeProv: h.api, name: "noo-wl-rhaddon-worker-scratch0"}
	h.p.api = fp
	h.entry.Env["RHADDON_SLOTS"] = "2"
	err := h.provision()
	var ne *nodewl.Error
	if err == nil || !errors.As(err, &ne) || ne.Code != nodewl.ReasonContainerConflict {
		t.Fatalf("err = %v", err)
	}
}

type foreignVol struct {
	*fakeProv
	name string
}

func (f *foreignVol) RemoveVolumeByName(_ context.Context, n string) (bool, error) {
	return n == f.name, nil
}
